# -*- coding: utf-8 -*-
"""
메시지 관리 모듈
"""

import logging
import threading
import os
import re
import sqlite3
import time
from datetime import datetime, timezone, timedelta

from app.models.base import get_db, safe_file_delete

try:
    from config import UPLOAD_FOLDER
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from config import UPLOAD_FOLDER

logger = logging.getLogger(__name__)

# 서버 통계
server_stats = {
    'start_time': None,
    'total_messages': 0,
    'total_connections': 0,
    'active_connections': 0
}
_stats_lock = threading.Lock()
_fts5_probe_lock = threading.Lock()
_fts5_probe_state = {'available': None, 'checked_at': 0.0}
_FTS5_PROBE_TTL_SECONDS = 60.0
_ws_split_re = re.compile(r'\s+')


def _fts5_available(cursor) -> bool:
    now = time.monotonic()
    with _fts5_probe_lock:
        cached = _fts5_probe_state.get('available')
        checked_at = float(_fts5_probe_state.get('checked_at') or 0.0)
        if cached is not None and (now - checked_at) < _FTS5_PROBE_TTL_SECONDS:
            return bool(cached)

    available = False
    try:
        cursor.execute("SELECT 1 FROM messages_fts LIMIT 1")
        cursor.fetchone()
        available = True
    except Exception:
        available = False

    with _fts5_probe_lock:
        _fts5_probe_state['available'] = bool(available)
        _fts5_probe_state['checked_at'] = now
    return available


def _fts5_build_query(text: str | None) -> str | None:
    raw = (text or '').strip()
    if not raw:
        return None
    parts = [p for p in _ws_split_re.split(raw) if p]
    if not parts:
        return None
    escaped = [p.replace('"', '""') for p in parts]
    return ' AND '.join([f'"{token}"' for token in escaped])


def update_server_stats(key, value=1, increment=True):
    """서버 통계 업데이트"""
    with _stats_lock:
        if increment:
            server_stats[key] += value
        else:
            server_stats[key] = value


def get_server_stats():
    """서버 통계 조회"""
    with _stats_lock:
        return server_stats.copy()


def _now_kst() -> str:
    kst = timezone(timedelta(hours=9))
    return datetime.now(kst).strftime('%Y-%m-%d %H:%M:%S')


def _normalize_client_msg_id(client_msg_id: str | None) -> str | None:
    if not isinstance(client_msg_id, str):
        return None
    normalized = client_msg_id.strip()[:64]
    return normalized or None


def _insert_message_row(
    cursor,
    *,
    room_id: int,
    sender_id: int,
    content: str,
    encrypted: bool,
    message_type: str,
    file_path: str | None,
    file_name: str | None,
    reply_to: int | None,
    client_msg_id: str | None,
    created_at: str,
) -> int:
    cursor.execute(
        '''
        INSERT INTO messages (
            room_id, sender_id, content, encrypted, message_type,
            file_path, file_name, client_msg_id, reply_to, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            room_id,
            sender_id,
            content,
            1 if encrypted else 0,
            message_type,
            file_path,
            file_name,
            client_msg_id,
            reply_to,
            created_at,
        ),
    )
    return int(cursor.lastrowid or 0)


def _get_message_with_sender(cursor, message_id: int) -> dict | None:
    cursor.execute(
        '''
        SELECT m.*, u.nickname as sender_name, u.profile_image as sender_image,
               rm.content as reply_content, ru.nickname as reply_sender
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        LEFT JOIN messages rm ON m.reply_to = rm.id AND rm.room_id = m.room_id
        LEFT JOIN users ru ON rm.sender_id = ru.id
        WHERE m.id = ?
        ''',
        (message_id,),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def get_message_by_client_msg_id(room_id: int, sender_id: int, client_msg_id: str) -> dict | None:
    """Idempotency lookup helper for client message IDs."""
    normalized = _normalize_client_msg_id(client_msg_id)
    if not normalized:
        return None
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            '''
            SELECT id
            FROM messages
            WHERE room_id = ? AND sender_id = ? AND client_msg_id = ?
            ORDER BY id DESC
            LIMIT 1
            ''',
            (room_id, sender_id, normalized),
        )
        row = cursor.fetchone()
        if not row:
            return None
        message = _get_message_with_sender(cursor, int(row['id']))
        if message:
            message['__created'] = False
        return message
    except Exception as e:
        logger.error(f"Get message by client_msg_id error: {e}")
        return None


def create_message(
    room_id,
    sender_id,
    content,
    message_type='text',
    file_path=None,
    file_name=None,
    reply_to=None,
    encrypted=True,
    client_msg_id: str | None = None,
):
    """메시지 생성"""
    now_kst = _now_kst()
    normalized_client_msg_id = _normalize_client_msg_id(client_msg_id)

    conn = get_db()
    cursor = conn.cursor()
    try:
        message_id = _insert_message_row(
            cursor,
            room_id=int(room_id),
            sender_id=int(sender_id),
            content=content,
            encrypted=bool(encrypted),
            message_type=message_type,
            file_path=file_path,
            file_name=file_name,
            reply_to=reply_to,
            client_msg_id=normalized_client_msg_id,
            created_at=now_kst,
        )
        conn.commit()
        message = _get_message_with_sender(cursor, message_id)

        update_server_stats('total_messages')

        if message:
            message['__created'] = True
        return message
    except sqlite3.IntegrityError as e:
        # Duplicate (room_id, sender_id, client_msg_id) replay -> return existing row.
        if normalized_client_msg_id:
            existing = get_message_by_client_msg_id(int(room_id), int(sender_id), normalized_client_msg_id)
            if existing:
                return existing
        logger.error(f"Create message integrity error: {e}")
        return None
    except Exception as e:
        logger.error(f"Create message error: {e}")
        return None


def create_file_message_with_record(
    room_id: int,
    sender_id: int,
    *,
    content: str,
    message_type: str,
    file_path: str,
    file_name: str | None = None,
    file_size: int | None = None,
    reply_to: int | None = None,
    client_msg_id: str | None = None,
) -> dict | None:
    """
    Atomically create a file/image message and its room_files row.
    Rolls back DB state and deletes uploaded file on failure.
    """
    now_kst = _now_kst()
    normalized_client_msg_id = _normalize_client_msg_id(client_msg_id)
    conn = get_db()
    cursor = conn.cursor()
    full_path = os.path.join(UPLOAD_FOLDER, file_path)
    try:
        message_id = _insert_message_row(
            cursor,
            room_id=int(room_id),
            sender_id=int(sender_id),
            content=content,
            encrypted=False,
            message_type=message_type,
            file_path=file_path,
            file_name=file_name,
            reply_to=reply_to,
            client_msg_id=normalized_client_msg_id,
            created_at=now_kst,
        )
        cursor.execute(
            '''
            INSERT INTO room_files (room_id, uploaded_by, file_path, file_name, file_size, file_type, message_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (room_id, sender_id, file_path, file_name or '', file_size, message_type, message_id),
        )
        conn.commit()
        message = _get_message_with_sender(cursor, message_id)
        update_server_stats('total_messages')
        if message:
            message['__created'] = True
        return message
    except sqlite3.IntegrityError as e:
        try:
            conn.rollback()
        except Exception:
            pass
        if normalized_client_msg_id:
            existing = get_message_by_client_msg_id(room_id, sender_id, normalized_client_msg_id)
            if existing:
                # Duplicate replay with a freshly uploaded file should not leak orphan files.
                safe_file_delete(full_path)
                return existing
        safe_file_delete(full_path)
        logger.error(f"Create file message integrity error: {e}")
        return None
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        safe_file_delete(full_path)
        logger.error(f"Create file message error: {e}")
        return None


def get_room_messages(room_id, limit=50, before_id=None, include_reactions=True):
    """대화방 메시지 조회"""
    from app.models.reactions import get_messages_reactions
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        if before_id:
            cursor.execute('''
                SELECT m.*, u.nickname as sender_name, u.profile_image as sender_image,
                       rm.content as reply_content, ru.nickname as reply_sender
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                LEFT JOIN messages rm ON m.reply_to = rm.id AND rm.room_id = m.room_id
                LEFT JOIN users ru ON rm.sender_id = ru.id
                WHERE m.room_id = ? AND m.id < ?
                ORDER BY m.id DESC
                LIMIT ?
            ''', (room_id, before_id, limit))
        else:
            cursor.execute('''
                SELECT m.*, u.nickname as sender_name, u.profile_image as sender_image,
                       rm.content as reply_content, ru.nickname as reply_sender
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                LEFT JOIN messages rm ON m.reply_to = rm.id AND rm.room_id = m.room_id
                LEFT JOIN users ru ON rm.sender_id = ru.id
                WHERE m.room_id = ?
                ORDER BY m.id DESC
                LIMIT ?
            ''', (room_id, limit))
        
        messages = cursor.fetchall()
        message_list = [dict(m) for m in reversed(messages)]
        
        if include_reactions and message_list:
            message_ids = [m['id'] for m in message_list]
            reactions_map = get_messages_reactions(message_ids)
            for msg in message_list:
                msg['reactions'] = reactions_map.get(msg['id'], [])
        
        return message_list
    except Exception as e:
        logger.error(f"Get room messages error: {e}")
        return []


def update_last_read(room_id, user_id, message_id):
    """마지막 읽은 메시지 업데이트"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE room_members SET last_read_message_id = ?
            WHERE room_id = ? AND user_id = ? AND last_read_message_id < ?
              AND EXISTS (
                  SELECT 1
                  FROM messages m
                  WHERE m.id = ? AND m.room_id = ?
              )
        ''', (message_id, room_id, user_id, message_id, message_id, room_id))
        conn.commit()
    except Exception as e:
        logger.error(f"Update last read error: {e}")


def get_unread_count(room_id, message_id, sender_id=None):
    """메시지를 읽지 않은 사람 수"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        if sender_id:
            cursor.execute('''
                SELECT COUNT(*) FROM room_members
                WHERE room_id = ? AND last_read_message_id < ? AND user_id != ?
            ''', (room_id, message_id, sender_id))
        else:
            cursor.execute('''
                SELECT COUNT(*) FROM room_members
                WHERE room_id = ? AND last_read_message_id < ?
            ''', (room_id, message_id))
        return cursor.fetchone()[0]
    except Exception as e:
        logger.error(f"Get unread count error: {e}")
        return 0


def get_room_last_reads(room_id: int):
    """대화방 멤버들의 마지막 읽은 메시지 ID 목록"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT last_read_message_id, user_id FROM room_members WHERE room_id = ?
        ''', (room_id,))
        return [(row[0] or 0, row[1]) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Get room last reads error: {e}")
        return []


def get_message_room_id(message_id: int):
    """메시지 ID로 대화방 ID 조회"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT room_id FROM messages WHERE id = ?', (message_id,))
        result = cursor.fetchone()
        return result['room_id'] if result else None
    except Exception as e:
        logger.error(f"Get message room_id error: {e}")
        return None


def delete_message(message_id, user_id):
    """메시지 삭제"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT sender_id, room_id, file_path FROM messages WHERE id = ?', (message_id,))
        msg = cursor.fetchone()
        if not msg or msg['sender_id'] != user_id:
            return False, "삭제 권한이 없습니다."
        
        cursor.execute("UPDATE messages SET content = '[삭제된 메시지]', encrypted = 0, file_path = NULL, file_name = NULL WHERE id = ?", (message_id,))
        
        if msg['file_path']:
            cursor.execute('DELETE FROM room_files WHERE file_path = ?', (msg['file_path'],))
             
        conn.commit()
        
        if msg['file_path']:
            full_path = os.path.join(UPLOAD_FOLDER, msg['file_path'])
            safe_file_delete(full_path)
        
        return True, msg['room_id']
    except Exception as e:
        logger.error(f"Delete message error: {e}")
        return False, "메시지 삭제 중 오류가 발생했습니다."


def edit_message(message_id, user_id, new_content):
    """메시지 수정"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT sender_id, room_id FROM messages WHERE id = ?', (message_id,))
        msg = cursor.fetchone()
        if not msg or msg['sender_id'] != user_id:
            return False, "수정 권한이 없습니다.", None
        
        cursor.execute("UPDATE messages SET content = ? WHERE id = ?", (new_content, message_id))
        conn.commit()
        return True, "", msg['room_id']
    except Exception as e:
        logger.error(f"Edit message error: {e}")
        return False, "메시지 수정 중 오류가 발생했습니다.", None


def search_messages(user_id, query, offset=0, limit=50):
    """메시지 검색 - 암호화되지 않은 메시지 기준"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        q = (query or '').strip()
        if not q:
            return {'messages': [], 'total': 0, 'offset': offset, 'limit': limit, 'has_more': False}
        fts_query = _fts5_build_query(q)

        if fts_query and _fts5_available(cursor):
            cursor.execute('''
                SELECT COUNT(*)
                FROM messages_fts f
                JOIN room_members rm ON rm.room_id = f.room_id
                WHERE rm.user_id = ? AND f.content MATCH ?
            ''', (user_id, fts_query))
            total_count = cursor.fetchone()[0]

            cursor.execute('''
                WITH hits AS (
                    SELECT rowid AS id, bm25(messages_fts) AS rank
                    FROM messages_fts
                    WHERE content MATCH ?
                )
                SELECT m.*, r.name as room_name, u.nickname as sender_name
                FROM hits h
                JOIN messages m ON m.id = h.id
                JOIN rooms r ON m.room_id = r.id
                JOIN room_members rm ON r.id = rm.room_id AND rm.user_id = ?
                JOIN users u ON m.sender_id = u.id
                WHERE m.encrypted = 0
                ORDER BY h.rank ASC, m.created_at DESC
                LIMIT ? OFFSET ?
            ''', (fts_query, user_id, limit, offset))
            messages = [dict(m) for m in cursor.fetchall()]

            return {
                'messages': messages,
                'total': total_count,
                'offset': offset,
                'limit': limit,
                'has_more': offset + len(messages) < total_count,
                'note': '\uc554\ud638\ud654\ub41c \uba54\uc2dc\uc9c0\ub294 \uc11c\ubc84 \uac80\uc0c9\uc5d0\uc11c \uc81c\uc678\ub429\ub2c8\ub2e4.',
            }

        cursor.execute('''
            SELECT COUNT(DISTINCT m.id)
            FROM messages m
            JOIN rooms r ON m.room_id = r.id
            JOIN room_members rm ON r.id = rm.room_id
            WHERE rm.user_id = ? AND m.encrypted = 0 AND m.content LIKE ?
        ''', (user_id, f'%{query}%'))
        total_count = cursor.fetchone()[0]

        cursor.execute('''
            SELECT m.*, r.name as room_name, u.nickname as sender_name
            FROM messages m
            JOIN rooms r ON m.room_id = r.id
            JOIN room_members rm ON r.id = rm.room_id
            JOIN users u ON m.sender_id = u.id
            WHERE rm.user_id = ? AND m.encrypted = 0 AND m.content LIKE ?
            ORDER BY m.created_at DESC
            LIMIT ? OFFSET ?
        ''', (user_id, f'%{query}%', limit, offset))
        messages = [dict(m) for m in cursor.fetchall()]

        return {
            'messages': messages,
            'total': total_count,
            'offset': offset,
            'limit': limit,
            'has_more': offset + len(messages) < total_count,
            'note': '\uc554\ud638\ud654\ub41c \uba54\uc2dc\uc9c0\ub294 \uc11c\ubc84 \uac80\uc0c9\uc5d0\uc11c \uc81c\uc678\ub429\ub2c8\ub2e4.',
        }
    except Exception as e:
        logger.error(f"Search messages error: {e}")
        return {'messages': [], 'total': 0, 'offset': 0, 'limit': limit, 'has_more': False}


def advanced_search(user_id: int, query: str = None, room_id: int = None,
                    sender_id: int = None, date_from: str = None, date_to: str = None,
                    file_only: bool = False, limit: int = 50, offset: int = 0):
    """고급 메시지 검색 - FTS 또는 LIKE 기반"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        def _like_escape(text: str) -> str:
            # Escape for SQLite LIKE with ESCAPE '\'
            return (text or '').replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')

        conditions = ['rm.user_id = ?']
        params = [user_id]

        if room_id:
            conditions.append('m.room_id = ?')
            params.append(room_id)
        if sender_id:
            conditions.append('m.sender_id = ?')
            params.append(sender_id)
        if date_from:
            conditions.append('m.created_at >= ?')
            params.append(date_from)
        if date_to:
            conditions.append('m.created_at <= ?')
            params.append(date_to)

        if file_only:
            conditions.append("m.message_type IN ('file', 'image')")
            if query:
                # Optimize file name search:
                # 1) Prefer prefix match (uses idx_messages_file_name)
                # 2) Fallback to contains match (still supported)
                q = _like_escape(query.strip())
                if q:
                    where_base = ' AND '.join(conditions)

                    prefix = f'{q}%'
                    contains = f'%{q}%'

                    # Count
                    count_params = params.copy() + [prefix] + params.copy() + [contains, prefix]
                    cursor.execute(f'''
                        SELECT COUNT(DISTINCT id) FROM (
                            SELECT m.id AS id
                            FROM messages m
                            JOIN rooms r ON m.room_id = r.id
                            JOIN room_members rm ON r.id = rm.room_id
                            WHERE {where_base}
                              AND m.file_name LIKE ? ESCAPE '\\'
                            UNION ALL
                            SELECT m.id AS id
                            FROM messages m
                            JOIN rooms r ON m.room_id = r.id
                            JOIN room_members rm ON r.id = rm.room_id
                            WHERE {where_base}
                              AND m.file_name LIKE ? ESCAPE '\\'
                              AND m.file_name NOT LIKE ? ESCAPE '\\'
                        ) t
                    ''', count_params)
                    total_count = cursor.fetchone()[0]

                    list_params = params.copy() + [prefix] + params.copy() + [contains, prefix, limit, offset]
                    cursor.execute(f'''
                        SELECT * FROM (
                            SELECT m.*, r.name as room_name, u.nickname as sender_name
                            FROM messages m
                            JOIN rooms r ON m.room_id = r.id
                            JOIN room_members rm ON r.id = rm.room_id
                            JOIN users u ON m.sender_id = u.id
                            WHERE {where_base}
                              AND m.file_name LIKE ? ESCAPE '\\'
                            UNION ALL
                            SELECT m.*, r.name as room_name, u.nickname as sender_name
                            FROM messages m
                            JOIN rooms r ON m.room_id = r.id
                            JOIN room_members rm ON r.id = rm.room_id
                            JOIN users u ON m.sender_id = u.id
                            WHERE {where_base}
                              AND m.file_name LIKE ? ESCAPE '\\'
                              AND m.file_name NOT LIKE ? ESCAPE '\\'
                        )
                        ORDER BY created_at DESC
                        LIMIT ? OFFSET ?
                    ''', list_params)

                    messages = [dict(r) for r in cursor.fetchall()]
                    return {
                        'messages': messages,
                        'total': total_count,
                        'offset': offset,
                        'limit': limit,
                        'has_more': offset + len(messages) < total_count,
                    }
        else:
            if query:
                conditions.append('m.encrypted = 0')

                fts_query = _fts5_build_query(query)
                if fts_query and _fts5_available(cursor):
                    where_clause = ' AND '.join(conditions)

                    count_params = [fts_query] + params.copy()
                    cursor.execute(f'''
                        WITH hits AS (
                            SELECT rowid AS id, bm25(messages_fts) AS rank
                            FROM messages_fts
                            WHERE content MATCH ?
                        )
                        SELECT COUNT(DISTINCT m.id)
                        FROM hits h
                        JOIN messages m ON m.id = h.id
                        JOIN rooms r ON m.room_id = r.id
                        JOIN room_members rm ON r.id = rm.room_id
                        WHERE {where_clause}
                    ''', count_params)
                    total_count = cursor.fetchone()[0]

                    list_params = [fts_query] + params + [limit, offset]
                    cursor.execute(f'''
                        WITH hits AS (
                            SELECT rowid AS id, bm25(messages_fts) AS rank
                            FROM messages_fts
                            WHERE content MATCH ?
                        )
                        SELECT m.*, r.name as room_name, u.nickname as sender_name
                        FROM hits h
                        JOIN messages m ON m.id = h.id
                        JOIN rooms r ON m.room_id = r.id
                        JOIN room_members rm ON r.id = rm.room_id
                        JOIN users u ON m.sender_id = u.id
                        WHERE {where_clause}
                        ORDER BY h.rank ASC, m.created_at DESC
                        LIMIT ? OFFSET ?
                    ''', list_params)

                    messages = [dict(r) for r in cursor.fetchall()]
                    out = {
                        'messages': messages,
                        'total': total_count,
                        'offset': offset,
                        'limit': limit,
                        'has_more': offset + len(messages) < total_count,
                        'note': '\uc554\ud638\ud654\ub41c \uba54\uc2dc\uc9c0\ub294 \uc11c\ubc84 \uac80\uc0c9\uc5d0\uc11c \uc81c\uc678\ub429\ub2c8\ub2e4.',
                    }
                    return out

                # FTS5 unavailable -> fallback to LIKE
                conditions.append('m.content LIKE ?')
                params.append(f'%{query}%')

        where_clause = ' AND '.join(conditions)

        count_params = params.copy()
        cursor.execute(f'''
            SELECT COUNT(DISTINCT m.id)
            FROM messages m
            JOIN rooms r ON m.room_id = r.id
            JOIN room_members rm ON r.id = rm.room_id
            WHERE {where_clause}
        ''', count_params)
        total_count = cursor.fetchone()[0]

        params.extend([limit, offset])
        cursor.execute(f'''
            SELECT m.*, r.name as room_name, u.nickname as sender_name
            FROM messages m
            JOIN rooms r ON m.room_id = r.id
            JOIN room_members rm ON r.id = rm.room_id
            JOIN users u ON m.sender_id = u.id
            WHERE {where_clause}
            ORDER BY m.created_at DESC
            LIMIT ? OFFSET ?
        ''', params)

        messages = [dict(r) for r in cursor.fetchall()]
        out = {
            'messages': messages,
            'total': total_count,
            'offset': offset,
            'limit': limit,
            'has_more': offset + len(messages) < total_count
        }
        if query and not file_only:
            out['note'] = '\uc554\ud638\ud654\ub41c \uba54\uc2dc\uc9c0\ub294 \uc11c\ubc84 \uac80\uc0c9\uc5d0\uc11c \uc81c\uc678\ub429\ub2c8\ub2e4.'
        return out
    except Exception as e:
        logger.error(f"Advanced search error: {e}")
        return {'messages': [], 'total': 0, 'offset': 0, 'limit': limit, 'has_more': False}
def pin_message(room_id: int, pinned_by: int, message_id: int = None, content: str = None):
    """메시지 고정"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO pinned_messages (room_id, message_id, content, pinned_by)
            VALUES (?, ?, ?, ?)
        ''', (room_id, message_id, content, pinned_by))
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        logger.error(f"Pin message error: {e}")
        return None


def unpin_message(pin_id: int, user_id: int, room_id: int = None):
    """공지 해제"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT pinned_by, room_id FROM pinned_messages WHERE id = ?', (pin_id,))
        pin = cursor.fetchone()
        if not pin:
            return False, "공지를 찾을 수 없습니다."

        if room_id is not None and pin['room_id'] != room_id:
            return False, "요청한 대화방과 공지의 대화방이 일치하지 않습니다."
        
        cursor.execute('DELETE FROM pinned_messages WHERE id = ?', (pin_id,))
        if cursor.rowcount < 1:
            conn.rollback()
            return False, "공지를 해제하지 못했습니다."
        conn.commit()
        return True, None
    except Exception as e:
        logger.error(f"Unpin message error: {e}")
        return False, "공지 해제 중 오류가 발생했습니다."


def get_pinned_messages(room_id: int):
    """고정된 메시지 목록"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            SELECT pm.*, u.nickname as pinned_by_name,
                   m.content as message_content, m.sender_id as message_sender_id
            FROM pinned_messages pm
            JOIN users u ON pm.pinned_by = u.id
            LEFT JOIN messages m ON pm.message_id = m.id
            WHERE pm.room_id = ?
            ORDER BY pm.pinned_at DESC
        ''', (room_id,))
        return [dict(p) for p in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Get pinned messages error: {e}")
        return []

# -*- coding: utf-8 -*-
"""
업로드 토큰 저장소

DB 기반 토큰 저장으로 내구성(서버 재시작) 및 멀티 워커 호환성을 확보한다.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import sqlite3
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

TOKEN_TTL_SECONDS = 300  # 5 minutes
CONSUMED_TOKEN_RETENTION_SECONDS = 600  # 10 minutes
ORPHAN_FILE_GRACE_SECONDS = 1800  # 30 minutes


def _get_db():
    import app.models.base as base_module
    return base_module.get_db()


def _safe_file_delete(path: str) -> bool:
    import app.models.base as base_module
    return base_module.safe_file_delete(path)


def _get_upload_folder() -> str:
    fallback = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'uploads')
    candidates: list[str] = []

    # 테스트/스크립트 환경에서는 config 모듈 값이 가장 신뢰 가능하다.
    try:
        import config  # type: ignore

        folder = str(getattr(config, 'UPLOAD_FOLDER', '') or '').strip()
        if folder:
            candidates.append(folder)
    except Exception:
        pass

    try:
        from flask import current_app

        folder = str(current_app.config.get('UPLOAD_FOLDER') or '').strip()
        if folder:
            candidates.append(folder)
    except Exception:
        pass

    candidates.append(fallback)

    normalized: list[str] = []
    seen: set[str] = set()
    for folder in candidates:
        real_folder = os.path.realpath(os.path.abspath(folder))
        if real_folder in seen:
            continue
        seen.add(real_folder)
        normalized.append(real_folder)

    for folder in normalized:
        if os.path.isdir(folder):
            return folder
    return normalized[0] if normalized else os.path.realpath(os.path.abspath(fallback))


def _now_ts() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _ts_after(seconds: int) -> str:
    return (datetime.now() + timedelta(seconds=max(0, int(seconds)))).strftime('%Y-%m-%d %H:%M:%S')


def _ts_before(seconds: int) -> str:
    return (datetime.now() - timedelta(seconds=max(0, int(seconds)))).strftime('%Y-%m-%d %H:%M:%S')


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def _normalize_rel_path(path: str) -> str:
    return str(path or '').replace('\\', '/').strip('/')


def _ensure_upload_token_table(conn) -> None:
    cursor = conn.cursor()
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS upload_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL,
            room_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_type TEXT,
            file_size INTEGER,
            issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            consumed_at TIMESTAMP
        )
        '''
    )
    cursor.execute(
        'CREATE INDEX IF NOT EXISTS idx_upload_tokens_expires_at '
        'ON upload_tokens(expires_at)'
    )
    cursor.execute(
        'CREATE INDEX IF NOT EXISTS idx_upload_tokens_consumed_at '
        'ON upload_tokens(consumed_at)'
    )
    cursor.execute(
        'CREATE INDEX IF NOT EXISTS idx_upload_tokens_room_user '
        'ON upload_tokens(room_id, user_id)'
    )
    conn.commit()


def purge_expired_upload_tokens(*, retain_consumed_seconds: int | None = None) -> int:
    """만료 토큰/오래된 consumed 토큰 정리"""
    conn = _get_db()
    _ensure_upload_token_table(conn)
    cursor = conn.cursor()
    now = _now_ts()
    retain = CONSUMED_TOKEN_RETENTION_SECONDS if retain_consumed_seconds is None else retain_consumed_seconds
    consumed_cutoff = _ts_before(retain)
    cursor.execute(
        '''
        DELETE FROM upload_tokens
        WHERE expires_at <= ?
           OR (consumed_at IS NOT NULL AND consumed_at <= ?)
        ''',
        (now, consumed_cutoff),
    )
    removed = int(cursor.rowcount or 0)
    conn.commit()
    return removed


def issue_upload_token(
    user_id: int,
    room_id: int,
    file_path: str,
    file_name: str,
    file_type: str,
    file_size: int,
) -> str:
    """업로드 토큰 발급"""
    purge_expired_upload_tokens()
    conn = _get_db()
    _ensure_upload_token_table(conn)
    cursor = conn.cursor()
    normalized_path = _normalize_rel_path(file_path)
    expires_at = _ts_after(TOKEN_TTL_SECONDS)

    # 매우 드문 해시 충돌/중복에 대비한 재시도
    for _ in range(5):
        token = secrets.token_urlsafe(32)
        token_hash = _hash_token(token)
        try:
            cursor.execute(
                '''
                INSERT INTO upload_tokens (
                    token_hash, user_id, room_id, file_path, file_name, file_type, file_size, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    token_hash,
                    int(user_id),
                    int(room_id),
                    normalized_path,
                    str(file_name or ''),
                    str(file_type or ''),
                    int(file_size or 0),
                    expires_at,
                ),
            )
            conn.commit()
            return token
        except sqlite3.IntegrityError:
            continue
        except Exception as e:
            logger.error(f"Issue upload token error: {e}")
            break
    return ''


def _get_token_row_by_hash(conn, token_hash: str):
    cursor = conn.cursor()
    cursor.execute(
        '''
        SELECT id, user_id, room_id, file_path, file_name, file_type, file_size, expires_at, consumed_at
        FROM upload_tokens
        WHERE token_hash = ?
        LIMIT 1
        ''',
        (token_hash,),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def get_upload_token_failure_reason(
    token: str,
    user_id: int,
    room_id: int,
    expected_type: str = None,
) -> str:
    """업로드 토큰 검증 실패 사유 조회 (소비하지 않음)"""
    if not token or not isinstance(token, str):
        return '업로드 토큰이 필요합니다.'

    conn = _get_db()
    _ensure_upload_token_table(conn)
    token_row = _get_token_row_by_hash(conn, _hash_token(token))
    if not token_row:
        return '업로드 토큰이 유효하지 않습니다.'

    now = _now_ts()
    if token_row.get('consumed_at'):
        return '업로드 토큰이 이미 사용되었거나 만료되었습니다.'
    if str(token_row.get('expires_at') or '') <= now:
        try:
            conn.execute('DELETE FROM upload_tokens WHERE id = ?', (int(token_row['id']),))
            conn.commit()
        except Exception:
            pass
        return '업로드 토큰이 만료되었습니다.'
    if int(token_row.get('user_id') or 0) != int(user_id):
        return '업로드 토큰 사용자 정보가 일치하지 않습니다.'
    if int(token_row.get('room_id') or 0) != int(room_id):
        return '업로드 토큰의 대화방 정보가 일치하지 않습니다.'
    if expected_type and str(token_row.get('file_type') or '') not in ('', expected_type):
        return '업로드 토큰 파일 유형이 일치하지 않습니다.'

    full_path = os.path.join(_get_upload_folder(), str(token_row.get('file_path') or ''))
    if not os.path.isfile(full_path):
        try:
            conn.execute('DELETE FROM upload_tokens WHERE id = ?', (int(token_row['id']),))
            conn.commit()
        except Exception:
            pass
        return '업로드 파일을 찾을 수 없습니다.'
    return ''


def consume_upload_token(
    token: str,
    user_id: int,
    room_id: int,
    expected_type: str = None,
):
    """업로드 토큰 1회 소비"""
    if not token or not isinstance(token, str):
        return None

    conn = _get_db()
    _ensure_upload_token_table(conn)
    cursor = conn.cursor()
    now = _now_ts()
    token_hash = _hash_token(token)

    try:
        conn.execute('BEGIN IMMEDIATE')
    except Exception:
        pass

    try:
        row = _get_token_row_by_hash(conn, token_hash)
        if not row:
            conn.rollback()
            return None

        if row.get('consumed_at'):
            conn.rollback()
            return None
        if str(row.get('expires_at') or '') <= now:
            cursor.execute('DELETE FROM upload_tokens WHERE id = ?', (int(row['id']),))
            conn.commit()
            return None
        if int(row.get('user_id') or 0) != int(user_id):
            conn.rollback()
            return None
        if int(row.get('room_id') or 0) != int(room_id):
            conn.rollback()
            return None
        if expected_type and str(row.get('file_type') or '') not in ('', expected_type):
            conn.rollback()
            return None

        full_path = os.path.join(_get_upload_folder(), str(row.get('file_path') or ''))
        if not os.path.isfile(full_path):
            cursor.execute('DELETE FROM upload_tokens WHERE id = ?', (int(row['id']),))
            conn.commit()
            return None

        cursor.execute(
            '''
            UPDATE upload_tokens
            SET consumed_at = ?
            WHERE id = ? AND consumed_at IS NULL
            ''',
            (now, int(row['id'])),
        )
        if int(cursor.rowcount or 0) < 1:
            conn.rollback()
            return None
        conn.commit()
        return {
            'user_id': int(row['user_id']),
            'room_id': int(row['room_id']),
            'file_path': str(row['file_path'] or ''),
            'file_name': str(row['file_name'] or ''),
            'file_type': str(row.get('file_type') or ''),
            'file_size': int(row.get('file_size') or 0),
        }
    except Exception as e:
        logger.error(f"Consume upload token error: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return None


def cleanup_orphan_upload_files(*, grace_seconds: int | None = None) -> int:
    """
    room_files / active upload_tokens 어디에도 추적되지 않는 업로드 파일 정리.
    profiles 폴더는 제외한다.
    """
    purge_expired_upload_tokens()
    conn = _get_db()
    _ensure_upload_token_table(conn)
    cursor = conn.cursor()
    now = datetime.now()
    grace = ORPHAN_FILE_GRACE_SECONDS if grace_seconds is None else max(0, int(grace_seconds))
    cutoff = now - timedelta(seconds=grace)

    tracked_paths: set[str] = set()
    cursor.execute('SELECT file_path FROM room_files')
    tracked_paths.update(_normalize_rel_path(row['file_path']) for row in cursor.fetchall() if row['file_path'])

    cursor.execute(
        '''
        SELECT file_path
        FROM upload_tokens
        WHERE consumed_at IS NULL AND expires_at > ?
        ''',
        (_now_ts(),),
    )
    tracked_paths.update(_normalize_rel_path(row['file_path']) for row in cursor.fetchall() if row['file_path'])
    held_paths: set[str] = set()
    try:
        cursor.execute(
            '''
            SELECT target_id
            FROM legal_holds
            WHERE hold_type = 'file_path'
              AND active = 1
            '''
        )
        held_paths.update(_normalize_rel_path(row['target_id']) for row in cursor.fetchall() if row['target_id'])
    except Exception:
        # legal_holds table may not exist on very old snapshots
        held_paths = set()

    removed = 0
    upload_root = os.path.realpath(_get_upload_folder())
    if not os.path.isdir(upload_root):
        return 0

    for root, dirs, files in os.walk(upload_root):
        rel_dir = os.path.relpath(root, upload_root).replace('\\', '/')
        if rel_dir == '.':
            rel_dir = ''

        # 프로필 이미지는 수명주기 정책이 다르므로 제외
        dirs[:] = [d for d in dirs if _normalize_rel_path(os.path.join(rel_dir, d)) != 'profiles']
        if rel_dir.startswith('profiles'):
            continue

        for name in files:
            if name == '.gitkeep':
                continue
            rel_path = _normalize_rel_path(os.path.join(rel_dir, name))
            if rel_path in tracked_paths:
                continue
            if rel_path in held_paths:
                continue

            full_path = os.path.join(root, name)
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(full_path))
            except Exception:
                mtime = now
            if mtime > cutoff:
                continue

            if _safe_file_delete(full_path):
                removed += 1
    if removed > 0:
        logger.info(f"Cleaned up {removed} orphan upload files")
    return removed

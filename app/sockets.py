# -*- coding: utf-8 -*-
"""
Socket.IO 이벤트 핸들러 (성능 최적화 버전)
"""

import logging
import time
import traceback
from threading import Lock
from flask import session, request, current_app
from flask_socketio import emit, join_room, leave_room

from app.api_response import build_socket_error_payload
from app.i18n import resolve_socket_locale
from app.models import (
    update_user_status, get_user_by_id, is_room_member, is_room_admin,
    create_message, create_file_message_with_record, update_last_read, server_stats,
    get_user_rooms, edit_message, delete_message,
    get_user_session_token, get_message_room_id, get_message_reactions, get_message_by_client_msg_id,
    get_poll, get_pinned_messages, get_room_admins
)
from app.upload_tokens import consume_upload_token, get_upload_token_failure_reason
try:
    from config import REQUIRE_MESSAGE_ENCRYPTION
except ImportError:
    REQUIRE_MESSAGE_ENCRYPTION = False

logger = logging.getLogger(__name__)

# 온라인 사용자 관리
online_users = {}  # {sid: user_id}
user_sids = {}     # {user_id: [sid1, sid2, ...]} - 다중 세션 지원
online_users_lock = Lock()
stats_lock = Lock()
_socketio_instance = None

# 사용자별 캐시 (닉네임, 방 목록)
user_cache = {}  # {user_id: {'nickname': str, 'rooms': [int], 'updated': float}}
cache_lock = Lock()
MAX_CACHE_SIZE = 1000  # [v4.1] 최대 캐시 크기
CACHE_TTL = 300  # [v4.1] 캐시 유효 시간 (5분)

# [v4.14] 타이핑 이벤트 레이트 리미팅
typing_last_emit = {}  # {(user_id, room_id): timestamp}
typing_rate_lock = Lock()
TYPING_RATE_LIMIT = 1.0  # 최소 1초 간격


def _emit_error_i18n(message_ko: str, *, code: str | None = None, key: str | None = None) -> None:
    locale_code = resolve_socket_locale(request)
    payload = build_socket_error_payload(
        message_ko,
        locale_code=locale_code,
        explicit_code=code,
        explicit_key=key,
    )
    emit('error', payload)


def cleanup_old_cache():
    """오래된 캐시 항목 정리 (메모리 누수 방지)"""
    current_time = time.time()
    expired_keys = []
    
    with cache_lock:
        # 10분 이상 된 캐시 항목 식별
        for user_id, data in user_cache.items():
            if current_time - data.get('updated', 0) > 600:  # 10분
                expired_keys.append(user_id)
        
        # 만료된 항목 삭제
        for key in expired_keys:
            del user_cache[key]
        
        # 캐시 크기 제한 (FIFO 방식)
        if len(user_cache) > MAX_CACHE_SIZE:
            sorted_items = sorted(user_cache.items(), key=lambda x: x[1].get('updated', 0))
            to_remove = len(user_cache) - MAX_CACHE_SIZE
            for i in range(to_remove):
                del user_cache[sorted_items[i][0]]
    
    if expired_keys:
        logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")


def get_user_room_ids(user_id):
    """사용자의 방 ID 목록 (캐시 사용)"""
    with cache_lock:
        cached = user_cache.get(user_id)
        # 캐시가 있고 TTL 이내면 사용
        if cached and (time.time() - cached.get('updated', 0)) < CACHE_TTL:
            if 'room_set' not in cached:
                cached['room_set'] = set(cached.get('rooms') or [])
            return cached.get('rooms', [])
    
    # 캐시 없거나 만료되면 DB에서 조회
    try:
        rooms = get_user_rooms(user_id)
        room_ids = [r['id'] for r in rooms]
        
        with cache_lock:
            # 캐시 정리 (주기적으로)
            if len(user_cache) > MAX_CACHE_SIZE // 2:
                cleanup_old_cache()
            
            if user_id not in user_cache:
                user_cache[user_id] = {}
            user_cache[user_id]['rooms'] = room_ids
            user_cache[user_id]['room_set'] = set(room_ids)
            user_cache[user_id]['updated'] = time.time()
        
        return room_ids
    except Exception as e:
        logger.error(f"Get user rooms error: {e}")
        return []


def invalidate_user_cache(user_id):
    """사용자 캐시 무효화"""
    with cache_lock:
        if user_id in user_cache:
            del user_cache[user_id]


def get_user_room_id_set(user_id: int) -> set[int]:
    """사용자의 방 ID 집합 (멤버십 체크 핫패스 최적화)"""
    with cache_lock:
        cached = user_cache.get(user_id)
        if cached and (time.time() - cached.get('updated', 0)) < CACHE_TTL:
            room_set = cached.get('room_set')
            if isinstance(room_set, set):
                return set(room_set)
            rebuilt = set(cached.get('rooms') or [])
            cached['room_set'] = rebuilt
            return set(rebuilt)
    return set(get_user_room_ids(user_id))


def user_has_room_access(user_id: int, room_id: int) -> bool:
    """
    Fast membership check:
    1) cache hit path
    2) DB fallback on cache miss
    3) refresh cache when DB says member
    """
    try:
        normalized_user_id = int(user_id)
        normalized_room_id = int(room_id)
    except (TypeError, ValueError):
        return False
    if normalized_user_id <= 0 or normalized_room_id <= 0:
        return False

    allowed_room_ids = get_user_room_id_set(normalized_user_id)
    if normalized_room_id in allowed_room_ids:
        return True

    if not is_room_member(normalized_room_id, normalized_user_id):
        return False

    invalidate_user_cache(normalized_user_id)
    refreshed = get_user_room_id_set(normalized_user_id)
    return normalized_room_id in refreshed


def force_remove_user_from_room(user_id: int, room_id: int) -> int:
    """
    Force all active sockets of a user to leave a room immediately.
    Used by REST leave/kick paths to close the membership/socket timing gap.
    """
    try:
        normalized_user_id = int(user_id)
        normalized_room_id = int(room_id)
    except (TypeError, ValueError):
        return 0
    if normalized_user_id <= 0 or normalized_room_id <= 0:
        return 0

    socketio_instance = _socketio_instance
    if socketio_instance is None:
        return 0

    with online_users_lock:
        sid_list = list(user_sids.get(normalized_user_id, []))
    if not sid_list:
        invalidate_user_cache(normalized_user_id)
        return 0

    room_name = f'room_{normalized_room_id}'
    removed = 0
    for sid in sid_list:
        try:
            socketio_instance.server.leave_room(  # type: ignore[attr-defined]
                sid=sid,
                room=room_name,
                namespace='/',
            )
            removed += 1
        except TypeError:
            try:
                socketio_instance.server.leave_room(sid, room_name)  # type: ignore[attr-defined]
                removed += 1
            except Exception:
                pass
        except Exception:
            pass

    invalidate_user_cache(normalized_user_id)
    return removed


def register_socket_events(socketio):
    """Socket.IO 이벤트 등록"""
    global _socketio_instance
    _socketio_instance = socketio
    
    @socketio.on('connect')
    def handle_connect():
        if 'user_id' not in session:
            return False

        user_id = session['user_id']
        current_token = get_user_session_token(user_id)
        if current_token and session.get('session_token') != current_token:
            return False

        with online_users_lock:
            online_users[request.sid] = user_id
            if user_id not in user_sids:
                user_sids[user_id] = []
            user_sids[user_id].append(request.sid)
            was_offline = len(user_sids[user_id]) == 1

        # Personal channel for direct user-targeted events.
        try:
            join_room(f'user_{int(user_id)}')
        except Exception:
            pass

        # Join all my rooms so this client receives room events without polling.
        room_ids = get_user_room_ids(user_id)
        for room_id in room_ids:
            try:
                join_room(f'room_{room_id}')
            except Exception:
                pass

        # 첫 연결일 때만 상태 업데이트
        if was_offline:
            update_user_status(user_id, 'online')
            # 해당 사용자의 방에만 상태 전송 (broadcast 대신)
            for room_id in room_ids:
                emit('user_status', {'user_id': user_id, 'status': 'online'},
                     room=f'room_{room_id}')

        with stats_lock:
            server_stats['total_connections'] += 1
            server_stats['active_connections'] += 1
            # [v4.22] 100개 연결마다 캐시 정리 (메모리 누수 방지)
            should_cleanup = server_stats['total_connections'] % 100 == 0

        if should_cleanup:
            cleanup_old_cache()
    
    @socketio.on('disconnect')
    def handle_disconnect():
        user_id = None
        still_online = False
        room_ids = []  # [v4.2] 락 내에서 미리 저장
        
        with online_users_lock:
            user_id = online_users.pop(request.sid, None)
            if user_id and user_id in user_sids:
                if request.sid in user_sids[user_id]:
                    user_sids[user_id].remove(request.sid)
                still_online = len(user_sids[user_id]) > 0
                if not still_online:
                    del user_sids[user_id]
                    # [v4.2] 락 내에서 방 목록 캐시 복사
                    if user_id in user_cache:
                        room_ids = user_cache[user_id].get('rooms', []).copy()
        
        # [v4.2] 락 해제 후 DB 작업 및 브로드캐스트 (락 내에서 가져온 정보 사용)
        if user_id and not still_online:
            update_user_status(user_id, 'offline')
            # 캐시가 없었으면 DB에서 조회
            if not room_ids:
                room_ids = get_user_room_ids(user_id)
            try:
                for room_id in room_ids:
                    emit('user_status', {'user_id': user_id, 'status': 'offline'}, 
                         room=f'room_{room_id}')
            except Exception as e:
                logger.error(f"Disconnect broadcast error: {e}")
            
            # [v4.15] 사용자의 타이핑 레이트 리밋 정보 정리 (메모리 누수 방지)
            with typing_rate_lock:
                keys_to_remove = [k for k in typing_last_emit if k[0] == user_id]
                for k in keys_to_remove:
                    del typing_last_emit[k]
        
        with stats_lock:
            server_stats['active_connections'] = max(0, server_stats['active_connections'] - 1)
    
    @socketio.on('subscribe_rooms')
    def handle_subscribe_rooms(data):
        try:
            if 'user_id' not in session:
                return

            room_ids = data.get('room_ids') if isinstance(data, dict) else None
            if not isinstance(room_ids, list):
                return

            room_ids = [rid for rid in room_ids if isinstance(rid, int) and rid > 0]
            if not room_ids:
                return

            user_id = session['user_id']
            allowed = get_user_room_id_set(user_id)
            for rid in room_ids:
                if rid in allowed:
                    join_room(f'room_{rid}')
                    continue

                # Cache can be stale right after room creation/invite; fallback to DB check.
                if user_has_room_access(user_id, rid):
                    join_room(f'room_{rid}')
        except Exception as e:
            logger.error(f"Subscribe rooms error: {e}")

    @socketio.on('join_room')
    def handle_join_room(data):
        try:
            room_id = data.get('room_id') if isinstance(data, dict) else None
            if room_id and 'user_id' in session:
                try:
                    normalized_room_id = int(room_id)
                except (TypeError, ValueError):
                    normalized_room_id = 0
                if normalized_room_id <= 0:
                    _emit_error_i18n('잘못된 대화방 ID입니다.')
                    return
                if user_has_room_access(session['user_id'], normalized_room_id):
                    join_room(f'room_{normalized_room_id}')
                    emit('joined_room', {'room_id': normalized_room_id})
                else:
                    _emit_error_i18n('대화방 접근 권한이 없습니다.')
        except Exception as e:
            logger.error(f"Join room error: {e}")
    
    @socketio.on('leave_room')
    def handle_leave_room(data):
        try:
            room_id = data.get('room_id')
            if room_id:
                leave_room(f'room_{room_id}')
                # 캐시 무효화
                if 'user_id' in session:
                    invalidate_user_cache(session['user_id'])
        except Exception as e:
            logger.error(f"Leave room error: {e}")
    
    @socketio.on('send_message')
    def handle_send_message(data):
        try:
            if not isinstance(data, dict):
                data = {}
            if 'user_id' not in session:
                _emit_error_i18n('로그인이 필요합니다.')
                return {'ok': False, 'error': '로그인이 필요합니다.'}
            
            # [v4.2] 입력 유효성 검사 강화
            room_id = data.get('room_id')
            if not isinstance(room_id, int) or room_id <= 0:
                _emit_error_i18n('잘못된 대화방 ID입니다.')
                return {'ok': False, 'error': '잘못된 대화방 ID입니다.'}
            
            content = data.get('content', '')
            if isinstance(content, str):
                content = content.strip()
            else:
                content = ''
            
            message_type = data.get('type', 'text')
            if message_type == 'system':
                _emit_error_i18n('잘못된 요청입니다.')
                return {'ok': False, 'error': '잘못된 요청입니다.'}
            # 허용된 메시지 타입만 사용 (system은 서버 내부 이벤트 전용)
            allowed_types = {'text', 'file', 'image'}
            if message_type not in allowed_types:
                message_type = 'text'
            
            file_path = None
            file_name = None
            file_size = None
            reply_to = data.get('reply_to')
            if reply_to is not None and not isinstance(reply_to, int):
                reply_to = None
            if isinstance(reply_to, int) and reply_to <= 0:
                reply_to = None
            encrypted = bool(data.get('encrypted', True))
            client_msg_id = data.get('client_msg_id')
            if not isinstance(client_msg_id, str):
                client_msg_id = ''
            client_msg_id = client_msg_id.strip()[:64]

            if message_type == 'text':
                enforce_encryption = bool(current_app.config.get('REQUIRE_MESSAGE_ENCRYPTION', REQUIRE_MESSAGE_ENCRYPTION))
                if enforce_encryption and not encrypted:
                    _emit_error_i18n('암호화되지 않은 텍스트 메시지는 허용되지 않습니다.')
                    return {'ok': False, 'error': '암호화되지 않은 텍스트 메시지는 허용되지 않습니다.'}
                if encrypted:
                    # Do not truncate ciphertext; reject only extreme payload size.
                    if len(content) > 200000:
                        _emit_error_i18n('잘못된 요청입니다.')
                        return {'ok': False, 'error': '잘못된 요청입니다.'}
                else:
                    # Plaintext is bounded by policy.
                    if len(content) > 10000:
                        _emit_error_i18n('잘못된 요청입니다.')
                        return {'ok': False, 'error': '잘못된 요청입니다.'}

            if not user_has_room_access(session['user_id'], room_id):
                _emit_error_i18n('대화방 접근 권한이 없습니다.')
                return {'ok': False, 'error': '대화방 접근 권한이 없습니다.'}

            if reply_to is not None:
                reply_room_id = get_message_room_id(reply_to)
                if reply_room_id is None or int(reply_room_id) != int(room_id):
                    _emit_error_i18n('잘못된 요청입니다.')
                    return {'ok': False, 'error': '잘못된 요청입니다.'}

            # Idempotency shortcut for retries/reconnects.
            if client_msg_id:
                existing_message = get_message_by_client_msg_id(room_id, session['user_id'], client_msg_id)
                if existing_message:
                    return {'ok': True, 'message_id': int(existing_message.get('id') or 0)}

            if message_type in ('file', 'image'):
                token = data.get('upload_token')
                reason = get_upload_token_failure_reason(
                    token=token,
                    user_id=session['user_id'],
                    room_id=room_id,
                    expected_type=message_type,
                )
                if reason:
                    _emit_error_i18n(str(reason))
                    return {'ok': False, 'error': str(reason)}

                token_data = consume_upload_token(
                    token=token,
                    user_id=session['user_id'],
                    room_id=room_id,
                    expected_type=message_type,
                )
                if not token_data:
                    _emit_error_i18n('업로드 토큰이 이미 사용되었거나 만료되었습니다.')
                    return {'ok': False, 'error': '업로드 토큰이 이미 사용되었거나 만료되었습니다.'}

                file_path = token_data.get('file_path')
                file_name = token_data.get('file_name')
                file_size = token_data.get('file_size')
                encrypted = False
                content = file_name or content

            if not content and not file_path:
                return {'ok': False, 'error': '잘못된 요청입니다.'}

            if message_type in ('file', 'image') and file_path:
                normalized_file_size = None
                try:
                    if file_size is not None:
                        normalized_file_size = int(file_size)
                except (TypeError, ValueError):
                    normalized_file_size = None
                message = create_file_message_with_record(
                    room_id=int(room_id),
                    sender_id=int(session['user_id']),
                    content=content,
                    message_type=message_type,
                    file_path=str(file_path),
                    file_name=str(file_name or ''),
                    file_size=normalized_file_size,
                    reply_to=reply_to,
                    client_msg_id=client_msg_id or None,
                )
            else:
                message = create_message(
                    room_id,
                    session['user_id'],
                    content,
                    message_type,
                    file_path,
                    file_name,
                    reply_to,
                    encrypted,
                    client_msg_id=client_msg_id or None,
                )
            if message:
                created = bool(message.pop('__created', True))
                message_id = int(message.get('id') or 0)
                if not created:
                    return {'ok': True, 'message_id': message_id}
                if client_msg_id:
                    message['client_msg_id'] = client_msg_id
                # unread_count is currently not consumed by desktop real-time rendering.
                # Keep field for compatibility while avoiding per-message COUNT query.
                message['unread_count'] = 0

                emit('new_message', message, room=f'room_{room_id}')
                # broadcast 대신 해당 방 멤버들의 모든 세션에 전송
                logger.debug(f"Message sent: room={room_id}, user={session['user_id']}, type={message_type}")
                return {'ok': True, 'message_id': message_id}
            else:
                logger.warning(f"Message creation failed: room={room_id}, user={session['user_id']}")
                _emit_error_i18n('메시지 저장에 실패했습니다.')
                return {'ok': False, 'error': '메시지 저장에 실패했습니다.'}
        except Exception as e:
            logger.error(f"Send message error: {e}\n{traceback.format_exc()}")
            _emit_error_i18n('메시지 전송에 실패했습니다.')
            return {'ok': False, 'error': '메시지 전송에 실패했습니다.'}
    
    @socketio.on('message_read')
    def handle_message_read(data):
        try:
            if 'user_id' not in session:
                return
            
            room_id = data.get('room_id')
            message_id = data.get('message_id')

            try:
                normalized_room_id = int(room_id)
                normalized_message_id = int(message_id)
            except (TypeError, ValueError):
                return

            if normalized_room_id <= 0 or normalized_message_id <= 0:
                return

            # [v4.13] 멤버십 확인
            if not is_room_member(normalized_room_id, session['user_id']):
                return

            message_room_id = get_message_room_id(normalized_message_id)
            if message_room_id is None or int(message_room_id) != normalized_room_id:
                _emit_error_i18n('잘못된 요청입니다.')
                return

            update_last_read(normalized_room_id, session['user_id'], normalized_message_id)
            emit('read_updated', {
                'room_id': normalized_room_id,
                'user_id': session['user_id'],
                'message_id': normalized_message_id
            }, room=f'room_{normalized_room_id}')
        except Exception as e:
            logger.error(f"Message read error: {e}")
    
    @socketio.on('typing')
    def handle_typing(data):
        try:
            if 'user_id' not in session:
                return
            
            room_id = data.get('room_id')
            if not room_id:
                return
            try:
                room_id = int(room_id)
            except (TypeError, ValueError):
                return
            if room_id <= 0:
                return
            
            user_id = session['user_id']
            
            # [v4.21] 멤버십 검증
            if not user_has_room_access(user_id, room_id):
                return
            
            # [v4.14] 타이핑 레이트 리미팅
            current_time = time.time()
            rate_key = (user_id, room_id)
            with typing_rate_lock:
                last_emit = typing_last_emit.get(rate_key, 0)
                if current_time - last_emit < TYPING_RATE_LIMIT:
                    return  # 너무 빈번한 이벤트 무시
                typing_last_emit[rate_key] = current_time
                # 오래된 항목 정리 (5분 이상)
                if len(typing_last_emit) > 1000:
                    expired = [k for k, v in typing_last_emit.items() if current_time - v > 300]
                    for k in expired:
                        del typing_last_emit[k]
            
            is_typing = data.get('is_typing', False)
            # 세션에서 닉네임 가져오기 (없으면 DB 조회)
            nickname = session.get('nickname', '')
            if not nickname:
                user = get_user_by_id(user_id)
                nickname = user.get('nickname', '사용자') if user else '사용자'
            
            emit('user_typing', {
                'room_id': room_id,
                'user_id': user_id,
                'nickname': nickname,
                'is_typing': is_typing
            }, room=f'room_{room_id}', include_self=False)
        except Exception as e:
            logger.error(f"Typing event error: {e}")
    
    # 방 이름 변경 알림
    @socketio.on('room_name_updated')
    def handle_room_name_updated(data):
        try:
            room_id = data.get('room_id')
            new_name = data.get('name')
            if room_id and new_name and 'user_id' in session:
                # [v4.9] 관리자 권한 확인
                if not is_room_admin(room_id, session['user_id']):
                    _emit_error_i18n('관리자만 방 이름을 변경할 수 있습니다.')
                    return
                
                # 시스템 메시지 생성
                nickname = session.get('nickname', '사용자')
                content = f"{nickname}님이 방 이름을 '{new_name}'(으)로 변경했습니다."
                sys_msg = create_message(room_id, session['user_id'], content, 'system')
                
                # 시스템 메시지 전송
                if sys_msg:
                    emit('new_message', sys_msg, room=f'room_{room_id}')
                
                emit('room_name_updated', {'room_id': room_id, 'name': new_name}, room=f'room_{room_id}')
        except Exception as e:
            logger.error(f"Room name update broadcast error: {e}")
    
    # 멤버 변경 알림
    @socketio.on('room_members_updated')
    def handle_room_members_updated(data):
        try:
            # [v4.14] 세션 검증 추가
            if 'user_id' not in session:
                return
            
            room_id = data.get('room_id')
            if room_id:
                # 관련 사용자들의 캐시 무효화
                emit('room_members_updated', {'room_id': room_id}, room=f'room_{room_id}')
        except Exception as e:
            logger.error(f"Room members update broadcast error: {e}")
    
    # 프로필 업데이트 알림
    @socketio.on('profile_updated')
    def handle_profile_updated(data):
        try:
            if 'user_id' in session:
                user_id = session['user_id']
                nickname = data.get('nickname')
                profile_image = data.get('profile_image')
                
                # 모든 클라이언트에게 브로드캐스트 (본인 제외)
                emit('user_profile_updated', {
                    'user_id': user_id,
                    'nickname': nickname,
                    'profile_image': profile_image
                }, broadcast=True, include_self=False)
                
                logger.info(f"Profile updated broadcast: user_id={user_id}, nickname={nickname}, image={profile_image}")
        except Exception as e:
            logger.error(f"Profile update broadcast error: {e}")

    # 메시지 수정
    @socketio.on('edit_message')
    def handle_edit_message(data):
        try:
            if 'user_id' not in session:
                return
            
            message_id = data.get('message_id')
            encrypted = data.get('encrypted', True)
            content = data.get('content', '')
            if isinstance(content, str):
                content = content.strip()
            else:
                content = ''

            if encrypted:
                if len(content) > 200000:
                    _emit_error_i18n('잘못된 요청입니다.')
                    return
            else:
                if len(content) > 10000:
                    _emit_error_i18n('잘못된 요청입니다.')
                    return
            
            if not message_id or not content:
                _emit_error_i18n('잘못된 요청입니다.')
                return
            
            success, error_msg, room_id = edit_message(message_id, session['user_id'], content)
            if success:
                emit('message_edited', {
                    'room_id': room_id,
                    'message_id': message_id,
                    'content': content,
                    'encrypted': encrypted
                }, room=f'room_{room_id}')
            else:
                _emit_error_i18n(str(error_msg))
        except Exception as e:
            logger.error(f"Edit message error: {e}")
            _emit_error_i18n('메시지 수정에 실패했습니다.')

    # 메시지 삭제
    @socketio.on('delete_message')
    def handle_delete_message(data):
        try:
            if 'user_id' not in session:
                return
            
            message_id = data.get('message_id')
            
            if not message_id:
                _emit_error_i18n('잘못된 요청입니다.')
                return
            
            success, result = delete_message(message_id, session['user_id'])
            if success:
                room_id = result
                emit('message_deleted', {
                    'room_id': room_id,
                    'message_id': message_id
                }, room=f'room_{room_id}')
            else:
                _emit_error_i18n(str(result))
        except Exception as e:
            logger.error(f"Delete message error: {e}")
            _emit_error_i18n('메시지 삭제에 실패했습니다.')

    # ============================================================================
    # v4.0 추가 이벤트
    # ============================================================================
    
    # 리액션 업데이트
    @socketio.on('reaction_updated')
    def handle_reaction_updated(data):
        try:
            room_id = data.get('room_id')
            message_id = data.get('message_id')
            
            # [v4.21] 세션 및 멤버십 확인 강화
            if 'user_id' not in session:
                _emit_error_i18n('로그인이 필요합니다.')
                return
            if not room_id or not message_id:
                _emit_error_i18n('잘못된 요청입니다.')
                return
            if not is_room_member(room_id, session['user_id']):
                _emit_error_i18n('대화방 멤버만 리액션을 추가할 수 있습니다.')
                return

            message_room_id = get_message_room_id(int(message_id))
            if message_room_id != int(room_id):
                _emit_error_i18n('잘못된 요청입니다.')
                return

            reactions = get_message_reactions(int(message_id))
            
            emit('reaction_updated', {
                'room_id': room_id,
                'message_id': message_id,
                'reactions': reactions
            }, room=f'room_{room_id}')
        except Exception as e:
            logger.error(f"Reaction update broadcast error: {e}")
    
    # 투표 업데이트
    @socketio.on('poll_updated')
    def handle_poll_updated(data):
        try:
            room_id = data.get('room_id')
            poll_payload = data.get('poll') if isinstance(data.get('poll'), dict) else {}
            poll_id = data.get('poll_id') or poll_payload.get('id')
            
            # [v4.21] 세션 및 멤버십 확인 강화
            if 'user_id' not in session:
                _emit_error_i18n('로그인이 필요합니다.')
                return
            if not room_id or not poll_id:
                _emit_error_i18n('잘못된 요청입니다.')
                return
            if not is_room_member(room_id, session['user_id']):
                _emit_error_i18n('대화방 멤버만 투표를 업데이트할 수 있습니다.')
                return

            poll = get_poll(int(poll_id))
            if not poll or int(poll.get('room_id') or 0) != int(room_id):
                _emit_error_i18n('잘못된 요청입니다.')
                return
            
            emit('poll_updated', {
                'room_id': room_id,
                'poll': poll
            }, room=f'room_{room_id}')
        except Exception as e:
            logger.error(f"Poll update broadcast error: {e}")
    
    # 투표 생성
    @socketio.on('poll_created')
    def handle_poll_created(data):
        try:
            room_id = data.get('room_id')
            poll_payload = data.get('poll') if isinstance(data.get('poll'), dict) else {}
            poll_id = data.get('poll_id') or poll_payload.get('id')
            
            # [v4.21] 세션 및 멤버십 확인 강화
            if 'user_id' not in session:
                _emit_error_i18n('로그인이 필요합니다.')
                return
            if not room_id or not poll_id:
                _emit_error_i18n('잘못된 요청입니다.')
                return
            if not is_room_member(room_id, session['user_id']):
                _emit_error_i18n('대화방 멤버만 투표를 생성할 수 있습니다.')
                return

            poll = get_poll(int(poll_id))
            if not poll or int(poll.get('room_id') or 0) != int(room_id):
                _emit_error_i18n('잘못된 요청입니다.')
                return
            
            emit('poll_created', {
                'room_id': room_id,
                'poll': poll
            }, room=f'room_{room_id}')
        except Exception as e:
            logger.error(f"Poll created broadcast error: {e}")
    
    # 공지 업데이트
    @socketio.on('pin_updated')
    def handle_pin_updated(data):
        try:
            room_id = data.get('room_id')
            
            if room_id and 'user_id' in session:
                # [v4.10] 모든 멤버가 공지 가능
                if not is_room_member(room_id, session['user_id']):
                    _emit_error_i18n('대화방 멤버만 공지를 수정할 수 있습니다.')
                    return
                
                # 시스템 메시지 생성
                nickname = session.get('nickname', '사용자')
                content = f"{nickname}님이 공지사항을 업데이트했습니다."
                sys_msg = create_message(room_id, session['user_id'], content, 'system')
                
                if sys_msg:
                    emit('new_message', sys_msg, room=f'room_{room_id}')

                pins = get_pinned_messages(int(room_id))
                
                emit('pin_updated', {
                    'room_id': room_id,
                    'pins': pins
                }, room=f'room_{room_id}')
        except Exception as e:
            logger.error(f"Pin update broadcast error: {e}")
    
    # 관리자 변경
    @socketio.on('admin_updated')
    def handle_admin_updated(data):
        try:
            room_id = data.get('room_id')
            target_user_id = data.get('user_id')
            
            # [v4.9] 관리자 권한 확인
            if room_id and target_user_id is not None and 'user_id' in session:
                if not is_room_admin(room_id, session['user_id']):
                    _emit_error_i18n('관리자만 권한을 변경할 수 있습니다.')
                    return
                admins = get_room_admins(int(room_id))
                admin_ids = {int(a.get('id')) for a in admins}
                emit('admin_updated', {
                    'room_id': room_id,
                    'user_id': target_user_id,
                    'is_admin': int(target_user_id) in admin_ids
                }, room=f'room_{room_id}')
        except Exception as e:
            logger.error(f"Admin update broadcast error: {e}")


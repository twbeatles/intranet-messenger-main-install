# -*- coding: utf-8 -*-
"""
Flask HTTP 라우트
"""

import os
import uuid
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify, session, send_from_directory, render_template
from werkzeug.utils import secure_filename

from app.models import (
    create_user, authenticate_user, get_all_users, get_user_rooms,
    create_room, get_room_messages, get_room_members, get_room_key,
    add_room_member, leave_room_db, update_room_name, get_room_by_id,
    pin_room, mute_room, get_online_users, delete_message, edit_message,
    search_messages, log_access, get_unread_count, update_user_profile,
    get_user_by_id, is_room_member, get_db, get_message_room_id,
    # v4.0 추가 기능
    pin_message, unpin_message, get_pinned_messages,
    create_poll, get_poll, get_room_polls, vote_poll, get_user_votes, close_poll,
    add_room_file, get_room_files, delete_room_file,
    add_reaction, remove_reaction, toggle_reaction, get_message_reactions, get_messages_reactions,
    set_room_admin, is_room_admin, get_room_admins, advanced_search,
    # v4.1 추가 기능
    change_password, delete_user, get_user_session_token,
    request_user_approval, get_user_approval_status, review_user_approval,
    # [v4.15] 파일 삭제 안전 함수
    safe_file_delete,
    # [v4.19] 성능 최적화 함수
    get_room_last_reads,
    get_maintenance_status,
)
from app.utils import sanitize_input, allowed_file, validate_file_header
from app.extensions import limiter, csrf
from app.upload_tokens import issue_upload_token
from app.security.upload_scanner import scan_upload_stream, scan_saved_file
from app.auth_tokens import (
    issue_device_session,
    rotate_device_session_token,
    get_device_session_by_token,
    touch_device_session,
    revoke_device_session_by_token,
    revoke_device_session_by_id,
    list_active_device_sessions,
)
from app.i18n import load_catalog, resolve_locale, to_display_locale

# config 임포트 (PyInstaller 호환)
try:
    from config import (
        UPLOAD_FOLDER,
        DEVICE_SESSION_TTL_DAYS,
        DEVICE_SESSION_SHORT_TTL_DAYS,
        DESKTOP_ONLY_MODE,
        DESKTOP_CLIENT_MIN_VERSION,
        DESKTOP_CLIENT_LATEST_VERSION,
        DESKTOP_CLIENT_DOWNLOAD_URL,
        DESKTOP_CLIENT_RELEASE_NOTES_URL,
        DESKTOP_CLIENT_CHANNEL_DEFAULT,
        DESKTOP_CLIENT_CANARY_MIN_VERSION,
        DESKTOP_CLIENT_CANARY_LATEST_VERSION,
        DESKTOP_CLIENT_CANARY_DOWNLOAD_URL,
        DESKTOP_CLIENT_CANARY_RELEASE_NOTES_URL,
        DESKTOP_CLIENT_ARTIFACT_SHA256,
        DESKTOP_CLIENT_ARTIFACT_SIGNATURE,
        DESKTOP_CLIENT_SIGNATURE_ALG,
        DESKTOP_CLIENT_CANARY_ARTIFACT_SHA256,
        DESKTOP_CLIENT_CANARY_ARTIFACT_SIGNATURE,
        DESKTOP_CLIENT_CANARY_SIGNATURE_ALG,
        ALLOW_SELF_REGISTER,
        ENTERPRISE_AUTH_ENABLED,
        ENTERPRISE_AUTH_PROVIDER,
    )
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import (
        UPLOAD_FOLDER,
        DEVICE_SESSION_TTL_DAYS,
        DEVICE_SESSION_SHORT_TTL_DAYS,
        DESKTOP_ONLY_MODE,
        DESKTOP_CLIENT_MIN_VERSION,
        DESKTOP_CLIENT_LATEST_VERSION,
        DESKTOP_CLIENT_DOWNLOAD_URL,
        DESKTOP_CLIENT_RELEASE_NOTES_URL,
        DESKTOP_CLIENT_CHANNEL_DEFAULT,
        DESKTOP_CLIENT_CANARY_MIN_VERSION,
        DESKTOP_CLIENT_CANARY_LATEST_VERSION,
        DESKTOP_CLIENT_CANARY_DOWNLOAD_URL,
        DESKTOP_CLIENT_CANARY_RELEASE_NOTES_URL,
        DESKTOP_CLIENT_ARTIFACT_SHA256,
        DESKTOP_CLIENT_ARTIFACT_SIGNATURE,
        DESKTOP_CLIENT_SIGNATURE_ALG,
        DESKTOP_CLIENT_CANARY_ARTIFACT_SHA256,
        DESKTOP_CLIENT_CANARY_ARTIFACT_SIGNATURE,
        DESKTOP_CLIENT_CANARY_SIGNATURE_ALG,
        ALLOW_SELF_REGISTER,
        ENTERPRISE_AUTH_ENABLED,
        ENTERPRISE_AUTH_PROVIDER,
    )

logger = logging.getLogger(__name__)


def register_routes(app):
    """라우트 등록"""

    def _parse_version(version: str) -> tuple[int, int, int]:
        parts = (version or '0.0.0').strip().split('.')
        normalized = []
        for i in range(3):
            try:
                normalized.append(int(parts[i]))
            except Exception:
                normalized.append(0)
        return tuple(normalized)  # type: ignore[return-value]

    def _emit_socket_event(
        event: str,
        payload: dict | None = None,
        *,
        room_id: int | None = None,
        user_ids: list[int] | None = None,
        broadcast: bool = False,
    ) -> None:
        """REST 처리 결과를 소켓으로 동기화한다."""
        try:
            from app import socketio as socketio_instance
        except Exception:
            return

        if socketio_instance is None:
            return

        emitted = False
        body = payload or {}
        if room_id is not None:
            socketio_instance.emit(event, body, room=f'room_{int(room_id)}')
            emitted = True

        if user_ids:
            seen_user_ids: set[int] = set()
            for user_id in user_ids:
                try:
                    normalized = int(user_id)
                except (TypeError, ValueError):
                    continue
                if normalized <= 0 or normalized in seen_user_ids:
                    continue
                seen_user_ids.add(normalized)
                socketio_instance.emit(event, body, room=f'user_{normalized}')
                emitted = True

        # Backward-compatible fallback.
        if not emitted and broadcast:
            socketio_instance.emit(event, body)
    
    @app.route('/')
    def index():
        if DESKTOP_ONLY_MODE:
            download = DESKTOP_CLIENT_DOWNLOAD_URL or '관리자에게 데스크톱 설치 파일을 요청하세요.'
            notes = DESKTOP_CLIENT_RELEASE_NOTES_URL or '-'
            html = f"""
            <!DOCTYPE html>
            <html lang="ko">
            <head><meta charset="UTF-8"><title>Desktop Only</title></head>
            <body style="font-family:Segoe UI,sans-serif;padding:36px;background:#0f172a;color:#e2e8f0;">
              <h1>사내 메신저 데스크톱 전용 모드</h1>
              <p>웹 접속은 비활성화되었습니다. 설치형 클라이언트를 사용해주세요.</p>
              <ul>
                <li>최소 버전: {DESKTOP_CLIENT_MIN_VERSION}</li>
                <li>최신 버전: {DESKTOP_CLIENT_LATEST_VERSION}</li>
                <li>다운로드: {download}</li>
                <li>릴리즈 노트: {notes}</li>
              </ul>
            </body>
            </html>
            """
            return html, 200, {'Content-Type': 'text/html; charset=utf-8'}
        return render_template('index.html')
    
    @app.route('/api/me')
    def get_current_user():
        """현재 로그인된 사용자 정보 반환 (새로고침 시 세션 체크용)"""
        if 'user_id' in session:
            user = get_user_by_id(session['user_id'])
            if user:
                return jsonify({'logged_in': True, 'user': user})
        return jsonify({'logged_in': False})

    @app.route('/api/i18n/<domain>')
    @csrf.exempt
    def get_i18n_catalog(domain: str):
        allowed_domains = {'server', 'client', 'web', 'server_gui'}
        if domain not in allowed_domains:
            return jsonify({'error': '지원하지 않는 i18n 도메인입니다.'}), 404

        requested = request.args.get('lang') or request.headers.get('X-App-Language')
        locale_code = resolve_locale(req=request, sess=session, manual_value=requested)
        catalog = load_catalog(locale_code, domain)
        return jsonify(
            {
                'domain': domain,
                'locale': to_display_locale(locale_code),
                'catalog': catalog,
            }
        )
    
    def _begin_user_session(user: dict) -> str:
        """Start a fresh Flask session and return a new CSRF token."""
        session.clear()
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['nickname'] = user.get('nickname', user['username'])
        token = get_user_session_token(user['id'])
        if token:
            session['session_token'] = token
        return generate_csrf()

    def _json_dict() -> dict:
        payload = request.get_json(silent=True)
        return payload if isinstance(payload, dict) else {}

    def _extract_device_token() -> str:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header.split(' ', 1)[1].strip()

        header_token = request.headers.get('X-Device-Token', '').strip()
        if header_token:
            return header_token

        payload = _json_dict()
        token = payload.get('device_token', '')
        return token.strip() if isinstance(token, str) else ''

    def _approval_gate_for_user(user: dict):
        user_id = int(user.get('id') or 0)
        if user_id <= 0:
            return None
        status = get_user_approval_status(user_id)
        if status == 'pending':
            return jsonify({'error': '계정 승인 대기 중입니다.'}), 403
        if status == 'rejected':
            return jsonify({'error': '승인이 거부된 계정입니다.'}), 403
        return None

    def _is_platform_admin() -> bool:
        try:
            return int(session.get('user_id') or 0) == 1
        except Exception:
            return False

    @app.route('/api/register', methods=['POST'])
    @csrf.exempt  # [v4.2] 회원가입은 미인증 상태이므로 CSRF 예외
    @limiter.limit("5 per minute")
    def register():
        data = _json_dict()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        nickname = data.get('nickname', '').strip() or username
        
        if not username or not password:
            return jsonify({'error': '아이디와 비밀번호를 입력해주세요.'}), 400
        
        # [v4.15] 아이디 형식 검사
        from app.utils import validate_username, validate_password
        if not validate_username(username):
            return jsonify({'error': '아이디는 3-20자 영문, 숫자, 밑줄만 사용 가능합니다.'}), 400
        
        # [v4.3] 비밀번호 강도 검사
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            return jsonify({'error': error_msg}), 400

        allow_self_register = bool(app.config.get('ALLOW_SELF_REGISTER', ALLOW_SELF_REGISTER))
        if not allow_self_register:
            user_id = create_user(username, password, nickname)
            if not user_id:
                return jsonify({'error': '이미 존재하는 아이디입니다.'}), 400
            if not request_user_approval(int(user_id), reason='self-register-disabled'):
                return jsonify({'error': '승인 요청 생성에 실패했습니다.'}), 500
            log_access(user_id, 'register_pending_approval', request.remote_addr, request.user_agent.string)
            return jsonify({'success': True, 'pending_approval': True, 'user_id': user_id}), 202

        user_id = create_user(username, password, nickname)
        if user_id:
            log_access(user_id, 'register', request.remote_addr, request.user_agent.string)
            return jsonify({'success': True, 'user_id': user_id})
        return jsonify({'error': '이미 존재하는 아이디입니다.'}), 400
    
    from flask_wtf.csrf import generate_csrf

    @app.route('/api/login', methods=['POST'])
    @csrf.exempt  # [v4.2] 로그인은 미인증 상태이므로 CSRF 예외
    @limiter.limit("10 per minute")
    def login():
        data = _json_dict()
        user = authenticate_user(data.get('username', ''), data.get('password', ''))
        if user:
            blocked = _approval_gate_for_user(user)
            if blocked:
                return blocked
            new_csrf_token = _begin_user_session(user)
            log_access(user['id'], 'login', request.remote_addr, request.user_agent.string)

            return jsonify({
                'success': True, 
                'user': user,
                'csrf_token': new_csrf_token
            })
        return jsonify({'error': '아이디 또는 비밀번호가 올바르지 않습니다.'}), 401

    @app.route('/api/device-sessions', methods=['POST'])
    @csrf.exempt
    @limiter.limit("10 per minute")
    def create_device_session_route():
        data = _json_dict()
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''
        raw_remember = data.get('remember', True)
        device_name = (data.get('device_name') or 'Desktop Client').strip()

        if not username or not password:
            return jsonify({'error': '아이디와 비밀번호를 입력해주세요.'}), 400
        if not isinstance(raw_remember, bool):
            return jsonify({'error': 'remember는 boolean 값이어야 합니다.'}), 400
        remember = raw_remember

        user = authenticate_user(username, password)
        if not user:
            return jsonify({'error': '아이디 또는 비밀번호가 올바르지 않습니다.'}), 401
        blocked = _approval_gate_for_user(user)
        if blocked:
            return blocked

        ttl_days = DEVICE_SESSION_TTL_DAYS if remember else DEVICE_SESSION_SHORT_TTL_DAYS
        issued = issue_device_session(
            user_id=user['id'],
            device_name=device_name,
            ip=request.remote_addr or '',
            user_agent=request.user_agent.string or '',
            ttl_days=ttl_days,
            remember=remember,
        )
        csrf_token = _begin_user_session(user)
        session['device_session_id'] = issued['session_id']
        session['device_id'] = issued['device_id']
        session['remember_device'] = bool(issued.get('remember', remember))
        log_access(user['id'], 'login_device', request.remote_addr, request.user_agent.string)

        return jsonify({
            'access_ok': True,
            'device_token': issued['device_token'],
            'expires_at': issued['expires_at'],
            'user': user,
            'csrf_token': csrf_token,
            'device_session_id': issued['session_id'],
            'remember': bool(issued.get('remember', remember)),
        })

    @app.route('/api/device-sessions/refresh', methods=['POST'])
    @csrf.exempt
    @limiter.limit("30 per minute")
    def refresh_device_session_route():
        token = _extract_device_token()
        if not token:
            return jsonify({'error': 'device_token이 필요합니다.'}), 400

        rotated = rotate_device_session_token(
            token=token,
            ip=request.remote_addr or '',
            user_agent=request.user_agent.string or '',
            ttl_days=DEVICE_SESSION_TTL_DAYS,
        )
        if not rotated:
            return jsonify({'error': '유효하지 않거나 만료된 토큰입니다.'}), 401

        user = get_user_by_id(rotated['user_id'])
        if not user:
            return jsonify({'error': '사용자를 찾을 수 없습니다.'}), 401

        csrf_token = _begin_user_session(user)
        session['device_session_id'] = rotated['session_id']
        session['device_id'] = rotated['device_id']
        session['remember_device'] = bool(rotated.get('remember', True))
        touch_device_session(
            session_id=rotated['session_id'],
            ip=request.remote_addr or '',
            user_agent=request.user_agent.string or '',
        )
        log_access(user['id'], 'refresh_device_session', request.remote_addr, request.user_agent.string)

        return jsonify({
            'access_ok': True,
            'device_token_rotated': rotated['device_token'],
            'expires_at': rotated['expires_at'],
            'user': user,
            'csrf_token': csrf_token,
            'device_session_id': rotated['session_id'],
            'remember': bool(rotated.get('remember', True)),
        })

    @app.route('/api/device-sessions/current', methods=['DELETE'])
    @csrf.exempt
    def revoke_current_device_session_route():
        token = _extract_device_token()
        revoked = False
        user_id = session.get('user_id')

        if token:
            active = get_device_session_by_token(token)
            if active:
                user_id = active.get('user_id', user_id)
            revoked = revoke_device_session_by_token(token)
        elif user_id and session.get('device_session_id'):
            revoked = revoke_device_session_by_id(user_id, int(session['device_session_id']))

        if user_id:
            log_access(user_id, 'logout_device', request.remote_addr, request.user_agent.string)
        session.clear()
        return jsonify({'success': True, 'revoked': bool(revoked)})

    @app.route('/api/device-sessions')
    def list_device_sessions_route():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401

        include_expired = str(request.args.get('include_expired', '')).lower() in ('1', 'true', 'yes')
        sessions = list_active_device_sessions(session['user_id'], include_expired=include_expired)
        current_session_id = int(session.get('device_session_id') or 0)
        for row in sessions:
            row['is_current'] = (row.get('id') == current_session_id)
        return jsonify({'sessions': sessions})

    @app.route('/api/device-sessions/<int:device_session_id>', methods=['DELETE'])
    def revoke_device_session_route(device_session_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401

        revoked = revoke_device_session_by_id(session['user_id'], device_session_id)
        if not revoked:
            return jsonify({'error': '세션을 찾을 수 없습니다.'}), 404

        if int(session.get('device_session_id') or 0) == device_session_id:
            session.clear()
            return jsonify({'success': True, 'current_revoked': True})
        return jsonify({'success': True, 'current_revoked': False})

    @app.route('/api/auth/enterprise-login', methods=['POST'])
    @csrf.exempt
    @limiter.limit("20 per minute")
    def enterprise_login():
        if not bool(app.config.get('ENTERPRISE_AUTH_ENABLED', ENTERPRISE_AUTH_ENABLED)):
            return jsonify({'error': '엔터프라이즈 인증이 비활성화되어 있습니다.'}), 501
        if not str(app.config.get('ENTERPRISE_AUTH_PROVIDER', ENTERPRISE_AUTH_PROVIDER) or '').strip():
            return jsonify({'error': '엔터프라이즈 인증 제공자가 구성되지 않았습니다.'}), 400
        return jsonify({'error': '엔터프라이즈 인증 스캐폴딩만 구현되었습니다.'}), 501

    @app.route('/api/admin/users/approve', methods=['POST'])
    def admin_approve_user():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        if not _is_platform_admin():
            return jsonify({'error': '관리자 권한이 필요합니다.'}), 403

        data = _json_dict()
        target_user_id = data.get('user_id')
        action = str(data.get('action') or '').strip().lower()
        reason = str(data.get('reason') or '').strip()

        try:
            target_user_id = int(target_user_id)
        except (TypeError, ValueError):
            return jsonify({'error': '유효한 사용자 ID가 필요합니다.'}), 400
        if target_user_id <= 0:
            return jsonify({'error': '유효한 사용자 ID가 필요합니다.'}), 400
        if action not in ('approve', 'reject'):
            return jsonify({'error': 'action은 approve/reject만 허용됩니다.'}), 400
        if not get_user_by_id(target_user_id):
            return jsonify({'error': '사용자를 찾을 수 없습니다.'}), 404

        if not review_user_approval(
            user_id=target_user_id,
            status=action,
            reviewed_by=int(session['user_id']),
            reason=reason,
        ):
            return jsonify({'error': '승인 상태 변경에 실패했습니다.'}), 500

        log_access(int(session['user_id']), f'approve_user_{action}', request.remote_addr, request.user_agent.string)
        return jsonify({'success': True, 'user_id': target_user_id, 'status': 'approved' if action == 'approve' else 'rejected'})

    @app.route('/api/security/audit')
    def security_audit_route():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401

        user_id = int(session['user_id'])
        limit = request.args.get('limit', type=int) or 50
        if limit < 1:
            limit = 1
        if limit > 200:
            limit = 200

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT id, action, ip_address, user_agent, created_at
            FROM access_logs
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            ''',
            (user_id, limit),
        )
        logs = [dict(row) for row in cursor.fetchall()]

        cursor.execute(
            '''
            SELECT action, COUNT(*) AS count
            FROM access_logs
            WHERE user_id = ?
              AND created_at >= datetime('now', '-30 days')
            GROUP BY action
            ORDER BY count DESC
            ''',
            (user_id,),
        )
        action_counts = {row['action']: int(row['count']) for row in cursor.fetchall()}

        sessions = list_active_device_sessions(user_id)
        revoked_recent = 0
        cursor.execute(
            '''
            SELECT COUNT(*) AS count
            FROM device_sessions
            WHERE user_id = ?
              AND revoked_at IS NOT NULL
              AND revoked_at >= datetime('now', '-30 days')
            ''',
            (user_id,),
        )
        row = cursor.fetchone()
        if row:
            revoked_recent = int(row['count'] or 0)

        return jsonify(
            {
                'user_id': user_id,
                'window_days': 30,
                'actions': action_counts,
                'recent_access_logs': logs,
                'active_device_sessions': sessions,
                'revoked_device_sessions_recent': revoked_recent,
            }
        )

    @app.route('/api/system/health')
    def system_health():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401

        db_ok = True
        db_error = ''
        try:
            conn = get_db()
            conn.execute('SELECT 1')
        except Exception as e:
            db_ok = False
            db_error = str(e)

        try:
            from app import get_session_guard_stats

            guard_stats = get_session_guard_stats()
        except Exception:
            guard_stats = {'fail_open_count': 0, 'last_fail_open_at': None}

        tls_effective = (os.environ.get('MESSENGER_TLS_EFFECTIVE') or '').strip() == '1'
        if not tls_effective:
            tls_effective = bool(request.is_secure)

        payload = {
            'status': 'ok' if db_ok else 'degraded',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'tls': {
                'configured': bool(app.config.get('SESSION_COOKIE_SECURE', False)),
                'effective': bool(tls_effective),
                'enforce_https': bool(app.config.get('ENFORCE_HTTPS', False)),
            },
            'db': {
                'ok': bool(db_ok),
            },
            'session_guard': {
                'fail_open_enabled': bool(app.config.get('SESSION_TOKEN_FAIL_OPEN', True)),
                'fail_open_count': int(guard_stats.get('fail_open_count') or 0),
                'last_fail_open_at': guard_stats.get('last_fail_open_at'),
            },
            'maintenance': get_maintenance_status(),
            'rate_limit': {
                'storage_uri': str(app.config.get('RATE_LIMIT_STORAGE_URI', 'memory://')),
                'key_mode': str(app.config.get('RATE_LIMIT_KEY_MODE', 'ip')),
            },
        }
        if db_error:
            payload['db']['error'] = db_error
        return jsonify(payload), (200 if db_ok else 503)
    
    @app.route('/api/logout', methods=['POST'])
    @csrf.exempt  # [v4.2] 로그아웃 CSRF 예외 (세션 삭제 작업으로 위험 낮음)
    def logout():
        if 'user_id' in session:
            log_access(session['user_id'], 'logout', request.remote_addr, request.user_agent.string)
        if session.get('user_id') and session.get('device_session_id'):
            revoke_device_session_by_id(int(session['user_id']), int(session['device_session_id']))
        else:
            # Desktop client may only send bearer token.
            token = _extract_device_token()
            if token:
                revoke_device_session_by_token(token)
        session.clear()
        return jsonify({'success': True})

    @app.route('/api/client/update')
    def client_update_check():
        """
        Desktop client update check endpoint.
        Query: ?client_version=1.0.0&channel=stable|canary
        """
        client_version = (request.args.get('client_version') or '').strip()
        channel = (request.args.get('channel') or DESKTOP_CLIENT_CHANNEL_DEFAULT or 'stable').strip().lower()
        if channel not in ('stable', 'canary'):
            channel = 'stable'

        if channel == 'canary':
            minimum_version = DESKTOP_CLIENT_CANARY_MIN_VERSION or DESKTOP_CLIENT_MIN_VERSION
            latest_version = DESKTOP_CLIENT_CANARY_LATEST_VERSION or DESKTOP_CLIENT_LATEST_VERSION
            download_url = DESKTOP_CLIENT_CANARY_DOWNLOAD_URL or DESKTOP_CLIENT_DOWNLOAD_URL
            release_notes_url = DESKTOP_CLIENT_CANARY_RELEASE_NOTES_URL or DESKTOP_CLIENT_RELEASE_NOTES_URL
            artifact_sha256 = DESKTOP_CLIENT_CANARY_ARTIFACT_SHA256 or DESKTOP_CLIENT_ARTIFACT_SHA256
            artifact_signature = DESKTOP_CLIENT_CANARY_ARTIFACT_SIGNATURE or DESKTOP_CLIENT_ARTIFACT_SIGNATURE
            signature_alg = DESKTOP_CLIENT_CANARY_SIGNATURE_ALG or DESKTOP_CLIENT_SIGNATURE_ALG
        else:
            minimum_version = DESKTOP_CLIENT_MIN_VERSION
            latest_version = DESKTOP_CLIENT_LATEST_VERSION
            download_url = DESKTOP_CLIENT_DOWNLOAD_URL
            release_notes_url = DESKTOP_CLIENT_RELEASE_NOTES_URL
            artifact_sha256 = DESKTOP_CLIENT_ARTIFACT_SHA256
            artifact_signature = DESKTOP_CLIENT_ARTIFACT_SIGNATURE
            signature_alg = DESKTOP_CLIENT_SIGNATURE_ALG

        current = _parse_version(client_version) if client_version else (0, 0, 0)
        minimum = _parse_version(minimum_version)
        latest = _parse_version(latest_version)

        force_update = current < minimum
        update_available = current < latest

        response_payload = {
            'channel': channel,
            'desktop_only_mode': bool(DESKTOP_ONLY_MODE),
            'minimum_version': minimum_version,
            'latest_version': latest_version,
            'download_url': download_url,
            'release_notes_url': release_notes_url,
            'client_version': client_version or None,
            'update_available': update_available,
            'force_update': force_update,
        }
        if artifact_sha256:
            response_payload['artifact_sha256'] = artifact_sha256
        if artifact_signature:
            response_payload['artifact_signature'] = artifact_signature
        if signature_alg:
            response_payload['signature_alg'] = signature_alg
        return jsonify(response_payload)
    
    @app.route('/api/users')
    def get_users():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        users = get_all_users()
        return jsonify([u for u in users if u['id'] != session['user_id']])
    
    @app.route('/api/rooms')
    def get_rooms():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        include_members = str(request.args.get('include_members', '')).lower() in ('1', 'true', 'yes')
        rooms = get_user_rooms(session['user_id'], include_members=include_members)
        return jsonify(rooms)
    
    @app.route('/api/rooms', methods=['POST'])
    def create_room_route():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        data = _json_dict()
        if not isinstance(data, dict):
            return jsonify({'error': '잘못된 요청 형식입니다.'}), 400
        has_members = 'members' in data
        has_member_ids = 'member_ids' in data
        if has_members:
            raw_members = data.get('members')
            if has_member_ids:
                logger.warning("Both members and member_ids were provided; members will be used.")
        else:
            raw_members = data.get('member_ids', [])

        if raw_members is None:
            raw_members = []
        if not isinstance(raw_members, list):
            return jsonify({'error': 'members 또는 member_ids는 배열이어야 합니다.'}), 400

        normalized_members = []
        seen = set()
        for value in raw_members:
            try:
                member_id = int(value)
            except (TypeError, ValueError):
                return jsonify({'error': '멤버 ID는 정수여야 합니다.'}), 400
            if member_id <= 0 or member_id in seen:
                continue
            seen.add(member_id)
            normalized_members.append(member_id)

        if session['user_id'] not in seen:
            normalized_members.append(session['user_id'])
            seen.add(session['user_id'])

        member_ids = [uid for uid in normalized_members if get_user_by_id(uid)]
        if session['user_id'] not in member_ids:
            member_ids.append(session['user_id'])
        
        room_type = 'direct' if len(member_ids) == 2 else 'group'
        name = data.get('name', '')
        
        try:
            room_id = create_room(name, room_type, session['user_id'], member_ids)
            _emit_socket_event(
                'room_updated',
                {
                    'room_id': room_id,
                    'action': 'room_created',
                    'by_user_id': int(session['user_id']),
                },
                user_ids=[int(uid) for uid in member_ids],
            )
            return jsonify({'success': True, 'room_id': room_id})
        except Exception as e:
            logger.error(f"Room creation failed: {e}")
            return jsonify({'error': '대화방 생성에 실패했습니다.'}), 500
    
    @app.route('/api/rooms/<int:room_id>/messages')
    def get_messages(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        # 대화방 멤버십 확인
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '대화방 접근 권한이 없습니다.'}), 403
        
        try:
            before_id = request.args.get('before_id', type=int)
            limit = request.args.get('limit', type=int) or 50
            if limit < 1:
                limit = 1
            if limit > 200:
                limit = 200

            include_meta = str(request.args.get('include_meta', '1')).lower() in ('1', 'true', 'yes')

            messages = get_room_messages(room_id, before_id=before_id, limit=limit)
            members = get_room_members(room_id) if include_meta else None
            encryption_key = get_room_key(room_id) if include_meta else None
            
            # [v4.31] 읽음 상태 계산 최적화: O(n*m) → O(n+m)
            if messages:
                if include_meta and members:
                    # members already includes last_read_message_id; reuse it
                    user_last_read = {}
                    last_read_ids = []
                    for m in members:
                        try:
                            uid = m.get('id')
                            v = m.get('last_read_message_id') or 0
                        except Exception:
                            continue
                        if uid is None:
                            continue
                        user_last_read[uid] = v
                        last_read_ids.append(v)
                else:
                    last_reads = get_room_last_reads(room_id)
                    user_last_read = {}
                    last_read_ids = []
                    for lr, uid in last_reads:
                        v = lr or 0
                        user_last_read[uid] = v
                        last_read_ids.append(v)
                last_read_ids.sort()
                from bisect import bisect_left
                
                # 읽지 않은 사용자 수 계산: O(n log m) (m=멤버 수)
                for msg in messages:
                    sender_id = msg['sender_id']
                    msg_id = msg['id']
                
                    unread = bisect_left(last_read_ids, msg_id)
                    sender_lr = user_last_read.get(sender_id, 0)
                    if sender_lr < msg_id:
                        unread -= 1
                    if unread < 0:
                        unread = 0
                    msg['unread_count'] = unread
            
            resp = {'messages': messages}
            if include_meta:
                resp['members'] = members
                resp['encryption_key'] = encryption_key
            return jsonify(resp)
        except Exception as e:
            logger.error(f"메시지 로드 오류: {e}")
            return jsonify({'error': '메시지 로드 실패'}), 500
    
    @app.route('/api/rooms/<int:room_id>/members', methods=['POST'])
    def invite_member(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        # [v4.5] 멤버십 확인 - 방 멤버만 초대 가능
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '대화방 접근 권한이 없습니다.'}), 403
        
        data = _json_dict()
        user_ids = data.get('user_ids', [])
        user_id = data.get('user_id')
        
        if user_id:
            user_ids = [user_id]
        
        # [v4.8] 존재하는 사용자만 필터링
        valid_user_ids = [uid for uid in user_ids if get_user_by_id(uid)]
        
        added = 0
        added_user_ids: list[int] = []
        for uid in valid_user_ids:
            if add_room_member(room_id, uid):
                added += 1
                added_user_ids.append(int(uid))
        
        if added > 0:
            _emit_socket_event(
                'room_members_updated',
                {
                    'room_id': room_id,
                    'action': 'members_invited',
                    'by_user_id': int(session['user_id']),
                    'added_count': added,
                },
                room_id=room_id,
            )
            _emit_socket_event(
                'room_updated',
                {
                    'room_id': room_id,
                    'action': 'members_invited',
                    'by_user_id': int(session['user_id']),
                },
                room_id=room_id,
                user_ids=added_user_ids,
            )
            return jsonify({'success': True, 'added_count': added})
        return jsonify({'error': '이미 참여중인 사용자입니다.'}), 400
    
    @app.route('/api/rooms/<int:room_id>/leave', methods=['POST'])
    def leave_room_route(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401

        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '대화방 접근 권한이 없습니다.'}), 403

        left_user_id = int(session['user_id'])
        success = leave_room_db(room_id, left_user_id)
        if not success:
            return jsonify({'error': '대화방 나가기에 실패했습니다.'}), 400

        _emit_socket_event(
            'room_members_updated',
            {
                'room_id': room_id,
                'action': 'member_left',
                'user_id': left_user_id,
                'by_user_id': left_user_id,
            },
            room_id=room_id,
            user_ids=[left_user_id],
        )
        _emit_socket_event(
            'room_updated',
            {
                'room_id': room_id,
                'action': 'member_left',
                'user_id': left_user_id,
            },
            room_id=room_id,
            user_ids=[left_user_id],
        )
        return jsonify({'success': True})
    
    @app.route('/api/rooms/<int:room_id>/members/<int:target_user_id>', methods=['DELETE'])
    def kick_member(room_id, target_user_id):
        """[v4.9] 관리자가 멤버를 강제 퇴장시키기"""
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401

        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '대화방 접근 권한이 없습니다.'}), 403

        # 관리자 권한 확인
        if not is_room_admin(room_id, session['user_id']):
            return jsonify({'error': '관리자만 멤버를 퇴장시킬 수 있습니다.'}), 403
        
        # 자기 자신은 퇴장시킬 수 없음
        if target_user_id == session['user_id']:
            return jsonify({'error': '자신을 퇴장시킬 수 없습니다.'}), 400
        
        # [v4.10] 대상이 관리자인지 확인 - 관리자는 강퇴 불가
        if is_room_admin(room_id, target_user_id):
            return jsonify({'error': '관리자는 강퇴할 수 없습니다.'}), 403
        
        # 대상이 해당 방의 멤버인지 확인
        if not is_room_member(room_id, target_user_id):
            return jsonify({'error': '해당 사용자는 대화방 멤버가 아닙니다.'}), 400

        success = leave_room_db(room_id, target_user_id)
        if not success:
            return jsonify({'error': '강퇴 처리에 실패했습니다.'}), 400

        actor_id = int(session['user_id'])
        _emit_socket_event(
            'room_members_updated',
            {
                'room_id': room_id,
                'action': 'member_kicked',
                'user_id': int(target_user_id),
                'by_user_id': actor_id,
            },
            room_id=room_id,
            user_ids=[int(target_user_id)],
        )
        _emit_socket_event(
            'room_updated',
            {
                'room_id': room_id,
                'action': 'member_kicked',
                'user_id': int(target_user_id),
                'by_user_id': actor_id,
            },
            room_id=room_id,
            user_ids=[int(target_user_id)],
        )
        return jsonify({'success': True})
    
    @app.route('/api/rooms/<int:room_id>/name', methods=['PUT'])
    def update_room_name_route(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        # [v4.4] 멤버십 및 관리자 권한 확인
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '대화방 접근 권한이 없습니다.'}), 403
        if not is_room_admin(room_id, session['user_id']):
            return jsonify({'error': '관리자만 대화방 이름을 변경할 수 있습니다.'}), 403
        
        data = _json_dict()
        new_name = sanitize_input(data.get('name', ''), max_length=50)
        if not new_name:
            return jsonify({'error': '대화방 이름을 입력해주세요.'}), 400
        
        update_room_name(room_id, new_name)
        _emit_socket_event(
            'room_name_updated',
            {
                'room_id': room_id,
                'name': new_name,
                'by_user_id': int(session['user_id']),
            },
            room_id=room_id,
        )
        _emit_socket_event(
            'room_updated',
            {
                'room_id': room_id,
                'action': 'room_renamed',
                'name': new_name,
                'by_user_id': int(session['user_id']),
            },
            room_id=room_id,
        )
        return jsonify({'success': True})
    
    # NOTE: /pin-room is the explicit alias; /pin is kept for backwards compatibility.
    @app.route('/api/rooms/<int:room_id>/pin-room', methods=['POST'])
    @app.route('/api/rooms/<int:room_id>/pin', methods=['POST'])
    def pin_room_route(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        # [v4.4] 멤버십 확인
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '대화방 접근 권한이 없습니다.'}), 403
        
        data = _json_dict()
        pinned = data.get('pinned', True)
        if pin_room(session['user_id'], room_id, pinned):
            return jsonify({'success': True})
        return jsonify({'error': '설정 변경에 실패했습니다.'}), 400
    
    @app.route('/api/rooms/<int:room_id>/mute', methods=['POST'])
    def mute_room_route(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        # [v4.4] 멤버십 확인
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '대화방 접근 권한이 없습니다.'}), 403
        
        data = _json_dict()
        muted = data.get('muted', True)
        if mute_room(session['user_id'], room_id, muted):
            return jsonify({'success': True})
        return jsonify({'error': '설정 변경에 실패했습니다.'}), 400
    
    @app.route('/api/users/online')
    def get_online_users_route():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        users = get_online_users()
        users = [u for u in users if u['id'] != session['user_id']]
        return jsonify(users)
    
    @app.route('/api/messages/<int:message_id>', methods=['DELETE'])
    def delete_message_route(message_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        success, result = delete_message(message_id, session['user_id'])
        if success:
            return jsonify({'success': True, 'room_id': result})
        return jsonify({'error': result}), 403
    
    @app.route('/api/messages/<int:message_id>', methods=['PUT'])
    def edit_message_route(message_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        data = _json_dict()
        new_content = data.get('content', '')
        if not new_content:
            return jsonify({'error': '메시지 내용을 입력해주세요.'}), 400
        
        success, error, room_id = edit_message(message_id, session['user_id'], new_content)
        if success:
            return jsonify({'success': True, 'room_id': room_id})
        return jsonify({'error': error}), 403
    
    @app.route('/api/rooms/<int:room_id>/info')
    def get_room_info(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        # [v4.8] 멤버십 확인 추가
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '대화방 접근 권한이 없습니다.'}), 403
        
        room = get_room_by_id(room_id)
        if not room:
            return jsonify({'error': '대화방을 찾을 수 없습니다.'}), 404
        
        members = get_room_members(room_id)
        room['members'] = members
        room.pop('encryption_key', None)
        return jsonify(room)
    
    @app.route('/api/search')
    @limiter.limit("30 per minute")
    def search():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
    
        query = request.args.get('q')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        file_only = str(request.args.get('file_only', '')).lower() in ('1', 'true', 'yes')
        room_id = request.args.get('room_id', type=int)
        offset = request.args.get('offset', type=int)
        limit = request.args.get('limit', type=int)
        offset = max(offset if offset is not None else 0, 0)
        limit = min(max(limit if limit is not None else 50, 1), 200)
    
        # If no filters, return empty list (frontend expects list)
        if (not query or not query.strip()) and not date_from and not date_to and not file_only:
            return jsonify([])
    
        q = (query or '').strip()
        if q and len(q) < 2:
            return jsonify([])
    
        results = advanced_search(
            user_id=session['user_id'],
            query=(q or None),
            room_id=room_id,
            date_from=(date_from or None),
            date_to=(date_to or None),
            file_only=file_only,
            limit=limit,
            offset=offset,
        )
        return jsonify(results.get('messages', []))
    
    @app.route('/api/upload', methods=['POST'])
    def upload_file():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        upload_folder = app.config.get('UPLOAD_FOLDER', UPLOAD_FOLDER)

        room_id = request.form.get('room_id', type=int)
        if not room_id:
            return jsonify({'error': 'room_id가 필요합니다.'}), 400
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '대화방 접근 권한이 없습니다.'}), 403
        
        # [v4.2] 선제적 파일 크기 검사 (메모리 로드 전)
        max_size = 16 * 1024 * 1024  # 16MB
        if request.content_length and request.content_length > max_size:
            return jsonify({'error': f'파일 크기는 16MB 이하여야 합니다.'}), 413
        
        if 'file' not in request.files:
            return jsonify({'error': '파일이 없습니다.'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '파일이 선택되지 않았습니다.'}), 400
        
        if file and allowed_file(file.filename):
            # [v4.3] 파일 내용 검증 (Magic Number)
            if not validate_file_header(file):
                logger.warning(f"File signature mismatch: {file.filename}")
                return jsonify({'error': '파일 내용이 확장자와 일치하지 않습니다.'}), 400

            ok, reason = scan_upload_stream(
                file,
                filename=str(file.filename or ''),
                content_type=str(getattr(file, 'content_type', '') or ''),
            )
            if not ok:
                return jsonify({'error': reason or '업로드 스캔 정책에 의해 차단되었습니다.'}), 400

            filename = secure_filename(file.filename)
            # [v4.14] UUID 추가로 동시 업로드 시 파일명 충돌 방지
            unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}_{filename}"
            file_path = os.path.join(upload_folder, unique_filename)
            file.save(file_path)
            ok, reason = scan_saved_file(
                file_path,
                filename=filename,
                content_type=str(getattr(file, 'content_type', '') or ''),
            )
            if not ok:
                safe_file_delete(file_path)
                return jsonify({'error': reason or '업로드 파일 보안 검증에 실패했습니다.'}), 400
            file_size = os.path.getsize(file_path)
            ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            file_type = 'image' if ext in {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico'} else 'file'
            upload_token = issue_upload_token(
                user_id=session['user_id'],
                room_id=room_id,
                file_path=unique_filename,
                file_name=filename,
                file_type=file_type,
                file_size=file_size,
            )
            if not upload_token:
                safe_file_delete(file_path)
                return jsonify({'error': '업로드 토큰 발급에 실패했습니다.'}), 500
            return jsonify({
                'success': True,
                'file_path': unique_filename,
                'file_name': filename,
                'file_type': file_type,
                'upload_token': upload_token,
            })
        
        return jsonify({'error': '허용되지 않는 파일 형식입니다.'}), 400
    
    @app.route('/uploads/<path:filename>')
    def uploaded_file(filename):
        # 인증 확인
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        upload_folder = app.config.get('UPLOAD_FOLDER', UPLOAD_FOLDER)

        # 파일명 정규화
        safe_filename = secure_filename(os.path.basename(filename))

        # 하위 경로 검증 (profiles만 허용)
        is_profile = False
        if '/' in filename:
            subdir = os.path.dirname(filename)
            allowed_subdirs = ['profiles']
            if subdir not in allowed_subdirs:
                return jsonify({'error': '접근 권한이 없습니다.'}), 403
            safe_path = os.path.join(subdir, safe_filename)
            is_profile = (subdir == 'profiles')
        else:
            safe_path = safe_filename

        # 경로 검증
        full_path = os.path.realpath(os.path.join(upload_folder, safe_path))
        if not full_path.startswith(os.path.realpath(upload_folder)):
            logger.warning(f"Path traversal attempt: {filename}")
            return jsonify({'error': '잘못된 요청입니다.'}), 400

        if not os.path.isfile(full_path):
            return jsonify({'error': '파일을 찾을 수 없습니다.'}), 404

        download_name = safe_filename
        if not is_profile:
            # room_files에서 소유 방 확인 후 접근 제어
            try:
                conn = get_db()
                cursor = conn.cursor()
                lookup_path = safe_path.replace('\\', '/')
                cursor.execute(
                    'SELECT room_id, file_name FROM room_files WHERE file_path = ? ORDER BY id DESC LIMIT 1',
                    (lookup_path,),
                )
                row = cursor.fetchone()
            except Exception as e:
                logger.warning(f"Upload auth lookup failed: {e}")
                row = None

            if not row:
                return jsonify({'error': '파일을 찾을 수 없습니다.'}), 404

            room_id = row['room_id']
            download_name = row['file_name'] or download_name
            if not is_room_member(room_id, session['user_id']):
                return jsonify({'error': '접근 권한이 없습니다.'}), 403

        # Content-Disposition: 이미지는 inline, 그 외 파일은 attachment
        ext = os.path.splitext(safe_filename)[1].lower().lstrip('.')
        inline_exts = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico'}
        as_attachment = (not is_profile) and (ext not in inline_exts)

        response = send_from_directory(
            os.path.dirname(full_path),
            os.path.basename(full_path),
            as_attachment=as_attachment,
            download_name=download_name if as_attachment else None,
        )

        # 인증 리소스 캐시 정책
        if is_profile:
            response.headers['Cache-Control'] = 'private, max-age=3600'
        else:
            response.headers['Cache-Control'] = 'private, no-store'
        response.headers['Vary'] = 'Accept-Encoding'
        if not as_attachment and ext in inline_exts:
            response.headers['Content-Disposition'] = 'inline'
        return response

    # Service Worker
    @app.route('/sw.js')
    def service_worker():
        return send_from_directory(app.static_folder, 'sw.js', mimetype='application/javascript')
    
    # ============================================================================
    # 프로필 API
    # ============================================================================
    @app.route('/api/profile')
    def get_profile():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        user = get_user_by_id(session['user_id'])
        if user:
            return jsonify(user)
        return jsonify({'error': '사용자를 찾을 수 없습니다.'}), 404
    
    @app.route('/api/profile', methods=['PUT'])
    def update_profile():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        data = _json_dict()
        nickname = sanitize_input(data.get('nickname', ''), max_length=20)
        status_message = sanitize_input(data.get('status_message', ''), max_length=100)
        
        if nickname and len(nickname) < 2:
            return jsonify({'error': '닉네임은 2자 이상이어야 합니다.'}), 400
        
        success = update_user_profile(
            session['user_id'],
            nickname=nickname if nickname else None,
            status_message=status_message if status_message else None
        )
        
        if success:
            # 세션 닉네임도 업데이트
            if nickname:
                session['nickname'] = nickname
            return jsonify({'success': True})
        return jsonify({'error': '프로필 업데이트에 실패했습니다.'}), 500
    
    @app.route('/api/profile/image', methods=['POST'])
    def upload_profile_image():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        upload_folder = app.config.get('UPLOAD_FOLDER', UPLOAD_FOLDER)
        
        if 'file' not in request.files:
            return jsonify({'error': '파일이 없습니다.'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '파일이 선택되지 않았습니다.'}), 400
        
        # 이미지 파일만 허용
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
        if ext not in allowed_extensions:
            return jsonify({'error': '이미지 파일만 업로드 가능합니다.'}), 400
        
        # [v4.3] 파일 내용 검증
        if not validate_file_header(file):
            return jsonify({'error': '유효하지 않은 이미지 파일입니다.'}), 400
        
        # 파일 크기 제한 (5MB)
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        if size > 5 * 1024 * 1024:
            return jsonify({'error': '파일 크기는 5MB 이하여야 합니다.'}), 400
        
        # 프로필 이미지 폴더 생성
        profile_folder = os.path.join(upload_folder, 'profiles')
        os.makedirs(profile_folder, exist_ok=True)
        
        # [v4.12] 기존 프로필 이미지 삭제 (디스크 공간 절약)
        user = get_user_by_id(session['user_id'])
        if user and user.get('profile_image'):
            try:
                old_image_path = os.path.join(upload_folder, user['profile_image'])
                # [v4.14] safe_file_delete 사용
                if safe_file_delete(old_image_path):
                    logger.debug(f"Old profile image deleted: {user['profile_image']}")
            except Exception as e:
                logger.warning(f"Old profile image deletion failed: {e}")
        
        # 파일 저장 - [v4.14] UUID 추가로 동시 업로드 시 파일명 충돌 방지
        filename = f"{session['user_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}.{ext}"
        file_path = os.path.join(profile_folder, filename)
        file.save(file_path)
        
        # DB 업데이트
        try:
            profile_image = f"profiles/{filename}"
            success = update_user_profile(session['user_id'], profile_image=profile_image)
            
            if success:
                return jsonify({'success': True, 'profile_image': profile_image})
            return jsonify({'error': '프로필 이미지 데이터베이스 업데이트 실패'}), 500
        except Exception as e:
            logger.error(f"Profile update error: {e}")
            return jsonify({'error': '프로필 처리 중 오류가 발생했습니다.'}), 500
    
    @app.route('/api/profile/image', methods=['DELETE'])
    def delete_profile_image():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        # [v4.4] 기존 프로필 이미지 조회 후 삭제
        user = get_user_by_id(session['user_id'])
        upload_folder = app.config.get('UPLOAD_FOLDER', UPLOAD_FOLDER)
        if user and user.get('profile_image'):
            try:
                old_image_path = os.path.join(upload_folder, user['profile_image'])
                # [v4.14] safe_file_delete 사용
                safe_file_delete(old_image_path)
            except Exception as e:
                logger.warning(f"Profile image file deletion failed: {e}")
        
        # DB에서 프로필 이미지 삭제 (null로 설정)
        success = update_user_profile(session['user_id'], profile_image='')
        
        if success:
            return jsonify({'success': True})
        return jsonify({'error': '프로필 이미지 삭제에 실패했습니다.'}), 500
    
    # ============================================================================
    # 공지사항 (Pinned Messages) API
    # ============================================================================
    @app.route('/api/rooms/<int:room_id>/pins')
    def get_room_pins(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '접근 권한이 없습니다.'}), 403
        pins = get_pinned_messages(room_id)
        return jsonify(pins)
    
    @app.route('/api/rooms/<int:room_id>/pins', methods=['POST'])
    def create_pin(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '접근 권한이 없습니다.'}), 403
        
        # [v4.20] 모든 멤버가 공지 등록 가능 (관리자 제한 제거)
        
        data = _json_dict()
        message_id = data.get('message_id')
        content = sanitize_input(data.get('content', ''), max_length=500)
        
        if not message_id and not content:
            return jsonify({'error': '고정할 메시지 또는 내용을 입력해주세요.'}), 400
        
        pin_id = pin_message(room_id, session['user_id'], message_id, content)
        if pin_id:
            _emit_socket_event(
                'pin_updated',
                {
                    'room_id': room_id,
                    'pin_id': pin_id,
                    'action': 'pin_created',
                    'by_user_id': int(session['user_id']),
                },
                room_id=room_id,
            )
            return jsonify({'success': True, 'pin_id': pin_id})
        return jsonify({'error': '공지 고정에 실패했습니다.'}), 500
    
    @app.route('/api/rooms/<int:room_id>/pins/<int:pin_id>', methods=['DELETE'])
    def delete_pin(room_id, pin_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '접근 권한이 없습니다.'}), 403
        
        # [v4.20] 모든 멤버가 공지 삭제 가능 (관리자 제한 제거)
        
        success, error = unpin_message(pin_id, session['user_id'], room_id)
        if success:
            _emit_socket_event(
                'pin_updated',
                {
                    'room_id': room_id,
                    'pin_id': pin_id,
                    'action': 'pin_deleted',
                    'by_user_id': int(session['user_id']),
                },
                room_id=room_id,
            )
            return jsonify({'success': True})
        if error == '공지를 찾을 수 없습니다.':
            return jsonify({'error': error}), 404
        if error == '요청한 대화방과 공지의 대화방이 일치하지 않습니다.':
            return jsonify({'error': error}), 403
        return jsonify({'error': error or '공지 해제에 실패했습니다.'}), 400
    
    # ============================================================================
    # 투표 (Polls) API
    # ============================================================================
    @app.route('/api/rooms/<int:room_id>/polls')
    def get_polls(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '접근 권한이 없습니다.'}), 403
        
        polls = get_room_polls(room_id)
        for poll in polls:
            poll['my_votes'] = get_user_votes(poll['id'], session['user_id'])
        return jsonify(polls)
    
    @app.route('/api/rooms/<int:room_id>/polls', methods=['POST'])
    def create_poll_route(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '접근 권한이 없습니다.'}), 403
        
        data = _json_dict()
        question = sanitize_input(data.get('question', ''), max_length=200)
        options = data.get('options', [])
        multiple_choice = data.get('multiple_choice', False)
        anonymous = data.get('anonymous', False)
        ends_at = data.get('ends_at')  # [v4.8] ISO 형식 날짜/시간 문자열
        
        if not question:
            return jsonify({'error': '질문을 입력해주세요.'}), 400
        if len(options) < 2:
            return jsonify({'error': '최소 2개의 옵션이 필요합니다.'}), 400
        
        # [v4.9] ends_at 형식 검증
        if ends_at:
            from datetime import datetime
            try:
                # ISO 형식 파싱 시도
                ends_at_dt = datetime.fromisoformat(ends_at.replace('Z', '+00:00'))
                if ends_at_dt < datetime.now(ends_at_dt.tzinfo) if ends_at_dt.tzinfo else ends_at_dt < datetime.now():
                    return jsonify({'error': '마감 시간은 현재 시간 이후여야 합니다.'}), 400
                # DB 저장 형식으로 변환 (UTC 없이 문자열)
                ends_at = ends_at_dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                return jsonify({'error': '올바른 날짜/시간 형식이 아닙니다. (ISO 8601)'}), 400
        
        options = [sanitize_input(opt, max_length=100) for opt in options[:10]]
        
        poll_id = create_poll(room_id, session['user_id'], question, options, multiple_choice, anonymous, ends_at)
        if poll_id:
            poll = get_poll(poll_id)
            if poll:
                _emit_socket_event(
                    'poll_created',
                    {
                        'room_id': room_id,
                        'poll': poll,
                        'action': 'poll_created',
                        'by_user_id': int(session['user_id']),
                    },
                    room_id=room_id,
                )
                return jsonify({'success': True, 'poll': poll})
            logger.error(f"Poll created but lookup failed: poll_id={poll_id}")
            return jsonify({'error': '투표 생성 후 조회에 실패했습니다.'}), 500
        return jsonify({'error': '투표 생성에 실패했습니다.'}), 500
    
    @app.route('/api/polls/<int:poll_id>/vote', methods=['POST'])
    def vote_poll_route(poll_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        # [v4.6] 투표가 속한 방의 멤버십 확인
        poll = get_poll(poll_id)
        if not poll:
            return jsonify({'error': '투표를 찾을 수 없습니다.'}), 404
        if not is_room_member(poll['room_id'], session['user_id']):
            return jsonify({'error': '접근 권한이 없습니다.'}), 403
        
        data = _json_dict()
        option_ids = data.get('option_ids')
        option_id = data.get('option_id')
        selected: list[int] = []

        if isinstance(option_ids, list):
            for value in option_ids:
                try:
                    normalized = int(value)
                except (TypeError, ValueError):
                    continue
                if normalized > 0 and normalized not in selected:
                    selected.append(normalized)
        elif option_id is not None:
            try:
                normalized = int(option_id)
            except (TypeError, ValueError):
                normalized = 0
            if normalized > 0:
                selected.append(normalized)

        if not selected:
            return jsonify({'error': '옵션을 선택해주세요.'}), 400

        success, error = vote_poll(poll_id, selected, session['user_id'])
        if success:
            poll = get_poll(poll_id)
            poll['my_votes'] = get_user_votes(poll_id, session['user_id'])
            _emit_socket_event(
                'poll_updated',
                {
                    'room_id': int(poll.get('room_id') or 0),
                    'poll': poll,
                    'action': 'poll_voted',
                    'by_user_id': int(session['user_id']),
                },
                room_id=int(poll.get('room_id') or 0),
            )
            return jsonify({'success': True, 'poll': poll})
        return jsonify({'error': error}), 400
    
    @app.route('/api/polls/<int:poll_id>/close', methods=['POST'])
    def close_poll_route(poll_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        # [v4.5] 투표가 속한 방의 멤버십 확인
        poll = get_poll(poll_id)
        if not poll:
            return jsonify({'error': '투표를 찾을 수 없습니다.'}), 404
        if not is_room_member(poll['room_id'], session['user_id']):
            return jsonify({'error': '접근 권한이 없습니다.'}), 403
        
        # [v4.21] 투표 생성자 또는 관리자만 마감 가능
        is_admin = is_room_admin(poll['room_id'], session['user_id'])
        success, error = close_poll(poll_id, session['user_id'], is_admin=is_admin)
        if success:
            updated_poll = get_poll(poll_id)
            if updated_poll:
                _emit_socket_event(
                    'poll_updated',
                    {
                        'room_id': int(updated_poll.get('room_id') or 0),
                        'poll': updated_poll,
                        'action': 'poll_closed',
                        'by_user_id': int(session['user_id']),
                    },
                    room_id=int(updated_poll.get('room_id') or 0),
                )
            return jsonify({'success': True})
        return jsonify({'error': error or '투표 마감에 실패했습니다.'}), 403
    
    # ============================================================================
    # 파일 저장소 (Room Files) API
    # ============================================================================
    @app.route('/api/rooms/<int:room_id>/files')
    def get_files(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '접근 권한이 없습니다.'}), 403
        
        file_type = request.args.get('type')  # 'image', 'file', etc.
        files = get_room_files(room_id, file_type)
        return jsonify(files)
    
    @app.route('/api/rooms/<int:room_id>/files/<int:file_id>', methods=['DELETE'])
    def delete_file_route(room_id, file_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '접근 권한이 없습니다.'}), 403
        # [v4.8] 관리자도 파일 삭제 가능
        is_admin = is_room_admin(room_id, session['user_id'])
        # [v4.9] room_id 전달하여 다른 방 파일 삭제 방지
        success, file_path = delete_room_file(file_id, session['user_id'], room_id=room_id, is_admin=is_admin)
        if success:
            return jsonify({'success': True})
        return jsonify({'error': '파일 삭제 권한이 없습니다.'}), 403
    
    # ============================================================================
    # 리액션 (Reactions) API
    # ============================================================================
    @app.route('/api/messages/<int:message_id>/reactions')
    def get_reactions(message_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        # [v4.4] 메시지 접근 권한 확인
        room_id = get_message_room_id(message_id)
        if room_id is None or not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '대화방 접근 권한이 없습니다.'}), 403
        
        reactions = get_message_reactions(message_id)
        return jsonify(reactions)
    
    @app.route('/api/messages/<int:message_id>/reactions', methods=['POST'])
    def add_reaction_route(message_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        # [v4.4] 메시지 접근 권한 확인
        room_id = get_message_room_id(message_id)
        if room_id is None or not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '대화방 접근 권한이 없습니다.'}), 403
        
        data = _json_dict()
        emoji = data.get('emoji', '')
        if not emoji or len(emoji) > 10:
            return jsonify({'error': '유효하지 않은 이모지입니다.'}), 400
        
        success, action = toggle_reaction(message_id, session['user_id'], emoji)
        if success:
            reactions = get_message_reactions(message_id)
            return jsonify({'success': True, 'action': action, 'reactions': reactions})
        return jsonify({'error': '리액션 추가에 실패했습니다.'}), 500
    
    # ============================================================================
    # 관리자 권한 (Admin) API
    # ============================================================================
    @app.route('/api/rooms/<int:room_id>/admins')
    def get_admins(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '접근 권한이 없습니다.'}), 403
        
        admins = get_room_admins(room_id)
        return jsonify(admins)
    
    @app.route('/api/rooms/<int:room_id>/admins', methods=['POST'])
    def set_admin_route(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '접근 권한이 없습니다.'}), 403
        if not is_room_admin(room_id, session['user_id']):
            return jsonify({'error': '관리자 권한이 필요합니다.'}), 403
        
        data = _json_dict()
        target_user_id = data.get('user_id')
        if not isinstance(data.get('is_admin', True), bool):
            return jsonify({'error': 'is_admin은 boolean 값이어야 합니다.'}), 400
        is_admin = bool(data.get('is_admin', True))

        if target_user_id is None:
            return jsonify({'error': '사용자를 선택해주세요.'}), 400
        try:
            target_user_id = int(target_user_id)
        except (TypeError, ValueError):
            return jsonify({'error': '유효한 사용자 ID가 필요합니다.'}), 400
        if target_user_id <= 0:
            return jsonify({'error': '유효한 사용자 ID가 필요합니다.'}), 400
        if not is_room_member(room_id, target_user_id):
            return jsonify({'error': '해당 사용자는 대화방 멤버가 아닙니다.'}), 400
        
        # [v4.13] 마지막 관리자 해제 방지
        if not is_admin:
            admins = get_room_admins(room_id)
            if len(admins) <= 1:
                return jsonify({'error': '최소 한 명의 관리자가 필요합니다.'}), 400
        
        if set_room_admin(room_id, target_user_id, is_admin):
            _emit_socket_event(
                'admin_updated',
                {
                    'room_id': room_id,
                    'user_id': int(target_user_id),
                    'is_admin': bool(is_admin),
                    'by_user_id': int(session['user_id']),
                },
                room_id=room_id,
            )
            _emit_socket_event(
                'room_members_updated',
                {
                    'room_id': room_id,
                    'action': 'admin_updated',
                    'user_id': int(target_user_id),
                    'is_admin': bool(is_admin),
                    'by_user_id': int(session['user_id']),
                },
                room_id=room_id,
            )
            return jsonify({'success': True})
        return jsonify({'error': '관리자 설정에 실패했습니다.'}), 500
    
    @app.route('/api/rooms/<int:room_id>/admin-check')
    def check_admin(room_id):
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        # [v4.22] 멤버십 확인 추가
        if not is_room_member(room_id, session['user_id']):
            return jsonify({'error': '접근 권한이 없습니다.'}), 403
        is_admin = is_room_admin(room_id, session['user_id'])
        return jsonify({'is_admin': is_admin})
    
    # ============================================================================
    # 고급 검색 API
    # ============================================================================
    @app.route('/api/search/advanced', methods=['POST'])
    def advanced_search_route():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
        
        data = _json_dict()
        results = advanced_search(
            user_id=session['user_id'],
            query=data.get('query'),
            room_id=data.get('room_id'),
            sender_id=data.get('sender_id'),
            date_from=data.get('date_from'),
            date_to=data.get('date_to'),
            file_only=data.get('file_only', False)
        )
        return jsonify(results)

    # ============================================================================
    # [v4.1] 계정 보안 라우트
    # ============================================================================
    @app.route('/api/me/password', methods=['PUT'])
    def update_password():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
            
        data = _json_dict()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'error': '입력값이 부족합니다.'}), 400
            
        # [v4.3] 비밀번호 강도 검사
        from app.utils import validate_password
        is_valid, error_msg = validate_password(new_password)
        if not is_valid:
            return jsonify({'error': error_msg}), 400
            
        # [v4.21] 새 세션 토큰과 함께 비밀번호 변경
        success, error, new_session_token = change_password(session['user_id'], current_password, new_password)
        
        if success:
            # 현재 세션에 새 토큰 저장 (다른 세션은 무효화됨)
            if new_session_token:
                session['session_token'] = new_session_token
            log_access(session['user_id'], 'change_password', request.remote_addr, request.user_agent.string)
            return jsonify({
                'success': True,
                'message': '비밀번호가 변경되었습니다. 다른 기기에서의 세션은 로그아웃됩니다.'
            })
        else:
            return jsonify({'error': error}), 400

    @app.route('/api/me', methods=['DELETE'])
    def delete_account():
        if 'user_id' not in session:
            return jsonify({'error': '로그인이 필요합니다.'}), 401
            
        data = _json_dict()
        password = data.get('password')
        
        if not password:
            return jsonify({'error': '비밀번호를 입력해주세요.'}), 400
            
        success, error = delete_user(session['user_id'], password)
        
        if success:
            log_access(session['user_id'], 'delete_account', request.remote_addr, request.user_agent.string)
            session.clear()
            return jsonify({'success': True})
        else:
            return jsonify({'error': error}), 400


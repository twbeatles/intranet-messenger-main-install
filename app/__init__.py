# -*- coding: utf-8 -*-
"""
사내 메신저 v4.1 앱 패키지
Flask 앱 팩토리 패턴
"""

import os
import sys
import logging
import secrets
from datetime import datetime, timedelta

# gevent monkey patching (반드시 다른 import 전에 실행)
# [v4.1] GUI 모드에서는 PyQt6와 충돌하므로 비활성화
# [v4.2] server_launcher.py에서 이미 패치한 경우 감지
_IS_TESTING_PROCESS = bool(os.environ.get('PYTEST_CURRENT_TEST')) or ('pytest' in sys.modules)
_SKIP_GEVENT = os.environ.get('SKIP_GEVENT_PATCH', '0') == '1' or _IS_TESTING_PROCESS
_GEVENT_AVAILABLE = False
_GEVENT_ALREADY_PATCHED = False

# 이미 gevent가 패치되었는지 확인
try:
    from gevent import monkey
    _GEVENT_ALREADY_PATCHED = monkey.is_module_patched('socket')
    if _GEVENT_ALREADY_PATCHED:
        _GEVENT_AVAILABLE = True
except ImportError:
    pass

if not _SKIP_GEVENT and not _GEVENT_ALREADY_PATCHED:
    try:
        from gevent import monkey
        monkey.patch_all()
        _GEVENT_AVAILABLE = True
    except ImportError:
        _GEVENT_AVAILABLE = False

import json

from flask import Flask, request, session
from flask_socketio import SocketIO
from app.extensions import limiter, csrf, compress
from flask_session import Session
from app.api_response import enrich_error_payload_if_needed
from app.i18n import resolve_locale
try:
    from cachelib.file import FileSystemCache
except Exception:  # pragma: no cover
    FileSystemCache = None


# config 임포트 (PyInstaller 호환)
try:
    from config import (
        BASE_DIR, DATABASE_PATH, UPLOAD_FOLDER, MAX_CONTENT_LENGTH,
        SESSION_TIMEOUT_HOURS, APP_NAME, VERSION, USE_HTTPS,
        STATIC_FOLDER, TEMPLATE_FOLDER,
        ASYNC_MODE, PING_TIMEOUT, PING_INTERVAL, MAX_HTTP_BUFFER_SIZE,
        MAX_CONNECTIONS, MESSAGE_QUEUE,
        SOCKETIO_CORS_ALLOWED_ORIGINS,
        RATE_LIMIT_STORAGE_URI, RATE_LIMIT_KEY_MODE,
        SESSION_TOKEN_FAIL_OPEN,
        ENFORCE_HTTPS, ALLOW_SELF_REGISTER,
        UPLOAD_SCAN_ENABLED, UPLOAD_SCAN_PROVIDER,
        ENTERPRISE_AUTH_ENABLED, ENTERPRISE_AUTH_PROVIDER,
        REQUIRE_MESSAGE_ENCRYPTION,
    )
except ImportError:
    # 패키징된 환경에서 상대 경로 시도
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import (
        BASE_DIR, DATABASE_PATH, UPLOAD_FOLDER, MAX_CONTENT_LENGTH,
        SESSION_TIMEOUT_HOURS, APP_NAME, VERSION, USE_HTTPS,
        STATIC_FOLDER, TEMPLATE_FOLDER,
        ASYNC_MODE, PING_TIMEOUT, PING_INTERVAL, MAX_HTTP_BUFFER_SIZE,
        MAX_CONNECTIONS, MESSAGE_QUEUE,
        SOCKETIO_CORS_ALLOWED_ORIGINS,
        RATE_LIMIT_STORAGE_URI, RATE_LIMIT_KEY_MODE,
        SESSION_TOKEN_FAIL_OPEN,
        ENFORCE_HTTPS, ALLOW_SELF_REGISTER,
        UPLOAD_SCAN_ENABLED, UPLOAD_SCAN_PROVIDER,
        ENTERPRISE_AUTH_ENABLED, ENTERPRISE_AUTH_PROVIDER,
        REQUIRE_MESSAGE_ENCRYPTION,
    )

# 로깅 설정
try:
    from logging.handlers import RotatingFileHandler
    # [v4.2] 로그 파일 로테이션 적용 (10MB, 5백업)
    file_handler = RotatingFileHandler(
        os.path.join(BASE_DIR, 'server.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            file_handler,
            logging.StreamHandler()
        ]
    )
except (PermissionError, OSError):
    # 파일 로깅 실패 시 콘솔만 사용
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
logger = logging.getLogger(__name__)

# SocketIO 인스턴스 (전역)
socketio = None
session_guard_stats = {
    'fail_open_count': 0,
    'last_fail_open_at': None,
    'fail_closed_count': 0,
    'last_fail_closed_at': None,
}


def get_session_guard_stats() -> dict:
    return {
        'fail_open_count': int(session_guard_stats.get('fail_open_count') or 0),
        'last_fail_open_at': session_guard_stats.get('last_fail_open_at'),
        'fail_closed_count': int(session_guard_stats.get('fail_closed_count') or 0),
        'last_fail_closed_at': session_guard_stats.get('last_fail_closed_at'),
    }


def create_app():
    """Flask 앱 팩토리"""
    global socketio

    # 테스트/런타임에서 config가 동적으로 바뀌는 경우를 반영한다.
    runtime_upload_folder = UPLOAD_FOLDER
    runtime_rate_limit_storage_uri = RATE_LIMIT_STORAGE_URI
    runtime_rate_limit_key_mode = RATE_LIMIT_KEY_MODE
    runtime_session_token_fail_open = SESSION_TOKEN_FAIL_OPEN
    runtime_enforce_https = ENFORCE_HTTPS
    runtime_allow_self_register = ALLOW_SELF_REGISTER
    runtime_upload_scan_enabled = UPLOAD_SCAN_ENABLED
    runtime_upload_scan_provider = UPLOAD_SCAN_PROVIDER
    runtime_enterprise_auth_enabled = ENTERPRISE_AUTH_ENABLED
    runtime_enterprise_auth_provider = ENTERPRISE_AUTH_PROVIDER
    runtime_require_message_encryption = REQUIRE_MESSAGE_ENCRYPTION
    try:
        import config as runtime_config  # type: ignore

        runtime_upload_folder = str(
            getattr(runtime_config, 'UPLOAD_FOLDER', runtime_upload_folder) or runtime_upload_folder
        )
        runtime_rate_limit_storage_uri = str(
            getattr(runtime_config, 'RATE_LIMIT_STORAGE_URI', runtime_rate_limit_storage_uri)
            or runtime_rate_limit_storage_uri
        )
        runtime_rate_limit_key_mode = str(
            getattr(runtime_config, 'RATE_LIMIT_KEY_MODE', runtime_rate_limit_key_mode)
            or runtime_rate_limit_key_mode
        )
        runtime_session_token_fail_open = bool(
            getattr(runtime_config, 'SESSION_TOKEN_FAIL_OPEN', runtime_session_token_fail_open)
        )
        runtime_enforce_https = bool(
            getattr(runtime_config, 'ENFORCE_HTTPS', runtime_enforce_https)
        )
        runtime_allow_self_register = bool(
            getattr(runtime_config, 'ALLOW_SELF_REGISTER', runtime_allow_self_register)
        )
        runtime_upload_scan_enabled = bool(
            getattr(runtime_config, 'UPLOAD_SCAN_ENABLED', runtime_upload_scan_enabled)
        )
        runtime_upload_scan_provider = str(
            getattr(runtime_config, 'UPLOAD_SCAN_PROVIDER', runtime_upload_scan_provider)
            or runtime_upload_scan_provider
        )
        runtime_enterprise_auth_enabled = bool(
            getattr(runtime_config, 'ENTERPRISE_AUTH_ENABLED', runtime_enterprise_auth_enabled)
        )
        runtime_enterprise_auth_provider = str(
            getattr(runtime_config, 'ENTERPRISE_AUTH_PROVIDER', runtime_enterprise_auth_provider)
            or runtime_enterprise_auth_provider
        )
        runtime_require_message_encryption = bool(
            getattr(runtime_config, 'REQUIRE_MESSAGE_ENCRYPTION', runtime_require_message_encryption)
        )
    except Exception:
        pass
    
    # Static/Template 폴더 설정 (config에서 가져옴)
    static_folder = STATIC_FOLDER
    template_folder = TEMPLATE_FOLDER
    
    # 폴더 존재 확인 (패키징 환경에서는 이미 존재)
    if not os.path.exists(static_folder):
        os.makedirs(static_folder, exist_ok=True)
    if not os.path.exists(template_folder):
        os.makedirs(template_folder, exist_ok=True)
    os.makedirs(runtime_upload_folder, exist_ok=True)
    os.makedirs(os.path.join(runtime_upload_folder, 'profiles'), exist_ok=True)  # 프로필 이미지 폴더
    
    # Flask 앱 생성
    app = Flask(
        __name__,
        static_folder=static_folder,
        static_url_path='/static',
        template_folder=template_folder
    )
    
    # 설정 - SECRET_KEY 영구 저장 (새로고침 시 세션 유지)
    secret_key_file = os.path.join(BASE_DIR, '.secret_key')
    if os.path.exists(secret_key_file):
        with open(secret_key_file, 'r') as f:
            app.config['SECRET_KEY'] = f.read().strip()
    else:
        new_key = secrets.token_hex(32)
        with open(secret_key_file, 'w') as f:
            f.write(new_key)
        app.config['SECRET_KEY'] = new_key
    
    # [v4.3] 보안 솔트 생성 및 로드 (비밀번호 해시용)
    salt_file = os.path.join(BASE_DIR, '.security_salt')
    if os.path.exists(salt_file):
        with open(salt_file, 'r') as f:
            app.config['PASSWORD_SALT'] = f.read().strip()
    else:
        # 기존 하드코딩된 값과의 호환성은 utils.py에서 처리하거나
        # 새 설치 시에만 적용. 여기서는 새 솔트 생성.
        new_salt = secrets.token_hex(16)
        with open(salt_file, 'w') as f:
            f.write(new_salt)
        app.config['PASSWORD_SALT'] = new_salt
    
    app.config['UPLOAD_FOLDER'] = runtime_upload_folder
    app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
    app.config['SESSION_COOKIE_SECURE'] = USE_HTTPS  # HTTPS일 때만 True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=SESSION_TIMEOUT_HOURS)
    app.config['RATELIMIT_STORAGE_URI'] = runtime_rate_limit_storage_uri
    app.config['RATE_LIMIT_STORAGE_URI'] = runtime_rate_limit_storage_uri
    app.config['RATE_LIMIT_KEY_MODE'] = runtime_rate_limit_key_mode
    app.config['SESSION_TOKEN_FAIL_OPEN'] = runtime_session_token_fail_open
    app.config['ENFORCE_HTTPS'] = runtime_enforce_https
    app.config['ALLOW_SELF_REGISTER'] = runtime_allow_self_register
    app.config['UPLOAD_SCAN_ENABLED'] = runtime_upload_scan_enabled
    app.config['UPLOAD_SCAN_PROVIDER'] = runtime_upload_scan_provider
    app.config['ENTERPRISE_AUTH_ENABLED'] = runtime_enterprise_auth_enabled
    app.config['ENTERPRISE_AUTH_PROVIDER'] = runtime_enterprise_auth_provider
    app.config['REQUIRE_MESSAGE_ENCRYPTION'] = runtime_require_message_encryption
    
    # [v4.6+] Server-Side Session (CacheLib backend)
    session_dir = os.path.join(BASE_DIR, 'flask_session')
    os.makedirs(session_dir, exist_ok=True)
    app.config['SESSION_TYPE'] = 'cachelib'
    app.config['SESSION_PERMANENT'] = True
    if FileSystemCache is not None:
        app.config['SESSION_CACHELIB'] = FileSystemCache(cache_dir=session_dir, threshold=5000, default_timeout=0)
    else:  # pragma: no cover
        # Fallback for environments without cachelib import availability.
        app.config['SESSION_TYPE'] = 'filesystem'
        app.config['SESSION_FILE_DIR'] = session_dir
    Session(app)

    
    # Socket.IO 초기화 - 비동기 모드 선택
    # 우선순위: gevent (이미 패치된 경우) > config 설정 > threading
    _async_mode = None
    
    # [v4.2] gevent가 이미 패치되었으면 무조건 gevent 모드 사용
    if _GEVENT_AVAILABLE:
        try:
            import gevent  # noqa: F401
            from gevent import pywsgi  # noqa: F401
            _async_mode = 'gevent'
            logger.info(f"gevent 비동기 모드 활성화 (고성능 동시 접속 지원)")
        except ImportError:
            logger.warning("gevent를 찾을 수 없습니다. 다른 모드로 대체합니다.")
    
    if _async_mode is None and ASYNC_MODE == 'eventlet':
        try:
            import eventlet  # noqa: F401
            eventlet.monkey_patch()
            _async_mode = 'eventlet'
            logger.info("eventlet 비동기 모드 활성화")
        except ImportError:
            logger.warning("eventlet을 찾을 수 없습니다. 다른 모드로 대체합니다.")
    
    if _async_mode is None:
        try:
            import simple_websocket  # noqa: F401
            import engineio.async_drivers.threading  # noqa: F401
            _async_mode = 'threading'
            logger.info("threading 비동기 모드 활성화 (동시 접속 제한적)")
        except ImportError:
            _async_mode = None
    
    # Socket.IO 인스턴스 생성
    socketio_kwargs = {
        'ping_timeout': PING_TIMEOUT,
        'ping_interval': PING_INTERVAL,
        'max_http_buffer_size': MAX_HTTP_BUFFER_SIZE,
        'async_mode': _async_mode,
        'logger': False,
        'engineio_logger': False
    }

    # CORS: 기본은 동일 출처. 필요 시 config에서 화이트리스트 지정.
    if SOCKETIO_CORS_ALLOWED_ORIGINS is not None:
        socketio_kwargs['cors_allowed_origins'] = SOCKETIO_CORS_ALLOWED_ORIGINS
    
    # Redis 메시지 큐 설정 (대규모 배포용)
    if MESSAGE_QUEUE:
        socketio_kwargs['message_queue'] = MESSAGE_QUEUE
        logger.info(f"메시지 큐 활성화: {MESSAGE_QUEUE}")
    
    try:
        socketio = SocketIO(app, **socketio_kwargs)
        logger.info(f"Socket.IO 초기화 완료 (모드: {_async_mode or 'default'})")
    except ValueError as e:
        logger.warning(f"Socket.IO 초기화 경고: {e}, 기본 모드로 재시도")
        # 재시도 시에도 CORS는 기본(동일 출처)을 유지
        socketio = SocketIO(app, logger=False, engineio_logger=False)
    
    # 라우트 등록
    from app.routes import register_routes
    register_routes(app)
    
    # [v4.3] 보안 확장 초기화
    try:
        limiter._storage_uri = runtime_rate_limit_storage_uri  # type: ignore[attr-defined]
    except Exception:
        pass
    limiter.init_app(app)
    csrf.init_app(app)
    
    # [v4.4] 성능 최적화 - Gzip 압축 활성화
    compress.init_app(app)
    
    # Socket.IO 이벤트 등록
    from app.sockets import register_socket_events
    register_socket_events(socketio)
    
    # 데이터베이스 초기화
    # 데이터베이스 초기화
    from app.models import init_db, close_thread_db
    init_db()
    
    # [v4.15] 요청 종료 시 DB 연결 정리 (스레드 로컬)
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        close_thread_db()

    @app.before_request
    def validate_session_token_guard():
        user_id = session.get('user_id')
        if not user_id:
            return None
        path = request.path or ''
        if path.startswith('/static/'):
            return None

        def _is_sensitive_guard_request() -> bool:
            method = str(request.method or 'GET').upper()
            if path.startswith('/uploads/'):
                return True
            if path.startswith('/api/upload'):
                return True
            if path in ('/api/profile', '/api/profile/image', '/api/me/password'):
                return True
            if method in ('POST', 'PUT', 'PATCH', 'DELETE') and path.startswith('/api/'):
                return True
            return False

        try:
            from app.models import get_user_session_token

            current_token = get_user_session_token(int(user_id))
            if not current_token:
                return None
            if session.get('session_token') == current_token:
                return None
        except Exception as e:
            if _is_sensitive_guard_request():
                session_guard_stats['fail_closed_count'] = int(session_guard_stats.get('fail_closed_count') or 0) + 1
                session_guard_stats['last_fail_closed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                logger.error(f"Session token guard fail-closed(sensitive): {e}")
                session.clear()
                return (
                    json.dumps(
                        {'error': '세션 검증 시스템 오류입니다. 잠시 후 다시 시도해주세요.'},
                        ensure_ascii=False,
                    ),
                    503,
                    {'Content-Type': 'application/json; charset=utf-8'},
                )
            if bool(app.config.get('SESSION_TOKEN_FAIL_OPEN', True)):
                # Default behavior: fail-open in case of transient DB error.
                session_guard_stats['fail_open_count'] = int(session_guard_stats.get('fail_open_count') or 0) + 1
                session_guard_stats['last_fail_open_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                logger.warning(f"Session token guard fail-open: {e}")
                return None
            session_guard_stats['fail_closed_count'] = int(session_guard_stats.get('fail_closed_count') or 0) + 1
            session_guard_stats['last_fail_closed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logger.error(f"Session token guard fail-closed: {e}")
            session.clear()
            return (
                json.dumps(
                    {'error': '세션 검증 시스템 오류입니다. 잠시 후 다시 시도해주세요.'},
                    ensure_ascii=False,
                ),
                503,
                {'Content-Type': 'application/json; charset=utf-8'},
            )

        session.clear()
        return (
            json.dumps({'error': '세션이 만료되었습니다. 다시 로그인해주세요.'}, ensure_ascii=False),
            401,
            {'Content-Type': 'application/json; charset=utf-8'},
        )
    
    logger.info(f"{APP_NAME} v{VERSION} 앱 초기화 완료")
    
    # [v4.3] 보안 헤더 설정
    @app.after_request
    def add_security_headers(response):
        content_type = response.headers.get('Content-Type', '')
        if response.status_code >= 400 and 'application/json' in content_type:
            try:
                payload = response.get_json(silent=True)
                if isinstance(payload, dict):
                    locale_code = resolve_locale(req=request, sess=session)
                    updated = enrich_error_payload_if_needed(payload, locale_code)
                    response.set_data(json.dumps(updated, ensure_ascii=False).encode('utf-8'))
            except Exception:
                pass

        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        # CSP: 기본적으로 self만 허용, 스타일과 스크립트 inline 허용 (onclick 핸들러 필요)
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:;"
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

    return app, socketio

[English version](../en/OPERATIONS_RUNBOOK.md)

# 운영 런북

## 1) 서버 기동 체크

1. Python 가상환경 활성화
2. `python server.py --cli` 실행
3. 헬스 확인:
- `GET /api/client/update`
- `GET /api/system/health`
- 로그인/메시지 송수신 샘플 점검

## 2) 클라이언트 기동 체크

1. `python -m client.main --server-url http://<server>:5000`
2. 로그인
3. 앱 종료 후 재실행
4. 자동 로그인 복원(refresh) 확인

## 3) 장애 대응 우선순위

1. 인증 장애
- `device_sessions` 만료/폐기 상태 확인
- 서버 시간 동기화(NTP) 확인
- `flask_session/` 권한/디스크 확인

2. 실시간 끊김
- Socket.IO 연결 상태 확인
- 프록시/방화벽의 WebSocket 정책 확인
- `ASYNC_MODE` 및 gevent 설치 상태 확인

3. 파일 전송 장애
- `/api/upload` 응답의 `upload_token` 존재 확인
- 토큰 만료(기본 단기 TTL) 여부 확인
- 업로드 파일 크기(`MAX_CONTENT_LENGTH`) 및 확장자 허용 목록 확인

## 4) 백업 정책

필수 백업 대상:
- `messenger.db`
- `uploads/`
- `.secret_key`
- `.security_salt`
- `.master_key`
- `config.py`

백업 점검 스크립트:
- `scripts/verify_backup_requirements.ps1`

권장 주기:
- 일 1회 전체 백업 + 7일 보관
- 배포 직전/직후 수동 스냅샷 추가

## 5) 로그/모니터링

- 서버 로그 파일: `server.log` (로테이션)
- 모니터링 지표(권장):
  - 로그인 성공/실패 비율
  - 소켓 동시 연결 수
  - 메시지 처리량
  - 파일 업로드 실패율
  - 디바이스 세션 refresh 실패율

## 6) 보안 점검 항목

- `DESKTOP_ONLY_MODE` 설정이 운영 의도와 일치하는지 확인
- `DESKTOP_CLIENT_MIN_VERSION` 정책이 실제 배포 버전과 일치하는지 확인
- `/uploads` 무인증 접근 차단 재검증
- 관리자 권한 API(`.../admins`) 권한 검증 재검증

## 7) 정책 스위치(기본값)

- `ENFORCE_HTTPS=False`: HTTPS 미강제(미적용 시 경고 로깅)
- `ALLOW_SELF_REGISTER=True`: 공개 회원가입 허용(운영정책으로 차단 가능)
- `REQUIRE_MESSAGE_ENCRYPTION=False`: 평문 텍스트 허용(강제 시 소켓 송신 거부)
- `SESSION_TOKEN_FAIL_OPEN=True`: 세션 토큰 DB 예외 시 fail-open
- `MAINTENANCE_INTERVAL_MINUTES=30`: 정리 작업 주기
- `RATE_LIMIT_STORAGE_URI=memory://`: 메모리 기반 레이트리밋 저장소
- `RATE_LIMIT_KEY_MODE=ip`: IP 기준 레이트리밋 키
- `UPLOAD_SCAN_ENABLED=False`, `UPLOAD_SCAN_PROVIDER=noop`: 업로드 스캔 스캐폴딩 기본 비활성

## 8) 정기 유지보수 권장 작업

- 만료/폐기된 `device_sessions` 정리 배치
- 오래된 업로드 파일 정리(정책 기반)
- 대용량 방 성능 점검(메시지 10만+ 시나리오)


# OFFLINE_MESSENGER_IMPLEMENTATION_RISK_ROADMAP_20260226

## 1. 배경/목표

이 문서는 오프라인 사내망 메신저 운영 기준에서 구현 리스크(R1~R12)와 확장 과제(A1~A12)를 코드/문서/테스트 기준으로 추적하기 위한 기준 문서다.

## 2. 현재 기준선 요약 (2026-02-27)

- 코드 기준: `config.py`, `app/routes.py`, `app/sockets.py`, `app/models/base.py`, `client/app_controller.py`, `client/services/*`
- 계약 문서: `docs/ko|en/API_SOCKET_CONTRACT.md`, `docs/ko|en/ARCHITECTURE.md`, `docs/ko|en/OPERATIONS_RUNBOOK.md`
- 검증 수치: `pytest tests -q` -> `160 passed`
- 정책 기본값(현행 동작 보존):
  - `ALLOW_SELF_REGISTER=True`
  - `ENFORCE_HTTPS=False`
  - `REQUIRE_MESSAGE_ENCRYPTION=False`
  - `SESSION_TOKEN_FAIL_OPEN=True`

## 3. 확정 리스크 상세 (R1~R12)

| ID | 상태 | 현상/근거 | 영향 | 현재 조치(착수/반영) | 검증근거 | 검증일 | 잔여 액션 | 우선순위 |
|---|---|---|---|---|---|---|---|---|
| R1 | 부분 | `IMPLEMENTATION_RISK_AUDIT_20260224/20260225.md` 삭제 상태 | 과거 기준선 추적 단절 | `claude.md`, `gemini.md`에 삭제 유지/리스크 수용 명시 | 문서 현행 기준: `IMPLEMENTATION_RISK_AUDIT_20260226.md`, `OFFLINE_MESSENGER_IMPLEMENTATION_RISK_ROADMAP_20260226.md` | 2026-02-27 | 이 문서를 단일 기준으로 유지 | P1 |
| R2 | 부분 | 백업 필수 항목에서 `.master_key` 누락 가능 | 복구 시 방 키/암호화 데이터 접근 불능 | `docs/ko|en/OPERATIONS_RUNBOOK.md`, `scripts/verify_backup_requirements.ps1` 반영 | `docs/ko/OPERATIONS_RUNBOOK.md`, `docs/en/OPERATIONS_RUNBOOK.md`, `scripts/verify_backup_requirements.ps1` | 2026-02-27 | 운영 백업 작업 스케줄러 연동 | P0 |
| R3 | 부분 | "E2E" 표현과 서버 키 중계 모델 간 용어 불일치 | 보안 기대치 오해 | `docs/ko|en/ARCHITECTURE.md`에 서버 신뢰형 키 중계 모델 명시 | `docs/ko/ARCHITECTURE.md`, `docs/en/ARCHITECTURE.md`, `README.md` | 2026-02-27 | UI/README 보안 문구 지속 정합화 | P1 |
| R4 | 부분 | 평문 텍스트 전송 경로 존재 | 정책 미정 시 평문 유입 가능 | `REQUIRE_MESSAGE_ENCRYPTION` 플래그 도입, `app/sockets.py` 강제 분기 추가 | `config.py`, `app/sockets.py`, 회귀: `tests -q` 통과 | 2026-02-27 | 운영에서 강제 전환 여부 결정 | P0 |
| R5 | 부분 | 메모리 기반 재시도 큐는 앱 종료 시 유실 | 미전송 메시지 손실 | `client/services/outbox_store.py` + 영속 outbox 복구 구현 | `client/services/outbox_store.py`, `client/app_controller.py`, `tests/test_client_outbox_persistence.py` | 2026-02-27 | 전송 백오프 정책 고도화 | P0 |
| R6 | 부분 | 런타임 자동 refresh 루프 부재 | 장기 세션 만료 시 UX 저하 | `client/app_controller.py` 런타임 refresh 루프 + 401 1회 재시도 | `client/app_controller.py`, `tests/test_client_refresh_runtime_loop.py`, `tests/test_client_update_api.py` | 2026-02-27 | refresh 실패 알림/메트릭 추가 | P0 |
| R7 | 부분 | HTTPS 미적용 시 HTTP 폴백 | 운영 보안 저하 가능 | `ENFORCE_HTTPS` 도입, 미적용 경고/health 노출 | `config.py`, `app/__init__.py`, `app/routes.py`(`/api/system/health`) | 2026-02-27 | 인증서 자동배포/갱신 체계화 | P1 |
| R8 | 부분 | `memory://` + IP 기준 레이트리밋 한계 | NAT 과차단/우회/재시작 초기화 | `RATE_LIMIT_STORAGE_URI`, `RATE_LIMIT_KEY_MODE` 추가 | `config.py`, `app/extensions.py`, `app/routes.py` health 노출 | 2026-02-27 | Redis 기반 외부 저장소 전환 설계 | P1 |
| R9 | 부분 | 세션 토큰 가드 DB 예외 fail-open | 장애 시 검증 우회 가능 | `SESSION_TOKEN_FAIL_OPEN` 분기 + 민감 경로 fail-closed + 통계/health 노출 | `app/__init__.py`, `app/routes.py`, `tests/test_session_guard_fail_open_flag.py`, `tests/test_system_health_api.py` | 2026-02-27 | 운영 환경 전역 fail-closed 정책 검토 | P0 |
| R10 | 부분 | 정리 작업이 시작시점 중심 | 장기 가동 누적 데이터 증가 | `MAINTENANCE_INTERVAL_MINUTES` 기반 주기 스케줄러 추가 | `app/models/base.py`, `tests/test_maintenance_scheduler.py` | 2026-02-27 | SLA/보존 정책별 주기 튜닝 | P1 |
| R11 | 부분 | 공개 회원가입 기본 허용 | 사내 승인 정책 미적합 가능 | `ALLOW_SELF_REGISTER` + 승인 API 스캐폴딩(`/api/admin/users/approve`) | `config.py`, `app/routes.py`, `tests/test_register_policy_flag.py`, `tests/test_user_approval_flow_flagged.py` | 2026-02-27 | 기본값 전환 시점/승인운영 정의 | P1 |
| R12 | 미완료 | SQLite 단일 노드 + `MESSAGE_QUEUE=None` | SPOF/확장 한계 | 아키텍처 문서에 HA 전환 경로 명시 | `config.py` (`MESSAGE_QUEUE=None`), 문서 기준선 존재 | 2026-02-27 | RDBMS/Redis 단계 전환 리허설 | P2 |

## 4. 잠재 리스크/추가 기능 로드맵 (A1~A12)

| ID | 상태 | 항목 | 현재 상태 | 검증근거 | 검증일 | 다음 단계 | 우선순위 |
|---|---|---|---|---|---|---|---|
| A1 | 부분 | AD/LDAP/SSO 연동 | `/api/auth/enterprise-login` 스캐폴딩 | `app/routes.py`, `tests/test_enterprise_login_stub.py` | 2026-02-27 | provider 어댑터 구현 | P1 |
| A2 | 부분 | 승인형 프로비저닝 | `pending_user_approvals`, 승인 API 스캐폴딩 | `app/models/*approval*`, `app/routes.py`, `tests/test_user_approval_flow_flagged.py` | 2026-02-27 | 관리자 UX/감사로그 확장 | P1 |
| A3 | 미완료 | TLS 강제/인증서 자동화 | 경고/가시성 중심 반영 | `ENFORCE_HTTPS` 플래그/health 노출까지 확인 | 2026-02-27 | 강제모드/배포 자동화 설계 | P1 |
| A4 | 부분 | 영속 Outbox | 클라이언트 SQLite outbox 구현 | `client/services/outbox_store.py`, `tests/test_client_outbox_persistence.py` | 2026-02-27 | 재시도 백오프/충돌정책 고도화 | P0 |
| A5 | 부분 | 보존주기/법적보존 | `legal_holds` 스키마 착수 | `app/upload_tokens.py` hold 제외 처리, 관련 테스트 통과 | 2026-02-27 | 정책별 hold 적용 범위 확대 | P1 |
| A6 | 부분 | 주기 스케줄러 | maintenance scheduler 도입 | `app/models/base.py`, `tests/test_maintenance_scheduler.py` | 2026-02-27 | 운영 파라미터 표준화 | P1 |
| A7 | 부분 | 운영 지표/알림 | `/api/system/health` 추가 | `app/routes.py`, `tests/test_system_health_api.py` | 2026-02-27 | 외부 모니터링 연계 | P1 |
| A8 | 부분 | 백업-복구 자동검증 | `verify_backup_requirements.ps1` 추가 | `scripts/verify_backup_requirements.ps1`, `scripts/rehearse_disaster.ps1` | 2026-02-27 | CI/배포 파이프라인 연동 | P0 |
| A9 | 부분 | 업로드 스캔/DLP | scanner provider `noop` 스캐폴딩 | `app/security/upload_scanner.py`, `tests/test_upload_scan_hook.py` | 2026-02-27 | AV/DLP provider 연동 | P1 |
| A10 | 부분 | 업데이트 서명검증 | update metadata/검증 훅 스캐폴딩 | `client/services/update_checker.py`, `client/app_controller.py`, 관련 테스트 통과 | 2026-02-27 | 서명 필수 정책/키배포 체계 | P1 |
| A11 | 미완료 | HA 전환 경로 | 문서 설계 착수 | 문서 기준선만 존재, 실행 PoC 미수행 | 2026-02-27 | 단계별 PoC/마이그레이션 | P2 |
| A12 | 부분 | DR 리허설/장애주입 | `scripts/rehearse_disaster.ps1` 착수 | `scripts/rehearse_disaster.ps1` 존재 확인 | 2026-02-27 | 정례 리허설/복구시간 측정 | P1 |

## 5. 우선순위 실행 계획 (P0/P1/P2)

- 즉시(1~2주, P0)
  - 백업 검증 자동화 운영 반영(A8/R2)
  - Outbox/refresh 안정화(A4/R5/R6)
  - 세션 가드 전역 fail-closed 정책 운영결정(R9)
- 단기(1~2개월, P1)
  - enterprise/approval 실사용 수준 확장(A1/A2/R11)
  - TLS/업로드스캔/업데이트서명 정책 고도화(A3/A9/A10/R7)
  - 지표/스케줄러 튜닝(A6/A7/R10)
- 중기(분기, P2)
  - SQLite -> RDBMS/Redis 전환 리허설(A11/R12)
  - DR 정례화 및 장애주입 확대(A12)

## 6. 검증 시나리오 / 수용 기준

- 기준선 검증: `pytest tests -q` 전체 통과
- 근거 추적성: 리스크별 코드/문서 경로 매핑
- 오프라인 운영성: 재시작/단절/재연결 시 메시지/세션 복원 확인
- 보안성: 인증/토큰/TLS/업로드/세션 가드 플래그별 동작 점검
- 복구성: `.master_key` 포함 백업 필수항목 점검 스크립트 통과
- 완료 수용 기준: 각 항목에 `현상-영향-개선-검증` 4요소가 기록되어야 함

## 7. 부록: 근거 파일 인덱스

- 서버: `app/__init__.py`, `app/routes.py`, `app/sockets.py`, `app/extensions.py`, `app/models/base.py`
- 클라이언트: `client/app_controller.py`, `client/services/api_client.py`, `client/services/outbox_store.py`, `client/services/update_checker.py`
- 스크립트: `scripts/verify_backup_requirements.ps1`, `scripts/rehearse_disaster.ps1`
- 문서: `docs/ko|en/API_SOCKET_CONTRACT.md`, `docs/ko|en/ARCHITECTURE.md`, `docs/ko|en/OPERATIONS_RUNBOOK.md`, `claude.md`, `gemini.md`

## 8. 성능 리팩토링 반영 기록 (2026-02-27)

- 클라이언트
  - 방 목록 렌더 dedupe/소켓 room 재구독 dedupe/원격 검색 캐시 도입
  - 사이드바 검색 API 기본 limit 하향(20)
  - 메시지 row 인덱스 도입으로 증분 업데이트 비용 절감
- 서버
  - 소켓 멤버십 캐시 set + 핫패스 접근 체크 도입
  - 메시지 송신 핫패스에서 불필요한 unread COUNT 쿼리 제거
  - FTS 가용성 probe 결과 캐시(60초) 도입
- 근거 테스트
  - `tests/test_client_rooms_performance.py`
  - `tests/test_client_search_api_limit.py`
  - `tests/test_messages_fts_probe_cache.py`
  - `tests/test_socket_room_access_cache.py`
  - 전체 회귀: `pytest tests -q` -> `160 passed`

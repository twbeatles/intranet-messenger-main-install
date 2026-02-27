# 기능 구현 리스크 및 추가 과제 점검 보고서 (2026-02-26)

## 0) 점검 범위와 기준

- 참조 문서
  - `claude.md`
  - `README.md`
  - `IMPLEMENTATION_RISK_AUDIT_20260225.md`
- 코드 점검 범위
  - 서버: `app/__init__.py`, `app/routes.py`, `app/sockets.py`, `app/upload_tokens.py`, `app/models/*`
  - 클라이언트: `client/app_controller.py`, `client/services/socket_client.py`, `client/ui/main_window.py`
- 목적
  - 기능 구현 관점에서 잠재 장애/권한 누수/운영 리스크를 재점검하고, 즉시 반영 가능한 보강 과제를 우선순위화

## 1) 실행 검증 결과 (2026-02-27 재검증)

### 1.1 테스트 실행 상태

- 실행 명령: `pytest tests -q`
- 결과: **160 passed (0:02:38)**

### 1.2 핵심 시나리오 재검증

- 압축 fallback: `tests/test_compress_fallback.py`
- 강퇴/퇴장 직후 소켓 차단: `tests/test_socket_membership_unsubscribe.py`
- 프로필 이미지 원자성/고아 정리: `tests/test_profile_image_atomicity.py`
- 검색 debounce: `tests/test_client_search_debounce.py`
- 고급 검색 방어선: `tests/test_advanced_search_guards.py`
- 세션 가드 민감 경로 fail-closed: `tests/test_session_guard_fail_open_flag.py`

## 2) 리스크별 상태 (R1~R6)

| ID | 상태 | 검증근거 | 검증일 | 잔여 액션 |
|---|---|---|---|---|
| R1 | 완료 | `requirements.txt`에 `brotli` 추가, `app/extensions.py`에 `flask_compress` import 실패 fallback 추가, `tests/test_compress_fallback.py` 통과 | 2026-02-27 | 없음 |
| R2 | 완료 | `app/sockets.py` `force_remove_user_from_room`, `app/routes.py` leave/kick 성공 경로 강제 unsubscribe, `client/services/socket_client.py` `leave_room`, `client/app_controller.py` self-kick/self-leave 즉시 leave emit, `tests/test_socket_membership_unsubscribe.py` 통과 | 2026-02-27 | 없음 |
| R3 | 완료 | `app/routes.py` 프로필 이미지 저장/DB 반영/기존파일 삭제 순서 보강 + 실패 시 신규 파일 롤백, `app/upload_tokens.py` `cleanup_orphan_profile_files` 추가, `app/models/base.py` 유지보수 루프 통합, `tests/test_profile_image_atomicity.py` 통과 | 2026-02-27 | 없음 |
| R4 | 완료 | `client/app_controller.py` 검색 입력 300ms debounce (`_on_search_input_changed`, `_flush_search_request`) 적용, `tests/test_client_search_debounce.py` 통과 | 2026-02-27 | 없음 |
| R5 | 완료 | `app/routes.py` `/api/search/advanced`에 `@limiter.limit("30 per minute")` 및 query/date/id/file_only/limit/offset 검증 추가, `tests/test_advanced_search_guards.py`(400/200/429) 통과 | 2026-02-27 | 없음 |
| R6 | 부분 | `app/__init__.py` 민감 경로 강제 fail-closed + `fail_closed_count/last_fail_closed_at` 통계 추가, `app/routes.py` `/api/system/health` 확장 필드 반영, `tests/test_session_guard_fail_open_flag.py`, `tests/test_system_health_api.py` 통과 | 2026-02-27 | 운영 정책(전역 fail-closed 전환 여부) 최종 결정 필요 |

## 3) 요약

- 감사 문서 기준 미완료 핵심 항목 R1~R5는 코드/테스트로 완료 처리했습니다.
- 선택 정책 R6(민감 경로 fail-closed)도 코드/테스트 반영 완료했으나, 전역 정책 전환은 운영 의사결정이 남아 `부분`으로 유지합니다.
- 최종 상태는 전체 회귀(`pytest tests -q`) 결과와 일치하도록 확정했습니다.

## 4) 성능 최적화 리팩토링 반영 (2026-02-27)

### 4.1 문서 기준 참조

- `docs/ko/ARCHITECTURE.md`
  - 데스크톱 신뢰성 계층의 debounce/증분 동기화 원칙
- `docs/ko/OPERATIONS_RUNBOOK.md`
  - 대용량 방/장기 운영 성능 점검 항목

### 4.2 클라이언트 최적화

- `client/app_controller.py`
  - 방 목록 렌더 dedupe(`_set_rooms_view`) 도입
  - 소켓 `subscribe_rooms` dedupe(`_sync_socket_room_subscriptions`) 도입
  - 원격 검색 결과 단기 캐시(기본 5초) 도입으로 동일 질의 재호출 억제
- `client/services/api_client.py`
  - 사이드바 검색 API 기본 `limit=20` 적용(기존 기본 50 대비 페이로드/쿼리 부담 축소)
- `client/ui/main_window.py`
  - 메시지 ID -> row 인덱스 도입으로 `reaction_updated`/`message_edited`/`message_deleted` 갱신 시 선형 탐색 비용 축소

### 4.3 서버 최적화

- `app/sockets.py`
  - 사용자 방 멤버십 집합 캐시(`get_user_room_id_set`) 및 빠른 접근 체크(`user_has_room_access`) 도입
  - `subscribe_rooms`/`join_room`/`send_message`/`typing` 핫패스에서 캐시 우선 검증 적용
  - `send_message` 핫패스의 메시지당 unread COUNT 쿼리를 제거하고 호환 필드는 유지(`unread_count=0`)
- `app/models/messages.py`
  - FTS 가용성 probe 결과 캐시(60초 TTL) 도입
  - FTS query builder 정적 헬퍼화로 중복 파싱/프로브 비용 축소

### 4.4 검증 결과

- 신규/수정 테스트:
  - `tests/test_client_rooms_performance.py`
  - `tests/test_client_search_api_limit.py`
  - `tests/test_messages_fts_probe_cache.py`
  - `tests/test_socket_room_access_cache.py`
- 전체 회귀:
  - `pytest tests -q` -> **160 passed** (2026-02-27)

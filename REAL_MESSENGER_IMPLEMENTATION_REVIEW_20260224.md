# 실제 메신저 구현 점검 보고서 (2026-02-24)

## 0) 점검 기준

- 참조 문서:
  - `claude.md`
  - `README.md`
  - `TRANSITION_CHECKLIST.md`
- 코드 기준선:
  - 서버: `app/routes.py`, `app/sockets.py`, `app/models/*`
  - 데스크톱: `client/app_controller.py`, `client/ui/*`, `client/services/*`
- 현재 테스트 상태:
  - `pytest tests -q` 통과 (`92 passed`)

## 1) 핵심 결론

- 현재 빌드는 안정적으로 동작하지만, "실서비스 메신저" 기준으로 보면 **보안/실시간 동기화/기능 동등성**에서 아직 보강이 필요한 구간이 남아 있습니다.
- 특히 아래 2건은 우선 보완이 필요합니다.
  - **비인증 소켓 연결 허용**
  - **답장(reply_to) 참조를 통한 타 방 메시지 메타 노출 가능성**

## 2) 우선순위 이슈 (심각도 순)

## Critical-1. 비인증 소켓 연결이 허용됨

- 근거:
  - `app/sockets.py:120` (`connect` 핸들러)
  - `app/sockets.py:122` (`if 'user_id' in session:` 분기만 존재, 비인증 분기 거부 없음)
- 영향:
  - 로그인하지 않은 클라이언트도 WebSocket 연결 자체는 유지 가능.
  - 이벤트 핸들러에서 대부분 재검증하더라도 연결 리소스 소모/남용(DoS 표면) 위험.
- 권장 조치:
  - `connect`에서 `user_id` 없으면 즉시 `return False`.
  - 비인증 소켓 연결 거부 단위 테스트 추가.

## Critical-2. reply_to 참조 무결성 검증 부재로 타 방 메시지 정보 노출 가능

- 근거:
  - `app/sockets.py:288` (`reply_to` 입력 수용)
  - `app/sockets.py:343` (`create_message(..., reply_to, ...)`)
  - `app/models/messages.py:70`, `app/models/messages.py:97`, `app/models/messages.py:109`
    - `LEFT JOIN messages rm ON m.reply_to = rm.id` (같은 방 조건 없음)
- 영향:
  - 공격자가 다른 방 메시지 ID를 추정해 `reply_to`로 넣으면, 답장 미리보기(`reply_content`, `reply_sender`)가 현재 방에 노출될 수 있음.
- 권장 조치:
  - 저장 전 `reply_to` 메시지가 **동일 room_id**인지 검증.
  - 조회 SQL에 `rm.room_id = m.room_id` 조건 추가.
  - 회귀 테스트: 교차 방 `reply_to` 차단 시나리오.

## High-1. 읽음 처리(message_read) 위변조 가능성

- 근거:
  - `app/sockets.py:373` (`message_read` 이벤트)
  - `app/sockets.py:387` (`update_last_read` 호출 전 메시지-방 정합성 검증 없음)
  - `app/models/messages.py:131` (`update_last_read`는 message_id 존재/room 소속 검증 없음)
- 영향:
  - 임의/과도한 `message_id`로 읽음 상태를 비정상 갱신 가능.
  - 읽음 수/상태 신뢰도 저하.
- 권장 조치:
  - `message_id`가 실제로 `room_id` 소속인지 검증 후 업데이트.
  - 실패 시 소켓 에러 반환 및 무시.

## High-2. REST 변경사항의 실시간 동기화 경로가 불완전

- 근거:
  - `app/routes.py`의 방/멤버/이름/투표/공지/관리자 API 처리 경로에 소켓 브로드캐스트 없음.
  - `client/app_controller.py`는 일부 소켓 이벤트를 수신하지만, API 성공 후 대응 이벤트 송신 로직이 제한적.
- 영향:
  - 다중 클라이언트 환경에서 상태 반영이 지연되거나 새로고침 의존.
- 권장 조치:
  - 서버 측에서 REST 성공 시 canonical 이벤트를 직접 emit.
  - 이벤트 payload 표준화(`room_updated`, `poll_updated`, `pin_updated`, `admin_updated` 등).

## High-3. 데스크톱 클라이언트 기능 동등성 미완

- 근거:
  - `client/services/api_client.py`에 구현된 메서드 다수가 UI에서 사용되지 않음:
    - `create_room`, `invite_room_members`, `leave_room`, `update_room_name`, `get_profile`, `update_profile` 등
  - `client/ui/main_window.py` 액션 구성은 현재 `새로고침/설정/로그아웃/투표/파일/관리자` 중심.
- 영향:
  - 실제 메신저 핵심 기능(대화방 생성/초대/나가기/방이름 변경/프로필 관리)의 데스크톱 단독 운영 완성도 부족.
- 권장 조치:
  - Room Composer(새 대화), Member Invite, Leave Room, Room Rename, Profile Editor UI 추가.

## High-4. 타이핑 표시 송신 경로 미연결

- 근거:
  - `client/services/socket_client.py:127` (`send_typing` 구현 존재)
  - 클라이언트 컨트롤러/UI에서 `send_typing` 호출 경로 없음.
- 영향:
  - 수신 UI는 있으나 송신이 없어 타이핑 UX가 실질적으로 동작하지 않음.
- 권장 조치:
  - 입력창 변경 이벤트에 debounce(예: 500ms) 타이핑 송신/종료 송신 연결.

## Medium-1. 세션 저장소(keyring/fallback) 일관성 이슈

- 근거:
  - `client/services/session_store.py`:
    - keyring 사용 시 fallback 파일을 읽지 않음
    - keyring 경로에서 clear 시 fallback 파일 정리 생략
- 영향:
  - 환경 변경(키링 사용 가능/불가 전환) 시 자동로그인 복원/정리 불일치 가능.
- 권장 조치:
  - load 시 keyring 실패/빈값이면 fallback 재시도.
  - clear 시 keyring + fallback 동시 정리.

## Medium-2. 내부 예외 문자열 응답 노출

- 근거:
  - `app/routes.py:1054` (`str(e)`를 그대로 사용자 응답에 포함)
- 영향:
  - 서버 내부 정보(경로/라이브러리 오류) 노출 가능.
- 권장 조치:
  - 사용자 응답은 일반화된 메시지로 고정, 상세는 서버 로그로만 기록.

## Medium-3. 운영 기본값이 HTTP(비TLS) 중심

- 근거:
  - `config.py:44` (`USE_HTTPS = False`)
  - `app/__init__.py:158` (`SESSION_COOKIE_SECURE = USE_HTTPS`)
- 영향:
  - 운영 환경에서 TLS 미적용 시 세션 쿠키/트래픽 보안 위험.
- 권장 조치:
  - 운영 프로파일 분리(`dev`/`prod`) 및 prod 기본 TLS 강제.

## Medium-4. 업데이트 채널(canary) 설정 UI 부재

- 근거:
  - 서버/클라이언트는 채널 파라미터를 지원하지만(`channel=stable|canary`),
  - 설정 UI(`client/ui/settings_dialog.py`)에 채널 선택 항목 없음.
- 영향:
  - 채널 분리 기능이 운영자/테스터에게 가시적이지 않음.
- 권장 조치:
  - Settings에 채널 선택(Stable/Canary) 추가 + `QSettings('updates/channel')` 저장.

## Medium-5. 메시지 송신 ACK/재전송 전략 부재

- 근거:
  - `client/ui/main_window.py`에서 송신 즉시 입력창 초기화.
  - 소켓 송신 성공 ACK 기반의 로컬 pending 상태 관리 없음.
- 영향:
  - 네트워크 불안정 시 사용자 입장에서 "전송 성공/실패" 구분 어려움.
- 권장 조치:
  - client-side pending message + timeout/retry + failed badge 도입.

## 3) 실서비스 관점 추가 권장 기능

1. 운영/보안
- 관리자 행동 로그(강퇴/권한변경/공지삭제) 별도 감사 추적 강화
- 계정 보호(연속 로그인 실패 잠금/지연, 2FA 옵션)

2. 메신저 UX
- 메시지 편집/삭제/답장/리액션/공지 액션 UI를 데스크톱에서 직접 제공
- 대화방 생성/초대/나가기/이름 변경 전체 플로우 제공

3. 신뢰성
- 전송 ACK/재전송
- 재접속 후 missed events 동기화(최종 event id 기반)

4. 확장성
- SQLite 유지 시 고부하 한계 도달 전 모니터링 지표(락 대기/쿼리 지연) 추가
- 중장기 DB 전환(PostgreSQL) 마이그레이션 설계 초안 수립

## 4) 권장 실행 순서

1. Critical-1/2 선반영 (소켓 인증, reply_to 무결성)
2. High-1/2 (읽음 정합성, REST->Socket 실시간 브릿지)
3. High-3/4 (데스크톱 기능 동등성 + 타이핑 송신)
4. Medium 항목(세션스토어/오류노출/TLS/채널UI/ACK)

## 5) 비고

- 본 문서는 "현재 코드 기준 잠재 리스크 + 실서비스 전환 보강 포인트" 점검 결과입니다.
- 기능 추가 시 `docs/API_SOCKET_CONTRACT.md`, `TRANSITION_CHECKLIST.md`, 테스트 파일을 함께 갱신하는 것을 권장합니다.

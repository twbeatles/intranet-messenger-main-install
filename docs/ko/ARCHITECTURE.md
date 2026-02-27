[English version](../en/ARCHITECTURE.md)

# 아키텍처 개요

## 목표

기존 기능/비즈니스 로직을 유지하면서 웹 브라우저 의존을 제거하고, 설치형 데스크톱 메신저 중심 구조로 전환합니다.

## 시스템 구성

1. 중앙 서버
- 기술: `Flask + Flask-SocketIO + SQLite`
- 책임:
  - 인증/세션/권한
  - 메시지/파일/투표/관리자 API
  - 소켓 실시간 중계
  - 디바이스 세션 토큰 발급/회전/폐기

2. 데스크톱 클라이언트
- 기술: `PySide6 + httpx + python-socketio`
- 책임:
  - 사용자 로그인/세션 복원
  - 방/메시지 UI
  - 파일/투표/관리자 기능 UI
  - 트레이 상주/알림/자동실행

3. 저장소/파일
- DB: `messenger.db` (SQLite)
- 파일 저장: `uploads/`
- 세션 파일: `flask_session/` (서버사이드 세션)

## 서버 계층

- 엔트리: `server.py`
- 앱 팩토리: `app/__init__.py`
- 라우트: `app/routes.py`
- 소켓 이벤트: `app/sockets.py`
- 인증 토큰: `app/auth_tokens.py`
- 모델: `app/models/*`

## 클라이언트 계층

- 엔트리: `client/main.py`
- 오케스트레이션: `client/app_controller.py`
- UI 위젯: `client/ui/*`
- 서비스: `client/services/*`

## 인증/세션 설계

1. 로그인(`POST /api/device-sessions`)
- 아이디/비밀번호 검증
- `device_token` 발급
- 서버는 `token_hash`만 저장

2. 앱 재시작 자동 로그인
- 로컬 저장소(Windows Credential Manager + fallback 파일)에서 토큰 로드
- `POST /api/device-sessions/refresh`로 회전
- 성공 시 Flask 세션 재수립

3. 로그아웃
- `DELETE /api/device-sessions/current` 호출
- 로컬 토큰 삭제

4. 활성 세션 조회(`GET /api/device-sessions`)
- 기본은 미만료(active) 세션만 반환
- `include_expired=1` 지정 시 만료 세션 포함 반환

## 실시간 정합성 계층

- Socket.IO 연결 시 인증 세션이 없으면 `connect` 즉시 거부
- Socket `connect` 성공 시 사용자 전용 룸(`user_{user_id}`) + 소속 방 룸(`room_{room_id}`) join
- 소켓 멤버십 확인은 사용자별 room set 캐시를 우선 사용하고, 캐시 miss 시 DB fallback + 캐시 갱신으로 처리
- `send_message`:
  - 클라이언트 허용 타입은 `text|file|image` (`system`은 서버 내부 전용)
  - `reply_to`는 동일 방 메시지인지 검증
  - `client_msg_id` 기준 DB idempotency (`room_id + sender_id + client_msg_id` unique)
  - 파일/이미지는 `upload_token` 검증 후 처리
  - ACK 응답(`ok`, `message_id`/`error`) 제공
  - 중복 재전송은 기존 `message_id`로 ACK하고 재삽입/재중계는 하지 않음
- `message_read`:
  - `message_id`와 `room_id` 정합성 검증 후 읽음 반영
- REST 성공 시 서버가 canonical socket 이벤트를 관련 방/사용자에게만 emit하여 다중 클라이언트 동기화 보장

## 데스크톱 신뢰성 계층

- 입력창 `typing` 이벤트 debounce 송신(기본 500ms)
- 방 목록 렌더링은 시그니처 비교 기반 dedupe로 불필요한 전체 re-render를 억제
- 소켓 `subscribe_rooms`는 room ID 집합 변경 시에만 재구독
- 검색은 300ms debounce + 원격 검색 결과 단기 캐시(기본 5초)로 호출량 감소
- 텍스트/파일 모두 메시지 송신 pending/failed/retry + ACK 파이프라인으로 처리
- 로컬 `OutboxStore`(SQLite)로 미전송 메시지 영속화, 앱 재시작 시 복구
- 런타임 토큰 refresh 루프(만료 임계치 접근/401 1회 재시도)로 장기 세션 복원력 강화
- 메시지/타이핑 본인 판별은 닉네임이 아니라 `user_id` 기준으로 처리
- `read_updated`, `reaction_updated`, `message_edited`, `message_deleted`는 증분 반영 우선(실패 시 fallback reload)
- 메시지 위젯 갱신은 `message_id -> row` 인덱스로 처리해 증분 이벤트 비용을 줄임
- 설정에서 업데이트 채널(`stable`/`canary`) 선택 지원

## 보안/운영 포인트

- 메시지 E2E: `v2` 포맷 + `v1` 호환
- 서버는 메시지 평문 복호화 없이 저장/중계
- 현재 모델은 **서버 신뢰형 키 중계 모델**입니다.
  - 서버는 방 키(`encryption_key`)를 저장하고 API로 클라이언트에 전달할 수 있습니다.
  - 즉, "서버가 키를 알 수 없는 완전한 서버-비복호 E2E"와는 다릅니다.
- 파일 메시지 전송은 `upload_token` 검증 필수
- 방 생성자 퇴장 시 `created_by`는 남은 관리자 우선, 없으면 멤버에게 재할당(없으면 `NULL`)
- Socket.IO CORS는 기본 동일 출처 정책
- 운영 환경에서 `USE_HTTPS` 기본값은 환경변수(`MESSENGER_ENV`, `USE_HTTPS`) 기반으로 결정
- `/api/system/health`로 TLS/DB/session guard/maintenance/rate-limit 상태 노출
- 유지보수 정리 작업은 스케줄러(`MAINTENANCE_INTERVAL_MINUTES`) 기반 주기 실행

## 전환 정책

- 하이브리드 모드: `DESKTOP_ONLY_MODE=False`
- 데스크톱 전용 모드: `DESKTOP_ONLY_MODE=True`
- 모드 변경 자동화: `scripts/set_cutover_mode.ps1`

## 고가용성 전환(설계 착수)

현행은 SQLite 단일 노드 기반입니다. 확장 단계는 다음 순서를 권장합니다.

1. `SQLite` 유지 + 운영 가시성/백업 자동 검증 강화
2. 서버형 RDBMS(예: PostgreSQL) 이행 설계 및 마이그레이션 리허설
3. 메시지/레이트리밋 저장소 외부화(예: Redis)
4. 다중 인스턴스 + 장애 조치(Health check + 롤링 배포)

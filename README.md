# 사내 메신저 (Desktop-First)

English README: `README.en.md`

`Flask + Socket.IO` 서버와 `PySide6` 설치형 클라이언트로 구성된 사내 메신저입니다.  
기본 UI 언어는 한국어(`ko-KR`)이며, 영어(`en-US`)를 함께 지원합니다.

## 빠른 시작

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python server.py --cli
python -m client.main --server-url http://127.0.0.1:5000
```

## 핵심 기능

- 데스크톱 클라이언트: 트레이 상주, 자동 실행, 세션 복원
- 보안: 메시지 암호화(v2) + v1 복호화 호환 (서버 신뢰형 키 중계 모델)
- 인증: `device_sessions` 기반 토큰 발급/회전/폐기
- 운영: `GET /api/system/health` 및 정책 스위치 기반 운영 가시성
- 서버 응답 i18n 호환: `error` 유지 + `error_code`/`error_localized` 추가
- 웹 클라이언트: 유지보수 목적 i18n 지원(디자인 전면 개편 대상 아님)

## 문서

- 문서 허브: `docs/README.md`
- 한국어 문서 인덱스: `docs/ko/README.md`
- 영어 문서 인덱스: `docs/en/README.md`
- 정합성 점검 보고서(KO/EN): `docs/ko/CONSISTENCY_AUDIT_20260224.md`, `docs/en/CONSISTENCY_AUDIT_20260224.md`
- 구현 리스크/로드맵: `OFFLINE_MESSENGER_IMPLEMENTATION_RISK_ROADMAP_20260226.md`
- 루트 빌드/배포 가이드: `BUILD_DEPLOY_GUIDE.md`
- 세션 가이드: `claude.md`, `gemini.md`

## 디렉터리

```text
app/                 Flask routes, sockets, models
client/              PySide6 desktop client
gui/                 PyQt6 server management GUI
i18n/                ko/en catalogs (server/client/web/server_gui)
packaging/wix/       MSI .wxs templates
scripts/             build/cutover automation
docs/                ko/en documentation
```

## 테스트

```powershell
pytest tests -q
python -m compileall app client gui
```

[English version](../en/BUILD_EXE_GUIDE.md)

# EXE 빌드 가이드 (서버/클라이언트)

## 목적

spec 분리 빌드 기반으로 아래 2개 실행파일을 생성합니다.

- `MessengerServer.exe`
- `MessengerClient.exe`

## 사전 준비

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install pyinstaller
```

## 1) 자동 빌드 (권장)

```powershell
.\scripts\build_exe.ps1 -Target all -Clean
```

주요 결과:

- 원본 EXE:
  - `dist\MessengerServer.exe`
  - `dist\MessengerClient.exe`
- MSI 입력용 정리 폴더:
  - `dist\exe\server\MessengerServer.exe`
  - `dist\exe\client\MessengerClient.exe`

## 2) 수동 빌드

```powershell
pyinstaller messenger.spec --noconfirm --clean
pyinstaller messenger_client.spec --noconfirm --clean
```

## 3) 타겟별 준비

서버 패키지 폴더만 갱신:

```powershell
.\scripts\build_exe.ps1 -Target server
```

클라이언트 패키지 폴더만 갱신:

```powershell
.\scripts\build_exe.ps1 -Target client
```

## 4) 실패 시 점검

- `pyinstaller` 없음:
  - `pip install pyinstaller`
- 빌드 후 EXE 미생성:
  - `messenger.spec` 경로 확인
  - `build/`, `dist/` 정리 후 `-Clean` 재시도
- 누락 모듈 오류:
  - 가상환경에서 `pip install -r requirements.txt` 재실행
  - `messenger.spec`, `messenger_client.spec`는 `collect_submodules("app"|"client")`를 사용하므로
    신규 하위 모듈(`app/security/*`, `client/services/*`)은 기본적으로 자동 포함됨

## 5) 다음 단계 (MSI)

```powershell
.\scripts\build_msi.ps1 -Target server -BuildDir "dist\exe\server"
.\scripts\build_msi.ps1 -Target client -BuildDir "dist\exe\client"
```

## 6) 채널/서명 운영 (권장)

업데이트 채널(stable/canary) 구성:

```powershell
.\scripts\set_release_channel.ps1 -DefaultChannel stable -StableLatestVersion "1.0.0" -CanaryLatestVersion "1.1.0"
```

코드서명 자동화:

```powershell
.\scripts\sign_release.ps1 -Target all -CertThumbprint "<thumbprint>"
```


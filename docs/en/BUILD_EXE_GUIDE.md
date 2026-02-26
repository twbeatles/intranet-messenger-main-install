[Korean version](../ko/BUILD_EXE_GUIDE.md)

# EXE Build Guide (Server/Client)

## Purpose

Build these two binaries from separated PyInstaller specs:

- `MessengerServer.exe`
- `MessengerClient.exe`

## Prerequisites

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install pyinstaller
```

## 1) Automatic Build (Recommended)

```powershell
.\scripts\build_exe.ps1 -Target all -Clean
```

Main outputs:
- raw EXEs:
  - `dist\MessengerServer.exe`
  - `dist\MessengerClient.exe`
- MSI input folders:
  - `dist\exe\server\MessengerServer.exe`
  - `dist\exe\client\MessengerClient.exe`

## 2) Manual Build

```powershell
pyinstaller messenger.spec --noconfirm --clean
pyinstaller messenger_client.spec --noconfirm --clean
```

## 3) Per-target Build

Server only:

```powershell
.\scripts\build_exe.ps1 -Target server
```

Client only:

```powershell
.\scripts\build_exe.ps1 -Target client
```

## 4) Troubleshooting

- `pyinstaller` missing:
  - `pip install pyinstaller`
- EXE not generated:
  - verify `messenger.spec`/`messenger_client.spec`
  - clean `build/`, `dist/` and retry with `-Clean`
- missing module error:
  - run `pip install -r requirements.txt` again inside venv
  - `messenger.spec` and `messenger_client.spec` use `collect_submodules("app"|"client")`,
    so new submodules (`app/security/*`, `client/services/*`) are included by default

## 5) Next Step (MSI)

```powershell
.\scripts\build_msi.ps1 -Target server -BuildDir "dist\exe\server"
.\scripts\build_msi.ps1 -Target client -BuildDir "dist\exe\client"
```

## 6) Channel/Signing Operations (Recommended)

Configure update channels (stable/canary):

```powershell
.\scripts\set_release_channel.ps1 -DefaultChannel stable -StableLatestVersion "1.0.0" -CanaryLatestVersion "1.1.0"
```

Automate code signing:

```powershell
.\scripts\sign_release.ps1 -Target all -CertThumbprint "<thumbprint>"
```

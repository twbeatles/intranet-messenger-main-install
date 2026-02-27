# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller server spec
Builds: MessengerServer.exe

Usage:
  pyinstaller messenger.spec --noconfirm --clean
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


block_cipher = None
ROOT = Path(SPECPATH)

EXCLUDES = [
    "tkinter",
    "_tkinter",
    "matplotlib",
    "numpy",
    "pandas",
    "scipy",
    "cv2",
    "IPython",
    "jupyter",
    "pytest",
    "unittest",
    "doctest",
    "test",
    "pysqlite2",
    "MySQLdb",
    # Server build uses PyQt6 only.
    "PySide6",
]

hiddenimports = sorted(
    set(
        [
            "flask",
            "flask_socketio",
            "flask_session",
            "flask_limiter",
            "flask_wtf",
            "flask_compress",
            # Compression backends used by Flask-Compress.
            "brotli",
            "brotlicffi",
            "socketio",
            "engineio",
            "engineio.async_drivers.gevent",
            "engineio.async_drivers.threading",
            "simple_websocket",
            "gevent",
            "greenlet",
            "bcrypt",
            "Crypto",
            "Crypto.Cipher.AES",
            "Crypto.Util.Padding",
            "httpx",
            "keyring",
            "keyring.backends",
        ]
        + collect_submodules("app")
        + collect_submodules("gui")
    )
)

a = Analysis(
    ["server.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        ("static", "static"),
        ("templates", "templates"),
        ("certs", "certs"),
    ],
    hiddenimports=hiddenimports,
    hookspath=[str(ROOT)],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="MessengerServer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

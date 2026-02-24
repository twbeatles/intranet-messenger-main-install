# -*- coding: utf-8 -*-
"""
Persistent storage for device session token.
"""

from __future__ import annotations

import json
import os
import base64
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any


try:
    import keyring  # type: ignore
except Exception:  # pragma: no cover - optional dependency in some envs
    keyring = None


APP_SERVICE_NAME = 'IntranetMessengerDesktop'
APP_ACCOUNT_NAME = 'device_session'

_DPAPI_PREFIX = 'dpapi:'


if os.name == 'nt':
    CRYPTPROTECT_UI_FORBIDDEN = 0x1

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
else:  # pragma: no cover
    DATA_BLOB = object  # type: ignore
    _crypt32 = None
    _kernel32 = None


@dataclass
class StoredSession:
    server_url: str
    device_token: str
    device_name: str

    @staticmethod
    def from_dict(data: dict[str, Any]) -> 'StoredSession | None':
        if not isinstance(data, dict):
            return None
        server_url = str(data.get('server_url') or '').strip()
        token = str(data.get('device_token') or '').strip()
        device_name = str(data.get('device_name') or 'Desktop Client').strip()
        if not server_url or not token:
            return None
        return StoredSession(server_url=server_url, device_token=token, device_name=device_name)

    def to_dict(self) -> dict[str, str]:
        return {
            'server_url': self.server_url,
            'device_token': self.device_token,
            'device_name': self.device_name,
        }


class SessionStore:
    def __init__(self):
        appdata = os.environ.get('APPDATA') or os.path.expanduser('~')
        self._fallback_path = os.path.join(appdata, 'IntranetMessenger', 'session.json')

    @staticmethod
    def _dpapi_encrypt(raw: str) -> str:
        if os.name != 'nt':
            return raw
        data = raw.encode('utf-8')
        in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
        out_blob = DATA_BLOB()
        if not _crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        ):
            raise OSError('CryptProtectData failed')
        try:
            encrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return _DPAPI_PREFIX + base64.b64encode(encrypted).decode('ascii')
        finally:
            if out_blob.pbData:
                _kernel32.LocalFree(out_blob.pbData)

    @staticmethod
    def _dpapi_decrypt(raw: str) -> str:
        if os.name != 'nt' or not raw.startswith(_DPAPI_PREFIX):
            return raw
        payload = base64.b64decode(raw[len(_DPAPI_PREFIX):].encode('ascii'))
        in_blob = DATA_BLOB(len(payload), ctypes.cast(ctypes.create_string_buffer(payload), ctypes.POINTER(ctypes.c_byte)))
        out_blob = DATA_BLOB()
        if not _crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        ):
            raise OSError('CryptUnprotectData failed')
        try:
            decrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            return decrypted.decode('utf-8')
        finally:
            if out_blob.pbData:
                _kernel32.LocalFree(out_blob.pbData)

    def save(self, payload: StoredSession) -> None:
        raw = json.dumps(payload.to_dict(), ensure_ascii=True)
        if keyring:
            try:
                keyring.set_password(APP_SERVICE_NAME, APP_ACCOUNT_NAME, raw)
                return
            except Exception:
                pass

        os.makedirs(os.path.dirname(self._fallback_path), exist_ok=True)
        protected = self._dpapi_encrypt(raw)
        with open(self._fallback_path, 'w', encoding='utf-8') as fp:
            fp.write(protected)

    def load(self) -> StoredSession | None:
        raw = ''
        if keyring:
            try:
                raw = keyring.get_password(APP_SERVICE_NAME, APP_ACCOUNT_NAME) or ''
            except Exception:
                raw = ''

        if not raw and os.path.exists(self._fallback_path):
            with open(self._fallback_path, 'r', encoding='utf-8') as fp:
                raw = fp.read()

        if not raw:
            return None

        try:
            decoded = self._dpapi_decrypt(raw)
            data = json.loads(decoded)
        except Exception:
            return None
        return StoredSession.from_dict(data)

    def clear(self) -> None:
        if keyring:
            try:
                keyring.delete_password(APP_SERVICE_NAME, APP_ACCOUNT_NAME)
            except Exception:
                pass

        if os.path.exists(self._fallback_path):
            try:
                os.remove(self._fallback_path)
            except OSError:
                pass

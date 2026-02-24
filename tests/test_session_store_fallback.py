# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os

import client.services.session_store as session_store_module
from client.services.session_store import SessionStore, StoredSession


class _DummyKeyring:
    def __init__(self, stored_value: str = ''):
        self.stored_value = stored_value
        self.deleted = False

    def get_password(self, _service: str, _account: str) -> str:
        return self.stored_value

    def set_password(self, _service: str, _account: str, value: str) -> None:
        self.stored_value = value

    def delete_password(self, _service: str, _account: str) -> None:
        self.deleted = True
        self.stored_value = ''


def test_load_falls_back_to_file_when_keyring_has_no_value(monkeypatch, tmp_path):
    dummy_keyring = _DummyKeyring(stored_value='')
    monkeypatch.setattr(session_store_module, 'keyring', dummy_keyring)
    monkeypatch.setenv('APPDATA', str(tmp_path))

    store = SessionStore()
    expected = StoredSession(
        server_url='http://127.0.0.1:5000',
        device_token='token-from-fallback',
        device_name='Desktop',
    )

    raw = json.dumps(expected.to_dict(), ensure_ascii=True)
    os.makedirs(os.path.dirname(store._fallback_path), exist_ok=True)
    with open(store._fallback_path, 'w', encoding='utf-8') as fp:
        fp.write(store._dpapi_encrypt(raw))

    loaded = store.load()
    assert loaded is not None
    assert loaded.server_url == expected.server_url
    assert loaded.device_token == expected.device_token
    assert loaded.device_name == expected.device_name


def test_clear_removes_fallback_file_even_when_keyring_enabled(monkeypatch, tmp_path):
    dummy_keyring = _DummyKeyring(stored_value='{}')
    monkeypatch.setattr(session_store_module, 'keyring', dummy_keyring)
    monkeypatch.setenv('APPDATA', str(tmp_path))

    store = SessionStore()
    os.makedirs(os.path.dirname(store._fallback_path), exist_ok=True)
    with open(store._fallback_path, 'w', encoding='utf-8') as fp:
        fp.write('dummy')
    assert os.path.exists(store._fallback_path)

    store.clear()

    assert dummy_keyring.deleted is True
    assert not os.path.exists(store._fallback_path)


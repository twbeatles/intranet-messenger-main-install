# -*- coding: utf-8 -*-

from __future__ import annotations

from client.services.api_client import APIClient


def test_search_messages_uses_optimized_default_limit(monkeypatch):
    api = APIClient('http://localhost:5000')
    captured = {}

    def _request(method, path, *, params=None, **_kwargs):
        captured['method'] = method
        captured['path'] = path
        captured['params'] = dict(params or {})
        return []

    monkeypatch.setattr(api, '_request', _request)
    api.search_messages('hello')

    assert captured['method'] == 'GET'
    assert captured['path'] == '/api/search'
    assert captured['params']['q'] == 'hello'
    assert captured['params']['limit'] == 20


def test_search_messages_limit_is_clamped(monkeypatch):
    api = APIClient('http://localhost:5000')
    captured = {}

    def _request(method, path, *, params=None, **_kwargs):
        captured['params'] = dict(params or {})
        return []

    monkeypatch.setattr(api, '_request', _request)
    api.search_messages('hello', room_id=7, limit=9999)
    assert captured['params']['room_id'] == 7
    assert captured['params']['limit'] == 200

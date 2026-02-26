# -*- coding: utf-8 -*-

import pytest

from client.services.api_client import APIClient, ApiError


class _Resp:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = {'content-type': 'application/json'}

    def json(self):
        return dict(self._payload)


def test_api_client_retries_once_after_401_with_hook(monkeypatch):
    api = APIClient('http://localhost:5000')
    calls = {'request': 0, 'hook': 0}

    def _request(*args, **kwargs):
        calls['request'] += 1
        if calls['request'] == 1:
            return _Resp(401, {'error': 'expired'})
        return _Resp(200, {'ok': True})

    def _hook():
        calls['hook'] += 1
        return True

    monkeypatch.setattr(api._client, 'request', _request)
    api.set_unauthorized_retry_hook(_hook)

    payload = api._request('GET', '/api/test')
    assert payload['ok'] is True
    assert calls['hook'] == 1
    assert calls['request'] == 2


def test_api_client_raises_when_retry_hook_fails(monkeypatch):
    api = APIClient('http://localhost:5000')

    def _request(*args, **kwargs):
        return _Resp(401, {'error': 'expired', 'error_code': 'AUTH_TOKEN_INVALID_OR_EXPIRED'})

    monkeypatch.setattr(api._client, 'request', _request)
    api.set_unauthorized_retry_hook(lambda: False)

    with pytest.raises(ApiError):
        api._request('GET', '/api/test')

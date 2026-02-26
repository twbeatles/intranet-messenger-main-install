# -*- coding: utf-8 -*-


def _register_and_login(client, username: str):
    r = client.post(
        '/api/register',
        json={'username': username, 'password': 'Password123!', 'nickname': username},
    )
    assert r.status_code == 200
    login = client.post('/api/login', json={'username': username, 'password': 'Password123!'})
    assert login.status_code == 200


def test_session_guard_fail_open_default(client, monkeypatch):
    _register_and_login(client, 'guard_open')

    import app.models as models

    def _boom(_user_id):
        raise RuntimeError('db failure')

    monkeypatch.setattr(models, 'get_user_session_token', _boom)
    response = client.get('/api/rooms')
    assert response.status_code == 200


def test_session_guard_fail_closed_when_disabled(client, monkeypatch):
    _register_and_login(client, 'guard_closed')
    client.application.config['SESSION_TOKEN_FAIL_OPEN'] = False

    import app.models as models

    def _boom(_user_id):
        raise RuntimeError('db failure')

    monkeypatch.setattr(models, 'get_user_session_token', _boom)
    response = client.get('/api/rooms')
    assert response.status_code == 503

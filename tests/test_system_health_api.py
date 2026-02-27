# -*- coding: utf-8 -*-


def _register_and_login(client, username: str = 'health_user'):
    r = client.post(
        '/api/register',
        json={'username': username, 'password': 'Password123!', 'nickname': username},
    )
    assert r.status_code in (200, 202)
    login = client.post('/api/login', json={'username': username, 'password': 'Password123!'})
    assert login.status_code == 200


def test_system_health_requires_login(client):
    response = client.get('/api/system/health')
    assert response.status_code == 401


def test_system_health_shape(client):
    _register_and_login(client, 'health_user_ok')
    response = client.get('/api/system/health')
    assert response.status_code in (200, 503)
    payload = response.json
    assert 'status' in payload
    assert 'timestamp' in payload
    assert 'tls' in payload
    assert 'db' in payload
    assert 'session_guard' in payload
    assert 'maintenance' in payload
    assert 'rate_limit' in payload
    assert 'fail_closed_count' in payload['session_guard']
    assert 'last_fail_closed_at' in payload['session_guard']

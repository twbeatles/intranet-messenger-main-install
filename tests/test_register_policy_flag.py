# -*- coding: utf-8 -*-


def test_register_default_policy_allows_signup(client):
    response = client.post(
        '/api/register',
        json={'username': 'reg_default', 'password': 'Password123!', 'nickname': 'Default'},
    )
    assert response.status_code == 200
    assert response.json.get('success') is True


def test_register_pending_approval_when_self_register_disabled(client):
    client.application.config['ALLOW_SELF_REGISTER'] = False

    response = client.post(
        '/api/register',
        json={'username': 'reg_pending', 'password': 'Password123!', 'nickname': 'Pending'},
    )
    assert response.status_code == 202
    assert response.json.get('pending_approval') is True

    login = client.post('/api/login', json={'username': 'reg_pending', 'password': 'Password123!'})
    assert login.status_code == 403

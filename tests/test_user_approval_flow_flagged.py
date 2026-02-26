# -*- coding: utf-8 -*-


def _register(client, username: str):
    return client.post(
        '/api/register',
        json={'username': username, 'password': 'Password123!', 'nickname': username},
    )


def _login(client, username: str):
    return client.post('/api/login', json={'username': username, 'password': 'Password123!'})


def _device_login(client, username: str):
    return client.post(
        '/api/device-sessions',
        json={
            'username': username,
            'password': 'Password123!',
            'device_name': 'test-device',
            'remember': True,
        },
    )


def test_user_approval_approve_and_reject_flow(client):
    admin_reg = _register(client, 'platform_admin')
    assert admin_reg.status_code == 200
    admin_login = _login(client, 'platform_admin')
    assert admin_login.status_code == 200

    client.application.config['ALLOW_SELF_REGISTER'] = False

    pending = _register(client, 'pending_user')
    assert pending.status_code == 202
    pending_user_id = int(pending.json['user_id'])

    blocked_login = _device_login(client, 'pending_user')
    assert blocked_login.status_code == 403

    approve = client.post(
        '/api/admin/users/approve',
        json={'user_id': pending_user_id, 'action': 'approve', 'reason': 'ok'},
    )
    assert approve.status_code == 200

    allowed_login = _device_login(client, 'pending_user')
    assert allowed_login.status_code == 200
    _login(client, 'platform_admin')

    pending2 = _register(client, 'pending_user_2')
    assert pending2.status_code == 202
    pending_user_id2 = int(pending2.json['user_id'])
    reject = client.post(
        '/api/admin/users/approve',
        json={'user_id': pending_user_id2, 'action': 'reject', 'reason': 'deny'},
    )
    assert reject.status_code == 200
    rejected_login = _device_login(client, 'pending_user_2')
    assert rejected_login.status_code == 403

# -*- coding: utf-8 -*-

from __future__ import annotations


def _register(client, username: str, password: str = 'Password123!') -> None:
    response = client.post(
        '/api/register',
        json={
            'username': username,
            'password': password,
            'nickname': username,
        },
    )
    assert response.status_code == 200


def _login(client, username: str, password: str = 'Password123!') -> None:
    response = client.post('/api/login', json={'username': username, 'password': password})
    assert response.status_code == 200


def _room_message(room_id: int, text: str) -> dict:
    return {
        'room_id': int(room_id),
        'content': text,
        'type': 'text',
        'encrypted': False,
    }


def test_kicked_member_socket_stops_receiving_room_messages(app):
    from app import socketio

    owner_client = app.test_client()
    member_client = app.test_client()

    _register(owner_client, 'kick_owner_socket')
    _register(owner_client, 'kick_target_socket')

    _login(owner_client, 'kick_owner_socket')
    users = owner_client.get('/api/users').json
    target = next(u for u in users if u['username'] == 'kick_target_socket')
    room_resp = owner_client.post('/api/rooms', json={'name': 'Kick Room', 'members': [target['id']]})
    assert room_resp.status_code == 200
    room_id = int(room_resp.json['room_id'])

    _login(member_client, 'kick_target_socket')

    owner_socket = socketio.test_client(app, flask_test_client=owner_client)
    target_socket = socketio.test_client(app, flask_test_client=member_client)
    assert owner_socket.is_connected()
    assert target_socket.is_connected()

    try:
        owner_socket.get_received()
        target_socket.get_received()

        kicked = owner_client.delete(f'/api/rooms/{room_id}/members/{int(target["id"])}')
        assert kicked.status_code == 200

        # Consume membership update events and validate next room broadcast isolation.
        target_socket.get_received()
        owner_socket.emit('send_message', _room_message(room_id, 'after-kick'))
        owner_events = owner_socket.get_received()
        target_events = target_socket.get_received()

        assert any(evt['name'] == 'new_message' for evt in owner_events)
        assert not any(
            evt['name'] == 'new_message' and int((evt['args'][0] or {}).get('room_id') or 0) == room_id
            for evt in target_events
        )
    finally:
        owner_socket.disconnect()
        target_socket.disconnect()


def test_left_member_socket_stops_receiving_room_messages(app):
    from app import socketio

    owner_client = app.test_client()
    leaver_client = app.test_client()

    _register(owner_client, 'leave_owner_socket')
    _register(owner_client, 'leave_target_socket')

    _login(owner_client, 'leave_owner_socket')
    users = owner_client.get('/api/users').json
    leaver = next(u for u in users if u['username'] == 'leave_target_socket')
    room_resp = owner_client.post('/api/rooms', json={'name': 'Leave Room', 'members': [leaver['id']]})
    assert room_resp.status_code == 200
    room_id = int(room_resp.json['room_id'])

    _login(leaver_client, 'leave_target_socket')

    owner_socket = socketio.test_client(app, flask_test_client=owner_client)
    leaver_socket = socketio.test_client(app, flask_test_client=leaver_client)
    assert owner_socket.is_connected()
    assert leaver_socket.is_connected()

    try:
        owner_socket.get_received()
        leaver_socket.get_received()

        leave_response = leaver_client.post(f'/api/rooms/{room_id}/leave')
        assert leave_response.status_code == 200

        leaver_socket.get_received()
        owner_socket.emit('send_message', _room_message(room_id, 'after-leave'))
        owner_events = owner_socket.get_received()
        leaver_events = leaver_socket.get_received()

        assert any(evt['name'] == 'new_message' for evt in owner_events)
        assert not any(
            evt['name'] == 'new_message' and int((evt['args'][0] or {}).get('room_id') or 0) == room_id
            for evt in leaver_events
        )
    finally:
        owner_socket.disconnect()
        leaver_socket.disconnect()

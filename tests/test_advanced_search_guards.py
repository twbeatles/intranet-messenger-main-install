# -*- coding: utf-8 -*-

from __future__ import annotations

from unittest.mock import patch

import pytest


def _register_and_login(client, username: str) -> None:
    register = client.post(
        '/api/register',
        json={'username': username, 'password': 'Password123!', 'nickname': username},
    )
    assert register.status_code == 200
    login = client.post('/api/login', json={'username': username, 'password': 'Password123!'})
    assert login.status_code == 200


@pytest.mark.parametrize(
    ('payload', 'expected_error'),
    [
        ({'query': ['invalid']}, 'query는 문자열이어야 합니다.'),
        ({'room_id': 0}, 'room_id는 1 이상의 정수여야 합니다.'),
        ({'sender_id': 'abc'}, 'sender_id는 정수여야 합니다.'),
        ({'date_from': '2026/02/27'}, 'YYYY-MM-DD'),
        ({'file_only': 'not-bool'}, 'file_only는 boolean 값이어야 합니다.'),
        ({'limit': 'x'}, 'limit/offset은 정수여야 합니다.'),
    ],
)
def test_advanced_search_rejects_invalid_payload(client, payload, expected_error):
    _register_and_login(client, 'adv_invalid_user')
    response = client.post('/api/search/advanced', json=payload)
    assert response.status_code == 400
    assert expected_error in str((response.json or {}).get('error') or '')


def test_advanced_search_normalizes_payload_and_returns_200(client):
    _register_and_login(client, 'adv_valid_user')

    with patch('app.routes.advanced_search', return_value={'messages': []}) as mocked:
        response = client.post(
            '/api/search/advanced',
            json={
                'query': '  hello  ',
                'room_id': '7',
                'sender_id': 3,
                'date_from': '2026-02-01',
                'date_to': '2026-02-27',
                'file_only': 'true',
                'limit': 999,
                'offset': -50,
            },
        )
    assert response.status_code == 200
    assert response.json == {'messages': []}

    kwargs = mocked.call_args.kwargs
    assert kwargs['query'] == 'hello'
    assert kwargs['room_id'] == 7
    assert kwargs['sender_id'] == 3
    assert kwargs['date_from'] == '2026-02-01'
    assert kwargs['date_to'] == '2026-02-27'
    assert kwargs['file_only'] is True
    assert kwargs['limit'] == 200
    assert kwargs['offset'] == 0


def test_advanced_search_rate_limited_to_30_per_minute(client):
    _register_and_login(client, 'adv_rl_user')

    with patch('app.routes.advanced_search', return_value={'messages': []}):
        for _ in range(30):
            ok = client.post('/api/search/advanced', json={'query': 'hello'})
            assert ok.status_code == 200

        blocked = client.post('/api/search/advanced', json={'query': 'hello'})
    assert blocked.status_code == 429

# -*- coding: utf-8 -*-

from __future__ import annotations


def test_user_has_room_access_hits_cache_without_db(monkeypatch):
    import app.sockets as sockets

    monkeypatch.setattr(sockets, 'get_user_room_id_set', lambda _user_id: {10, 20})

    called = {'db': 0}

    def _db_check(_room_id, _user_id):
        called['db'] += 1
        return False

    monkeypatch.setattr(sockets, 'is_room_member', _db_check)
    assert sockets.user_has_room_access(1, 10) is True
    assert called['db'] == 0


def test_user_has_room_access_falls_back_to_db_on_cache_miss(monkeypatch):
    import app.sockets as sockets

    calls = {'cache': 0, 'db': 0, 'invalidate': 0}

    def _room_set(_user_id):
        calls['cache'] += 1
        # 1st call: miss, 2nd call(after invalidate): refreshed hit
        return set() if calls['cache'] == 1 else {30}

    def _db_check(room_id, user_id):
        calls['db'] += 1
        return int(room_id) == 30 and int(user_id) == 1

    def _invalidate(_user_id):
        calls['invalidate'] += 1

    monkeypatch.setattr(sockets, 'get_user_room_id_set', _room_set)
    monkeypatch.setattr(sockets, 'is_room_member', _db_check)
    monkeypatch.setattr(sockets, 'invalidate_user_cache', _invalidate)

    assert sockets.user_has_room_access(1, 30) is True
    assert calls['db'] == 1
    assert calls['invalidate'] == 1

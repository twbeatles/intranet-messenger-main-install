# -*- coding: utf-8 -*-

from __future__ import annotations

from client.app_controller import MessengerAppController


class _FakeMainWindow:
    def __init__(self):
        self.calls: list[list[dict]] = []

    def set_rooms(self, rooms):
        self.calls.append([dict(room) for room in rooms])


class _FakeSocket:
    def __init__(self):
        self.calls: list[list[int]] = []

    def subscribe_rooms(self, room_ids):
        self.calls.append(list(room_ids))


class _FakeApi:
    def __init__(self):
        self.calls = 0

    def search_messages(self, query, room_id=None, *, limit=20):
        self.calls += 1
        return [{'room_id': 2}]


def _controller() -> MessengerAppController:
    controller = MessengerAppController.__new__(MessengerAppController)
    controller.main_window = _FakeMainWindow()
    controller.socket = _FakeSocket()
    controller.api = _FakeApi()
    controller.rooms_cache = []
    controller.current_room_id = None
    controller._visible_rooms_signature = None
    controller._last_subscribed_room_ids = ()
    controller._remote_search_cache = {}
    controller._remote_search_cache_ttl_seconds = 60.0
    return controller


def test_set_rooms_view_skips_redundant_rerender():
    controller = _controller()
    rooms = [{'id': 1, 'name': 'alpha', 'last_message_preview': 'hello', 'unread_count': 0, 'pinned': 0}]

    rendered = controller._set_rooms_view(rooms)
    assert rendered is True
    assert len(controller.main_window.calls) == 1

    rendered_again = controller._set_rooms_view([dict(rooms[0])])
    assert rendered_again is False
    assert len(controller.main_window.calls) == 1


def test_sync_socket_room_subscriptions_only_when_changed():
    controller = _controller()

    controller._sync_socket_room_subscriptions([{'id': 3}, {'id': 1}, {'id': 3}, {'id': 2}])
    controller._sync_socket_room_subscriptions([{'id': 2}, {'id': 1}, {'id': 3}])
    controller._sync_socket_room_subscriptions([{'id': 1}, {'id': 4}])

    assert controller.socket.calls == [[1, 2, 3], [1, 4]]


def test_remote_search_cache_reuses_previous_lookup():
    controller = _controller()
    controller.rooms_cache = [
        {'id': 1, 'name': 'alpha', 'last_message_preview': 'one'},
        {'id': 2, 'name': 'beta', 'last_message_preview': 'two'},
    ]

    controller._on_search_requested('zz')
    controller._on_search_requested('zz')

    assert controller.api.calls == 1

# -*- coding: utf-8 -*-

from __future__ import annotations

from client.app_controller import MessengerAppController


class _FakeTimer:
    def __init__(self):
        self.started_with: list[int | None] = []

    def start(self, interval: int | None = None) -> None:
        self.started_with.append(interval)


def test_search_debounce_coalesces_rapid_input():
    controller = MessengerAppController.__new__(MessengerAppController)
    controller._search_debounce_timer = _FakeTimer()
    controller._pending_search_query = ''
    flushed: list[str] = []
    controller._on_search_requested = lambda query: flushed.append(str(query))

    controller._on_search_input_changed('h')
    controller._on_search_input_changed('he')
    controller._on_search_input_changed('hello')

    assert controller._pending_search_query == 'hello'
    assert controller._search_debounce_timer.started_with == [300, 300, 300]

    controller._flush_search_request()
    assert flushed == ['hello']

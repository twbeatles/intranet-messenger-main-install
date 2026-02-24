# -*- coding: utf-8 -*-
"""
Socket.IO client wrapper.
"""

from __future__ import annotations

from typing import Any, Callable

import socketio


EventCallback = Callable[[dict[str, Any]], None]
AckCallback = Callable[[dict[str, Any]], None]


class SocketClient:
    def __init__(self):
        self._client = socketio.Client(reconnection=True, logger=False, engineio_logger=False)
        self._handlers: dict[str, list[EventCallback]] = {}
        self._register_internal_handlers()

    def _register_internal_handlers(self) -> None:
        @self._client.on('connect')
        def _on_connect():
            self._emit_local('connect', {})

        @self._client.on('disconnect')
        def _on_disconnect():
            self._emit_local('disconnect', {})

        @self._client.on('new_message')
        def _on_new_message(data):
            self._emit_local('new_message', data or {})

        @self._client.on('read_updated')
        def _on_read_updated(data):
            self._emit_local('read_updated', data or {})

        @self._client.on('user_typing')
        def _on_user_typing(data):
            self._emit_local('user_typing', data or {})

        @self._client.on('room_updated')
        def _on_room_updated(data):
            self._emit_local('room_updated', data or {})

        @self._client.on('room_name_updated')
        def _on_room_name_updated(data):
            self._emit_local('room_name_updated', data or {})

        @self._client.on('room_members_updated')
        def _on_room_members_updated(data):
            self._emit_local('room_members_updated', data or {})

        @self._client.on('message_deleted')
        def _on_message_deleted(data):
            self._emit_local('message_deleted', data or {})

        @self._client.on('message_edited')
        def _on_message_edited(data):
            self._emit_local('message_edited', data or {})

        @self._client.on('reaction_updated')
        def _on_reaction_updated(data):
            self._emit_local('reaction_updated', data or {})

        @self._client.on('poll_updated')
        def _on_poll_updated(data):
            self._emit_local('poll_updated', data or {})

        @self._client.on('poll_created')
        def _on_poll_created(data):
            self._emit_local('poll_created', data or {})

        @self._client.on('pin_updated')
        def _on_pin_updated(data):
            self._emit_local('pin_updated', data or {})

        @self._client.on('admin_updated')
        def _on_admin_updated(data):
            self._emit_local('admin_updated', data or {})

        @self._client.on('error')
        def _on_error(data):
            self._emit_local('error', data or {})

    def _emit_local(self, event: str, payload: dict[str, Any]) -> None:
        for callback in self._handlers.get(event, []):
            callback(payload)

    def on(self, event: str, callback: EventCallback) -> None:
        self._handlers.setdefault(event, []).append(callback)

    def connect(self, server_url: str, cookie_header: str = '', language: str = '') -> None:
        headers = {}
        if cookie_header:
            headers['Cookie'] = cookie_header
        if language:
            headers['X-App-Language'] = language

        base_url = server_url.rstrip('/')
        if language:
            sep = '&' if '?' in base_url else '?'
            base_url = f'{base_url}{sep}lang={language}'

        self._client.connect(base_url, headers=headers, transports=['websocket', 'polling'])

    def disconnect(self) -> None:
        if self._client.connected:
            self._client.disconnect()

    def emit(self, event: str, payload: dict[str, Any]) -> None:
        self._client.emit(event, payload)

    def join_room(self, room_id: int) -> None:
        self.emit('join_room', {'room_id': room_id})

    def subscribe_rooms(self, room_ids: list[int]) -> None:
        self.emit('subscribe_rooms', {'room_ids': room_ids})

    def send_message(self, payload: dict[str, Any], ack_callback: AckCallback | None = None) -> None:
        if ack_callback is None:
            self.emit('send_message', payload)
            return

        def _callback(*args: Any) -> None:
            if args and isinstance(args[0], dict):
                ack_callback(args[0])
                return
            ack_callback({})

        self._client.emit('send_message', payload, callback=_callback)

    def send_read(self, room_id: int, message_id: int) -> None:
        self.emit('message_read', {'room_id': room_id, 'message_id': message_id})

    def send_typing(self, room_id: int, is_typing: bool) -> None:
        self.emit('typing', {'room_id': room_id, 'is_typing': is_typing})

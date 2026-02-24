# -*- coding: utf-8 -*-
"""
HTTP API wrapper for the desktop client.
"""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from client.i18n import t


class ApiError(RuntimeError):
    def __init__(self, message: str, *, status_code: int, error_code: str = ''):
        super().__init__(message)
        self.status_code = int(status_code)
        self.error_code = str(error_code or '')


class APIClient:
    def __init__(self, base_url: str, timeout: float = 15.0, language_getter=None):
        self.base_url = base_url.rstrip('/')
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout)
        self._csrf_token = ''
        self._language_getter = language_getter

    def update_base_url(self, base_url: str) -> None:
        self.base_url = base_url.rstrip('/')
        self._client.close()
        self._client = httpx.Client(base_url=self.base_url, timeout=15.0)
        self._csrf_token = ''

    def set_language_getter(self, language_getter) -> None:
        self._language_getter = language_getter

    def close(self) -> None:
        self._client.close()

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._language_getter:
            try:
                locale_value = str(self._language_getter() or '').strip()
                if locale_value:
                    headers['X-App-Language'] = locale_value
            except Exception:
                pass
        if self._csrf_token:
            headers['X-CSRFToken'] = self._csrf_token
        if extra:
            headers.update(extra)
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        response = self._client.request(
            method,
            path,
            json=json_data,
            params=params,
            headers=self._headers(headers),
        )
        content_type = response.headers.get('content-type', '')
        payload: Any = {}
        if 'application/json' in content_type:
            payload = response.json()

        if response.status_code >= 400:
            error_code = ''
            if isinstance(payload, dict):
                message = payload.get('error_localized') or payload.get('error') or f'HTTP {response.status_code}'
                error_code = str(payload.get('error_code') or '')
            else:
                message = f'HTTP {response.status_code}'
            raise ApiError(str(message), status_code=response.status_code, error_code=error_code)

        return payload

    def get_cookie_header(self) -> str:
        parts = []
        for cookie in self._client.cookies.jar:
            parts.append(f'{cookie.name}={cookie.value}')
        return '; '.join(parts)

    def set_csrf_token(self, csrf_token: str) -> None:
        self._csrf_token = csrf_token or ''

    def register(self, username: str, password: str, nickname: str) -> dict[str, Any]:
        return self._request(
            'POST',
            '/api/register',
            json_data={
                'username': username,
                'password': password,
                'nickname': nickname,
            },
        )

    def login(self, username: str, password: str) -> dict[str, Any]:
        payload = self._request(
            'POST',
            '/api/login',
            json_data={'username': username, 'password': password},
        )
        self._csrf_token = payload.get('csrf_token', '')
        return payload

    def logout(self, device_token: str = '') -> dict[str, Any]:
        headers = {'X-Device-Token': device_token} if device_token else None
        return self._request('POST', '/api/logout', headers=headers)

    def create_device_session(
        self,
        username: str,
        password: str,
        device_name: str,
        remember: bool = True,
    ) -> dict[str, Any]:
        payload = self._request(
            'POST',
            '/api/device-sessions',
            json_data={
                'username': username,
                'password': password,
                'device_name': device_name,
                'remember': remember,
            },
        )
        self._csrf_token = payload.get('csrf_token', '')
        return payload

    def refresh_device_session(self, device_token: str) -> dict[str, Any]:
        payload = self._request(
            'POST',
            '/api/device-sessions/refresh',
            json_data={'device_token': device_token},
            headers={'X-Device-Token': device_token},
        )
        self._csrf_token = payload.get('csrf_token', '')
        return payload

    def revoke_current_device_session(self, device_token: str = '') -> dict[str, Any]:
        headers = {'X-Device-Token': device_token} if device_token else None
        return self._request(
            'DELETE',
            '/api/device-sessions/current',
            json_data={'device_token': device_token} if device_token else None,
            headers=headers,
        )

    def get_device_sessions(self, include_expired: bool = False) -> list[dict[str, Any]]:
        params = {'include_expired': 1} if include_expired else None
        payload = self._request('GET', '/api/device-sessions', params=params)
        return payload.get('sessions', [])

    def revoke_device_session(self, session_id: int) -> dict[str, Any]:
        return self._request('DELETE', f'/api/device-sessions/{session_id}')

    def get_me(self) -> dict[str, Any]:
        return self._request('GET', '/api/me')

    def get_users(self) -> list[dict[str, Any]]:
        return self._request('GET', '/api/users')

    def get_rooms(self, include_members: bool = False) -> list[dict[str, Any]]:
        params = {'include_members': 1 if include_members else 0}
        return self._request('GET', '/api/rooms', params=params)

    def create_room(self, member_ids: list[int], name: str = '') -> dict[str, Any]:
        return self._request(
            'POST',
            '/api/rooms',
            json_data={'members': member_ids, 'name': name},
        )

    def get_messages(
        self,
        room_id: int,
        *,
        before_id: int | None = None,
        limit: int = 50,
        include_meta: bool = True,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            'limit': limit,
            'include_meta': 1 if include_meta else 0,
        }
        if before_id:
            params['before_id'] = before_id
        return self._request('GET', f'/api/rooms/{room_id}/messages', params=params)

    def get_online_users(self) -> list[dict[str, Any]]:
        return self._request('GET', '/api/users/online')

    def search_messages(self, query: str, room_id: int | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {'q': query}
        if room_id:
            params['room_id'] = room_id
        return self._request('GET', '/api/search', params=params)

    def check_client_update(self, client_version: str, channel: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {'client_version': client_version}
        normalized_channel = (channel or '').strip().lower()
        if normalized_channel in ('stable', 'canary'):
            params['channel'] = normalized_channel
        return self._request(
            'GET',
            '/api/client/update',
            params=params,
        )

    def get_room_info(self, room_id: int) -> dict[str, Any]:
        return self._request('GET', f'/api/rooms/{room_id}/info')

    def update_room_name(self, room_id: int, name: str) -> dict[str, Any]:
        return self._request('PUT', f'/api/rooms/{room_id}/name', json_data={'name': name})

    def invite_room_members(self, room_id: int, user_ids: list[int]) -> dict[str, Any]:
        return self._request(
            'POST',
            f'/api/rooms/{room_id}/members',
            json_data={'user_ids': user_ids},
        )

    def leave_room(self, room_id: int) -> dict[str, Any]:
        return self._request('POST', f'/api/rooms/{room_id}/leave')

    def get_room_polls(self, room_id: int) -> list[dict[str, Any]]:
        return self._request('GET', f'/api/rooms/{room_id}/polls')

    def create_room_poll(
        self,
        room_id: int,
        question: str,
        options: list[str],
        multiple_choice: bool = False,
        anonymous: bool = False,
        ends_at: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            'question': question,
            'options': options,
            'multiple_choice': multiple_choice,
            'anonymous': anonymous,
        }
        if ends_at:
            payload['ends_at'] = ends_at
        return self._request('POST', f'/api/rooms/{room_id}/polls', json_data=payload)

    def vote_poll(self, poll_id: int, option_ids: int | list[int]) -> dict[str, Any]:
        if isinstance(option_ids, list):
            normalized = []
            seen = set()
            for value in option_ids:
                try:
                    option_id = int(value)
                except (TypeError, ValueError):
                    continue
                if option_id > 0 and option_id not in seen:
                    seen.add(option_id)
                    normalized.append(option_id)
            payload: dict[str, Any] = {'option_ids': normalized}
            if normalized:
                payload['option_id'] = normalized[0]
            return self._request('POST', f'/api/polls/{poll_id}/vote', json_data=payload)
        return self._request('POST', f'/api/polls/{poll_id}/vote', json_data={'option_id': int(option_ids)})

    def close_poll(self, poll_id: int) -> dict[str, Any]:
        return self._request('POST', f'/api/polls/{poll_id}/close')

    def get_room_files(self, room_id: int, file_type: str | None = None) -> list[dict[str, Any]]:
        params = {'type': file_type} if file_type else None
        return self._request('GET', f'/api/rooms/{room_id}/files', params=params)

    def delete_room_file(self, room_id: int, file_id: int) -> dict[str, Any]:
        return self._request('DELETE', f'/api/rooms/{room_id}/files/{file_id}')

    def upload_file(self, room_id: int, file_path: str) -> dict[str, Any]:
        file_obj = Path(file_path)
        if not file_obj.exists() or not file_obj.is_file():
            raise RuntimeError(t('files.local_not_found', 'File not found.'))

        mime, _ = mimetypes.guess_type(str(file_obj))
        with file_obj.open('rb') as fp:
            response = self._client.post(
                '/api/upload',
                data={'room_id': str(room_id)},
                files={'file': (file_obj.name, fp, mime or 'application/octet-stream')},
                headers=self._headers(),
            )
        payload = response.json() if 'application/json' in response.headers.get('content-type', '') else {}
        if response.status_code >= 400:
            message = payload.get('error_localized') or payload.get('error') or f'HTTP {response.status_code}'
            error_code = str(payload.get('error_code') or '') if isinstance(payload, dict) else ''
            raise ApiError(str(message), status_code=response.status_code, error_code=error_code)
        return payload

    def download_upload_file(self, remote_file_path: str, save_path: str) -> str:
        encoded_path = '/'.join(quote(part) for part in remote_file_path.split('/'))
        response = self._client.get(f'/uploads/{encoded_path}', headers=self._headers())
        if response.status_code >= 400:
            payload = response.json() if 'application/json' in response.headers.get('content-type', '') else {}
            message = payload.get('error_localized') or payload.get('error') or f'HTTP {response.status_code}'
            error_code = str(payload.get('error_code') or '') if isinstance(payload, dict) else ''
            raise ApiError(str(message), status_code=response.status_code, error_code=error_code)

        output = Path(save_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(response.content)
        return str(output)

    def get_room_admins(self, room_id: int) -> list[dict[str, Any]]:
        return self._request('GET', f'/api/rooms/{room_id}/admins')

    def set_room_admin(self, room_id: int, user_id: int, is_admin: bool = True) -> dict[str, Any]:
        return self._request(
            'POST',
            f'/api/rooms/{room_id}/admins',
            json_data={'user_id': user_id, 'is_admin': is_admin},
        )

    def is_room_admin(self, room_id: int) -> bool:
        payload = self._request('GET', f'/api/rooms/{room_id}/admin-check')
        return bool(payload.get('is_admin', False))

    def get_profile(self) -> dict[str, Any]:
        return self._request('GET', '/api/profile')

    def update_profile(self, nickname: str, status_message: str = '') -> dict[str, Any]:
        return self._request(
            'PUT',
            '/api/profile',
            json_data={'nickname': nickname, 'status_message': status_message},
        )

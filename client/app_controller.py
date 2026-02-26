# -*- coding: utf-8 -*-
"""
Desktop messenger application controller.
"""

from __future__ import annotations

import mimetypes
import re
import socket
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QSettings, QTimer
from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog, QMessageBox

from client.i18n import i18n_manager, t
from client.services.api_client import APIClient, ApiError
from client.services.crypto_compat import CryptoError, decrypt_message, encrypt_message
from client.services.outbox_store import OutboxStore
from client.services.session_store import SessionStore, StoredSession
from client.services.socket_client import SocketClient
from client.services.startup_manager import StartupManager
from client.services.tray_manager import TrayManager
from client.services.update_checker import UpdateChecker
from client.ui.login_window import LoginWindow
from client.ui.admin_dialog import AdminDialog
from client.ui.files_dialog import FilesDialog
from client.ui.main_window import MainWindow
from client.ui.polls_dialog import PollsDialog
from client.ui.settings_dialog import SettingsDialog


class MessengerAppController(QObject):
    def __init__(self, app: QApplication, default_server_url: str, client_version: str = '1.0.0'):
        super().__init__()
        self.app = app
        self.default_server_url = default_server_url.rstrip('/')
        self.client_version = client_version

        self.i18n = i18n_manager
        self._settings = QSettings('IntranetMessenger', 'Desktop')
        self.session_store = SessionStore()
        self.outbox_store = OutboxStore()
        self.startup_manager = StartupManager()
        self.api = APIClient(self.default_server_url, language_getter=lambda: self.i18n.display_locale)
        self.update_checker = UpdateChecker(
            self.api,
            self.client_version,
            channel_getter=lambda: self._settings.value('updates/channel', 'stable', type=str),
            metadata_verifier=self._verify_update_metadata,
        )
        self.api.set_unauthorized_retry_hook(self._retry_after_unauthorized)
        self.socket = SocketClient()

        self.login_window = LoginWindow()
        self.main_window = MainWindow()
        self.settings_dialog = SettingsDialog(self.main_window)
        self.polls_dialog = PollsDialog(self.main_window)
        self.files_dialog = FilesDialog(self.main_window)
        self.admin_dialog = AdminDialog(self.main_window)
        self.tray = TrayManager(t('app.name', 'Intranet Messenger'), translator=t)

        self.current_user: dict[str, Any] | None = None
        self.current_room_id: int | None = None
        self.current_room_key: str = ''
        self.current_device_token: str = ''
        self._remember_device: bool = False
        self._session_expires_at_epoch: float = 0.0
        self._session_ttl_seconds: float = 0.0
        self._refresh_inflight = False
        self.current_server_url: str = self.default_server_url
        self.preferred_server_url: str = self.default_server_url
        self.rooms_cache: list[dict[str, Any]] = []
        self.current_room_members: list[dict[str, Any]] = []
        self.current_admin_ids: set[int] = set()
        self.current_is_admin: bool = False
        self._messages_page_size = 100
        self._message_history_has_more = False
        self._message_history_loading = False
        self._rooms_reload_timer = QTimer(self)
        self._rooms_reload_timer.setSingleShot(True)
        self._rooms_reload_timer.setInterval(250)
        self._rooms_reload_timer.timeout.connect(self._load_rooms)
        self._typing_debounce_timer = QTimer(self)
        self._typing_debounce_timer.setSingleShot(True)
        self._typing_debounce_timer.setInterval(500)
        self._typing_debounce_timer.timeout.connect(self._flush_typing_state)
        self._typing_pending: bool | None = None
        self._typing_sent = False
        self._typing_room_id: int | None = None

        self._pending_sends: dict[str, dict[str, Any]] = {}
        self._failed_send_ids: list[str] = []
        self._send_timeout_seconds = 4.0
        self._send_retry_limit = 2
        self._pending_send_timer = QTimer(self)
        self._pending_send_timer.setInterval(1000)
        self._pending_send_timer.timeout.connect(self._process_pending_sends)
        self._session_refresh_timer = QTimer(self)
        self._session_refresh_timer.setInterval(60_000)
        self._session_refresh_timer.timeout.connect(self._refresh_device_session_if_needed)

        self._bind_events()
        self.i18n.subscribe(self._on_language_changed)

    def _on_language_changed(self) -> None:
        self.tray.app_name = t('app.name', 'Intranet Messenger')
        self.tray.set_translator(t)

        for widget in (
            self.login_window,
            self.main_window,
            self.settings_dialog,
            self.polls_dialog,
            self.files_dialog,
            self.admin_dialog,
        ):
            retranslate = getattr(widget, 'retranslate_ui', None)
            if callable(retranslate):
                retranslate()

    @staticmethod
    def _verify_update_metadata(payload: dict[str, Any]) -> tuple[bool, str]:
        sha = str(payload.get('artifact_sha256') or '').strip()
        sig = str(payload.get('artifact_signature') or '').strip()
        alg = str(payload.get('signature_alg') or '').strip()
        if not sha and not sig:
            return True, ''
        if not sha:
            return False, 'artifact_sha256 is missing'
        if not sig:
            return False, 'artifact_signature is missing'
        if not alg:
            return False, 'signature_alg is missing'
        return True, ''

    @staticmethod
    def _parse_server_ts(raw: object) -> float:
        text = str(raw or '').strip()
        if not text:
            return 0.0
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S'):
            try:
                return datetime.strptime(text, fmt).timestamp()
            except ValueError:
                continue
        return 0.0

    def _update_session_expiry(self, payload: dict[str, Any]) -> None:
        expires_epoch = self._parse_server_ts(payload.get('expires_at'))
        self._session_expires_at_epoch = expires_epoch
        if expires_epoch > 0:
            now = time.time()
            self._session_ttl_seconds = max(0.0, expires_epoch - now)

    def _retry_after_unauthorized(self) -> bool:
        return self._refresh_device_session_token(notify=False)

    def _refresh_device_session_token(self, *, notify: bool = False) -> bool:
        if self._refresh_inflight:
            return False
        if not self.current_device_token:
            return False
        self._refresh_inflight = True
        try:
            payload = self.api.refresh_device_session(self.current_device_token)
            rotated = str(payload.get('device_token_rotated') or self.current_device_token).strip()
            if not rotated:
                return False
            self.current_device_token = rotated
            self._update_session_expiry(payload)
            if self._remember_device:
                device_name = self.default_device_name()
                stored = self.session_store.load()
                if stored and stored.device_name:
                    device_name = stored.device_name
                self.session_store.save(
                    StoredSession(
                        server_url=self.current_server_url,
                        device_token=self.current_device_token,
                        device_name=device_name,
                    )
                )
            if notify:
                self.main_window.show_info(t('controller.session_refreshed', 'Session refreshed.'))
            return True
        except Exception:
            return False
        finally:
            self._refresh_inflight = False

    def _refresh_device_session_if_needed(self) -> None:
        if not self.current_user:
            return
        if not self.current_device_token:
            return
        if self._session_expires_at_epoch <= 0:
            return
        now = time.time()
        remaining = self._session_expires_at_epoch - now
        threshold = max(300.0, self._session_ttl_seconds * 0.2 if self._session_ttl_seconds > 0 else 0.0)
        if remaining > threshold:
            return
        self._refresh_device_session_token(notify=False)

    def _upsert_outbox_entry(self, client_msg_id: str, entry: dict[str, Any]) -> None:
        if not self.current_user:
            return
        user_id = int((self.current_user or {}).get('id') or 0)
        if user_id <= 0:
            return
        payload = entry.get('payload')
        if not isinstance(payload, dict):
            payload = {}
        self.outbox_store.upsert(
            user_id=user_id,
            server_url=self.current_server_url,
            client_msg_id=client_msg_id,
            payload=payload,
            created_at=float(entry.get('created_at') or time.time()),
            last_attempt_at=float(entry.get('last_attempt_at') or 0.0),
            retry_count=int(entry.get('retry_count') or 0),
            failed=bool(entry.get('failed')),
        )

    def _remove_outbox_entry(self, client_msg_id: str) -> None:
        if not self.current_user:
            return
        user_id = int((self.current_user or {}).get('id') or 0)
        if user_id <= 0:
            return
        self.outbox_store.remove(
            user_id=user_id,
            server_url=self.current_server_url,
            client_msg_id=client_msg_id,
        )

    def _restore_pending_sends_from_outbox(self) -> None:
        self._pending_sends.clear()
        self._failed_send_ids = []
        if not self.current_user:
            return
        user_id = int((self.current_user or {}).get('id') or 0)
        if user_id <= 0:
            return
        entries = self.outbox_store.list_entries(user_id=user_id, server_url=self.current_server_url)
        for row in entries:
            client_msg_id = str(row.get('client_msg_id') or '').strip()
            payload = row.get('payload') if isinstance(row.get('payload'), dict) else {}
            if not client_msg_id or not payload:
                continue
            self._pending_sends[client_msg_id] = {
                'payload': payload,
                'created_at': float(row.get('created_at') or time.time()),
                'last_attempt_at': float(row.get('last_attempt_at') or 0.0),
                'retry_count': int(row.get('retry_count') or 0),
                'failed': bool(row.get('failed')),
                'is_file': bool(payload.get('type') in ('file', 'image')),
                'file_name': str(payload.get('content') or ''),
            }
            if bool(row.get('failed')):
                self._failed_send_ids.append(client_msg_id)

    def _bind_events(self) -> None:
        self.login_window.login_requested.connect(self._on_login_requested)
        self.login_window.register_requested.connect(self._on_register_requested)

        self.main_window.refresh_rooms_requested.connect(self._load_rooms)
        self.main_window.room_selected.connect(self._on_room_selected)
        self.main_window.send_message_requested.connect(self._on_send_message_requested)
        self.main_window.send_file_requested.connect(self._on_send_file_requested)
        self.main_window.logout_requested.connect(self._logout)
        self.main_window.search_requested.connect(self._on_search_requested)
        self.main_window.open_settings_requested.connect(self._open_settings)
        self.main_window.create_room_requested.connect(self._create_room)
        self.main_window.invite_members_requested.connect(self._invite_members)
        self.main_window.rename_room_requested.connect(self._rename_room)
        self.main_window.leave_room_requested.connect(self._leave_room)
        self.main_window.edit_profile_requested.connect(self._edit_profile)
        self.main_window.open_polls_requested.connect(self._open_polls)
        self.main_window.open_files_requested.connect(self._open_files)
        self.main_window.open_admin_requested.connect(self._open_admin)
        self.main_window.load_older_messages_requested.connect(self._load_older_messages)
        self.main_window.typing_changed.connect(self._on_typing_changed)
        self.main_window.retry_send_requested.connect(self._retry_failed_sends)
        self.main_window.close_to_tray_requested.connect(
            lambda: self.tray.notify(t('app.name', 'Intranet Messenger'), t('tray.running', 'Running in tray.'))
        )

        self.socket.on('connect', lambda _: self.main_window.set_connected(True))
        self.socket.on('disconnect', lambda _: self.main_window.set_connected(False))
        self.socket.on('new_message', self._on_socket_new_message)
        self.socket.on('room_updated', self._on_socket_room_updated)
        self.socket.on('room_name_updated', self._on_socket_room_name_updated)
        self.socket.on('room_members_updated', self._on_socket_room_members_updated)
        self.socket.on('read_updated', self._on_socket_read_updated)
        self.socket.on('user_typing', self._on_socket_user_typing)
        self.socket.on('message_edited', self._on_socket_message_edited)
        self.socket.on('message_deleted', self._on_socket_message_deleted)
        self.socket.on('reaction_updated', self._on_socket_reaction_updated)
        self.socket.on('poll_updated', self._on_socket_poll_updated)
        self.socket.on('poll_created', self._on_socket_poll_updated)
        self.socket.on('pin_updated', self._on_socket_pin_updated)
        self.socket.on('admin_updated', self._on_socket_admin_updated)
        self.socket.on('error', self._on_socket_error)

        self.tray.show_requested.connect(self._show_main_window)
        self.tray.logout_requested.connect(self._logout)
        self.tray.quit_requested.connect(self._quit)

        self.settings_dialog.save_requested.connect(self._on_settings_saved)
        self.settings_dialog.check_update_requested.connect(self._check_update_policy)

        self.polls_dialog.refresh_requested.connect(self._refresh_polls)
        self.polls_dialog.create_requested.connect(self._create_poll)
        self.polls_dialog.vote_requested.connect(self._vote_poll)
        self.polls_dialog.close_requested.connect(self._close_poll)

        self.files_dialog.refresh_requested.connect(self._refresh_files)
        self.files_dialog.upload_requested.connect(self._on_send_file_requested)
        self.files_dialog.download_requested.connect(self._download_room_file)
        self.files_dialog.delete_requested.connect(self._delete_room_file)

        self.admin_dialog.refresh_requested.connect(self._refresh_admins)
        self.admin_dialog.set_admin_requested.connect(self._set_room_admin)

    def start(self) -> None:
        self._on_language_changed()
        try:
            startup_initialized = bool(self._settings.value('startup/initialized', False, type=bool))
            if not startup_initialized:
                self._settings.setValue('startup/initialized', True)
        except Exception:
            pass
        self.tray.show()
        restored = self._try_restore_session()
        if restored:
            return
        self.login_window.set_server_url(self.preferred_server_url)
        self.login_window.device_name_input.setText(self.default_device_name())
        self.login_window.show()

    def _try_restore_session(self) -> bool:
        stored = self.session_store.load()
        if not stored:
            return False

        try:
            self.api.update_base_url(stored.server_url)
            payload = self.api.refresh_device_session(stored.device_token)
            rotated = payload.get('device_token_rotated') or stored.device_token
            self._on_authenticated(
                payload=payload,
                server_url=stored.server_url,
                remember=True,
                device_name=stored.device_name,
                device_token=rotated,
            )
            return True
        except ApiError as exc:
            if int(getattr(exc, 'status_code', 0)) == 401 or getattr(exc, 'error_code', '') in (
                'AUTH_TOKEN_INVALID_OR_EXPIRED',
                'AUTH_DEVICE_TOKEN_REQUIRED',
            ):
                self.session_store.clear()
            return False
        except Exception:
            return False

    def _on_login_requested(
        self,
        server_url: str,
        username: str,
        password: str,
        device_name: str,
        remember: bool,
    ) -> None:
        self.login_window.set_busy(True)
        try:
            self.api.update_base_url(server_url)
            payload = self.api.create_device_session(
                username=username,
                password=password,
                device_name=device_name,
                remember=remember,
            )
            token = payload.get('device_token', '')
            if not token:
                raise RuntimeError(
                    t(
                        'controller.device_token_missing_in_response',
                        'device_token is missing in login response',
                    )
                )

            self._on_authenticated(
                payload=payload,
                server_url=server_url,
                remember=remember,
                device_name=device_name,
                device_token=token,
            )
        except Exception as exc:
            self.login_window.show_error(str(exc))
        finally:
            self.login_window.set_busy(False)

    def _on_register_requested(self, server_url: str, username: str, password: str, nickname: str) -> None:
        self.login_window.set_busy(True)
        try:
            self.api.update_base_url(server_url)
            self.api.register(username=username, password=password, nickname=nickname)
            self.login_window.show_info(t('controller.register_success', 'Registered successfully. Please log in.'))
        except Exception as exc:
            self.login_window.show_error(str(exc))
        finally:
            self.login_window.set_busy(False)

    def _on_authenticated(
        self,
        *,
        payload: dict[str, Any],
        server_url: str,
        remember: bool,
        device_name: str,
        device_token: str,
    ) -> None:
        self.current_user = payload.get('user') or {}
        self.current_server_url = server_url.rstrip('/')
        self.preferred_server_url = self.current_server_url
        self.current_device_token = device_token
        self._remember_device = bool(remember)
        self._update_session_expiry(payload)
        self.current_room_id = None
        self.current_room_key = ''
        self._message_history_has_more = False
        self._message_history_loading = False
        self._refresh_inflight = False

        if remember:
            self.session_store.save(
                StoredSession(
                    server_url=self.current_server_url,
                    device_token=device_token,
                    device_name=device_name,
                )
            )
        else:
            self.session_store.clear()

        self._restore_pending_sends_from_outbox()
        self.main_window.set_user(self.current_user)
        self._show_main_window()
        self.login_window.hide()

        try:
            cookie_header = self.api.get_cookie_header()
            self.socket.connect(
                self.current_server_url,
                cookie_header=cookie_header,
                language=self.i18n.display_locale,
            )
        except Exception as exc:
            self.main_window.show_error(
                t('controller.socket_connection_failed', 'Socket connection failed: {error}', error=str(exc))
            )

        self._load_rooms()
        self._check_update_policy()
        self._pending_send_timer.start()
        self._session_refresh_timer.start()
        for msg_id, entry in list(self._pending_sends.items()):
            if not entry.get('failed'):
                self._dispatch_pending_send(msg_id)
        self.tray.notify(t('app.name', 'Intranet Messenger'), t('tray.signed_in', 'Signed in successfully.'))

    def _show_main_window(self) -> None:
        self.main_window.show()
        self.main_window.activateWindow()
        self.main_window.raise_()

    def _load_rooms(self) -> None:
        if not self.current_user:
            return
        try:
            rooms = self.api.get_rooms(include_members=False)
            self.rooms_cache = rooms
            self.main_window.set_rooms(rooms)
            self.socket.subscribe_rooms([int(r['id']) for r in rooms if 'id' in r])
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _schedule_rooms_reload(self, delay_ms: int = 250) -> None:
        self._rooms_reload_timer.setInterval(max(100, int(delay_ms)))
        self._rooms_reload_timer.start()

    def _on_room_selected(self, room_id: int) -> None:
        if self._typing_sent and self._typing_room_id:
            try:
                self.socket.send_typing(int(self._typing_room_id), False)
            except Exception:
                pass
        self._typing_sent = False
        self._typing_pending = None
        self._typing_room_id = int(room_id)
        self.current_room_id = room_id
        room = next((r for r in self.rooms_cache if int(r.get('id', 0)) == room_id), None)
        self.main_window.set_room_title(
            (room or {}).get('name') or t('main.room_default_name', 'Room {room_id}', room_id=room_id)
        )
        self.socket.join_room(room_id)
        self._reload_current_room_messages(refresh_admins=True)

    def _reload_current_room_messages(self, *, silent: bool = False, refresh_admins: bool = False) -> None:
        room_id = self.current_room_id
        if not room_id:
            return
        try:
            data = self.api.get_messages(int(room_id), include_meta=True, limit=self._messages_page_size)
            self.current_room_key = data.get('encryption_key') or ''
            members = data.get('members')
            if isinstance(members, list):
                self.current_room_members = members
            messages = data.get('messages') or []
            for message in messages:
                self._decorate_message_content(message)
            self._message_history_has_more = len(messages) >= self._messages_page_size
            self._message_history_loading = False
            self.main_window.set_messages(messages, has_more=self._message_history_has_more)
            if refresh_admins:
                self._refresh_admins(silent=True)
        except Exception as exc:
            if not silent:
                self.main_window.show_error(str(exc))

    def _load_older_messages(self, before_id: int) -> None:
        room_id = self.current_room_id
        if (
            not room_id
            or before_id <= 0
            or self._message_history_loading
            or not self._message_history_has_more
        ):
            return

        target_room_id = int(room_id)
        self._message_history_loading = True
        try:
            data = self.api.get_messages(
                target_room_id,
                include_meta=False,
                limit=self._messages_page_size,
                before_id=before_id,
            )
            if int(self.current_room_id or 0) != target_room_id:
                return
            messages = data.get('messages') or []
            for message in messages:
                self._decorate_message_content(message)
            self._message_history_has_more = len(messages) >= self._messages_page_size
            self.main_window.prepend_messages(messages, has_more=self._message_history_has_more)
        except Exception as exc:
            self.main_window.prepend_messages([], has_more=self._message_history_has_more)
            self.main_window.show_error(str(exc))
        finally:
            self._message_history_loading = False

    def _decorate_message_content(self, message: dict[str, Any]) -> None:
        message_type = message.get('message_type', 'text')
        encrypted = bool(message.get('encrypted', False))
        content = str(message.get('content') or '')

        if message_type in ('image', 'file'):
            message['display_content'] = content
            return

        if encrypted and self.current_room_key:
            try:
                message['display_content'] = decrypt_message(content, self.current_room_key)
            except CryptoError:
                message['display_content'] = t('app.messages.encrypted', '[encrypted message]')
        else:
            message['display_content'] = content

    def _on_send_message_requested(self, text: str) -> None:
        if not self.current_room_id:
            self.main_window.show_info(t('main.select_room_first', 'Select a room first.'))
            return

        content = text
        encrypted = False
        if self.current_room_key:
            try:
                content = encrypt_message(text, self.current_room_key)
                encrypted = True
            except Exception:
                self.main_window.show_error(t('controller.message_encryption_failed', 'Message encryption failed.'))
                return

        client_msg_id = uuid.uuid4().hex
        payload = {
            'room_id': int(self.current_room_id),
            'content': content,
            'type': 'text',
            'encrypted': encrypted,
            'client_msg_id': client_msg_id,
        }
        entry = {
            'payload': payload,
            'created_at': time.time(),
            'last_attempt_at': 0.0,
            'retry_count': 0,
            'failed': False,
        }
        self._pending_sends[client_msg_id] = entry
        self._upsert_outbox_entry(client_msg_id, entry)
        self._dispatch_pending_send(client_msg_id)
        self._refresh_delivery_state()
        self._typing_pending = False
        self._typing_debounce_timer.start(120)

    def _on_send_file_requested(self, local_path: str) -> None:
        if not self.current_room_id:
            self.main_window.show_info(t('main.select_room_first', 'Select a room first.'))
            return
        try:
            upload = self.api.upload_file(int(self.current_room_id), local_path)
            token = upload.get('upload_token')
            if not token:
                raise RuntimeError(t('controller.upload_token_missing', 'Upload token is missing.'))

            file_name = upload.get('file_name') or Path(local_path).name
            message_type = self._guess_message_type(file_name, upload.get('file_type'))
            client_msg_id = uuid.uuid4().hex
            payload = {
                'room_id': int(self.current_room_id),
                'content': file_name,
                'type': message_type,
                'upload_token': token,
                'encrypted': False,
                'client_msg_id': client_msg_id,
            }
            entry = {
                'payload': payload,
                'created_at': time.time(),
                'last_attempt_at': 0.0,
                'retry_count': 0,
                'failed': False,
                'is_file': True,
                'file_name': file_name,
            }
            self._pending_sends[client_msg_id] = entry
            self._upsert_outbox_entry(client_msg_id, entry)
            self._dispatch_pending_send(client_msg_id)
            self._refresh_delivery_state()
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _dispatch_pending_send(self, client_msg_id: str) -> None:
        entry = self._pending_sends.get(client_msg_id)
        if not entry:
            return
        entry['last_attempt_at'] = time.time()
        entry['failed'] = False
        self._upsert_outbox_entry(client_msg_id, entry)
        payload = dict(entry.get('payload') or {})

        def _ack_callback(raw_ack: dict[str, Any] | Any) -> None:
            ack = raw_ack if isinstance(raw_ack, dict) else {}
            self._handle_send_ack(client_msg_id, ack)

        try:
            self.socket.send_message(payload, ack_callback=_ack_callback)
        except Exception:
            # keep pending; timeout loop will retry
            pass

    def _handle_send_ack(self, client_msg_id: str, ack: dict[str, Any]) -> None:
        entry = self._pending_sends.get(client_msg_id)
        if not entry:
            return
        if bool(ack.get('ok')):
            if bool(entry.get('is_file')):
                file_name = str(entry.get('file_name') or '')
                if file_name:
                    self.tray.notify(
                        t('app.name', 'Intranet Messenger'),
                        t('files.upload', 'Upload') + f': {file_name}',
                    )
            self._pending_sends.pop(client_msg_id, None)
            self._remove_outbox_entry(client_msg_id)
            if client_msg_id in self._failed_send_ids:
                self._failed_send_ids.remove(client_msg_id)
            self._refresh_delivery_state()
            return

        # 서버가 즉시 실패를 반환한 경우 재시도 없이 실패 처리
        entry['failed'] = True
        self._upsert_outbox_entry(client_msg_id, entry)
        if client_msg_id not in self._failed_send_ids:
            self._failed_send_ids.append(client_msg_id)
        error_message = str(ack.get('error') or '').strip()
        if error_message:
            self.main_window.show_error(error_message)
        self._refresh_delivery_state()

    def _process_pending_sends(self) -> None:
        now = time.time()
        changed = False
        for client_msg_id, entry in list(self._pending_sends.items()):
            if entry.get('failed'):
                continue
            last_attempt = float(entry.get('last_attempt_at') or 0.0)
            if last_attempt <= 0:
                continue
            if now - last_attempt < self._send_timeout_seconds:
                continue

            retries = int(entry.get('retry_count') or 0)
            if retries >= self._send_retry_limit:
                entry['failed'] = True
                self._upsert_outbox_entry(client_msg_id, entry)
                if client_msg_id not in self._failed_send_ids:
                    self._failed_send_ids.append(client_msg_id)
                changed = True
                continue

            entry['retry_count'] = retries + 1
            self._upsert_outbox_entry(client_msg_id, entry)
            self._dispatch_pending_send(client_msg_id)
            changed = True

        if changed:
            self._refresh_delivery_state()

    def _retry_failed_sends(self) -> None:
        pending_retry = [msg_id for msg_id in self._failed_send_ids if msg_id in self._pending_sends]
        self._failed_send_ids = []
        for client_msg_id in pending_retry:
            entry = self._pending_sends.get(client_msg_id)
            if not entry:
                continue
            entry['failed'] = False
            entry['retry_count'] = 0
            self._upsert_outbox_entry(client_msg_id, entry)
            self._dispatch_pending_send(client_msg_id)
        self._refresh_delivery_state()

    def _refresh_delivery_state(self) -> None:
        pending_count = len([1 for entry in self._pending_sends.values() if not entry.get('failed')])
        failed_count = len(self._failed_send_ids)
        if failed_count > 0:
            self.main_window.set_delivery_state('failed', failed_count)
            return
        if pending_count > 0:
            self.main_window.set_delivery_state('pending', pending_count)
            return
        self.main_window.set_delivery_state('idle', 0)

    def _on_typing_changed(self, is_typing: bool) -> None:
        if not self.current_room_id:
            return
        self._typing_pending = bool(is_typing)
        self._typing_debounce_timer.start(500 if is_typing else 150)

    def _flush_typing_state(self) -> None:
        if self._typing_pending is None:
            return
        room_id = int(self.current_room_id or 0)
        if room_id <= 0:
            return
        next_state = bool(self._typing_pending)
        if next_state == self._typing_sent and self._typing_room_id == room_id:
            return
        try:
            self.socket.send_typing(room_id, next_state)
            self._typing_sent = next_state
            self._typing_room_id = room_id
        except Exception:
            pass

    def _on_socket_new_message(self, message: dict[str, Any]) -> None:
        client_msg_id = str(message.get('client_msg_id') or '').strip()
        if client_msg_id:
            self._pending_sends.pop(client_msg_id, None)
            self._remove_outbox_entry(client_msg_id)
            if client_msg_id in self._failed_send_ids:
                self._failed_send_ids.remove(client_msg_id)
            self._refresh_delivery_state()

        room_id = int(message.get('room_id') or 0)
        sender_id = int(message.get('sender_id') or 0)
        current_user_id = int((self.current_user or {}).get('id') or 0)
        self._update_room_cache_from_message(
            room_id=room_id,
            message=message,
            increment_unread=bool(self.current_room_id != room_id and sender_id != current_user_id),
        )
        if self.current_room_id and room_id == int(self.current_room_id):
            self._decorate_message_content(message)
            self.main_window.append_message(message)
            message_id = int(message.get('id') or 0)
            if message_id:
                self.socket.send_read(room_id=room_id, message_id=message_id)
        else:
            sender = message.get('sender_name') or t('tray.new_message', 'New message', sender='').split(':')[0]
            self.tray.notify(
                t('app.name', 'Intranet Messenger'),
                t('tray.new_message', '{sender}: New message', sender=str(sender)),
            )
        self.main_window.set_rooms(self.rooms_cache)

    def _extract_room_id(self, payload: dict[str, Any]) -> int | None:
        value = payload.get('room_id')
        if value is None:
            poll = payload.get('poll') if isinstance(payload.get('poll'), dict) else {}
            value = poll.get('room_id')
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _on_socket_room_name_updated(self, payload: dict[str, Any]) -> None:
        room_id = self._extract_room_id(payload)
        if room_id and self.current_room_id == room_id:
            new_name = str(payload.get('name') or '')
            if new_name:
                self.main_window.set_room_title(new_name)
        self._update_room_cache_name(room_id, str(payload.get('name') or ''))
        self.main_window.set_rooms(self.rooms_cache)

    def _on_socket_room_updated(self, payload: dict[str, Any]) -> None:
        action = str(payload.get('action') or '').strip().lower()
        room_id = self._extract_room_id(payload)
        current_user_id = int((self.current_user or {}).get('id') or 0)
        try:
            affected_user_id = int(payload.get('user_id') or 0)
        except (TypeError, ValueError):
            affected_user_id = 0

        # room_name_updated 이벤트에서 이미 캐시를 즉시 갱신하므로 중복 re-fetch를 피한다.
        if action == 'room_renamed':
            return

        # 멤버십 변경은 room_members_updated에서 처리하므로 중복 방 목록 조회를 줄인다.
        if action in ('members_invited', 'member_left', 'member_kicked'):
            if affected_user_id > 0 and affected_user_id == current_user_id:
                self._schedule_rooms_reload(120)
            return

        if action == 'room_created':
            self._schedule_rooms_reload(120)
            return

        # 알 수 없는 action은 안전하게 debounce reload.
        self._schedule_rooms_reload(180)

    def _on_socket_room_members_updated(self, payload: dict[str, Any]) -> None:
        room_id = self._extract_room_id(payload)
        action = str(payload.get('action') or '').strip().lower()
        current_user_id = int((self.current_user or {}).get('id') or 0)
        try:
            affected_user_id = int(payload.get('user_id') or 0)
        except (TypeError, ValueError):
            affected_user_id = 0

        # 내가 현재 방에서 제거된 경우 즉시 UI 선택 상태를 정리하고 목록만 갱신한다.
        if (
            room_id
            and self.current_room_id == room_id
            and action in ('member_left', 'member_kicked')
            and affected_user_id > 0
            and affected_user_id == current_user_id
        ):
            self.current_room_id = None
            self.current_room_key = ''
            self.current_room_members = []
            self.main_window.clear_room_selection()
            self._schedule_rooms_reload(120)
            return

        if room_id and self.current_room_id == room_id:
            self._reload_current_room_messages(silent=True, refresh_admins=True)
        self._schedule_rooms_reload(220 if action == 'members_invited' else 200)

    def _on_socket_read_updated(self, payload: dict[str, Any]) -> None:
        room_id = self._extract_room_id(payload)
        if room_id and self.current_room_id == room_id:
            self._set_room_unread(room_id, 0)
            self.main_window.set_rooms(self.rooms_cache)

    def _on_socket_user_typing(self, payload: dict[str, Any]) -> None:
        room_id = self._extract_room_id(payload)
        if not room_id or self.current_room_id != room_id:
            return
        user_id = int(payload.get('user_id') or 0)
        nickname = str(payload.get('nickname') or '')
        is_typing = bool(payload.get('is_typing'))
        self.main_window.set_typing_user(user_id, nickname, is_typing)

    def _on_socket_message_edited(self, payload: dict[str, Any]) -> None:
        room_id = self._extract_room_id(payload)
        if not room_id:
            return
        if self.current_room_id and room_id == int(self.current_room_id):
            message_id = int(payload.get('message_id') or 0)
            content = str(payload.get('content') or '')
            encrypted = bool(payload.get('encrypted', False))
            display_content = content
            if encrypted and self.current_room_key:
                try:
                    display_content = decrypt_message(content, self.current_room_key)
                except CryptoError:
                    display_content = t('app.messages.encrypted', '[encrypted message]')
            updated = self.main_window.update_message_content(
                message_id=message_id,
                content=content,
                display_content=display_content,
                encrypted=encrypted,
            )
            if not updated:
                self._reload_current_room_messages(silent=True)
        self._schedule_rooms_reload(250)

    def _on_socket_message_deleted(self, payload: dict[str, Any]) -> None:
        room_id = self._extract_room_id(payload)
        if not room_id:
            return
        if self.current_room_id and room_id == int(self.current_room_id):
            message_id = int(payload.get('message_id') or 0)
            updated = self.main_window.mark_message_deleted(message_id)
            if not updated:
                self._reload_current_room_messages(silent=True)
        self._schedule_rooms_reload(250)

    def _on_socket_reaction_updated(self, payload: dict[str, Any]) -> None:
        room_id = self._extract_room_id(payload)
        if room_id and self.current_room_id == room_id:
            message_id = int(payload.get('message_id') or 0)
            reactions = payload.get('reactions')
            updated = self.main_window.update_message_reactions(
                message_id=message_id,
                reactions=reactions if isinstance(reactions, list) else [],
            )
            if not updated:
                self._reload_current_room_messages(silent=True)

    def _on_socket_poll_updated(self, payload: dict[str, Any]) -> None:
        room_id = self._extract_room_id(payload)
        if room_id and self.current_room_id == room_id and self.polls_dialog.isVisible():
            self._refresh_polls()

    def _on_socket_pin_updated(self, payload: dict[str, Any]) -> None:
        room_id = self._extract_room_id(payload)
        if room_id and self.current_room_id == room_id:
            # Pins are managed in dedicated dialogs/APIs; avoid full message reload.
            pass

    def _on_socket_admin_updated(self, payload: dict[str, Any]) -> None:
        room_id = self._extract_room_id(payload)
        if room_id and self.current_room_id == room_id and self.admin_dialog.isVisible():
            self._refresh_admins(silent=True)

    def _preview_for_message(self, message: dict[str, Any]) -> str:
        message_type = str(message.get('message_type') or message.get('type') or 'text')
        content = str(message.get('display_content') or message.get('content') or '')
        encrypted = bool(message.get('encrypted', False))
        file_name = str(message.get('file_name') or content or '')

        if message_type == 'image':
            return t('rooms.preview.image', '📷 Image')
        if message_type == 'file':
            return file_name or t('rooms.preview.file', '📎 File')
        if message_type == 'system':
            preview = content.strip()
            return preview[:25] + ('...' if len(preview) > 25 else '') if preview else t('rooms.preview.system', '🔔 System message')
        if encrypted:
            return t('rooms.preview.encrypted', '🔒 Encrypted message')
        preview = content.strip()
        if not preview:
            return t('rooms.preview.message', 'Message')
        return preview[:25] + ('...' if len(preview) > 25 else '')

    def _sort_rooms_cache(self) -> None:
        def _sort_key(room: dict[str, Any]):
            pinned = int(room.get('pinned') or 0)
            ts = str(room.get('last_message_time') or '')
            return (pinned, ts)

        self.rooms_cache.sort(key=_sort_key, reverse=True)

    def _update_room_cache_name(self, room_id: int | None, name: str) -> None:
        if not room_id or not name:
            return
        for room in self.rooms_cache:
            if int(room.get('id') or 0) == int(room_id):
                room['name'] = name
                break

    def _set_room_unread(self, room_id: int, unread: int) -> None:
        for room in self.rooms_cache:
            if int(room.get('id') or 0) == int(room_id):
                room['unread_count'] = max(0, int(unread))
                break

    def _update_room_cache_from_message(self, *, room_id: int, message: dict[str, Any], increment_unread: bool) -> None:
        if room_id <= 0:
            return
        target = None
        for room in self.rooms_cache:
            if int(room.get('id') or 0) == room_id:
                target = room
                break
        if not target:
            self._schedule_rooms_reload(150)
            return
        target['last_message_preview'] = self._preview_for_message(message)
        target['last_message_time'] = str(message.get('created_at') or target.get('last_message_time') or '')
        if increment_unread:
            target['unread_count'] = int(target.get('unread_count') or 0) + 1
        elif self.current_room_id and int(self.current_room_id) == room_id:
            target['unread_count'] = 0
        self._sort_rooms_cache()

    def _on_socket_error(self, payload: dict[str, Any]) -> None:
        message = (
            payload.get('message_localized')
            or payload.get('message')
            or t('controller.socket_error_generic', 'Socket error')
        )
        self.main_window.show_error(str(message))

    def _on_search_requested(self, query: str) -> None:
        query = query.strip()
        if not query:
            self.main_window.set_rooms(self.rooms_cache)
            return
        lowered = query.lower()
        filtered = [
            room
            for room in self.rooms_cache
            if lowered in str(room.get('name', '')).lower()
            or lowered in str(room.get('last_message_preview', '')).lower()
        ]
        if filtered:
            self.main_window.set_rooms(filtered)
            return

        if len(query) < 2:
            self.main_window.set_rooms([])
            return

        try:
            results = self.api.search_messages(query, int(self.current_room_id) if self.current_room_id else None)
            matched_room_ids = {
                int(row.get('room_id') or 0)
                for row in results
                if isinstance(row, dict) and int(row.get('room_id') or 0) > 0
            }
            remote_filtered = [
                room for room in self.rooms_cache if int(room.get('id') or 0) in matched_room_ids
            ]
            self.main_window.set_rooms(remote_filtered)
        except Exception:
            self.main_window.set_rooms([])

    @staticmethod
    def _guess_message_type(file_name: str, from_server: str | None = None) -> str:
        if from_server in ('image', 'file'):
            return from_server
        mime, _ = mimetypes.guess_type(file_name)
        if mime and mime.startswith('image/'):
            return 'image'
        return 'file'

    def _require_room(self) -> int | None:
        if not self.current_room_id:
            self.main_window.show_info(t('main.select_room_first', 'Select a room first.'))
            return None
        return int(self.current_room_id)

    @staticmethod
    def _parse_user_ids(raw: str) -> list[int]:
        parsed: list[int] = []
        seen: set[int] = set()
        tokens = re.split(r'[\s,]+', raw.strip())
        for token in tokens:
            if not token:
                continue
            try:
                user_id = int(token)
            except ValueError:
                continue
            if user_id > 0 and user_id not in seen:
                seen.add(user_id)
                parsed.append(user_id)
        return parsed

    def _prompt_user_ids(
        self,
        candidates: list[dict[str, Any]],
        *,
        title: str,
        label: str,
        excluded_ids: set[int] | None = None,
    ) -> list[int] | None:
        excluded_ids = excluded_ids or set()
        selectable = []
        for user in candidates:
            try:
                user_id = int(user.get('id') or 0)
            except Exception:
                user_id = 0
            if user_id <= 0 or user_id in excluded_ids:
                continue
            nickname = str(user.get('nickname') or user.get('username') or user_id)
            username = str(user.get('username') or '')
            if username and username != nickname:
                selectable.append(f"{user_id}: {nickname} (@{username})")
            else:
                selectable.append(f"{user_id}: {nickname}")

        if not selectable:
            self.main_window.show_info(t('controller.no_selectable_users', 'No selectable users found.'))
            return None

        preview = '\n'.join(selectable[:30])
        if len(selectable) > 30:
            preview += '\n...'
        prompt = (
            f"{label}\n\n"
            f"{t('controller.user_picker_help', 'Enter IDs separated by comma or whitespace.')}\n\n"
            f"{preview}"
        )
        raw_text, ok = QInputDialog.getMultiLineText(self.main_window, title, prompt)
        if not ok:
            return None
        user_ids = self._parse_user_ids(raw_text)
        if not user_ids:
            self.main_window.show_info(t('controller.user_picker_empty', 'No valid user IDs were entered.'))
            return None
        return user_ids

    def _create_room(self) -> None:
        try:
            users = self.api.get_users()
            selected_user_ids = self._prompt_user_ids(
                users,
                title=t('main.new_room', 'New Room'),
                label=t('controller.select_members_for_room', 'Select users to create a new conversation.'),
            )
            if selected_user_ids is None:
                return

            room_name, ok = QInputDialog.getText(
                self.main_window,
                t('main.new_room', 'New Room'),
                t('controller.room_name_optional', 'Room name (optional)'),
            )
            if not ok:
                return

            created = self.api.create_room(selected_user_ids, room_name.strip())
            room_id = int(created.get('room_id') or 0)
            self._load_rooms()
            if room_id > 0:
                self.main_window.select_room(room_id)
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _invite_members(self) -> None:
        room_id = self._require_room()
        if not room_id:
            return
        try:
            all_users = self.api.get_users()
            room_info = self.api.get_room_info(room_id)
            current_member_ids = {
                int(member.get('id') or 0)
                for member in (room_info.get('members') or [])
                if int(member.get('id') or 0) > 0
            }
            selected_user_ids = self._prompt_user_ids(
                all_users,
                title=t('main.invite_members', 'Invite Members'),
                label=t('controller.select_members_to_invite', 'Select users to invite to this room.'),
                excluded_ids=current_member_ids,
            )
            if selected_user_ids is None:
                return
            result = self.api.invite_room_members(room_id, selected_user_ids)
            added = int(result.get('added_count') or 0)
            self.main_window.show_info(
                t('controller.members_invited', '{count} members invited.', count=added)
            )
            self._reload_current_room_messages(refresh_admins=True)
            self._schedule_rooms_reload(120)
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _leave_room(self) -> None:
        room_id = self._require_room()
        if not room_id:
            return
        confirmed = QMessageBox.question(
            self.main_window,
            t('main.leave_room', 'Leave Room'),
            t('controller.leave_room_confirm', 'Do you want to leave this room?'),
        )
        if confirmed != QMessageBox.StandardButton.Yes:
            return
        try:
            self.api.leave_room(room_id)
            self.current_room_id = None
            self.current_room_key = ''
            self.current_room_members = []
            self.current_admin_ids = set()
            self.current_is_admin = False
            self._typing_pending = False
            self._typing_sent = False
            self._typing_room_id = None
            self.main_window.clear_room_selection()
            self._load_rooms()
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _rename_room(self) -> None:
        room_id = self._require_room()
        if not room_id:
            return
        try:
            if not self.api.is_room_admin(room_id):
                self.main_window.show_error(t('controller.admin_required', 'Administrator privilege is required.'))
                return
            current_name = next(
                (
                    str(room.get('name') or '')
                    for room in self.rooms_cache
                    if int(room.get('id') or 0) == room_id
                ),
                '',
            )
            new_name, ok = QInputDialog.getText(
                self.main_window,
                t('main.rename_room', 'Rename Room'),
                t('controller.new_room_name', 'New room name'),
                text=current_name,
            )
            if not ok:
                return
            normalized = new_name.strip()
            if not normalized:
                self.main_window.show_info(t('controller.room_name_required', 'Room name is required.'))
                return
            self.api.update_room_name(room_id, normalized)
            self._update_room_cache_name(room_id, normalized)
            self.main_window.set_room_title(normalized)
            self.main_window.set_rooms(self.rooms_cache)
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _edit_profile(self) -> None:
        try:
            profile = self.api.get_profile()
            nickname_default = str(
                profile.get('nickname')
                or (self.current_user or {}).get('nickname')
                or (self.current_user or {}).get('username')
                or ''
            )
            status_default = str(profile.get('status_message') or '')
            nickname, ok = QInputDialog.getText(
                self.main_window,
                t('main.edit_profile', 'Edit Profile'),
                t('controller.profile_nickname', 'Nickname'),
                text=nickname_default,
            )
            if not ok:
                return
            normalized_nickname = nickname.strip()
            if not normalized_nickname:
                self.main_window.show_info(t('controller.nickname_required', 'Nickname is required.'))
                return

            status, ok = QInputDialog.getText(
                self.main_window,
                t('main.edit_profile', 'Edit Profile'),
                t('controller.profile_status_message', 'Status message'),
                text=status_default,
            )
            if not ok:
                return

            self.api.update_profile(normalized_nickname, status.strip())
            if self.current_user is None:
                self.current_user = {}
            self.current_user['nickname'] = normalized_nickname
            self.current_user['status_message'] = status.strip()
            self.main_window.set_user(self.current_user)
            self.socket.emit(
                'profile_updated',
                {
                    'nickname': normalized_nickname,
                    'profile_image': self.current_user.get('profile_image', ''),
                },
            )
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _open_settings(self) -> None:
        self.settings_dialog.set_values(
            server_url=self.preferred_server_url,
            startup_enabled=self.startup_manager.is_enabled(),
            minimize_to_tray=self.main_window.minimize_to_tray,
            language_preference=self.i18n.preference,
            update_channel=self._settings.value('updates/channel', 'stable', type=str),
        )
        self.settings_dialog.show()
        self.settings_dialog.activateWindow()
        self.settings_dialog.raise_()

    def _on_settings_saved(
        self,
        server_url: str,
        startup_enabled: bool,
        minimize_to_tray: bool,
        language_preference: str,
        update_channel: str,
    ) -> None:
        try:
            self.startup_manager.set_enabled(startup_enabled)
        except Exception as exc:
            self.main_window.show_error(
                t(
                    'settings.startup_update_failed',
                    'Failed to update startup setting: {error}',
                    error=str(exc),
                )
            )
            return

        self.main_window.minimize_to_tray = minimize_to_tray
        if server_url:
            normalized = server_url.rstrip('/')
            self.preferred_server_url = normalized
            self.login_window.set_server_url(normalized)
            if normalized != self.current_server_url.rstrip('/'):
                self.main_window.show_info(
                    t(
                        'settings.server_applied_next_login',
                        'Server URL updated. It will be applied on next login.',
                    )
                )
        self.i18n.set_preference(language_preference or 'auto')
        normalized_channel = (update_channel or 'stable').strip().lower()
        if normalized_channel not in ('stable', 'canary'):
            normalized_channel = 'stable'
        self._settings.setValue('updates/channel', normalized_channel)
        self.settings_dialog.hide()
        self.main_window.show_info(t('settings.saved', 'Settings saved.'))

    def _open_polls(self) -> None:
        room_id = self._require_room()
        if not room_id:
            return
        self.polls_dialog.show()
        self.polls_dialog.activateWindow()
        self.polls_dialog.raise_()
        self._refresh_polls()

    def _refresh_polls(self) -> None:
        room_id = self._require_room()
        if not room_id:
            return
        try:
            polls = self.api.get_room_polls(room_id)
            self.polls_dialog.set_polls(polls)
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _create_poll(
        self,
        question: str,
        options: list,
        multiple_choice: bool,
        anonymous: bool,
        ends_at: object,
    ) -> None:
        room_id = self._require_room()
        if not room_id:
            return
        try:
            self.api.create_room_poll(
                room_id=room_id,
                question=question,
                options=[str(o) for o in options],
                multiple_choice=multiple_choice,
                anonymous=anonymous,
                ends_at=str(ends_at) if ends_at else None,
            )
            self._refresh_polls()
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _vote_poll(self, poll_id: int, option_ids: list[int]) -> None:
        try:
            self.api.vote_poll(poll_id, option_ids)
            self._refresh_polls()
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _close_poll(self, poll_id: int) -> None:
        try:
            self.api.close_poll(poll_id)
            self._refresh_polls()
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _open_files(self) -> None:
        room_id = self._require_room()
        if not room_id:
            return
        self.files_dialog.show()
        self.files_dialog.activateWindow()
        self.files_dialog.raise_()
        self._refresh_files()

    def _refresh_files(self) -> None:
        room_id = self._require_room()
        if not room_id:
            return
        try:
            files = self.api.get_room_files(room_id)
            self.files_dialog.set_files(files)
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _download_room_file(self, file_info: dict[str, Any]) -> None:
        file_path = str(file_info.get('file_path') or '')
        file_name = str(file_info.get('file_name') or Path(file_path).name or 'download.bin')
        if not file_path:
            self.main_window.show_error(t('controller.invalid_file_metadata', 'Invalid file metadata.'))
            return
        target, _ = QFileDialog.getSaveFileName(
            self.main_window,
            t('main.save_file', 'Save File'),
            file_name,
        )
        if not target:
            return
        try:
            saved = self.api.download_upload_file(file_path, target)
            self.main_window.show_info(t('main.saved', 'Saved: {path}', path=saved))
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _delete_room_file(self, file_id: int) -> None:
        room_id = self._require_room()
        if not room_id:
            return
        try:
            self.api.delete_room_file(room_id, file_id)
            self._refresh_files()
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _open_admin(self) -> None:
        room_id = self._require_room()
        if not room_id:
            return
        self.admin_dialog.show()
        self.admin_dialog.activateWindow()
        self.admin_dialog.raise_()
        self._refresh_admins()

    def _refresh_admins(self, silent: bool = False) -> None:
        room_id = self._require_room()
        if not room_id:
            return
        try:
            admins = self.api.get_room_admins(room_id)
            admin_ids = {int(a.get('id')) for a in admins}
            self.current_admin_ids = admin_ids
            self.current_is_admin = self.api.is_room_admin(room_id)

            # Ensure members are fresh enough for admin UI.
            if not self.current_room_members:
                info = self.api.get_room_info(room_id)
                self.current_room_members = info.get('members') or []

            self.admin_dialog.set_members(self.current_room_members, admin_ids)
        except Exception as exc:
            if not silent:
                self.main_window.show_error(str(exc))

    def _set_room_admin(self, user_id: int, is_admin: bool) -> None:
        room_id = self._require_room()
        if not room_id:
            return
        if not self.current_is_admin:
            self.main_window.show_error(t('controller.admin_required', 'Administrator privilege is required.'))
            return
        try:
            self.api.set_room_admin(room_id, user_id, is_admin=is_admin)
            self._refresh_admins()
        except Exception as exc:
            self.main_window.show_error(str(exc))

    def _check_update_policy(self) -> None:
        try:
            info = self.update_checker.check()
        except Exception:
            return

        if info.get('force_update'):
            self.main_window.show_error(
                t(
                    'controller.update_required',
                    'This client version is no longer supported. Update and sign in again.',
                )
            )
            self._logout()
            return

        if info.get('update_available'):
            latest = info.get('latest_version') or 'latest'
            self.main_window.show_info(
                t('controller.update_recommended', 'A newer version ({latest}) is available.', latest=latest)
            )

    def _logout(self) -> None:
        self._rooms_reload_timer.stop()
        self._typing_debounce_timer.stop()
        self._pending_send_timer.stop()
        self._session_refresh_timer.stop()
        try:
            self.socket.disconnect()
        except Exception:
            pass
        try:
            self.api.revoke_current_device_session(self.current_device_token)
        except Exception:
            pass
        try:
            if self.current_user:
                self.outbox_store.clear(
                    user_id=int((self.current_user or {}).get('id') or 0),
                    server_url=self.current_server_url,
                )
        except Exception:
            pass
        self.session_store.clear()
        self.current_user = None
        self.current_room_id = None
        self.current_room_key = ''
        self.current_device_token = ''
        self._remember_device = False
        self._session_expires_at_epoch = 0.0
        self._session_ttl_seconds = 0.0
        self._refresh_inflight = False
        self.current_room_members = []
        self.current_admin_ids = set()
        self.current_is_admin = False
        self._typing_pending = None
        self._typing_sent = False
        self._typing_room_id = None
        self._pending_sends.clear()
        self._failed_send_ids.clear()
        self.main_window.set_delivery_state('idle', 0)
        self.main_window.hide()
        self.polls_dialog.hide()
        self.files_dialog.hide()
        self.admin_dialog.hide()
        self.settings_dialog.hide()
        self.login_window.set_server_url(self.preferred_server_url)
        self.login_window.show()
        self.tray.notify(t('app.name', 'Intranet Messenger'), t('tray.signed_out', 'Signed out.'))

    def _quit(self) -> None:
        self._typing_debounce_timer.stop()
        self._pending_send_timer.stop()
        self._session_refresh_timer.stop()
        try:
            self.socket.disconnect()
        except Exception:
            pass
        self.api.close()
        self.tray.hide()
        self.app.quit()

    @staticmethod
    def default_device_name() -> str:
        return f"{socket.gethostname()} {t('common.desktop', 'Desktop')}"

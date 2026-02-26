# -*- coding: utf-8 -*-
"""
Main desktop messenger UI.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from client.i18n import i18n_manager, t


class _ComposerTextEdit(QTextEdit):
    send_shortcut_triggered = Signal()

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802
        if (
            event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
            and event.modifiers() & Qt.KeyboardModifier.ControlModifier
        ):
            event.accept()
            self.send_shortcut_triggered.emit()
            return
        super().keyPressEvent(event)


class MainWindow(QMainWindow):
    room_selected = Signal(int)
    refresh_rooms_requested = Signal()
    create_room_requested = Signal()
    invite_members_requested = Signal()
    rename_room_requested = Signal()
    leave_room_requested = Signal()
    edit_profile_requested = Signal()
    send_message_requested = Signal(str)
    logout_requested = Signal()
    search_requested = Signal(str)
    startup_toggled = Signal(bool)
    close_to_tray_requested = Signal()
    open_settings_requested = Signal()
    open_polls_requested = Signal()
    open_files_requested = Signal()
    open_admin_requested = Signal()
    send_file_requested = Signal(str)  # local path
    load_older_messages_requested = Signal(int)  # before message id
    typing_changed = Signal(bool)
    retry_send_requested = Signal()

    def __init__(self):
        super().__init__()
        self.resize(1260, 780)
        self.setMinimumSize(1080, 680)
        self.minimize_to_tray = True
        self._room_id_by_row: dict[int, int] = {}
        self._user_aliases: set[str] = set()
        self._current_user_id: int = 0
        self._current_room_name = t('main.select_room', 'Select a room')
        self._room_meta_base = t('main.select_room_desc', 'Choose a conversation from the left list.')
        self._typing_user = ''
        self._max_rendered_messages = 600
        self._connected = False
        self._history_has_more = False
        self._history_loading = False
        self._history_scroll_blocked = False
        self._history_banner_key = '__history_banner__'
        self._delivery_state = 'idle'
        self._delivery_count = 0
        self._build_ui()
        i18n_manager.subscribe(self.retranslate_ui)
        self.retranslate_ui()

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("AppRoot")
        self.setCentralWidget(root)

        layout = QVBoxLayout(root)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QFrame()
        left_panel.setProperty('sidebar', True)
        left_panel.setMinimumWidth(320)
        left_panel.setMaximumWidth(420)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(24, 28, 24, 24)
        left_layout.setSpacing(20)

        user_header = QHBoxLayout()
        user_info = QVBoxLayout()
        self.user_label = QLabel('')
        self.user_label.setProperty('section', True)
        self.connection_label = QLabel('')
        self._set_connection_style(connected=False)
        user_info.addWidget(self.user_label)
        user_info.addSpacing(2)
        user_info.addWidget(self.connection_label)
        
        self.settings_btn = QPushButton('⚙️')
        self.settings_btn.setFixedSize(36, 36)
        self.settings_btn.setStyleSheet("border-radius: 18px; border: none; background: #e2e8f0; font-size: 14pt;")
        self.profile_btn = QPushButton('')
        
        user_header.addLayout(user_info)
        user_header.addStretch()
        user_header.addWidget(self.profile_btn)
        user_header.addWidget(self.settings_btn)

        inbox_title = QLabel('')
        inbox_title.setProperty('subtitle', True)
        self._inbox_title_label = inbox_title

        self.search_input = QLineEdit()
        self.rooms_list = QListWidget()
        self.rooms_list.setSpacing(6)
        self.rooms_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.rooms_list.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        
        left_layout.addLayout(user_header)
        left_layout.addSpacing(4)
        left_layout.addWidget(self.search_input)
        left_layout.addSpacing(4)
        left_layout.addWidget(inbox_title)
        left_layout.addWidget(self.rooms_list)

        left_actions = QHBoxLayout()
        self.new_room_btn = QPushButton('')
        self.refresh_btn = QPushButton('')
        self.logout_btn = QPushButton('')
        self.logout_btn.setProperty('variant', 'danger')
        left_actions.addWidget(self.new_room_btn)
        left_actions.addWidget(self.refresh_btn)
        left_actions.addStretch()
        left_actions.addWidget(self.logout_btn)
        left_layout.addLayout(left_actions)

        splitter.addWidget(left_panel)

        right_panel = QFrame()
        right_panel.setProperty('chatArea', True)
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        # Room Header
        room_header = QFrame()
        room_header.setStyleSheet("background: #ffffff; border-bottom: 1px solid #e2e8f0; border-top-right-radius: 12px;")
        room_header_layout = QHBoxLayout(room_header)
        room_header_layout.setContentsMargins(28, 22, 28, 22)
        
        self.room_title = QLabel('')
        self.room_title.setProperty('section', True)
        self.room_title.setStyleSheet("font-size: 16pt;")
        self.room_meta = QLabel('')
        self.room_meta.setProperty('muted', True)

        self.polls_btn = QPushButton('')
        self.files_btn = QPushButton('')
        self.admin_btn = QPushButton('')
        self.invite_btn = QPushButton('')
        self.rename_btn = QPushButton('')
        self.leave_btn = QPushButton('')
        self.leave_btn.setProperty('variant', 'danger')
        self.polls_btn.setProperty('variant', 'primary')

        header_titles = QVBoxLayout()
        header_titles.setSpacing(4)
        header_titles.addWidget(self.room_title)
        header_titles.addWidget(self.room_meta)
        room_header_layout.addLayout(header_titles)
        room_header_layout.addStretch()
        room_header_layout.addWidget(self.invite_btn)
        room_header_layout.addWidget(self.rename_btn)
        room_header_layout.addWidget(self.leave_btn)
        room_header_layout.addWidget(self.polls_btn)
        room_header_layout.addWidget(self.files_btn)
        room_header_layout.addWidget(self.admin_btn)

        self.messages_list = QListWidget()
        self.messages_list.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.messages_list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.messages_list.setSpacing(18)  # 메시지 간 여유
        self.messages_list.setStyleSheet("background: #f8fafc; padding: 24px 32px; border: none;")
        self.messages_list.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.messages_list.verticalScrollBar().valueChanged.connect(self._on_messages_scrolled)

        compose_box = QFrame()
        compose_box.setStyleSheet("background: #ffffff; border-top: 1px solid #e2e8f0; border-bottom-right-radius: 12px;")
        compose_box_layout = QVBoxLayout(compose_box)
        compose_box_layout.setContentsMargins(24, 20, 24, 20)
        compose_box_layout.setSpacing(12)

        self.message_input = _ComposerTextEdit()
        self.message_input.setFixedHeight(94)
        self.message_input.setStyleSheet("border: none; background: transparent; font-size: 11pt;")
        
        compose_meta = QHBoxLayout()
        self.compose_hint_label = QLabel('')
        self.compose_hint_label.setProperty('muted', True)
        compose_meta.addWidget(self.compose_hint_label)
        self.delivery_state_label = QLabel('')
        self.delivery_state_label.setProperty('muted', True)
        self.retry_send_btn = QPushButton('')
        self.retry_send_btn.setVisible(False)
        self.retry_send_btn.setProperty('variant', 'danger')
        compose_meta.addWidget(self.delivery_state_label)
        compose_meta.addWidget(self.retry_send_btn)
        compose_meta.addStretch()

        self.attach_btn = QPushButton('')
        self.send_btn = QPushButton('')
        self.send_btn.setProperty('variant', 'primary')
        self.send_btn.setMinimumWidth(80)
        compose_meta.addWidget(self.attach_btn)
        compose_meta.addWidget(self.send_btn)
        
        compose_box_layout.addWidget(self.message_input)
        compose_box_layout.addLayout(compose_meta)

        right_layout.addWidget(room_header)
        right_layout.addWidget(self.messages_list)
        right_layout.addWidget(compose_box)

        splitter.addWidget(right_panel)
        splitter.setSizes([330, 930])
        layout.addWidget(splitter)

        self.profile_btn.clicked.connect(self.edit_profile_requested.emit)
        self.refresh_btn.clicked.connect(self.refresh_rooms_requested.emit)
        self.new_room_btn.clicked.connect(self.create_room_requested.emit)
        self.logout_btn.clicked.connect(self.logout_requested.emit)
        self.settings_btn.clicked.connect(self.open_settings_requested.emit)
        self.invite_btn.clicked.connect(self.invite_members_requested.emit)
        self.rename_btn.clicked.connect(self.rename_room_requested.emit)
        self.leave_btn.clicked.connect(self.leave_room_requested.emit)
        self.polls_btn.clicked.connect(self.open_polls_requested.emit)
        self.files_btn.clicked.connect(self.open_files_requested.emit)
        self.admin_btn.clicked.connect(self.open_admin_requested.emit)
        self.retry_send_btn.clicked.connect(self.retry_send_requested.emit)
        self.send_btn.clicked.connect(self._emit_send_message)
        self.attach_btn.clicked.connect(self._select_file)
        self.rooms_list.currentRowChanged.connect(self._on_room_row_changed)
        self.search_input.textChanged.connect(self.search_requested.emit)
        self.message_input.send_shortcut_triggered.connect(self._emit_send_message)
        self.message_input.textChanged.connect(self._on_message_text_changed)
        self._set_room_actions_enabled(False)

    def set_user(self, user: dict[str, Any]) -> None:
        nickname = user.get('nickname') or user.get('username') or t('common.unknown', 'Unknown')
        username = user.get('username')
        try:
            self._current_user_id = int(user.get('id') or 0)
        except (TypeError, ValueError):
            self._current_user_id = 0
        if username and username != nickname:
            self.user_label.setText(f'{nickname} (@{username})')
        else:
            self.user_label.setText(str(nickname))
        self._user_aliases = {str(v) for v in (nickname, username) if v}

    def set_connected(self, connected: bool) -> None:
        self._set_connection_style(connected)

    def select_room(self, room_id: int) -> None:
        for row, mapped_id in self._room_id_by_row.items():
            if int(mapped_id) == int(room_id):
                self.rooms_list.setCurrentRow(row)
                return

    def clear_room_selection(self) -> None:
        self.rooms_list.setCurrentRow(-1)
        self.set_messages([], has_more=False)
        self.set_room_title(t('main.select_room', 'Select a room'))
        self._set_room_actions_enabled(False)

    def set_rooms(self, rooms: list[dict[str, Any]]) -> None:
        current_room_id = self._room_id_by_row.get(self.rooms_list.currentRow())
        self.rooms_list.clear()
        self._room_id_by_row.clear()
        selected_row = -1

        for room in rooms:
            room_id = room.get('id')
            try:
                normalized_room_id = int(room_id)
            except (TypeError, ValueError):
                continue

            item = QListWidgetItem()
            widget = self._build_room_item_widget(room)
            item.setSizeHint(widget.sizeHint())
            item.setData(Qt.ItemDataRole.UserRole, normalized_room_id)
            self.rooms_list.addItem(item)
            row = self.rooms_list.count() - 1
            self.rooms_list.setItemWidget(item, widget)
            self._room_id_by_row[row] = normalized_room_id
            if current_room_id and normalized_room_id == current_room_id:
                selected_row = row

        if self.rooms_list.count() == 0:
            empty_item = QListWidgetItem(t('main.rooms_empty', 'No rooms available.'))
            empty_item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.rooms_list.addItem(empty_item)
            self._set_room_actions_enabled(False)
            self.compose_hint_label.setText(t('main.compose_no_room', 'No room selected'))
            return

        if selected_row >= 0:
            self.rooms_list.setCurrentRow(selected_row)

    def set_room_title(self, title: str) -> None:
        self._current_room_name = title or t('main.select_room', 'Select a room')
        self.room_title.setText(self._current_room_name)
        self._update_compose_hint()

    def set_messages(self, messages: list[dict[str, Any]], has_more: bool = False) -> None:
        self._history_scroll_blocked = True
        self.messages_list.clear()
        self._history_has_more = bool(has_more)
        self._history_loading = False

        if len(messages) > self._max_rendered_messages:
            messages = messages[-self._max_rendered_messages:]
        if not messages:
            placeholder = QListWidgetItem(t('main.messages_empty', 'No messages yet.'))
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            placeholder.setData(Qt.ItemDataRole.UserRole, '__placeholder__')
            self.messages_list.addItem(placeholder)
            self._history_scroll_blocked = False
            return

        if self._history_has_more:
            self._insert_history_banner()

        for message in messages:
            self._append_message_item(message)
        self._update_history_banner()
        self.messages_list.scrollToBottom()
        self._history_scroll_blocked = False

    def prepend_messages(self, messages: list[dict[str, Any]], has_more: bool) -> None:
        self._history_scroll_blocked = True
        self._history_has_more = bool(has_more)
        self._history_loading = False

        if not messages:
            self._update_history_banner()
            self._history_scroll_blocked = False
            return

        scrollbar = self.messages_list.verticalScrollBar()
        prev_value = scrollbar.value()
        prev_max = scrollbar.maximum()

        if self.messages_list.count() == 1:
            first = self.messages_list.item(0)
            if first and str(first.data(Qt.ItemDataRole.UserRole) or '') == '__placeholder__':
                self.messages_list.clear()

        if self._history_has_more and not self._has_history_banner():
            self._insert_history_banner()

        for message in reversed(messages):
            self._insert_message_item(message, at_top=True)

        while self.messages_list.count() > self._max_rendered_messages + (1 if self._has_history_banner() else 0):
            self.messages_list.takeItem(self.messages_list.count() - 1)

        self._update_history_banner()

        new_max = scrollbar.maximum()
        delta = max(0, new_max - prev_max)
        scrollbar.setValue(prev_value + delta)
        self._history_scroll_blocked = False

    def append_message(self, message: dict[str, Any]) -> None:
        if self.messages_list.count() == 1:
            first_item = self.messages_list.item(0)
            if first_item and str(first_item.data(Qt.ItemDataRole.UserRole) or '') == '__placeholder__':
                self.messages_list.clear()
        self._append_message_item(message)
        while self.messages_list.count() > self._max_rendered_messages + (1 if self._has_history_banner() else 0):
            remove_index = 1 if self._has_history_banner() else 0
            self.messages_list.takeItem(remove_index)
        self.messages_list.scrollToBottom()

    def show_error(self, message: str) -> None:
        QMessageBox.critical(self, t('common.error', 'Error'), message)

    def show_info(self, message: str) -> None:
        QMessageBox.information(self, t('common.info', 'Info'), message)

    def _emit_send_message(self) -> None:
        text = self.message_input.toPlainText().strip()
        if not text:
            return
        self.send_message_requested.emit(text)
        self.message_input.clear()
        self._update_compose_hint()

    def _on_message_text_changed(self) -> None:
        self._update_compose_hint()
        self.typing_changed.emit(bool(self.message_input.toPlainText().strip()))

    def set_delivery_state(self, state: str, count: int = 0) -> None:
        self._delivery_state = state
        self._delivery_count = max(0, int(count))

        if state == 'pending' and self._delivery_count > 0:
            self.delivery_state_label.setText(
                t('main.delivery_pending', 'Sending... ({count})', count=self._delivery_count)
            )
            self.delivery_state_label.setStyleSheet('color:#7c2d12; background:#ffedd5; border-radius:8px; padding:2px 8px;')
            self.retry_send_btn.setVisible(False)
            return

        if state == 'failed' and self._delivery_count > 0:
            self.delivery_state_label.setText(
                t('main.delivery_failed', 'Failed to send ({count})', count=self._delivery_count)
            )
            self.delivery_state_label.setStyleSheet('color:#7f1d1d; background:#fee2e2; border-radius:8px; padding:2px 8px;')
            self.retry_send_btn.setVisible(True)
            return

        self.delivery_state_label.setText('')
        self.delivery_state_label.setStyleSheet('')
        self.retry_send_btn.setVisible(False)

    def _select_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, t('main.select_file', 'Select file'))
        if path:
            self.send_file_requested.emit(path)

    def _on_room_row_changed(self, row: int) -> None:
        room_id = self._room_id_by_row.get(row)
        if room_id:
            self._set_room_actions_enabled(True)
            self._room_meta_base = t('main.room_number', 'Room #{room_id}', room_id=room_id)
            self._typing_user = ''
            self._update_room_meta_label()
            self.room_selected.emit(room_id)
            return

        self._set_room_actions_enabled(False)
        self.room_title.setText(t('main.select_room', 'Select a room'))
        self._room_meta_base = t('main.select_room_desc', 'Choose a conversation from the left list.')
        self._typing_user = ''
        self._update_room_meta_label()
        self.compose_hint_label.setText(t('main.compose_no_room', 'No room selected'))

    def _set_connection_style(self, connected: bool) -> None:
        self._connected = connected
        if connected:
            self.connection_label.setText(t('common.connected', 'Connected'))
            self.connection_label.setStyleSheet(
                'color: #065f46; background: #d1fae5; border-radius: 9px; padding: 3px 10px;'
            )
            return
        self.connection_label.setText(t('common.disconnected', 'Disconnected'))
        self.connection_label.setStyleSheet(
            'color: #7f1d1d; background: #fee2e2; border-radius: 9px; padding: 3px 10px;'
        )

    def _set_room_actions_enabled(self, enabled: bool) -> None:
        self.polls_btn.setEnabled(enabled)
        self.files_btn.setEnabled(enabled)
        self.admin_btn.setEnabled(enabled)
        self.invite_btn.setEnabled(enabled)
        self.rename_btn.setEnabled(enabled)
        self.leave_btn.setEnabled(enabled)
        self.message_input.setEnabled(enabled)
        self.attach_btn.setEnabled(enabled)
        self.send_btn.setEnabled(enabled)
        self._update_compose_hint()

    def _update_compose_hint(self) -> None:
        if not self.message_input.isEnabled():
            self.compose_hint_label.setText(t('main.compose_no_room', 'No room selected'))
            return
        char_count = len(self.message_input.toPlainText())
        self.compose_hint_label.setText(
            t(
                'main.compose_hint_format',
                '{room} | {count} chars | Ctrl+Enter to send',
                room=self._current_room_name,
                count=char_count,
            )
        )

    def _append_message_item(self, message: dict[str, Any]) -> None:
        self._insert_message_item(message, at_top=False)

    def _insert_message_item(self, message: dict[str, Any], *, at_top: bool) -> None:
        message_copy = dict(message or {})
        container = self._build_message_container(message_copy)
        message_id = 0
        try:
            message_id = int(message_copy.get('id') or 0)
        except Exception:
            message_id = 0

        item = QListWidgetItem()
        if message_id > 0:
            item.setData(Qt.ItemDataRole.UserRole, int(message_id))
            item.setData(Qt.ItemDataRole.UserRole + 1, message_copy)
        item.setSizeHint(container.sizeHint())
        if at_top:
            insert_row = 1 if self._has_history_banner() else 0
            self.messages_list.insertItem(insert_row, item)
        else:
            self.messages_list.addItem(item)
        self.messages_list.setItemWidget(item, container)

    def _build_message_container(self, message: dict[str, Any]) -> QWidget:
        sender = str(
            message.get('sender_name')
            or message.get('sender_id')
            or t('common.unknown', 'unknown')
        )
        content = str(message.get('display_content') or message.get('content') or '')
        timestamp = str(message.get('created_at') or '')
        reply_sender = str(message.get('reply_sender') or '')
        reply_content = str(message.get('reply_content') or '')
        reactions = message.get('reactions') or []
        try:
            sender_id = int(message.get('sender_id') or 0)
        except (TypeError, ValueError):
            sender_id = 0
        is_own = sender_id > 0 and sender_id == self._current_user_id

        container = QWidget()
        container.setStyleSheet("background: transparent;")
        container_layout = QHBoxLayout(container)
        container_layout.setContentsMargins(4, 2, 4, 2)
        container_layout.setSpacing(12)

        bubble = QFrame()
        bubble.setProperty('messageOwn', is_own)
        bubble_layout = QVBoxLayout(bubble)
        bubble_layout.setContentsMargins(16, 12, 16, 12)
        bubble_layout.setSpacing(6)

        if not is_own:
            sender_label = QLabel(sender)
            sender_label.setStyleSheet("color: #3b82f6; font-weight: 700; font-size: 9.5pt;")
            bubble_layout.addWidget(sender_label)

        if reply_content:
            preview = reply_content if len(reply_content) <= 60 else f"{reply_content[:57]}..."
            reply = QLabel(
                t(
                    'main.reply_preview',
                    'Reply to {sender}: {preview}',
                    sender=reply_sender or t('common.unknown', 'unknown'),
                    preview=preview,
                )
            )
            reply.setStyleSheet("color: #64748b; font-size: 9pt; border-left: 2.5px solid #cbd5e1; padding-left: 8px;")
            reply.setWordWrap(True)
            bubble_layout.addWidget(reply)

        body = QLabel(content)
        body.setWordWrap(True)
        body.setStyleSheet("font-size: 10.5pt; line-height: 1.5;")
        body.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByKeyboard
            | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        if self._contains_mention(content):
            body.setStyleSheet('background: rgba(250, 204, 21, 0.25); border-radius: 6px; padding: 4px 6px; font-size: 10.5pt;')
        bubble_layout.addWidget(body)

        reaction_text = self._format_reactions(reactions)
        if reaction_text:
            reaction_label = QLabel(reaction_text)
            reaction_label.setProperty('muted', True)
            bubble_layout.addWidget(reaction_label)

        time_label = QLabel(timestamp)
        time_label.setProperty('muted', True)
        time_label.setStyleSheet("font-size: 8pt; margin-bottom: 2px;")
        time_layout = QVBoxLayout()
        time_layout.addStretch()
        time_layout.addWidget(time_label)

        if is_own:
            container_layout.addStretch()
            container_layout.addLayout(time_layout)
            container_layout.addWidget(bubble)
        else:
            avatar_label = QLabel(sender[0].upper() if sender else "?")
            avatar_label.setFixedSize(40, 40)
            avatar_label.setAlignment(Qt.AlignCenter)
            avatar_label.setStyleSheet("background-color: #cbd5e1; color: #ffffff; border-radius: 20px; font-weight: bold; font-size: 14pt;")

            avatar_layout = QVBoxLayout()
            avatar_layout.addWidget(avatar_label)
            avatar_layout.addStretch()

            container_layout.addLayout(avatar_layout)
            container_layout.addWidget(bubble)
            container_layout.addLayout(time_layout)
            container_layout.addStretch()

        return container

    def _find_message_row(self, message_id: int) -> int:
        if message_id <= 0:
            return -1
        start = 1 if self._has_history_banner() else 0
        for row in range(start, self.messages_list.count()):
            item = self.messages_list.item(row)
            if not item:
                continue
            try:
                current_id = int(item.data(Qt.ItemDataRole.UserRole) or 0)
            except (TypeError, ValueError):
                current_id = 0
            if current_id == message_id:
                return row
        return -1

    def _replace_message_item(self, row: int, message: dict[str, Any]) -> bool:
        if row < 0 or row >= self.messages_list.count():
            return False
        item = self.messages_list.item(row)
        if not item:
            return False
        item.setData(Qt.ItemDataRole.UserRole + 1, dict(message))
        widget = self._build_message_container(dict(message))
        item.setSizeHint(widget.sizeHint())
        self.messages_list.setItemWidget(item, widget)
        return True

    def update_message_reactions(self, message_id: int, reactions: list[dict[str, Any]]) -> bool:
        row = self._find_message_row(message_id)
        if row < 0:
            return False
        item = self.messages_list.item(row)
        if not item:
            return False
        stored = item.data(Qt.ItemDataRole.UserRole + 1)
        if not isinstance(stored, dict):
            return False
        updated = dict(stored)
        updated['reactions'] = reactions
        return self._replace_message_item(row, updated)

    def update_message_content(
        self,
        *,
        message_id: int,
        content: str,
        display_content: str,
        encrypted: bool,
    ) -> bool:
        row = self._find_message_row(message_id)
        if row < 0:
            return False
        item = self.messages_list.item(row)
        if not item:
            return False
        stored = item.data(Qt.ItemDataRole.UserRole + 1)
        if not isinstance(stored, dict):
            return False
        updated = dict(stored)
        updated['content'] = content
        updated['display_content'] = display_content
        updated['encrypted'] = bool(encrypted)
        return self._replace_message_item(row, updated)

    def mark_message_deleted(self, message_id: int) -> bool:
        row = self._find_message_row(message_id)
        if row < 0:
            return False
        item = self.messages_list.item(row)
        if not item:
            return False
        stored = item.data(Qt.ItemDataRole.UserRole + 1)
        if not isinstance(stored, dict):
            return False
        updated = dict(stored)
        deleted_text = t('main.message_deleted', '[deleted message]')
        updated['content'] = deleted_text
        updated['display_content'] = deleted_text
        updated['encrypted'] = False
        updated['file_path'] = ''
        updated['file_name'] = ''
        updated['message_type'] = 'text'
        return self._replace_message_item(row, updated)

    def _on_messages_scrolled(self, value: int) -> None:
        if self._history_scroll_blocked or value > 2 or not self._history_has_more or self._history_loading:
            return
        oldest_message_id = self._get_oldest_rendered_message_id()
        if oldest_message_id <= 0:
            return
        self._history_loading = True
        self._update_history_banner()
        self.load_older_messages_requested.emit(oldest_message_id)

    def _get_oldest_rendered_message_id(self) -> int:
        start = 1 if self._has_history_banner() else 0
        for row in range(start, self.messages_list.count()):
            item = self.messages_list.item(row)
            if not item:
                continue
            data = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(data, int) and data > 0:
                return int(data)
        return 0

    def _has_history_banner(self) -> bool:
        if self.messages_list.count() == 0:
            return False
        item = self.messages_list.item(0)
        if not item:
            return False
        return str(item.data(Qt.ItemDataRole.UserRole) or '') == self._history_banner_key

    def _insert_history_banner(self) -> None:
        if self._has_history_banner():
            return
        banner = QListWidgetItem('')
        banner.setFlags(Qt.ItemFlag.NoItemFlags)
        banner.setData(Qt.ItemDataRole.UserRole, self._history_banner_key)
        self.messages_list.insertItem(0, banner)

    def _update_history_banner(self) -> None:
        if self._history_has_more and not self._has_history_banner():
            self._insert_history_banner()

        if not self._has_history_banner():
            return

        banner = self.messages_list.item(0)
        if not banner:
            return

        if self._history_loading:
            banner.setText(t('main.history_loading', 'Loading earlier messages...'))
            return

        if self._history_has_more:
            banner.setText(t('main.history_more_hint', 'Scroll up to load earlier messages'))
            return

        banner.setText(t('main.history_reached_start', 'Reached the beginning of the conversation'))

    def set_typing_user(self, user_id: int, nickname: str, is_typing: bool) -> None:
        sender = (nickname or '').strip()
        if int(user_id or 0) == int(self._current_user_id):
            sender = ''
        self._typing_user = sender if is_typing else ''
        self._update_room_meta_label()

    def _update_room_meta_label(self) -> None:
        meta = self._room_meta_base or t('main.select_room_desc', 'Choose a conversation from the left list.')
        if self._typing_user:
            self.room_meta.setText(
                t(
                    'main.typing_meta',
                    '{meta} | {user} is typing...',
                    meta=meta,
                    user=self._typing_user,
                )
            )
            return
        self.room_meta.setText(meta)

    def _contains_mention(self, content: str) -> bool:
        lowered = content.lower()
        for alias in self._user_aliases:
            token = f"@{alias}".strip().lower()
            if token and token in lowered:
                return True
        return False

    @staticmethod
    def _format_reactions(reactions: Any) -> str:
        if not isinstance(reactions, list) or not reactions:
            return ''
        chunks = []
        for reaction in reactions:
            if not isinstance(reaction, dict):
                continue
            emoji = str(reaction.get('emoji') or '').strip()
            count = int(reaction.get('count') or 0)
            if not emoji:
                continue
            chunks.append(f"{emoji} {count}" if count > 0 else emoji)
        return '   '.join(chunks)

    def _build_room_item_widget(self, room: dict[str, Any]) -> QWidget:
        name = str(room.get('name') or t('main.room_default_name', 'Room {room_id}', room_id=room.get('id')))
        preview = str(room.get('last_message_preview') or t('main.no_recent_message', 'No recent message.'))
        unread = int(room.get('unread_count') or 0)

        wrapper = QWidget()
        wrapper_layout = QHBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(12, 12, 12, 12)
        wrapper_layout.setSpacing(14)

        avatar_label = QLabel(name[0].upper() if name else "?")
        avatar_label.setFixedSize(44, 44)
        avatar_label.setAlignment(Qt.AlignCenter)
        avatar_label.setStyleSheet("background-color: #e2e8f0; color: #475569; border-radius: 22px; font-weight: bold; font-size: 14pt;")

        content_layout = QVBoxLayout()
        content_layout.setSpacing(2)

        top = QHBoxLayout()
        title = QLabel(name)
        title.setStyleSheet("font-size: 11pt; font-weight: 600; color: #1e293b;")
        top.addWidget(title)
        top.addStretch()

        if unread > 0:
            badge = QLabel(str(unread))
            badge.setProperty('badge', True)
            top.addWidget(badge)

        preview_label = QLabel(preview)
        preview_label.setProperty('muted', True)
        preview_label.setStyleSheet("color: #64748b; font-size: 9.5pt;")
        preview_label.setFixedHeight(20)

        content_layout.addLayout(top)
        content_layout.addWidget(preview_label)

        wrapper_layout.addWidget(avatar_label)
        wrapper_layout.addLayout(content_layout)
        return wrapper

    def retranslate_ui(self) -> None:
        self.setWindowTitle(t('app.desktop_title', 'Intranet Messenger Desktop'))
        self._inbox_title_label.setText(t('main.conversations', 'Conversations'))
        self.search_input.setPlaceholderText(t('main.search_placeholder', 'Search rooms or previews'))
        self.profile_btn.setText(t('main.profile', 'Profile'))
        self.new_room_btn.setText(t('main.new_room', 'New Room'))
        self.refresh_btn.setText(t('main.refresh', 'Refresh'))
        self.settings_btn.setText(t('main.settings', 'Settings'))
        self.logout_btn.setText(t('main.logout', 'Logout'))
        self.invite_btn.setText(t('main.invite_members', 'Invite'))
        self.rename_btn.setText(t('main.rename_room', 'Rename'))
        self.leave_btn.setText(t('main.leave_room', 'Leave'))
        self.polls_btn.setText(t('main.polls', 'Polls'))
        self.files_btn.setText(t('main.files', 'Files'))
        self.admin_btn.setText(t('main.admin', 'Admin'))
        self.message_input.setPlaceholderText(t('main.compose_placeholder', 'Write a message... (Ctrl+Enter to send)'))
        self.attach_btn.setText(t('main.attach', 'Attach'))
        self.send_btn.setText(t('main.send', 'Send'))
        self.retry_send_btn.setText(t('main.retry_send', 'Retry'))
        if not self.message_input.isEnabled():
            self._current_room_name = t('main.select_room', 'Select a room')
            self.room_title.setText(self._current_room_name)
            self._room_meta_base = t('main.select_room_desc', 'Choose a conversation from the left list.')
            self._typing_user = ''
            self._update_room_meta_label()
        self._set_connection_style(self._connected)
        self._update_compose_hint()
        self.set_delivery_state(self._delivery_state, self._delivery_count)

    def closeEvent(self, event) -> None:  # noqa: N802
        if self.minimize_to_tray:
            event.ignore()
            self.hide()
            self.close_to_tray_requested.emit()
            return
        super().closeEvent(event)

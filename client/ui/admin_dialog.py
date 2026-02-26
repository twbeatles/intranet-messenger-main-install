# -*- coding: utf-8 -*-
"""
Room admin dialog.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from client.i18n import i18n_manager, t


class AdminDialog(QDialog):
    refresh_requested = Signal()
    set_admin_requested = Signal(int, bool)  # user_id, is_admin

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(760, 520)
        self.setObjectName("AppRoot")
        self._member_by_row: dict[int, dict[str, Any]] = {}
        self._admin_ids: set[int] = set()
        self._build_ui()
        i18n_manager.subscribe(self.retranslate_ui)
        self.retranslate_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        title = QLabel('')
        title.setProperty('title', True)
        subtitle = QLabel('')
        subtitle.setProperty('subtitle', True)
        root.addWidget(title)
        root.addWidget(subtitle)
        self._title_label = title
        self._subtitle_label = subtitle

        top = QHBoxLayout()
        self.summary_label = QLabel('')
        self.summary_label.setProperty('muted', True)
        self.refresh_btn = QPushButton('')
        self.grant_btn = QPushButton('')
        self.revoke_btn = QPushButton('')
        self.grant_btn.setProperty('variant', 'primary')
        self.revoke_btn.setProperty('variant', 'danger')
        top.addWidget(self.summary_label)
        top.addStretch()
        top.addWidget(self.refresh_btn)
        top.addWidget(self.grant_btn)
        top.addWidget(self.revoke_btn)
        root.addLayout(top)

        list_card = QFrame()
        list_card.setProperty('card', True)
        list_layout = QVBoxLayout(list_card)
        list_layout.setContentsMargins(20, 20, 20, 20)
        list_layout.setSpacing(12)
        self.member_list = QListWidget()
        self.member_list.setSpacing(8)
        list_layout.addWidget(self.member_list)
        root.addWidget(list_card, 1)

        self.selection_label = QLabel('')
        self.selection_label.setProperty('muted', True)
        root.addWidget(self.selection_label)

        self.refresh_btn.clicked.connect(self.refresh_requested.emit)
        self.grant_btn.clicked.connect(lambda: self._emit_set_admin(True))
        self.revoke_btn.clicked.connect(lambda: self._emit_set_admin(False))
        self.member_list.currentRowChanged.connect(self._on_selection_changed)
        self._set_action_state(False, False)

    def set_members(self, members: list[dict[str, Any]], admin_ids: set[int]) -> None:
        self._member_by_row.clear()
        self.member_list.clear()
        self._admin_ids = admin_ids
        self.summary_label.setText(t('admin.count', '{count} members', count=len(members)))

        if not members:
            item = QListWidgetItem(t('admin.none', 'No members found.'))
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.member_list.addItem(item)
            self.selection_label.setText(t('admin.none_detail', 'No member data available.'))
            self._set_action_state(False, False)
            return

        for idx, member in enumerate(members):
            uid = int(member.get('id'))
            marker = (
                f"[{t('admin.role.admin_short', 'ADMIN')}]"
                if uid in admin_ids
                else f"[{t('admin.role.user_short', 'USER')}]"
            )
            name = member.get('nickname') or str(uid)
            status = member.get('status') or t('admin.status.offline', 'offline')
            item = QListWidgetItem(f"{marker} {name} ({status})")
            item.setData(Qt.ItemDataRole.UserRole, uid)
            self.member_list.addItem(item)
            self._member_by_row[idx] = member

        self.selection_label.setText(t('admin.select_member_first', 'Select a member first.'))
        self._set_action_state(False, False)

    def _emit_set_admin(self, is_admin: bool) -> None:
        row = self.member_list.currentRow()
        member = self._member_by_row.get(row)
        if not member:
            self.show_error(t('admin.select_member_first', 'Select a member first.'))
            return
        uid = int(member['id'])
        if is_admin and uid in self._admin_ids:
            self.show_info(t('admin.already_admin', 'Selected member is already an admin.'))
            return
        if not is_admin and uid not in self._admin_ids:
            self.show_info(t('admin.not_admin', 'Selected member is not an admin.'))
            return
        self.set_admin_requested.emit(uid, is_admin)

    def _on_selection_changed(self, row: int) -> None:
        member = self._member_by_row.get(row)
        if not member:
            self.selection_label.setText(t('admin.select_member_first', 'Select a member first.'))
            self._set_action_state(False, False)
            return

        uid = int(member['id'])
        name = member.get('nickname') or str(uid)
        is_admin = uid in self._admin_ids
        self.selection_label.setText(
            t(
                'admin.selected_role',
                'Selected: {name} | role: {role}',
                name=name,
                role=t('admin.role.admin', 'admin') if is_admin else t('admin.role.user', 'user'),
            )
        )
        self._set_action_state(True, is_admin)

    def _set_action_state(self, has_selection: bool, is_admin: bool) -> None:
        self.grant_btn.setEnabled(has_selection and not is_admin)
        self.revoke_btn.setEnabled(has_selection and is_admin)

    def show_error(self, message: str) -> None:
        QMessageBox.critical(self, t('admin.window_title', 'Room Admin'), message)

    def show_info(self, message: str) -> None:
        QMessageBox.information(self, t('admin.window_title', 'Room Admin'), message)

    def retranslate_ui(self) -> None:
        self.setWindowTitle(t('admin.window_title', 'Room Admin'))
        self._title_label.setText(t('admin.title', 'Room Permission Management'))
        self._subtitle_label.setText(
            t('admin.subtitle', 'Grant or revoke admin permissions for selected members.')
        )
        self.summary_label.setText(t('admin.count', '{count} members', count=len(self._member_by_row)))
        self.refresh_btn.setText(t('common.refresh', 'Refresh'))
        self.grant_btn.setText(t('admin.grant', 'Grant Admin'))
        self.revoke_btn.setText(t('admin.revoke', 'Revoke Admin'))
        if not self._member_by_row:
            self.selection_label.setText(t('admin.select_member_first', 'Select a member first.'))

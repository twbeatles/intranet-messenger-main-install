# -*- coding: utf-8 -*-
"""
Settings dialog for desktop client.
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from client.i18n import i18n_manager, t


class SettingsDialog(QDialog):
    save_requested = Signal(str, bool, bool, str, str)  # server_url, startup_enabled, minimize_to_tray, language_preference, update_channel
    check_update_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(520, 360)
        self.setObjectName("AppRoot")

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(12)

        title = QLabel('')
        title.setProperty('title', True)
        subtitle = QLabel('')
        subtitle.setProperty('subtitle', True)
        root.addWidget(title)
        root.addWidget(subtitle)
        self._title_label = title
        self._subtitle_label = subtitle

        card = QFrame()
        card.setProperty('card', True)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(16)

        form = QFormLayout()
        form.setHorizontalSpacing(24)
        form.setVerticalSpacing(16)

        self.server_url_input = QLineEdit()
        self.auto_startup_check = QCheckBox('')
        self.tray_check = QCheckBox('')
        self.tray_check.setChecked(True)
        self.language_combo = QComboBox()
        self.language_combo.addItems(['auto', 'ko', 'en'])
        self.channel_combo = QComboBox()
        self.channel_combo.addItems(['stable', 'canary'])

        self.server_url_label = QLabel('')
        self.language_label = QLabel('')
        self.channel_label = QLabel('')

        form.addRow(self.server_url_label, self.server_url_input)
        form.addRow(self.language_label, self.language_combo)
        form.addRow(self.channel_label, self.channel_combo)
        form.addRow('', self.auto_startup_check)
        form.addRow('', self.tray_check)
        card_layout.addLayout(form)
        root.addWidget(card)

        self.status_label = QLabel('')
        self.status_label.setProperty('muted', True)
        root.addWidget(self.status_label)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self.check_update_btn = QPushButton('')
        self.check_update_btn.setProperty('variant', 'primary')
        self.save_btn = QPushButton('')
        self.close_btn = QPushButton('')
        self.save_btn.setProperty('variant', 'primary')
        self.save_btn.setMinimumWidth(80)
        self.close_btn.setMinimumWidth(80)
        btn_row.addWidget(self.check_update_btn)
        btn_row.addWidget(self.close_btn)
        btn_row.addWidget(self.save_btn)
        root.addLayout(btn_row)

        self.save_btn.clicked.connect(self._emit_save)
        self.check_update_btn.clicked.connect(self.check_update_requested.emit)
        self.close_btn.clicked.connect(self.hide)
        i18n_manager.subscribe(self.retranslate_ui)
        self.retranslate_ui()

    def set_values(
        self,
        server_url: str,
        startup_enabled: bool,
        minimize_to_tray: bool,
        language_preference: str = 'auto',
        update_channel: str = 'stable',
    ) -> None:
        self.server_url_input.setText(server_url)
        self.auto_startup_check.setChecked(startup_enabled)
        self.tray_check.setChecked(minimize_to_tray)
        idx = self.language_combo.findData((language_preference or 'auto').lower())
        if idx < 0:
            idx = self.language_combo.findData('auto')
        self.language_combo.setCurrentIndex(idx)
        channel_idx = self.channel_combo.findData((update_channel or 'stable').lower())
        if channel_idx < 0:
            channel_idx = self.channel_combo.findData('stable')
        self.channel_combo.setCurrentIndex(channel_idx)
        self.status_label.setText('')

    def _emit_save(self) -> None:
        server_url = self.server_url_input.text().strip().rstrip('/')
        if not server_url:
            self.status_label.setText(t('settings.server_required', 'Server URL is required.'))
            return
        self.status_label.setText(t('settings.saving', 'Saving...'))
        self.save_requested.emit(
            server_url,
            self.auto_startup_check.isChecked(),
            self.tray_check.isChecked(),
            str(self.language_combo.currentData() or 'auto'),
            str(self.channel_combo.currentData() or 'stable'),
        )

    def retranslate_ui(self) -> None:
        self.setWindowTitle(t('settings.window_title', 'Settings'))
        self._title_label.setText(t('settings.title', 'Desktop Settings'))
        self._subtitle_label.setText(
            t(
                'settings.subtitle',
                'Manage startup behavior, tray behavior, server URL and language.',
            )
        )
        self.server_url_label.setText(t('settings.server_url', 'Server URL'))
        self.language_label.setText(t('settings.language_label', 'Display Language'))
        self.channel_label.setText(t('settings.update_channel_label', 'Update Channel'))
        self.server_url_input.setPlaceholderText('http://127.0.0.1:5000')
        self.auto_startup_check.setText(t('settings.run_on_startup', 'Run on Windows startup'))
        self.tray_check.setText(t('settings.minimize_to_tray', 'Minimize to tray on close'))
        self.check_update_btn.setText(t('settings.check_update', 'Check Update'))
        self.check_update_btn.setToolTip(t('settings.check_update', 'Check Update'))
        self.save_btn.setText(t('common.save', 'Save'))
        self.close_btn.setText(t('common.close', 'Close'))

        current_value = str(self.language_combo.currentData() or 'auto')
        self.language_combo.blockSignals(True)
        self.language_combo.clear()
        self.language_combo.addItem(t('language.auto', 'Auto'), 'auto')
        self.language_combo.addItem(t('language.ko', '한국어'), 'ko')
        self.language_combo.addItem(t('language.en', 'English'), 'en')
        idx = self.language_combo.findData(current_value)
        if idx < 0:
            idx = self.language_combo.findData('auto')
        self.language_combo.setCurrentIndex(idx)
        self.language_combo.blockSignals(False)

        current_channel = str(self.channel_combo.currentData() or 'stable')
        self.channel_combo.blockSignals(True)
        self.channel_combo.clear()
        self.channel_combo.addItem(t('settings.channel.stable', 'Stable'), 'stable')
        self.channel_combo.addItem(t('settings.channel.canary', 'Canary'), 'canary')
        channel_idx = self.channel_combo.findData(current_channel)
        if channel_idx < 0:
            channel_idx = self.channel_combo.findData('stable')
        self.channel_combo.setCurrentIndex(channel_idx)
        self.channel_combo.blockSignals(False)

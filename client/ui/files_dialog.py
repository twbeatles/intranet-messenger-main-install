# -*- coding: utf-8 -*-
"""
Room file repository dialog.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
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


class FilesDialog(QDialog):
    refresh_requested = Signal()
    upload_requested = Signal(str)  # local file path
    download_requested = Signal(dict)  # file dict
    delete_requested = Signal(int)  # file_id

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(860, 560)
        self.setObjectName("AppRoot")
        self._files: list[dict[str, Any]] = []
        self._file_by_row: dict[int, dict[str, Any]] = {}
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

        actions = QHBoxLayout()
        self.summary_label = QLabel('')
        self.summary_label.setProperty('muted', True)
        self.refresh_btn = QPushButton('')
        self.upload_btn = QPushButton('')
        self.download_btn = QPushButton('')
        self.delete_btn = QPushButton('')
        self.upload_btn.setProperty('variant', 'primary')
        self.delete_btn.setProperty('variant', 'danger')
        actions.addWidget(self.summary_label)
        actions.addStretch()
        actions.addWidget(self.refresh_btn)
        actions.addWidget(self.upload_btn)
        actions.addWidget(self.download_btn)
        actions.addWidget(self.delete_btn)
        root.addLayout(actions)

        list_card = QFrame()
        list_card.setProperty('card', True)
        list_layout = QVBoxLayout(list_card)
        list_layout.setContentsMargins(20, 20, 20, 20)
        list_layout.setSpacing(12)
        self.file_list = QListWidget()
        self.file_list.setSpacing(8)
        list_layout.addWidget(self.file_list)
        root.addWidget(list_card, 1)

        self.selection_label = QLabel('')
        self.selection_label.setProperty('muted', True)
        root.addWidget(self.selection_label)

        self.refresh_btn.clicked.connect(self.refresh_requested.emit)
        self.upload_btn.clicked.connect(self._select_upload_file)
        self.download_btn.clicked.connect(self._emit_download_selected)
        self.delete_btn.clicked.connect(self._emit_delete_selected)
        self.file_list.currentRowChanged.connect(self._on_selection_changed)
        self._set_selection_enabled(False)

    def set_files(self, files: list[dict[str, Any]]) -> None:
        self._files = files
        self._file_by_row.clear()
        self.file_list.clear()
        self.summary_label.setText(t('files.count', '{count} files', count=len(files)))

        if not files:
            item = QListWidgetItem(t('files.none', 'No files in this room.'))
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.file_list.addItem(item)
            self.selection_label.setText(t('files.upload_hint', 'Upload a file to get started.'))
            self._set_selection_enabled(False)
            return

        for idx, file in enumerate(files):
            name = file.get('file_name') or file.get('file_path') or f"file_{file.get('id')}"
            uploader = file.get('uploader_name') or file.get('uploaded_by')
            ftype = file.get('file_type') or 'file'
            size = self._format_bytes(int(file.get('file_size') or 0))
            text = t(
                'files.item_format',
                '[{type}] {name}\nby {uploader} | {size}',
                type=ftype,
                name=name,
                uploader=uploader,
                size=size,
            )
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, file.get('id'))
            self.file_list.addItem(item)
            self._file_by_row[idx] = file

        self._set_selection_enabled(False)
        self.selection_label.setText(t('files.select_to_manage', 'Select a file to download or delete.'))

    def _selected_file(self) -> dict[str, Any] | None:
        return self._file_by_row.get(self.file_list.currentRow())

    def _select_upload_file(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(self, t('files.select_upload', 'Select file to upload'))
        if not selected:
            return
        self.upload_requested.emit(selected)

    def _emit_download_selected(self) -> None:
        file = self._selected_file()
        if not file:
            self.show_error(t('files.select_first', 'Select a file first.'))
            return
        self.download_requested.emit(file)

    def _emit_delete_selected(self) -> None:
        file = self._selected_file()
        if not file or not file.get('id'):
            self.show_error(t('files.select_first', 'Select a file first.'))
            return
        name = file.get('file_name') or f"file_{file.get('id')}"
        result = QMessageBox.question(
            self,
            t('files.delete_title', 'Delete File'),
            t('files.delete_confirm', 'Delete "{name}"?', name=name),
        )
        if result == QMessageBox.StandardButton.Yes:
            self.delete_requested.emit(int(file['id']))

    def _on_selection_changed(self, row: int) -> None:
        selected = self._file_by_row.get(row)
        if not selected:
            self._set_selection_enabled(False)
            self.selection_label.setText(t('files.select_action', 'Select a file to view actions.'))
            return

        self._set_selection_enabled(True)
        name = selected.get('file_name') or selected.get('file_path') or 'unknown'
        size = self._format_bytes(int(selected.get('file_size') or 0))
        self.selection_label.setText(t('files.selected', 'Selected: {name} ({size})', name=name, size=size))

    def _set_selection_enabled(self, enabled: bool) -> None:
        self.download_btn.setEnabled(enabled)
        self.delete_btn.setEnabled(enabled)

    def show_error(self, message: str) -> None:
        QMessageBox.critical(self, t('files.window_title', 'Files'), message)

    @staticmethod
    def _format_bytes(size: int) -> str:
        if size < 1024:
            return f'{size} B'
        if size < 1024 * 1024:
            return f'{size / 1024:.1f} KB'
        if size < 1024 * 1024 * 1024:
            return f'{size / (1024 * 1024):.1f} MB'
        return f'{size / (1024 * 1024 * 1024):.1f} GB'

    def retranslate_ui(self) -> None:
        self.setWindowTitle(t('files.window_title', 'Files'))
        self._title_label.setText(t('files.title', 'Room Files'))
        self._subtitle_label.setText(
            t('files.subtitle', 'Upload, review, download, and remove files in the current room.')
        )
        self.summary_label.setText(t('files.count', '{count} files', count=len(self._files)))
        self.refresh_btn.setText(t('common.refresh', 'Refresh'))
        self.upload_btn.setText(t('files.upload', 'Upload'))
        self.download_btn.setText(t('files.download', 'Download'))
        self.delete_btn.setText(t('files.delete', 'Delete'))
        if not self._file_by_row:
            self.selection_label.setText(t('files.select_action', 'Select a file to view actions.'))

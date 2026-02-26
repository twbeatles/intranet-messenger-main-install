# -*- coding: utf-8 -*-
"""
Poll management dialog.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QDateTime, Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDateTimeEdit,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from client.i18n import i18n_manager, t


class PollsDialog(QDialog):
    refresh_requested = Signal()
    create_requested = Signal(str, list, bool, bool, object)  # question, options, multiple_choice, anonymous, ends_at
    vote_requested = Signal(int, list)  # poll_id, option_ids
    close_requested = Signal(int)  # poll_id

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(900, 600)
        self.setObjectName("AppRoot")
        self._polls: list[dict[str, Any]] = []
        self._poll_by_row: dict[int, dict[str, Any]] = {}
        self._option_id_by_row: dict[int, int] = {}
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

        toolbar = QHBoxLayout()
        self.poll_count_label = QLabel('')
        self.poll_count_label.setProperty('muted', True)
        self.refresh_btn = QPushButton('')
        self.close_poll_btn = QPushButton('')
        self.close_poll_btn.setProperty('variant', 'danger')
        toolbar.addWidget(self.poll_count_label)
        toolbar.addStretch()
        toolbar.addWidget(self.refresh_btn)
        toolbar.addWidget(self.close_poll_btn)
        root.addLayout(toolbar)

        body = QHBoxLayout()
        body.setSpacing(10)

        left_card = QFrame()
        left_card.setProperty('card', True)
        left_layout = QVBoxLayout(left_card)
        left_layout.setContentsMargins(20, 20, 20, 20)
        left_layout.setSpacing(12)
        left_title = QLabel('')
        left_title.setProperty('section', True)
        self.poll_list = QListWidget()
        self.poll_list.setSpacing(4)
        left_layout.addWidget(left_title)
        left_layout.addWidget(self.poll_list)
        body.addWidget(left_card, 4)
        self._list_title_label = left_title

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)

        options_card = QFrame()
        options_card.setProperty('card', True)
        options_layout = QVBoxLayout(options_card)
        options_layout.setContentsMargins(20, 20, 20, 20)
        options_layout.setSpacing(12)
        options_title = QLabel('')
        options_title.setProperty('section', True)
        self.poll_meta_label = QLabel('')
        self.poll_meta_label.setProperty('muted', True)
        self.option_list = QListWidget()
        self.option_list.setSpacing(4)
        self.vote_btn = QPushButton('')
        self.vote_btn.setProperty('variant', 'primary')
        options_layout.addWidget(options_title)
        options_layout.addWidget(self.poll_meta_label)
        options_layout.addWidget(self.option_list)
        options_layout.addWidget(self.vote_btn)
        self._selected_title_label = options_title

        create_card = QFrame()
        create_card.setProperty('card', True)
        create_layout = QVBoxLayout(create_card)
        create_layout.setContentsMargins(20, 20, 20, 20)
        create_layout.setSpacing(12)
        create_title = QLabel('')
        create_title.setProperty('section', True)
        self._create_title_label = create_title

        self.question_input = QTextEdit()
        self.question_input.setFixedHeight(74)

        self.options_input = QTextEdit()
        self.options_input.setFixedHeight(126)

        flags = QHBoxLayout()
        self.multiple_choice_check = QCheckBox('')
        self.anonymous_check = QCheckBox('')
        self.ends_at_check = QCheckBox('')
        self.ends_at_input = QDateTimeEdit()
        self.ends_at_input.setCalendarPopup(True)
        self.ends_at_input.setDisplayFormat('yyyy-MM-dd HH:mm')
        self.ends_at_input.setDateTime(QDateTime.currentDateTime().addSecs(3600))
        self.ends_at_input.setEnabled(False)
        self.ends_at_check.toggled.connect(self.ends_at_input.setEnabled)
        flags.addWidget(self.multiple_choice_check)
        flags.addWidget(self.anonymous_check)
        flags.addWidget(self.ends_at_check)
        flags.addWidget(self.ends_at_input)
        flags.addStretch()

        self.create_btn = QPushButton('')
        self.create_btn.setProperty('variant', 'primary')
        self.form_hint = QLabel('')
        self.form_hint.setProperty('muted', True)

        create_layout.addWidget(create_title)
        create_layout.addWidget(self.question_input)
        create_layout.addWidget(self.options_input)
        create_layout.addLayout(flags)
        create_layout.addWidget(self.form_hint)
        create_layout.addWidget(self.create_btn)

        right_layout.addWidget(options_card, 3)
        right_layout.addWidget(create_card, 4)
        body.addWidget(right_panel, 6)
        root.addLayout(body)

        self.refresh_btn.clicked.connect(self.refresh_requested.emit)
        self.poll_list.currentRowChanged.connect(self._on_poll_selected)
        self.vote_btn.clicked.connect(self._emit_vote)
        self.create_btn.clicked.connect(self._emit_create)
        self.close_poll_btn.clicked.connect(self._emit_close_selected)
        self._update_action_state(has_poll=False, has_option=False)

    def set_polls(self, polls: list[dict[str, Any]]) -> None:
        self._polls = polls
        self._poll_by_row.clear()
        self.poll_list.clear()
        self.option_list.clear()
        self._option_id_by_row.clear()
        self.poll_meta_label.setText(t('polls.select_poll_first', 'Select a poll first.'))
        self.poll_count_label.setText(t('polls.count', '{count} polls', count=len(polls)))

        if not polls:
            item = QListWidgetItem(t('polls.none', 'No polls in this room.'))
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.poll_list.addItem(item)
            self._update_action_state(has_poll=False, has_option=False)
            return

        for idx, poll in enumerate(polls):
            closed = bool(poll.get('closed'))
            marker = f"[{t('polls.closed_short', 'Closed')}] " if closed else ''
            creator = poll.get('creator_name') or poll.get('created_by')
            voters = int(poll.get('total_voters') or 0)
            text = (
                f"{marker}{poll.get('question', '')}\n"
                + t('polls.by_voters', 'by {creator} | voters: {voters}', creator=creator, voters=voters)
            )
            self.poll_list.addItem(QListWidgetItem(text))
            self._poll_by_row[idx] = poll

        self._update_action_state(has_poll=True, has_option=False)

    def _on_poll_selected(self, row: int) -> None:
        self.option_list.clear()
        self._option_id_by_row.clear()
        poll = self._poll_by_row.get(row)
        if not poll:
            self.poll_meta_label.setText(t('polls.select_poll_first', 'Select a poll first.'))
            self._update_action_state(has_poll=False, has_option=False)
            return

        closed = bool(poll.get('closed'))
        creator = poll.get('creator_name') or poll.get('created_by')
        self.poll_meta_label.setText(
            t(
                'polls.meta',
                'Poll #{id} | by {creator} | {state}',
                id=poll.get('id'),
                creator=creator,
                state=t('polls.state.closed', 'closed') if closed else t('polls.state.open', 'open'),
            )
        )
        for idx, option in enumerate(poll.get('options', []) or []):
            text = t(
                'polls.option_votes',
                '{text} ({votes} votes)',
                text=option.get('option_text', ''),
                votes=option.get('vote_count', 0),
            )
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, option.get('id'))
            self.option_list.addItem(item)
            self._option_id_by_row[idx] = int(option.get('id'))

        if bool(poll.get('multiple_choice')):
            self.option_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        else:
            self.option_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self._update_action_state(has_poll=True, has_option=self.option_list.count() > 0)

    def _emit_vote(self) -> None:
        poll = self._poll_by_row.get(self.poll_list.currentRow())
        if not poll:
            self.show_error(t('polls.select_poll_first', 'Select a poll first.'))
            return
        selected_rows = []
        for item in self.option_list.selectedItems():
            row = self.option_list.row(item)
            selected_rows.append(row)
        option_ids = []
        for row in selected_rows:
            option_id = self._option_id_by_row.get(row)
            if option_id:
                option_ids.append(int(option_id))
        if not option_ids:
            self.show_error(t('polls.select_option_first', 'Select an option first.'))
            return
        if bool(poll.get('closed')):
            self.show_error(t('polls.already_closed', 'This poll is already closed.'))
            return
        self.vote_requested.emit(int(poll['id']), option_ids)

    def _emit_create(self) -> None:
        question = self.question_input.toPlainText().strip()
        options = [line.strip() for line in self.options_input.toPlainText().splitlines() if line.strip()]
        if not question:
            self.show_error(t('polls.question_required', 'Question is required.'))
            return
        if len(options) < 2:
            self.show_error(t('polls.options_required', 'At least two options are required.'))
            return
        self.create_requested.emit(
            question,
            options,
            self.multiple_choice_check.isChecked(),
            self.anonymous_check.isChecked(),
            self.ends_at_input.dateTime().toString(Qt.DateFormat.ISODate) if self.ends_at_check.isChecked() else None,
        )
        self.question_input.clear()
        self.options_input.clear()
        self.ends_at_check.setChecked(False)

    def _emit_close_selected(self) -> None:
        poll = self._poll_by_row.get(self.poll_list.currentRow())
        if not poll:
            self.show_error(t('polls.select_poll_first', 'Select a poll first.'))
            return
        if bool(poll.get('closed')):
            self.show_info(t('polls.already_closed', 'This poll is already closed.'))
            return
        result = QMessageBox.question(
            self,
            t('polls.close_title', 'Close Poll'),
            t('polls.close_confirm', 'Close the selected poll? Voting will be disabled.'),
        )
        if result == QMessageBox.StandardButton.Yes:
            self.close_requested.emit(int(poll['id']))

    def _update_action_state(self, has_poll: bool, has_option: bool) -> None:
        self.vote_btn.setEnabled(has_poll and has_option)
        self.close_poll_btn.setEnabled(has_poll)

    def show_error(self, message: str) -> None:
        QMessageBox.critical(self, t('polls.window_title', 'Polls'), message)

    def show_info(self, message: str) -> None:
        QMessageBox.information(self, t('polls.window_title', 'Polls'), message)

    def retranslate_ui(self) -> None:
        self.setWindowTitle(t('polls.window_title', 'Polls'))
        self._title_label.setText(t('polls.title', 'Room Polls'))
        self._subtitle_label.setText(
            t('polls.subtitle', 'Create quick decisions, vote, and close completed polls.')
        )
        self.poll_count_label.setText(t('polls.count', '{count} polls', count=len(self._polls)))
        self.refresh_btn.setText(t('common.refresh', 'Refresh'))
        self.close_poll_btn.setText(t('polls.close_selected', 'Close Selected'))
        self._list_title_label.setText(t('polls.list', 'Poll List'))
        self._selected_title_label.setText(t('polls.selected', 'Selected Poll'))
        self.vote_btn.setText(t('polls.vote_selected', 'Vote Selected Option'))
        self._create_title_label.setText(t('polls.create', 'Create New Poll'))
        self.question_input.setPlaceholderText(t('polls.question_placeholder', 'Question'))
        self.options_input.setPlaceholderText(t('polls.options_placeholder', 'Options (one per line)'))
        self.multiple_choice_check.setText(t('polls.multiple_choice', 'Multiple Choice'))
        self.anonymous_check.setText(t('polls.anonymous', 'Anonymous'))
        self.ends_at_check.setText(t('polls.ends_at_enabled', 'Use Deadline'))
        self.ends_at_input.setToolTip(t('polls.ends_at_hint', 'Set poll closing date and time'))
        self.create_btn.setText(t('polls.create_submit', 'Create Poll'))
        self.form_hint.setText(t('polls.options_required', 'At least two options are required.'))
        if not self._poll_by_row:
            self.poll_meta_label.setText(t('polls.select_poll_first', 'Select a poll first.'))

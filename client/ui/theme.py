# -*- coding: utf-8 -*-
"""
Shared visual theme for desktop messenger UI.
"""

from __future__ import annotations

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication


_BASE_STYLESHEET = """
/* ========================================================= */
/* 글로벌 & 윈도우 기본 폰트 설정
/* ========================================================= */
QWidget {
    color: #0f172a;  /* 더 진하고 또렷한 먹색 */
    font-family: "Pretendard", "Segoe UI Variable", "Segoe UI", "Malgun Gothic", sans-serif;
    font-size: 10.5pt;
    line-height: 1.5;
}

QMainWindow, QDialog, QWidget#AppRoot {
    background: #f1f5f9;  /* 은은한 매우 밝은 회색으로 세련됨 강조 */
}

/* ========================================================= */
/* 레이아웃 & 패널
/* ========================================================= */
QFrame[card="true"] {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 16px;
    /* Qt에서는 완전한 CSS Shadow가 어렵지만 주변 배경과 대비되어 card 형태가 됨 */
}

QFrame[sidebar="true"] {
    background: #f8fafc;
    border-right: 1px solid #e2e8f0;
    border-top-left-radius: 12px;
    border-bottom-left-radius: 12px;
}

QFrame[chatArea="true"] {
    background: #ffffff;
    border-top-right-radius: 12px;
    border-bottom-right-radius: 12px;
}

/* ========================================================= */
/* 메시지 버블
/* ========================================================= */
QFrame[messageOwn="true"] {
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-radius: 18px;
    border-bottom-right-radius: 4px;
}

QFrame[messageOwn="false"] {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 18px;
    border-bottom-left-radius: 4px;
}

/* ========================================================= */
/* 타이포그래피 태그 지정
/* ========================================================= */
QLabel[title="true"] {
    font-size: 22pt;
    font-weight: 800;
    color: #0f172a;
    letter-spacing: -0.5px;
}

QLabel[section="true"] {
    font-size: 14pt;
    font-weight: 700;
    color: #1e293b;
}

QLabel[subtitle="true"] {
    font-size: 11pt;
    color: #475569;
    font-weight: 500;
}

QLabel[muted="true"] {
    color: #64748b;
    font-size: 9.5pt;
}

QLabel[badge="true"] {
    background: #ef4444;
    color: #ffffff;
    font-weight: 700;
    font-size: 9pt;
    border-radius: 10px;
    padding: 2px 6px;
}

/* ========================================================= */
/* 입력 폼 & 목록
/* ========================================================= */
QLineEdit,
QTextEdit,
QListWidget {
    background: #ffffff;
    border: 1.5px solid #e2e8f0;
    border-radius: 10px;
    padding: 10px 14px;
    color: #1e293b;
    selection-background-color: #bfdbfe;
    selection-color: #0f172a;
}

QTextEdit {
    padding-top: 10px;
}

QLineEdit:focus,
QTextEdit:focus,
QListWidget:focus {
    border: 1.5px solid #3b82f6;  /* Blue 500 */
    background: #ffffff;
}

QLineEdit::placeholder,
QTextEdit::placeholder {
    color: #94a3b8;
}

QListWidget {
    background: transparent;
    border: none;
    outline: none;
}

QListWidget::item {
    border: none;
    border-radius: 10px;
    padding: 4px;
    margin-bottom: 4px;
}

QListWidget::item:hover {
    background: #f1f5f9;  /* Slate 100 */
}

QListWidget::item:selected {
    background: #e2e8f0;  /* Slate 200 */
    color: #0f172a;
}

/* ========================================================= */
/* 버튼
/* ========================================================= */
QPushButton {
    border-radius: 10px;
    border: 1px solid #cbd5e1;
    background: #ffffff;
    padding: 8px 18px;
    font-weight: 600;
    color: #334155;
    min-height: 32px;
}

QPushButton:hover {
    background: #f8fafc;
    border-color: #94a3b8;
}

QPushButton:pressed {
    background: #f1f5f9;
}

QPushButton:disabled {
    color: #94a3b8;
    border-color: #e2e8f0;
    background: #f8fafc;
}

/* Primary Button */
QPushButton[variant="primary"] {
    color: #ffffff;
    border: 1px solid #2563eb;
    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: 0 #3b82f6, stop: 1 #2563eb);
}

QPushButton[variant="primary"]:hover {
    border-color: #1d4ed8;
    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: 0 #2563eb, stop: 1 #1d4ed8);
}

QPushButton[variant="primary"]:pressed {
    background: #1e40af;
}

/* Danger Button */
QPushButton[variant="danger"] {
    color: #ef4444;
    border: 1px solid #fecaca;
    background: #ffffff;
}

QPushButton[variant="danger"]:hover {
    border-color: #f87171;
    background: #fef2f2;
}

/* ========================================================= */
/* 폼 요소 등
/* ========================================================= */
QCheckBox {
    spacing: 10px;
    color: #475569;
}

QCheckBox::indicator {
    width: 20px;
    height: 20px;
    border-radius: 6px;
    border: 1.5px solid #cbd5e1;
    background-color: #ffffff;
}

QCheckBox::indicator:hover {
    border-color: #94a3b8;
}

QCheckBox::indicator:checked {
    background-color: #3b82f6;
    border-color: #3b82f6;
    /* Qt 자체의 기본 아이콘 위에 색상을 씌우거나 커스텀을 주로 처리함 */
}

QSplitter::handle {
    background: #e2e8f0;
    width: 2px;
}

QScrollBar:vertical {
    border: none;
    background: transparent;
    width: 10px;
    margin: 4px 0px 4px 0px;
}

QScrollBar::handle:vertical {
    background: #cbd5e1;
    border-radius: 5px;
    min-height: 40px;
}

QScrollBar::handle:vertical:hover {
    background: #94a3b8;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    border: none;
    height: 0px;
}
"""


def apply_theme(app: QApplication) -> None:
    """Apply a unified palette and stylesheet for all PySide windows."""
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#f8fafc"))
    palette.setColor(QPalette.WindowText, QColor("#1e293b"))
    palette.setColor(QPalette.Base, QColor("#ffffff"))
    palette.setColor(QPalette.AlternateBase, QColor("#f8fafc"))
    palette.setColor(QPalette.Text, QColor("#1e293b"))
    palette.setColor(QPalette.Button, QColor("#ffffff"))
    palette.setColor(QPalette.ButtonText, QColor("#334155"))
    palette.setColor(QPalette.Highlight, QColor("#3b82f6"))
    palette.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)
    app.setStyleSheet(_BASE_STYLESHEET)

# -*- coding: utf-8 -*-
"""
Upload scanning provider abstraction.

Default provider is "noop" and keeps current behavior unchanged.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class UploadScanError(RuntimeError):
    pass


def _noop_scan(*args, **kwargs) -> tuple[bool, str]:
    return True, ''


def _provider_name() -> str:
    try:
        from flask import current_app

        return str(current_app.config.get('UPLOAD_SCAN_PROVIDER', 'noop') or 'noop').strip().lower()
    except Exception:
        return 'noop'


def _is_enabled() -> bool:
    try:
        from flask import current_app

        return bool(current_app.config.get('UPLOAD_SCAN_ENABLED', False))
    except Exception:
        return False


def scan_upload_stream(file_obj, *, filename: str = '', content_type: str = '') -> tuple[bool, str]:
    """
    Pre-save scanner hook.
    Returns (ok, reason).
    """
    if not _is_enabled():
        return True, ''

    provider = _provider_name()
    if provider == 'noop':
        return _noop_scan(file_obj, filename=filename, content_type=content_type)

    logger.warning(f"Unknown upload scan provider: {provider}")
    return False, '업로드 스캔 제공자가 구성되지 않았습니다.'


def scan_saved_file(full_path: str, *, filename: str = '', content_type: str = '') -> tuple[bool, str]:
    """
    Post-save scanner hook.
    Returns (ok, reason).
    """
    if not _is_enabled():
        return True, ''

    provider = _provider_name()
    if provider == 'noop':
        return _noop_scan(full_path, filename=filename, content_type=content_type)

    logger.warning(f"Unknown upload scan provider: {provider}")
    return False, '업로드 스캔 제공자가 구성되지 않았습니다.'

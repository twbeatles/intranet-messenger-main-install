# -*- coding: utf-8 -*-
"""
Desktop client update checker.
"""

from __future__ import annotations

from typing import Any

from client.services.api_client import APIClient


class UpdateChecker:
    def __init__(self, api_client: APIClient, current_version: str, channel_getter=None, metadata_verifier=None):
        self.api_client = api_client
        self.current_version = current_version
        self._channel_getter = channel_getter
        self._metadata_verifier = metadata_verifier

    def check(self) -> dict[str, Any]:
        channel = None
        if self._channel_getter:
            try:
                channel = str(self._channel_getter() or '').strip().lower()
            except Exception:
                channel = None
        payload = self.api_client.check_client_update(self.current_version, channel=channel)
        if callable(self._metadata_verifier):
            try:
                verified, reason = self._metadata_verifier(payload)
                payload['artifact_verified'] = bool(verified)
                if reason:
                    payload['artifact_verification_reason'] = str(reason)
            except Exception as exc:
                payload['artifact_verified'] = False
                payload['artifact_verification_reason'] = str(exc)
        return payload

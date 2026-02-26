# -*- coding: utf-8 -*-
"""
Persistent outbox storage for pending desktop sends.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any


class OutboxStore:
    def __init__(self, db_path: str | None = None):
        appdata = os.environ.get('APPDATA') or os.path.expanduser('~')
        base_dir = os.path.join(appdata, 'IntranetMessenger')
        os.makedirs(base_dir, exist_ok=True)
        self.db_path = db_path or os.path.join(base_dir, 'outbox.db')
        self._ensure_schema()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                '''
                CREATE TABLE IF NOT EXISTS outbox_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    server_url TEXT NOT NULL,
                    client_msg_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    last_attempt_at REAL NOT NULL DEFAULT 0,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    failed INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(user_id, server_url, client_msg_id)
                )
                '''
            )
            conn.execute(
                '''
                CREATE INDEX IF NOT EXISTS idx_outbox_messages_user_server
                ON outbox_messages(user_id, server_url, created_at)
                '''
            )
            conn.commit()
        finally:
            conn.close()

    def upsert(
        self,
        *,
        user_id: int,
        server_url: str,
        client_msg_id: str,
        payload: dict[str, Any],
        created_at: float | None = None,
        last_attempt_at: float = 0.0,
        retry_count: int = 0,
        failed: bool = False,
    ) -> None:
        conn = self._connect()
        try:
            conn.execute(
                '''
                INSERT INTO outbox_messages (
                    user_id, server_url, client_msg_id, payload_json,
                    created_at, last_attempt_at, retry_count, failed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id, server_url, client_msg_id)
                DO UPDATE SET
                    payload_json = excluded.payload_json,
                    created_at = excluded.created_at,
                    last_attempt_at = excluded.last_attempt_at,
                    retry_count = excluded.retry_count,
                    failed = excluded.failed
                ''',
                (
                    int(user_id),
                    str(server_url or '').rstrip('/'),
                    str(client_msg_id or ''),
                    json.dumps(payload or {}, ensure_ascii=False),
                    float(created_at if created_at is not None else time.time()),
                    float(last_attempt_at or 0.0),
                    int(retry_count or 0),
                    1 if failed else 0,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def remove(self, *, user_id: int, server_url: str, client_msg_id: str) -> None:
        conn = self._connect()
        try:
            conn.execute(
                '''
                DELETE FROM outbox_messages
                WHERE user_id = ? AND server_url = ? AND client_msg_id = ?
                ''',
                (int(user_id), str(server_url or '').rstrip('/'), str(client_msg_id or '')),
            )
            conn.commit()
        finally:
            conn.close()

    def clear(self, *, user_id: int | None = None, server_url: str | None = None) -> None:
        conn = self._connect()
        try:
            if user_id is None and server_url is None:
                conn.execute('DELETE FROM outbox_messages')
            elif user_id is not None and server_url is None:
                conn.execute('DELETE FROM outbox_messages WHERE user_id = ?', (int(user_id),))
            elif user_id is None and server_url is not None:
                conn.execute(
                    'DELETE FROM outbox_messages WHERE server_url = ?',
                    (str(server_url or '').rstrip('/'),),
                )
            else:
                conn.execute(
                    'DELETE FROM outbox_messages WHERE user_id = ? AND server_url = ?',
                    (int(user_id), str(server_url or '').rstrip('/')),
                )
            conn.commit()
        finally:
            conn.close()

    def list_entries(self, *, user_id: int, server_url: str) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT client_msg_id, payload_json, created_at, last_attempt_at, retry_count, failed
                FROM outbox_messages
                WHERE user_id = ? AND server_url = ?
                ORDER BY created_at ASC
                ''',
                (int(user_id), str(server_url or '').rstrip('/')),
            )
            rows = cursor.fetchall()
            entries: list[dict[str, Any]] = []
            for row in rows:
                try:
                    payload = json.loads(row['payload_json'])
                except Exception:
                    payload = {}
                entries.append(
                    {
                        'client_msg_id': str(row['client_msg_id']),
                        'payload': payload if isinstance(payload, dict) else {},
                        'created_at': float(row['created_at'] or 0),
                        'last_attempt_at': float(row['last_attempt_at'] or 0),
                        'retry_count': int(row['retry_count'] or 0),
                        'failed': bool(row['failed']),
                    }
                )
            return entries
        finally:
            conn.close()

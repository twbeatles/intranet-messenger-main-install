# -*- coding: utf-8 -*-

from __future__ import annotations


class _Cursor:
    def __init__(self, *, should_fail: bool = False):
        self.should_fail = should_fail
        self.execute_calls = 0

    def execute(self, _sql):
        self.execute_calls += 1
        if self.should_fail:
            raise RuntimeError('fts unavailable')
        return self

    def fetchone(self):
        return (1,)


def test_fts_probe_cache_reuses_recent_success():
    import app.models.messages as messages

    messages._fts5_probe_state['available'] = None
    messages._fts5_probe_state['checked_at'] = 0.0

    cursor = _Cursor(should_fail=False)
    assert messages._fts5_available(cursor) is True
    assert messages._fts5_available(cursor) is True
    assert cursor.execute_calls == 1


def test_fts_probe_cache_reuses_recent_failure():
    import app.models.messages as messages

    messages._fts5_probe_state['available'] = None
    messages._fts5_probe_state['checked_at'] = 0.0

    cursor = _Cursor(should_fail=True)
    assert messages._fts5_available(cursor) is False
    assert messages._fts5_available(cursor) is False
    assert cursor.execute_calls == 1

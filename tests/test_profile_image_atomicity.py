# -*- coding: utf-8 -*-

from __future__ import annotations

import io
import os
import time
from pathlib import Path


def _register(client, username: str, password: str = 'Password123!') -> None:
    response = client.post(
        '/api/register',
        json={
            'username': username,
            'password': password,
            'nickname': username,
        },
    )
    assert response.status_code == 200


def _login(client, username: str, password: str = 'Password123!') -> None:
    response = client.post('/api/login', json={'username': username, 'password': password})
    assert response.status_code == 200


def _png_bytes() -> bytes:
    return b'\x89PNG\r\n\x1a\n' + b'\x00' * 48


def _touch_old(path: Path, *, seconds_ago: int = 120) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_png_bytes())
    past = time.time() - max(1, int(seconds_ago))
    os.utime(path, (past, past))


def test_profile_image_upload_rolls_back_new_file_on_db_failure(app, monkeypatch):
    import app.routes as routes
    from app.models import get_user_by_id, update_user_profile
    from config import UPLOAD_FOLDER

    client = app.test_client()
    _register(client, 'profile_atomic_user')
    _login(client, 'profile_atomic_user')

    me = client.get('/api/me').json['user']
    user_id = int(me['id'])

    old_rel_path = 'profiles/old_profile.png'
    old_abs_path = Path(UPLOAD_FOLDER) / old_rel_path
    old_abs_path.parent.mkdir(parents=True, exist_ok=True)
    old_abs_path.write_bytes(_png_bytes())

    with app.app_context():
        assert update_user_profile(user_id, profile_image=old_rel_path)
        assert str(get_user_by_id(user_id).get('profile_image') or '') == old_rel_path

    monkeypatch.setattr(routes, 'update_user_profile', lambda *_args, **_kwargs: False)

    response = client.post(
        '/api/profile/image',
        data={'file': (io.BytesIO(_png_bytes()), 'new_profile.png')},
        content_type='multipart/form-data',
    )
    assert response.status_code == 500
    assert old_abs_path.exists()

    profile_dir = Path(UPLOAD_FOLDER) / 'profiles'
    files = sorted(p.name for p in profile_dir.iterdir() if p.is_file() and p.name != '.gitkeep')
    assert files == ['old_profile.png']

    with app.app_context():
        assert str(get_user_by_id(user_id).get('profile_image') or '') == old_rel_path


def test_cleanup_orphan_profile_files_keeps_tracked_profile_image(app):
    import app.upload_tokens as upload_tokens
    from app.models import update_user_profile, get_user_by_id
    from config import UPLOAD_FOLDER

    client = app.test_client()
    _register(client, 'profile_cleanup_user')
    _login(client, 'profile_cleanup_user')

    me = client.get('/api/me').json['user']
    user_id = int(me['id'])

    tracked_rel = 'profiles/tracked_profile.png'
    orphan_rel = 'profiles/orphan_profile.png'
    tracked_abs = Path(UPLOAD_FOLDER) / tracked_rel
    orphan_abs = Path(UPLOAD_FOLDER) / orphan_rel
    _touch_old(tracked_abs, seconds_ago=600)
    _touch_old(orphan_abs, seconds_ago=600)

    with app.app_context():
        assert update_user_profile(user_id, profile_image=tracked_rel)
        assert str(get_user_by_id(user_id).get('profile_image') or '') == tracked_rel

    removed = upload_tokens.cleanup_orphan_profile_files(grace_seconds=0)
    assert removed >= 1
    assert tracked_abs.exists()
    assert not orphan_abs.exists()

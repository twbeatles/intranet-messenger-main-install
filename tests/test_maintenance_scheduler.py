# -*- coding: utf-8 -*-


def test_run_maintenance_once_updates_status(app):
    from app.models import run_maintenance_once, get_maintenance_status

    with app.app_context():
        result = run_maintenance_once()
        status = get_maintenance_status()

    assert isinstance(result, dict)
    assert 'closed_polls' in result
    assert 'cleaned_access_logs' in result
    assert status.get('last_run_at')
    assert isinstance(status.get('last_results'), dict)

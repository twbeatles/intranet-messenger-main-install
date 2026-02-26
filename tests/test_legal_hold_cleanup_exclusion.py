# -*- coding: utf-8 -*-


def test_legal_hold_excludes_access_log_cleanup(app):
    from app.models import create_user, cleanup_old_access_logs, get_db

    with app.app_context():
        user_id = create_user('hold_user', 'Password123!', 'HoldUser')
        assert user_id

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO access_logs (user_id, action, ip_address, user_agent, created_at)
            VALUES (?, 'test', '127.0.0.1', 'pytest', '2000-01-01 00:00:00')
            ''',
            (int(user_id),),
        )
        held_log_id = int(cursor.lastrowid)

        cursor.execute(
            '''
            INSERT INTO access_logs (user_id, action, ip_address, user_agent, created_at)
            VALUES (?, 'test2', '127.0.0.1', 'pytest', '2000-01-01 00:00:00')
            ''',
            (int(user_id),),
        )
        removable_log_id = int(cursor.lastrowid)

        cursor.execute(
            '''
            INSERT INTO legal_holds (hold_type, target_id, active, reason)
            VALUES ('access_log', ?, 1, 'keep for audit')
            ''',
            (str(held_log_id),),
        )
        conn.commit()

        cleanup_old_access_logs(days_to_keep=0)

        conn2 = get_db()
        cur2 = conn2.cursor()
        cur2.execute('SELECT id FROM access_logs WHERE id = ?', (held_log_id,))
        assert cur2.fetchone() is not None
        cur2.execute('SELECT id FROM access_logs WHERE id = ?', (removable_log_id,))
        assert cur2.fetchone() is None

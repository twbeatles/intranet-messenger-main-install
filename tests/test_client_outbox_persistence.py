# -*- coding: utf-8 -*-

from client.services.outbox_store import OutboxStore


def test_outbox_store_persistence(tmp_path):
    db_path = str(tmp_path / 'outbox.db')
    store = OutboxStore(db_path=db_path)

    store.upsert(
        user_id=10,
        server_url='http://localhost:5000',
        client_msg_id='msg-1',
        payload={'room_id': 1, 'content': 'hello'},
        retry_count=1,
        failed=False,
    )
    store.upsert(
        user_id=10,
        server_url='http://localhost:5000',
        client_msg_id='msg-2',
        payload={'room_id': 1, 'content': 'world'},
        retry_count=2,
        failed=True,
    )

    loaded = store.list_entries(user_id=10, server_url='http://localhost:5000')
    assert len(loaded) == 2
    assert loaded[0]['client_msg_id'] == 'msg-1'
    assert loaded[1]['client_msg_id'] == 'msg-2'
    assert loaded[1]['failed'] is True

    store.remove(user_id=10, server_url='http://localhost:5000', client_msg_id='msg-1')
    loaded_after_remove = store.list_entries(user_id=10, server_url='http://localhost:5000')
    assert len(loaded_after_remove) == 1
    assert loaded_after_remove[0]['client_msg_id'] == 'msg-2'

    store.clear(user_id=10, server_url='http://localhost:5000')
    loaded_after_clear = store.list_entries(user_id=10, server_url='http://localhost:5000')
    assert loaded_after_clear == []

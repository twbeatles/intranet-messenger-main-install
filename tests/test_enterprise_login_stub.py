# -*- coding: utf-8 -*-


def test_enterprise_login_disabled_by_default(client):
    response = client.post('/api/auth/enterprise-login', json={'username': 'u', 'password': 'p'})
    assert response.status_code == 501


def test_enterprise_login_requires_provider_when_enabled(client):
    client.application.config['ENTERPRISE_AUTH_ENABLED'] = True
    client.application.config['ENTERPRISE_AUTH_PROVIDER'] = ''
    response = client.post('/api/auth/enterprise-login', json={'username': 'u', 'password': 'p'})
    assert response.status_code == 400


def test_enterprise_login_scaffold_response(client):
    client.application.config['ENTERPRISE_AUTH_ENABLED'] = True
    client.application.config['ENTERPRISE_AUTH_PROVIDER'] = 'ldap'
    response = client.post('/api/auth/enterprise-login', json={'username': 'u', 'password': 'p'})
    assert response.status_code == 501

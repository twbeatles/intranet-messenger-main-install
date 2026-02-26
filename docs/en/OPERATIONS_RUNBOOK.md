[Korean version](../ko/OPERATIONS_RUNBOOK.md)

# Operations Runbook

## 1) Server Startup Check

1. activate Python venv
2. run `python server.py --cli`
3. verify:
- `GET /api/client/update`
- `GET /api/system/health`
- sample login and message round-trip

## 2) Client Startup Check

1. run `python -m client.main --server-url http://<server>:5000`
2. sign in
3. close/restart app
4. verify auto-login restore via refresh

## 3) Incident Priority

1. Authentication issue
- verify `device_sessions` expiry/revoke state
- verify server NTP/time sync
- verify `flask_session/` permission and disk space

2. Realtime disconnect
- verify Socket.IO connectivity
- verify proxy/firewall WebSocket policy
- verify `ASYNC_MODE` and gevent installation

3. File transfer issue
- verify `upload_token` exists in `/api/upload` response
- verify token expiry
- verify `MAX_CONTENT_LENGTH` and allow-list extensions

## 4) Backup Policy

Must backup:
- `messenger.db`
- `uploads/`
- `.secret_key`
- `.security_salt`
- `.master_key`
- `config.py`

Backup verification script:
- `scripts/verify_backup_requirements.ps1`

Recommended frequency:
- daily full backup + 7-day retention
- extra manual snapshot before/after release

## 5) Logging/Monitoring

- server log file: `server.log` (rotation enabled)
- recommended metrics:
  - login success/failure ratio
  - concurrent socket connections
  - message throughput
  - file upload failure ratio
  - device session refresh failure ratio

## 6) Security Checklist

- verify `DESKTOP_ONLY_MODE` matches intent
- verify `DESKTOP_CLIENT_MIN_VERSION` matches actual deployment version
- re-validate unauthorized `/uploads` access blocking
- re-validate admin API authorization (`.../admins`)

## 7) Policy Switches (Defaults)

- `ENFORCE_HTTPS=False`: HTTPS is not forced (warnings are logged when not active)
- `ALLOW_SELF_REGISTER=True`: open self-registration allowed (can be disabled by policy)
- `REQUIRE_MESSAGE_ENCRYPTION=False`: plaintext text allowed (rejected when enforced)
- `SESSION_TOKEN_FAIL_OPEN=True`: fail-open when session-token DB check errors
- `MAINTENANCE_INTERVAL_MINUTES=30`: cleanup scheduler interval
- `RATE_LIMIT_STORAGE_URI=memory://`: in-memory rate-limit backend
- `RATE_LIMIT_KEY_MODE=ip`: IP-based rate-limit key strategy
- `UPLOAD_SCAN_ENABLED=False`, `UPLOAD_SCAN_PROVIDER=noop`: upload-scan scaffold disabled by default

## 8) Recurring Maintenance

- cleanup expired/revoked `device_sessions`
- cleanup stale uploads by policy
- performance checks for high-volume rooms (100k+ messages)

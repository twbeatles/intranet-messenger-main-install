[Korean version](../ko/API_SOCKET_CONTRACT.md)

# API / Socket Contract Summary

## Principles

- Keep existing REST/socket contracts and apply additive (non-breaking) extensions.
- Desktop migration changes are reflected through `device_sessions` APIs and client sync contracts.
- Error compatibility is preserved (`error`, `message` stay) while i18n metadata is added.

## Common Header / Locale Contract

- Request headers:
  - `X-App-Language`: supports `ko`, `ko-KR`, `en`, `en-US`
  - `Accept-Language`: fallback when `X-App-Language` is not provided
- API locale resolution priority:
  1. session preference
  2. `X-App-Language`
  3. `Accept-Language`
  4. default `ko-KR`
- Socket locale resolution priority:
  1. handshake query `lang`
  2. `X-App-Language`
  3. `Accept-Language`
  4. default `ko-KR`

## Error Schema (Backward Compatible)

1. HTTP API errors (`4xx/5xx`)
- Existing field kept: `error` (Korean canonical message)
- Added fields:
  - `error_code`
  - `error_localized`
  - `locale`
- Example:
```json
{
  "error": "로그인이 필요합니다.",
  "error_code": "AUTH_LOGIN_REQUIRED",
  "error_localized": "Login required.",
  "locale": "en-US"
}
```

2. Socket `error` event
- Existing field kept: `message` (Korean canonical message)
- Added fields:
  - `message_code`
  - `message_localized`
  - `locale`

## Auth / Session APIs

1. `POST /api/device-sessions`
- Request: `{ username, password, device_name, remember }`
- Response: `{ access_ok, device_token, expires_at, user, csrf_token, device_session_id, remember }`

2. `POST /api/device-sessions/refresh`
- Request: `{ device_token }` (or `X-Device-Token`)
- Response: `{ access_ok, device_token_rotated, expires_at, user, csrf_token, device_session_id, remember }`

3. `DELETE /api/device-sessions/current`
- revoke current device session

4. `GET /api/device-sessions`
- default: list only non-expired and non-revoked sessions for current user
- query: pass `include_expired=1|true|yes` to include expired sessions
- each session row includes `is_expired`

5. `DELETE /api/device-sessions/<id>`
- force logout a specific device session

## Update Policy API

- `GET /api/client/update`
- Query parameters:
  - `client_version` (optional)
  - `channel=stable|canary` (optional, default `stable`)
- Response:
  - `channel`, `desktop_only_mode`
  - `minimum_version`, `latest_version`
  - `download_url`, `release_notes_url`
  - optional metadata: `artifact_sha256`, `artifact_signature`, `signature_alg`
  - `update_available`, `force_update`

## Main REST APIs

- Auth: `/api/register`, `/api/login`, `/api/logout`, `/api/me`
- Enterprise auth (scaffold): `/api/auth/enterprise-login`
- Approval workflow (scaffold): `/api/admin/users/approve`
- Users: `/api/users`, `/api/users/online`, `/api/profile`
- Ops health: `/api/system/health`
- Rooms:
  - `/api/rooms` (GET/POST)
  - `/api/rooms/<room_id>/messages`
  - `/api/rooms/<room_id>/members` (POST)
  - `/api/rooms/<room_id>/members/<target_user_id>` (DELETE)
  - `/api/rooms/<room_id>/leave`
  - `/api/rooms/<room_id>/name`
  - `/api/rooms/<room_id>/info`
- Messages:
  - `/api/messages/<message_id>` (PUT/DELETE)
  - `/api/messages/<message_id>/reactions` (GET/POST)
- Search:
  - `/api/search`
  - `/api/search/advanced`
- Files:
  - `/api/upload`
  - `/uploads/<filename>`
  - `/api/rooms/<room_id>/files`
  - `/api/rooms/<room_id>/files/<file_id>`
- Polls:
  - `/api/rooms/<room_id>/polls`
  - `/api/polls/<poll_id>/vote`
  - `/api/polls/<poll_id>/close`
- Admin:
  - `/api/rooms/<room_id>/admins`
  - `/api/rooms/<room_id>/admin-check`

## File Upload Contract

1. Client uploads via `POST /api/upload`
2. Server returns `upload_token`, `file_name`, `file_path`, `file_type`
3. Client sends socket `send_message` with `upload_token`
4. Server validates token and stores/broadcasts file message

## Socket.IO Event Contract

### Client -> Server

- `subscribe_rooms`
- `join_room`
- `leave_room`
- `send_message`
- `message_read`
- `typing`
- `reaction_updated`
- `poll_updated`
- `poll_created`
- `pin_updated`
- `admin_updated`
- `edit_message`
- `delete_message`

### Server -> Client

- `new_message`
- `read_updated`
- `user_typing`
- `room_updated`
- `room_name_updated`
- `room_members_updated`
- `message_edited`
- `message_deleted`
- `reaction_updated`
- `poll_updated`
- `poll_created`
- `pin_updated`
- `admin_updated`
- `user_status`
- `error`

## `send_message` Detailed Contract

### Request payload

```json
{
  "room_id": 12,
  "content": "message or cipher text",
  "type": "text|file|image",
  "encrypted": true,
  "reply_to": 123,
  "upload_token": "optional-for-file",
  "client_msg_id": "optional-client-generated-id"
}
```

### Server validation

- reject unauthenticated socket connection/send
- reject client-originated `type=system` immediately (`system` is server-internal only)
- `reply_to` must reference a message in the same `room_id`
- `upload_token` required for file/image messages
- when `REQUIRE_MESSAGE_ENCRYPTION=True`, `type=text` requires `encrypted=true`
- reject invalid room access or malformed payload
- apply idempotency on `(room_id, sender_id, client_msg_id)` when `client_msg_id` exists

### ACK response (socket callback)

- success: `{ "ok": true, "message_id": 456 }`
- failure: `{ "ok": false, "error": "..." }`
- duplicate retry (same `client_msg_id`): return existing `message_id` with `ok=true`, without re-insert/re-broadcast

### `new_message` reflected field

- if request includes `client_msg_id`, broadcast payload includes the same value
- clients can match pending local messages with server-confirmed messages

## Socket Event Delivery Scope

- Global broadcast is not used as the default path; events are emitted to `room_{room_id}` and/or `user_{user_id}` targets.
- On socket `connect`, server joins `user_{user_id}` plus all membership rooms `room_{id}`.
- `room_updated` family events are sent only to related room members and direct target users.

## REST -> Socket Canonical Bridge

On successful REST operations, server emits canonical socket events directly (scoped to related rooms/users):

- `POST /api/rooms` -> `room_updated(action=room_created)` (to created member `user_{id}` targets)
- `POST /api/rooms/<room_id>/members` -> `room_members_updated`, `room_updated` (existing room + invited `user_{id}`)
- `POST /api/rooms/<room_id>/leave` -> `room_members_updated`, `room_updated` (existing room + leaving `user_{id}`)
- `DELETE /api/rooms/<room_id>/members/<target_user_id>` -> `room_members_updated`, `room_updated` (existing room + kicked `user_{id}`)
- `PUT /api/rooms/<room_id>/name` -> `room_name_updated`, `room_updated` (room only)
- `POST /api/rooms/<room_id>/pins` / `DELETE /api/rooms/<room_id>/pins/<pin_id>` -> `pin_updated`
- `POST /api/rooms/<room_id>/polls` -> `poll_created`
- `POST /api/polls/<poll_id>/vote` / `POST /api/polls/<poll_id>/close` -> `poll_updated`
- `POST /api/rooms/<room_id>/admins` -> `admin_updated`, `room_members_updated`

## Security Integrity Enhancements

- socket `connect` requires authenticated session
- `message_read` validates that `message_id` belongs to the given `room_id`
- `POST /api/rooms/<room_id>/leave` returns `403` for non-members and emits socket events only on actual membership removal
- reply JOIN in message queries is limited to same room (`rm.room_id = m.room_id`)

## Version Compatibility

- Encryption:
  - prefer `v2:salt:iv:cipher:hmac`
  - keep `v1` (`U2FsdGVkX...`) decrypt compatibility
- Server does not decrypt E2E plaintext; it stores/relays ciphertext only.

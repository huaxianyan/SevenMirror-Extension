# Transport Credential Rotation v1

Transport Credential Rotation v1 replaces one registered device's relay bearer credential without changing its workspace ID, device ID, device type, display name, or E2EE public key.

This protocol authorizes relay admission only. It does not establish E2EE trust, replace an approved-peer pin, or rotate an HPKE identity.

## Preconditions

- The endpoint is `POST /v1/devices/rotate` over HTTPS. Non-loopback cleartext is forbidden.
- Redirects are forbidden. A client MUST verify that the response endpoint is unchanged before treating any response as authoritative.
- A local administrator issued a short-lived, single-use rotation code bound to the exact workspace/device tuple.
- Before sending, the client generated a random 32-byte pending credential and durably retained both current and pending credentials.
- Rotation codes and credentials MUST NOT appear in URLs, query strings, logs, diagnostics, or `chrome.storage.sync`.

## Request

Content-Type is exactly `application/json` with these fields and no unknown or trailing data:

```json
{
  "workspace_id": "<canonical unpadded base64url, 16 bytes>",
  "device_id": "<canonical unpadded base64url, 16 bytes>",
  "current_auth_token": "<canonical unpadded base64url, 32 bytes>",
  "rotation_code": "<canonical unpadded base64url, 24 bytes>",
  "pending_auth_token": "<canonical unpadded base64url, 32 bytes>"
}
```

The pending credential MUST differ from the current credential. The server hashes both credentials immediately and clears temporary decoded byte buffers.

## Atomic server transition

In one database transaction the server MUST verify:

- the rotation code exists, is unexpired, unused, and bound to the exact workspace/device tuple;
- the device is not revoked;
- SHA-256 of `current_auth_token` equals the currently active credential hash;
- `pending_auth_token` differs from the current credential.

It then:

1. consumes the rotation code;
2. replaces `auth_token_hash` with SHA-256 of the pending credential;
3. increments the positive credential version exactly once;
4. commits all three changes atomically.

The server stores neither raw credential nor raw rotation code. Invalid, expired, consumed, concurrent, wrong-device, wrong-current, revoked, or same-token requests return one generic denial and do not consume a valid code on a failed attempt.

## Response

Success is HTTP `200`, `Content-Type: application/json`, with:

```json
{"status":"rotated"}
```

The response contains no credential or identifier. Errors do not reveal which proof failed.

## Recovery and promotion

A successful database commit immediately makes the pending credential active for new `SNA1` authentication and invalidates the old credential. The relay binds every authenticated session to the credential version returned by authentication. The running server revalidates connected versions and closes an old-version session with a fixed policy close after rotation.

The client MUST NOT delete its current credential merely because the HTTP request was locally sent or because HTTP `200` was received. It promotes pending and deletes current only after a WebSocket authenticated with pending receives exact `SNO1`.

If the request or response is lost:

- pending `SNA1` + `SNO1` proves the server committed rotation, so the client promotes pending;
- if pending authentication fails while current still authenticates, the client may retry the exact request with the same pending credential and rotation code;
- it MUST NOT generate another pending credential automatically for the same rotation attempt.

After server commit, replaying the old request fails generically because the code is consumed and the old credential is inactive. This is safe because the client already durably owns the pending credential.

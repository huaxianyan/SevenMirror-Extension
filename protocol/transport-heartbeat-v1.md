# Authenticated Transport Heartbeat v1

Status: provisional (`0.1.x-dev`)

The heartbeat keeps a Chrome MV3 extension service worker alive while an authenticated WebSocket is open and detects a relay connection that stopped producing observable browser events.

## Frames

Both frames are exactly four binary bytes:

- client request: ASCII `SNH1` (`53 4e 48 31`)
- server response: ASCII `SNH2` (`53 4e 48 32`)

## State machine

1. A client MUST NOT send `SNH1` before it has validated the server's `SNO1` authentication-success frame.
2. The relay recognizes `SNH1` only after transport authentication. It MUST answer on the same connection with one `SNH2` and MUST NOT route either heartbeat through the ciphertext hub.
3. A client MUST consume `SNH2` at the transport boundary. It MUST NOT pass a heartbeat to encrypted-envelope decoding or business reconciliation.
4. Chrome sends at most one outstanding heartbeat, every 20 seconds, and requires `SNH2` within 10 seconds. Missing or malformed responses close that connection and enter the existing bounded reconnect path.
5. Heartbeats contain no workspace, device ID, credential, key ID, cursor, operation ID, payload type, or encrypted business content.
6. Any other post-authentication binary data remains subject to canonical encrypted-envelope validation. Text frames remain forbidden.

The heartbeat proves only that the same authenticated relay socket answered recently. It does not acknowledge relay delivery, Android execution, Chrome reconciliation, action results, or general notification cursors.

# Encrypted Payload v1

Status: provisional Phase 0 protocol. The authoritative schema is
`proto/notification/v1/payload.proto`.

`EncryptedPayload` is protobuf-encoded and is passed as the HPKE plaintext. The
relay must never parse, log, persist, or otherwise inspect these bytes.

## Canonical encoding

Receivers MUST reject a plaintext unless all of the following hold:

1. its size is `1..524272` bytes (the Envelope v1 ciphertext limit minus the
   16-byte AES-GCM tag);
2. protobuf parsing succeeds;
3. no unknown fields occur at any message level;
4. `schema_version` is exactly `1`;
5. exactly one supported `body` is present;
6. every message-specific semantic constraint below holds; and
7. deterministic re-encoding produces exactly the received bytes.

The final check rejects duplicate fields, alternate field ordering and other
non-canonical wire encodings rather than relying on parser-specific behavior.
Protocol evolution must add an explicitly supported schema version before new
fields are emitted.

## `action_invoke`

An action invocation contains only opaque local identifiers. Android resolves
`notification_id` and `action_id` against its local notification/action table;
a `PendingIntent`, `RemoteInput`, package-private token, or other executable
capability is never serialized.

Constraints:

- `notification_id`: valid UTF-8, 1..512 encoded bytes;
- `notification_revision`: `1..2^63-1`;
- `action_id`: exactly 16 bytes;
- `idempotency_key`: exactly 16 bytes and not all zero;
- `reply_text`: absent for ordinary actions; when present, valid UTF-8 and
  1..4000 encoded bytes.

The source Android must validate the current notification revision and atomically
record `idempotency_key` before invoking any local side effect. Replay Ledger
acceptance happens before payload parsing; operation idempotency is a separate,
longer-lived guard against a logically duplicated request with a new envelope
message ID.

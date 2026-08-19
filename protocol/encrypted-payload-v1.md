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
4. `schema_version` matches the body: version `1` for `action_invoke`,
   `action_result`, or `action_result_ack`; version `2` for the E2EE identity
   lifecycle bodies defined by `e2ee-identity-key-transition-v1.md`; or version
   `3` for `notification_upsert`, `notification_removed`, and
   `notification_snapshot_manifest`;
5. exactly one supported `body` is present;
6. every message-specific semantic constraint below or in the identity
   lifecycle specification holds; and
7. deterministic re-encoding produces exactly the received bytes.

The final check rejects duplicate fields, alternate field ordering and other
non-canonical wire encodings rather than relying on parser-specific behavior.
Protocol evolution must add an explicitly supported schema version before new
fields are emitted. A body is accepted only under its version above; schema
versions are not interchangeable.

## Notification identity and revisions

The notification business key is `(authenticated sourceDeviceId,
notification_id)`. `sourceDeviceId` comes exclusively from the authenticated
envelope routing header and is therefore not duplicated inside the encrypted
payload. Receivers MUST NOT key notifications by `notification_id` alone.

For the per-item notification bodies and each snapshot entry:

- `notification_id`: valid UTF-8, 1..512 encoded bytes;
- `notification_revision`: `1..2^63-1`.

Android allocates revisions from one durable, source-wide monotonic counter. A
receiver stores the greatest accepted revision for each business key. A body
with a lower revision is stale and cannot change visible state. Repeating the
same revision and same state is idempotent; assigning different semantics to an
already accepted revision is invalid application behavior and MUST NOT roll
state backward. Envelope replay protection remains a separate security guard.

## `notification_upsert`

`notification_upsert` carries the current text state of one notification. At
least one of `title` and `body` MUST be present. When present:

- `title`: valid UTF-8, 1..512 encoded bytes;
- `body`: valid UTF-8, 1..4000 encoded bytes.

The internal alpha sends only application-owned synthetic notification text.
It does not send icons, avatars, rich media, action capabilities, package-private
tokens, or third-party notification content.

## `notification_removed`

`notification_removed` declares the notification absent at its revision. A
receiver retains this revision even after closing the visible notification so
a delayed older `notification_upsert` cannot resurrect it. This per-item state rule does not define a relay cursor, delivery
acknowledgement, or offline queue.

## `notification_snapshot_manifest`

A snapshot manifest declares the complete active notification set for its
authenticated Android source at `high_water_revision`. The source device ID is
again taken only from the authenticated routing header. The manifest contains
no title, body, action, media, or executable capability.

Constraints:

- `high_water_revision`: `0..2^63-1`; zero is valid only for an empty manifest
  from a source that has not allocated a notification revision;
- `active_notifications`: `0..200` entries;
- every entry contains a valid `notification_id` and a
  `notification_revision` in `1..high_water_revision`;
- entries are unique and strictly ascending by the unsigned lexicographic order
  of their UTF-8 `notification_id` bytes.

The sender captures one internally consistent active set and high-water mark.
It sends a current `notification_upsert` for each active entry, in the same
entry order, before sending the manifest in a separate fresh encrypted
envelope. If transport fails before the manifest is accepted, the sender retries
the complete sequence after reconnect; the relay does not retain or interpret
the snapshot.

The receiver durably reconciles one source device atomically:

1. a missing entry or a locally older entry means its preceding upsert was not
   durably observed, so the manifest fails closed and performs no deletion;
2. an entry at the same revision must be locally active; a locally newer state
   wins and is not rolled back;
3. a locally active item absent from the manifest is converted to a removed
   tombstone at `high_water_revision` only when its current revision is strictly
   lower than that high-water mark;
4. an absent active item already at `high_water_revision` conflicts with the
   supposedly complete manifest and fails closed;
5. a manifest below the greatest accepted source snapshot high-water mark is
   stale; repeating the same high-water mark is valid only with byte-identical
   canonical manifest content.

Snapshot-derived closes are programmatic reconciliation and MUST NOT emit a
user-dismiss operation. Snapshot business reconciliation is independent from
envelope replay tuples. This mechanism is not a relay cursor, per-delivery ACK,
history queue, or proof that a system notification was visibly presented.

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

## `action_result`

An action result reports only what the source Android observed while invoking the
local notification capability. `SUCCEEDED` means `PendingIntent.send()` returned
without a local error; it does not claim that a third-party remote service
completed the corresponding business operation.

Constraints:

- `idempotency_key`: the same non-zero 16-byte value from `action_invoke`;
- `status`: one defined value other than `UNSPECIFIED`;
- `detail`: absent by default; when present, valid UTF-8 and 1..256 encoded bytes.

Android stores the canonical result bytes with the operation tuple before
sending them. A duplicate request returns the stored result without invoking the
notification action again. If the operation tuple exists without a stored result
(for example, a process crash around the side effect), Android returns
`OUTCOME_UNKNOWN` and MUST NOT retry the side effect automatically.

## `action_result_ack`

An action-result acknowledgement proves only that the authenticated Chrome
recipient durably reconciled one exact canonical `action_result`. It does not
acknowledge Android execution before Chrome persistence, and it does not create
an acknowledgement-of-acknowledgement chain.

Constraints:

- `idempotency_key`: the same non-zero 16-byte value from `action_invoke` and
  `action_result`;
- `result_sha256`: exactly 32 bytes, not all zero, and equal to SHA-256 over the
  complete canonical encoded `EncryptedPayload` whose body is the acknowledged
  `action_result`.

Chrome MUST atomically persist terminal result reconciliation and an ACK intent
before sending this body. Android MUST authenticate the ACK sender, resolve the
completed operation by `(sender_key_id, idempotency_key)`, recompute the digest
from its exact stored canonical result bytes, and require a constant-time match
before deleting the corresponding recipient-bound result-outbox entry. A wrong
sender, digest, operation binding, or approved-peer state fails closed. A valid
duplicate ACK is idempotent even when the outbox entry was already deleted.

ACK delivery itself has no ACK. Chrome retains a bounded durable ACK intent and
may retry it or reactivate it when another identical result arrives. General
relay stream cursors remain a separate protocol concern and MUST NOT be inferred
from this per-operation acknowledgement.

## E2EE identity lifecycle bodies

`identity_key_transition`, `identity_key_transition_ack`, and
`identity_key_transition_commit` use `schema_version = 2`. Their field limits,
key/digest bindings, envelope requirements, durable state transitions, and
lost-key boundary are defined in `e2ee-identity-key-transition-v1.md`.

The canonical payload decoder validates non-zero fixed-width identifiers,
P-256 point encoding, `SHA-256(new_public_key) == new_key_id`, distinct old/new
key IDs, digest lengths, unknown fields, and deterministic wire bytes. The
stateful receiver must additionally bind the authenticated envelope tuple and
constant-time exact transition/ACK digests before changing trust state.

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
4. `schema_version` matches the body: version `2` for `action_invoke`,
   `action_result`, `action_result_ack`, and the E2EE identity lifecycle bodies
   defined by `e2ee-identity-key-transition-v1.md`; or version `7` for
   `notification_upsert`, `notification_removed`,
   `notification_snapshot_manifest`, and `notification_snapshot_request`;
5. exactly one supported `body` is present;
6. every message-specific semantic constraint below or in the identity
   lifecycle specification holds; and
7. deterministic re-encoding produces exactly the received bytes.

The final check rejects duplicate fields, alternate field ordering and other
non-canonical wire encodings rather than relying on parser-specific behavior.
Protocol evolution must add an explicitly supported schema version before new
fields are emitted. Current encoders emit action bodies only under version `2`.
Decoders additionally accept canonical version-`1` `action_invoke`,
`action_result`, and `action_result_ack` bytes that were durably persisted by
an earlier client. This compatibility is decode-only: a version-`1`
`action_invoke` MUST use a 16-byte `action_id`, MUST NOT select dismissal, and
MUST satisfy the original reply constraints. All other bodies are accepted only
under their version above; schema versions are not interchangeable.

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

`notification_upsert` carries the bounded display state of one notification.
Every upsert identifies the source application inside the same E2EE plaintext:

- `source_application_id`: stable Android package name, valid UTF-8, 1..255 encoded bytes;
- `source_application_name`: user-visible Android application label, valid UTF-8, 1..512 encoded bytes.

The application ID is used only for local filtering and shortcut-rule scope. The
application name is source application data and is displayed without translation.
Neither value appears in the authenticated routing header or relay metadata, and a
receiver MUST NOT infer either value from the opaque `notification_id`.

At least one of `title` and `body` MUST be present. When present:

- `title`: valid UTF-8, 1..512 encoded bytes;
- `body`: valid UTF-8, 1..4000 encoded bytes.

`app_icon` and `avatar` are independently optional, with at most one instance
of each. Every present `NotificationMedia` MUST satisfy all of the following:

- `content_sha256`: exactly SHA-256 of `encoded_bytes`;
- `mime_type`: `PNG` or `WEBP`, never unspecified;
- `width` and `height`: each `1..256`;
- `encoded_bytes`: `1..131072` bytes;
- PNG bytes begin with the exact eight-byte PNG signature;
- WebP bytes contain exact `RIFF` and `WEBP` signatures in the standard
  positions.

These checks establish a bounded canonical transport object; a receiver MUST
still decode the image in a bounded platform decoder and verify that the actual
decoded dimensions equal the declared dimensions before presentation. Decode
failure or dimension mismatch omits that media and uses the local default icon
without suppressing valid notification text. Receivers MUST NOT resolve a
resource identifier, content URI, file path or external URL from media bytes.
The avatar is preferred for the single image position exposed by
`chrome.notifications`; the app icon is the fallback.

`actions` preserves the source notification's display order and contains at
most 16 entries. Every `NotificationActionDescriptor` satisfies:

- `action_id`: exactly 16 opaque bytes and unique within this upsert;
- `title`: valid UTF-8, 1..256 encoded bytes, preserved as source application data;
- `requires_text_input`: true when Android requires one or more local
  `RemoteInput` values before invoking the action;
- `allows_free_form_input`: true only when `requires_text_input` is also true
  and at least one local input accepts free-form text.

The descriptor does not contain a `PendingIntent`, `RemoteInput`, result key,
choice value, resource identifier or other executable capability. Chrome may
show fewer actions than the payload carries because `chrome.notifications` has
platform-specific button limits. It MUST bind every shown button to the exact
notification revision and opaque `action_id`; unsupported text-input actions
remain unavailable rather than being invoked without required input.

When `contains_content_image` is true, `body` MUST contain the exact `[图片]`
placeholder. The original body image, URI and encoded bytes are forbidden from
this field; only normalized app icon and avatar media may be present. A literal
`[图片]` in source text is not sufficient to infer the flag when the sender did
not observe content media.

Media is part of the same deterministic notification plaintext and therefore
receives a separate Auth HPKE ciphertext for every recipient. The relay may
observe bounded ciphertext size and timing but cannot read media type, hash,
dimensions or bytes.

The internal alpha continues to send only application-owned synthetic
notifications. Only bounded action descriptors enter this payload; executable
capabilities, package-private tokens and third-party notification content remain
outside this slice.

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

- `recovery_request_id`: absent for an ordinary reconnect snapshot; when present,
  exactly 16 non-zero bytes copied from the authenticated recovery request;
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
envelope. Ordinary reconnect snapshots use explicit durable submission. A
recovery response bound to `recovery_request_id` is sent online-only so it can
cross an unresolved recipient history gap. If that response is interrupted,
Chrome retries the request with the same persisted recovery ID and Android sends
a fresh complete sequence. The relay never interprets snapshot plaintext.

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

## `notification_snapshot_request`

After `SNR1`, Chrome creates one fresh non-zero 16-byte `recovery_request_id`
for the persisted recovery session and sends a separately Auth HPKE-encrypted
request to every active authority-certified Android notification source. The
request contains:

- `recovery_request_id`: exactly 16 non-zero bytes;
- `reset_high_water_delivery_id`: `0..2^63-1`, equal to the persisted `SNR1`
  high-water for this recovery session.

The request contains no notification identifiers or content. It is safe for
durable relay submission, but its response is a complete snapshot sequence sent
online-only so it can be processed while the recipient cursor remains behind the
unavailable history. Android MUST authenticate the requesting Chrome certificate
and its notification-receiver role before responding. It sends current upserts
first and a manifest carrying the exact `recovery_request_id` last.

Chrome accepts a source as recovered only after durable reconciliation of that
source's matching manifest. A stale, unknown, or differently bound request ID
cannot complete recovery. After every active source captured in the persisted
recovery session has completed, Chrome atomically advances its relay cursor to
the `SNR1` high-water, clears the recovery session, and sends `SNC1` with that
cursor. A crash before sending `SNC1` is recovered by the normal connection
resume. Missing or revoked sources require a refreshed authority roster; they
must not be silently ignored from an existing recovery session.

## `action_invoke`

An action invocation contains only opaque local identifiers and selects exactly
one operation. A source action sets a 16-byte `action_id` and may include
`reply_text`. A SevenMirror-owned notification dismissal sets
`dismiss_notification = true` and MUST omit both `action_id` and `reply_text`.
A `PendingIntent`, `RemoteInput`, package-private token, or other executable
capability is never serialized.

Constraints:

- `notification_id`: valid UTF-8, 1..512 encoded bytes;
- `notification_revision`: `1..2^63-1`;
- `idempotency_key`: exactly 16 bytes and not all zero;
- source action: `action_id` is exactly 16 bytes and `dismiss_notification` is
  false;
- dismissal: `dismiss_notification` is true and `action_id` is empty;
- `reply_text`: absent for ordinary actions and dismissal; when present for a
  source action, valid UTF-8 and 1..4000 encoded bytes.

The source Android must validate the current notification revision and atomically
record `idempotency_key` before invoking any local side effect. A dismissal is
not a source-application action: Android requests `cancelNotification(key)` and
waits for the notification listener's authoritative removal callback. A
`SUCCEEDED` action result means only that the local dismissal request was
accepted; `notification_removed` remains the sole final lifecycle state.

Replay Ledger acceptance happens before payload parsing; operation idempotency
is a separate, longer-lived guard against a logically duplicated request with a
new envelope message ID.

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

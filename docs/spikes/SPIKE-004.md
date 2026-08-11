# SPIKE-004: Authenticated HPKE interoperability

Status: cryptographic core and real Chrome IndexedDB persistence validated

## Implementation

`src/crypto/auth-hpke.ts` wraps `@hpke/core` 1.9.0 with the suite proposed in ADR-002:

```text
Auth mode
DHKEM(P-256, HKDF-SHA256)
HKDF-SHA256
AES-128-GCM
info = "SyncNotifications-E2EE-v1"
```

`src/crypto/indexeddb-identity-store.ts` generates a non-extractable WebCrypto P-256 identity and persists its `CryptoKeyPair` through IndexedDB structured clone without exporting the private key.

`src/crypto/replay-guard.ts` retains the in-memory policy model. `src/crypto/indexeddb-replay-ledger.ts` implements the production persistence boundary with one atomic IndexedDB read/write transaction keyed by the 32-byte sender key ID and 16-byte message ID. It purges expired entries, serializes concurrent attempts, rejects duplicates after store reconstruction, and fails closed instead of evicting live entries at capacity.

`src/protocol/routing-header.ts` implements the fixed 160-byte big-endian Routing Header v1 codec. The exact encoded bytes are HPKE AAD; business message type and notification/action fields remain encrypted.

`src/protocol/encrypted-envelope.ts` implements the bounded binary frame. `src/crypto/envelope-receiver.ts` validates recipient identity and expiry, authenticates HPKE with the original header bytes, and returns plaintext only after the replay tuple is atomically accepted.

`src/protocol/encrypted-payload.ts` strictly validates canonical protobuf `action.invoke` and `action.result` payloads. `src/crypto/action-envelope-sender.ts` durably registers pending correlation and exact canonical invoke bytes before constructing a per-recipient encrypted frame. `src/crypto/indexeddb-pending-action-store.ts` retains the idempotency-key/expected-Android/key-ID/canonical-operation-digest and delivery retry state across Worker restarts, preventing accidental reuse of one key for different action semantics. `src/crypto/indexeddb-outbound-sequence-store.ts` atomically allocates positive per-recipient routing sequences. `src/crypto/action-invoke-outbox.ts` sends only to a still-approved Android pin over a `SNO1`-authenticated socket, recreates each retry with a fresh envelope message ID/sequence but the same canonical operation and business idempotency key, and preserves unsent work across Worker reconstruction. `src/crypto/action-result-receiver.ts` authenticates and atomically reconciles returned results, which immediately excludes completed operations from outbound delivery.

`src/protocol/trusted-device-pairing.ts` implements the server-independent canonical offer/approval records and `sntrust1:` QR representation used by the approval workflow. It validates the complete P-256 point on-curve, non-zero identifiers/nonces, safe bounded timestamps, exact offer hash, distinct device/key pairs, canonical base64url, and the transcript-derived 60-bit safety code. Decoding or scanning does not write `IndexedDbTrustedPeerStore`; explicit confirmation remains a separate required step.

`src/crypto/indexeddb-trust-pairing-session-store.ts` persists exactly one active offerer or approver transcript and refuses silent replacement. `trust-pairing-coordinator.ts` binds every session to the current local workspace/device/public key, restores it after Worker reconstruction, rejects expired/cross-workspace/self-pairing input, requires the caller to explicitly confirm the exact active safety code, and only then writes the immutable peer pin. It removes the exact session after pinning; if removal is interrupted, retry converges through `already-pinned` without key replacement.

`src/transport` now matches the Go `SNA1`/`SNO1` vector, performs bounded strict code-gated registration without credentials or referrers, stores the raw WebSocket credential only in extension-origin IndexedDB, refuses silent replacement, and sends `SNA1` as the first binary message. It consumes and validates fixed `SNO1` within five seconds before emitting the content-free `authenticated` diagnostic, so socket-open/local-enqueue is never presented as server acceptance. HTTPS is mandatory outside loopback, redirect/endpoint changes fail closed before credential disclosure, and diagnostics expose only fixed content-free state events.

The Options page now requests optional access only to the selected canonical server origin, creates/restores the non-extractable HPKE identity, consumes an administrator-issued code, and starts the Worker transport runtime after durable registration. Worker startup restores the credential only when its full SHA-256 identity key ID matches the existing HPKE public key; it never creates a replacement identity for partial state. The runtime reports `online` only after `SNO1` and clears its loaded raw token copy after constructing the first frame.

Inbound frames are serialized through `ActionResultDispatcher`. Before HPKE opening, it strictly decodes the bounded `SNE1` frame, checks workspace and recipient against the active credential, and resolves the exact sender device/key tuple only through `IndexedDbTrustedPeerStore`. That store accepts only valid P-256 points supplied by a separate approval workflow, is idempotent for the same pin, and refuses key replacement until explicit removal. An approved frame then passes through Auth HPKE, persistent replay consumption, canonical `action.result` validation, and pending-action reconciliation. Unknown pins or any asynchronous dispatch failure close the socket fail-closed. The durable approval core is connected to Options using the existing transport credential and non-extractable HPKE identity, with their SHA-256 key-ID relationship revalidated before every operation. Options supports offer creation, controlled `sntrust1:` payload copy/import, Worker-independent session restoration, full safety-code display, a mandatory explicit comparison checkbox, local approval, rejection/cancellation, and fail-closed recovery. Loaded transport-token copies are zeroed. Camera QR rendering/scanning is not implemented yet; textual payload exchange is only the controlled integration path for the upcoming synthetic relay test, and no server-provided entry is trusted automatically.

Network/socket termination now schedules one jittered exponential reconnect sequence bounded from 1 to 60 seconds. Duplicate `error`/`close` events for a connection generation cannot create duplicate retries, successful `SNO1` authentication resets the sequence, explicit lifecycle requests cancel stale timers, and persistent identity-binding failures do not retry. The production Worker backs the scheduler with named `chrome.alarms` one-shots so connection and 1/2/4/8-second action-delivery retries can wake an MV3 Worker after suspension; generation checks make obsolete in-memory callbacks harmless. `TransportRuntime.sendEnvelope` refuses every pre-`SNO1`, stale-generation, closed, or absent socket. Local encrypted-delivery corruption invokes `failClosed` and does not masquerade as a network retry.

## Evidence

- Chrome opens the Android-produced fixture.
- Android opens the deterministic Chrome-produced fixture.
- Deterministic key, encapsulation, and ciphertext bytes match the canonical vector.
- Sender substitution, AAD modification, and ciphertext modification fail.
- Non-extractable identity persistence/restore and authenticated HPKE use pass with IndexedDB unit coverage.
- Persistent replay reconstruction, concurrent duplicate attempts, expiry, capacity, and identifier validation pass with IndexedDB unit coverage.
- TypeScript matches the Go/Kotlin Routing Header v1 vector, rejects malformed fields, and proves that changing a routing byte breaks HPKE authentication.
- TypeScript matches the Encrypted Envelope v1 vector and rejects truncation, trailing bytes, bad magic, invalid points, and invalid ciphertext lengths.
- Receiver tests prove tampered HPKE ciphertext does not consume replay state, a valid frame is accepted once, and its repeat is rejected.
- TypeScript matches the canonical protobuf action payload, rejects unknown/duplicate/non-canonical and invalid semantic fields, round-trips `action.result`, and round-trips a generated authenticated action envelope without exposing notification ID or reply bytes in the frame.
- TypeScript matches Go/Kotlin's fixed Trusted Device Pairing v1 offer, approval, QR, and `4AFH-Q91K-PGVG` safety-code vector. Exact transcript mutation, wrong offer hash, invalid P-256 point, expired record, padded QR, and whitespace fail closed; no test path creates an approved-peer pin by scanning alone.
- Pairing coordinator tests reconstruct both offerer and approver stores, verify identical safety codes, prove a wrong confirmation leaves both the pin absent and the durable session present, then confirm each side independently and verify reciprocal immutable pins plus exact session removal. Cross-workspace and expired offers create no approver session. Approved-peer lookup now also recomputes the persisted public-key SHA-256 and validates the curve point before returning a pin, so corrupted key binding fails closed.
- Pending-operation tests cover persistence across reconstruction, concurrent registration, expected-sender binding, capacity exhaustion, identical result recovery, conflicting terminal results, exact canonical invoke persistence, bounded retry/dormancy, reactivation, and terminal-result delivery suppression.
- Action-invoke outbox tests prove persistence occurs before send, pre-`SNO1` transport send refusal, fresh persistent sequences for retries, exact idempotency-key recovery after reconstruction, runtime Auth HPKE opening by the pinned recipient identity, and pin removal preventing subsequent encryption.
- The action-result receive path performs HPKE/replay validation before persistent reconciliation; a new envelope carrying the same authenticated result is idempotent.
- Registration, credential reconstruction/replacement refusal, secure-origin validation, response bounds, `SNA1` codec, first-message ordering, and endpoint-change credential non-disclosure are covered.
- Type checking, 67 Vitest tests across 23 files, protocol verification, and the production build pass locally. GitHub Actions run `31508601050` independently passes all four gates for Options-wiring commit `42b7546`; actual two-device user confirmation remains separate blocking manual evidence.
- Popup exposes a browser-runtime persistence test; repeated runs retain the same fingerprint.

## Browser runtime evidence

Manual validation completed on 2026-08-06 using the unpacked production build
on Windows Chrome (exact browser version was not captured):

| Scenario | Public-key fingerprint | Private extractable | HPKE round trip | UTC time |
| --- | --- | --- | --- | --- |
| Initial run | `79692691f6d994b5c9a5e838f15cd1fd7e9fced991cfcbd33e0497513ba5b76c` | `false` | `true` | `2026-08-06T06:41:39.515Z` |
| After MV3 Worker termination | same | `false` | `true` | `2026-08-06T06:45:31.243Z` |
| After full Chrome restart | same | `false` | `true` | `2026-08-06T06:46:07.868Z` |

The unchanged SHA-256 public-key fingerprint proves that IndexedDB restored the
same non-extractable WebCrypto private identity rather than silently generating
a replacement.

Persistent replay-ledger validation completed on 2026-08-06:

| Scenario | Replay decision | Public-key fingerprint | UTC time |
| --- | --- | --- | --- |
| First authenticated tuple | `accepted` | `79692691f6d994b5c9a5e838f15cd1fd7e9fced991cfcbd33e0497513ba5b76c` | `2026-08-06T07:52:25.681Z` |
| Immediate repeat | `duplicate` | same | `2026-08-06T07:52:37.784Z` |
| After full Chrome restart | `duplicate` | same | `2026-08-06T07:53:34.190Z` |

Chrome did not expose a separately terminable Worker task during this run, so
an explicit Worker-only termination was not performed. A full browser exit
necessarily terminated the MV3 Worker and the subsequent `duplicate` decision
proves that the replay record was restored from IndexedDB rather than Worker
memory. All three runs also reported a non-extractable private key and a
successful HPKE round trip.

Authenticated transport runtime validation completed on 2026-08-07 with the
unpacked production build, the loopback test server, a dedicated SQLite test
registry, and synthetic registration data only. The user explicitly concluded
the test passed: registration reached `Online`, the Popup remained `Online`, and
a full Chrome restart increased the persisted `Worker starts observed` counter
to `16` while the authenticated connection recovered and stayed `Online`.
This is manual observation evidence, separate from the 48 automated tests; no
real notification content was transmitted.

Bounded reconnect validation completed on 2026-08-11 with the latest unpacked
production build, the same dedicated loopback registry, and no business frames.
The user observed the restored connection reach `Online`, then observed
`Offline` after the server stopped. The server remained unavailable for an
additional measured 35 seconds to cover MV3 Worker suspension before becoming
ready again. Without clicking connect/retry, reloading the extension, or opening
Options, the user then observed automatic recovery to `Online` within the
60-second maximum backoff window. This manual UI conclusion is recorded
separately from the 57 automated tests covering generation deduplication,
bounded delay, alarm wake handling, approved sender dispatch, replay, and
pending-result reconciliation.

Vendored vectors:

```text
protocol/test-vectors/hpke-auth-p256-aes128gcm.json
protocol/test-vectors/routing-header-v1.json
protocol/test-vectors/encrypted-payload-v1.json
protocol/test-vectors/encrypted-envelope-v1.json
protocol/test-vectors/trusted-device-pairing-v1.json
```

The authoritative copy and ADR-002 live in the server repository.

## Safety boundary

`SerializedHpkeKeyPair`, fixed IKM, and deterministic `ekm` are spike/test facilities. Production code now uses a non-extractable WebCrypto identity key plus persistent replay, trusted-peer-pin, pending-operation/delivery, and sequence stores in separate IndexedDB databases. The Popup runtime test records a fixed authenticated tuple once and must report `duplicate` after Worker/browser restart. A transport timeout leaves an operation pending and retries the exact operation under the same idempotency key; only Android's authenticated `OUTCOME_UNKNOWN` result marks the side effect as uncertain. Local WebSocket acceptance proves neither Android execution nor Chrome reconciliation. Chrome outbound `action.invoke` and Android inbound/result send are now individually wired, but real notification payloads remain blocked until approved-device provisioning and the complete synthetic relay loop are validated, end-to-end ACK/cursor semantics exist, pairing/rotation/revocation are complete, and the design passes security review.

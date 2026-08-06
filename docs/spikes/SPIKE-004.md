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

`src/protocol/encrypted-payload.ts` strictly validates canonical protobuf `action.invoke` and `action.result` payloads. `src/crypto/action-envelope-sender.ts` durably registers pending correlation before constructing a per-recipient encrypted frame. `src/crypto/indexeddb-pending-action-store.ts` retains the idempotency-key/expected-Android/canonical-operation-digest binding across Worker restarts, preventing accidental reuse of one key for different action semantics. `src/crypto/action-result-receiver.ts` authenticates and atomically reconciles returned results.

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
- Pending-operation tests cover persistence across reconstruction, concurrent registration, expected-sender binding, capacity exhaustion, identical result recovery, and conflicting terminal results.
- The action-result receive path performs HPKE/replay validation before persistent reconciliation; a new envelope carrying the same authenticated result is idempotent.
- Type checking, 33 Vitest tests, and production build pass.
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

Vendored vectors:

```text
protocol/test-vectors/hpke-auth-p256-aes128gcm.json
protocol/test-vectors/routing-header-v1.json
protocol/test-vectors/encrypted-payload-v1.json
protocol/test-vectors/encrypted-envelope-v1.json
```

The authoritative copy and ADR-002 live in the server repository.

## Safety boundary

`SerializedHpkeKeyPair`, fixed IKM, and deterministic `ekm` are spike/test facilities. Production code now uses a non-extractable WebCrypto identity key plus persistent replay and pending-operation stores in separate IndexedDB databases. The Popup runtime test records a fixed authenticated tuple once and must report `duplicate` after Worker/browser restart. A transport timeout leaves an operation pending; only Android's authenticated `OUTCOME_UNKNOWN` result marks the side effect as uncertain, and neither state permits automatic execution under a new idempotency key. Real notification payloads must not use this spike until the result sender/receiver are connected to an authenticated production WebSocket endpoint, pairing/rotation/revocation are complete, and the design passes security review.

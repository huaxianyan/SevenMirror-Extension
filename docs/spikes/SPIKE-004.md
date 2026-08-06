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

`src/crypto/replay-guard.ts` demonstrates bounded duplicate and expiry decisions. It is intentionally in-memory; production state must be atomic and persistent across MV3 worker restarts.

## Evidence

- Chrome opens the Android-produced fixture.
- Android opens the deterministic Chrome-produced fixture.
- Deterministic key, encapsulation, and ciphertext bytes match the canonical vector.
- Sender substitution, AAD modification, and ciphertext modification fail.
- Non-extractable identity persistence/restore and authenticated HPKE use pass with IndexedDB unit coverage.
- Type checking, 13 Vitest tests, and production build pass.
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

Vendored vector:

```text
protocol/test-vectors/hpke-auth-p256-aes128gcm.json
```

The authoritative copy and ADR-002 live in the server repository.

## Safety boundary

`SerializedHpkeKeyPair`, fixed IKM, and deterministic `ekm` are spike/test facilities. Production code now uses a non-extractable WebCrypto identity key stored as a `CryptoKey` in IndexedDB. Its fingerprint survives Worker termination and full browser restart. Real notification payloads must not use this spike until the persistent replay ledger, final envelope codec, pairing/rotation/revocation integration, and security review are complete.

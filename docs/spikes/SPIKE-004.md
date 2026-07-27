# SPIKE-004: Authenticated HPKE interoperability

Status: cryptographic core and IndexedDB persistence unit path validated; real Chrome restart test pending

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
- Popup exposes a browser-runtime persistence test; repeated runs must retain the same fingerprint.

Vendored vector:

```text
protocol/test-vectors/hpke-auth-p256-aes128gcm.json
```

The authoritative copy and ADR-002 live in the server repository.

## Safety boundary

`SerializedHpkeKeyPair`, fixed IKM, and deterministic `ekm` are spike/test facilities. Production code now uses a non-extractable WebCrypto identity key stored as a `CryptoKey` in IndexedDB. Real Chrome must still prove that the fingerprint survives Worker termination and full browser restart. Real notification payloads must not use this spike until that gate and the final envelope codec are complete.

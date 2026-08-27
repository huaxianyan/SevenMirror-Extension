# Vendored Protocol

This directory contains fixed copies of protocol material from the server repository.

- Schema version: see `PROTOCOL_VERSION`
- Upstream release/tag: see `UPSTREAM_REF`
- Schema integrity: see `SCHEMA_SHA256`

Run `npm run protocol:verify` after updating the schema. Do not edit the vendored `.proto` directly.

`test-vectors/` contains cross-platform fixtures. Private keys in those JSON fixtures are intentionally public test material and must never be used in production.

`routing-header-v1.md` and `test-vectors/routing-header-v1.json` are vendored copies of the provisional fixed-width HPKE AAD codec specification and canonical vector.

`encrypted-payload-v1.md`, `vendor/notification/v1/payload.proto`, and their vector define canonical encrypted action payloads, bounded source-application metadata and synthetic notification media, `notification_removed` payloads, and active snapshot manifests.

`e2ee-identity-key-transition-v1.md` and its vector define schema-v2 old-key transition, new-key-addressed peer ACK, new-key commit, durable dual-key state, and the lost-identity recovery boundary. `E2EE_IDENTITY_TRANSITION_SPEC_SHA256` and `E2EE_IDENTITY_TRANSITION_VECTOR_SHA256` pin these server-owned assets.

`encrypted-envelope-v1.md` and its vector define the bounded binary frame carrying the exact AAD, P-256 encapsulated key, and ciphertext. The canonical envelope plaintext is the payload vector.

`device-auth-frame-v1.md` and `test-vectors/device-auth-frame-v1.json` define the fixed 68-byte first WebSocket authentication message and fixed 4-byte `SNO1` server success acknowledgement. `DEVICE_AUTH_SPEC_SHA256` and `DEVICE_AUTH_VECTOR_SHA256` pin the server-owned copies. The fixture credential is public test material and must never be used for a real device.

`transport-heartbeat-v1.md` defines the post-authentication `SNH1`/`SNH2` liveness exchange consumed outside encrypted-envelope routing. `TRANSPORT_HEARTBEAT_SPEC_SHA256` pins the server-owned copy.

`transport-credential-rotation-v1.md` defines client-generated pending credentials, exact-device-bound administrator authorization, atomic server replacement, and `SNO1`-gated client promotion. `TRANSPORT_CREDENTIAL_ROTATION_SPEC_SHA256` pins the server-owned copy.

`workspace-membership-v1.md`, `vendor/membership/v1/membership.proto`, and their vector define ADR-005 identity-possession proof, authority-signed device certificates, monotonic signed rosters, roles, and revocation. `MEMBERSHIP_SCHEMA_SHA256`, `MEMBERSHIP_SPEC_SHA256`, and `MEMBERSHIP_VECTOR_SHA256` pin these assets.

`trusted-device-pairing-v1.md`, `e2ee-identity-key-transition-v1.md`, and their vectors are frozen historical SPIKE-004 artifacts. The extension has no runtime pairing or identity-transition implementation; Workspace Membership v1 is the only product trust source. These assets remain solely for protocol history and hash verification and must not be expanded.

After updating vendored schemas, regenerate committed TypeScript sources with the pinned configuration:

```sh
buf lint
buf generate
```

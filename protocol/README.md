# Vendored Protocol

This directory contains fixed copies of protocol material from the server repository.

- Schema version: see `PROTOCOL_VERSION`
- Upstream release/tag: see `UPSTREAM_REF`
- Schema integrity: see `SCHEMA_SHA256`

Run `npm run protocol:verify` after updating the schema. Do not edit the vendored `.proto` directly.

`test-vectors/` contains cross-platform fixtures. Private keys in those JSON fixtures are intentionally public test material and must never be used in production.

`routing-header-v1.md` and `test-vectors/routing-header-v1.json` are vendored copies of the provisional fixed-width HPKE AAD codec specification and canonical vector.

`encrypted-payload-v1.md`, `vendor/notification/v1/payload.proto`, and their vector define canonical encrypted `action.invoke`, `action.result`, and per-operation `action_result_ack` payloads.

`encrypted-envelope-v1.md` and its vector define the bounded binary frame carrying the exact AAD, P-256 encapsulated key, and ciphertext. The canonical envelope plaintext is the payload vector.

`device-auth-frame-v1.md` and `test-vectors/device-auth-frame-v1.json` define the fixed 68-byte first WebSocket authentication message and fixed 4-byte `SNO1` server success acknowledgement. `DEVICE_AUTH_SPEC_SHA256` and `DEVICE_AUTH_VECTOR_SHA256` pin the server-owned copies. The fixture credential is public test material and must never be used for a real device.

`transport-heartbeat-v1.md` defines the post-authentication `SNH1`/`SNH2` liveness exchange consumed outside encrypted-envelope routing. `TRANSPORT_HEARTBEAT_SPEC_SHA256` pins the server-owned copy.

`trusted-device-pairing-v1.md` and its vector define the server-independent canonical offer/approval QR transcript and 60-bit safety code required before writing immutable approved-peer pins. `TRUST_PAIRING_SPEC_SHA256` and `TRUST_PAIRING_VECTOR_SHA256` pin these assets. Scanning alone never establishes trust.

After updating vendored schemas, regenerate committed TypeScript sources with the pinned configuration:

```sh
buf lint
buf generate
```

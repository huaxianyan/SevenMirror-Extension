# Vendored Protocol

This directory contains fixed copies of protocol material from the server repository.

- Schema version: see `PROTOCOL_VERSION`
- Upstream release/tag: see `UPSTREAM_REF`
- Schema integrity: see `SCHEMA_SHA256`

Run `npm run verify:protocol` after updating the schema. Do not edit the vendored `.proto` directly.

`test-vectors/` contains cross-platform fixtures. Private keys in those JSON fixtures are intentionally public test material and must never be used in production.

`routing-header-v1.md` and `test-vectors/routing-header-v1.json` are vendored copies of the provisional fixed-width HPKE AAD codec specification and canonical vector.

# Notification Mirroring Chrome Extension

Manifest V3 extension for private, end-to-end encrypted Android notification mirroring. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SyncNotifications-Extension>

> Status: cryptographic, replay, pending-operation, strict registration, credential persistence, and authenticated WebSocket transport cores are implemented but not wired to production pairing UI or notification synchronization.

## Requirements

- Node.js 20 or newer
- npm
- Current stable Chrome

## Develop

```sh
npm install
npm test
npm run build
```

Load `dist/` as an unpacked extension from `chrome://extensions` after building.

## Current functionality

- MV3 service worker, Popup, and Options scaffolds
- Authenticated HPKE identity with non-extractable WebCrypto private key persistence
- Persistent replay and pending-action reconciliation ledgers
- Canonical encrypted action sender/result receiver
- Strict code-gated registration client and extension-origin-only transport credential store
- Device Auth Frame v1 and first-message authenticated WebSocket boundary
- Optional host permissions for explicit future pairing grants
- Provisional vendored protocol assets with SHA-256 verification

## Protocol

The server repository is the canonical protocol source. This repository vendors a fixed copy under `protocol/vendor` and records its version, upstream reference and SHA-256. Run:

```sh
node protocol/verify-schema.mjs
```

The current `0.1.0-dev` schema is unreleased and provisional.

## Security status

The transport core accepts only HTTPS origins outside loopback, never puts credentials in URLs or `chrome.storage.sync`, rejects silent credential replacement, and refuses to send the first authentication frame if the WebSocket endpoint changes. The bearer credential must remain available as bytes for the browser WebSocket API, so extension-origin IndexedDB and a minimal in-memory lifetime are the practical Chrome boundary; the HPKE private identity remains non-extractable.

Pairing UI, explicit optional-host permission requests, trusted-device E2EE approval, credential revocation/rotation, reconnect/offline convergence, and independent security review are still missing. No real notification content may use this transport yet.

## License

MIT

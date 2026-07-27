# Notification Mirroring Chrome Extension

Manifest V3 extension for private, end-to-end encrypted Android notification mirroring. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SyncNotifications-Extension>

> Status: foundation scaffold. Pairing, WebSocket and notification mirroring are not implemented yet.

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

- MV3 service worker scaffold
- Popup and options page scaffold
- Explicit local connection state
- Provisional vendored protocol schema with SHA-256 verification

## Protocol

The server repository is the canonical protocol source. This repository vendors a fixed copy under `protocol/vendor` and records its version, upstream reference and SHA-256. Run:

```sh
node protocol/verify-schema.mjs
```

The current `0.1.0-dev` schema is unreleased and provisional.

## Security status

No server address, credential, notification body or cryptographic key is handled yet. E2EE must be implemented before real notification synchronization is enabled. Sensitive state must never use Chrome Sync.

## License

MIT

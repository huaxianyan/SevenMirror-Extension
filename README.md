# Notification Mirroring Chrome Extension

Manifest V3 extension for private, end-to-end encrypted Android notification mirroring. This is one of three independent repositories.

Repository: <https://github.com/huaxianyan/SevenMirror-Extension>

> Status: cryptographic, replay, durable action invoke/result reconciliation, code-gated registration, Chrome recoverable credential rotation, textual trusted-device approval, and authenticated WebSocket lifecycle are implemented. Real notification synchronization remains disabled.

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

Load `dist/` as an unpacked extension from `chrome://extensions` after building. The Options page displays the current manifest version; user-visible extension iterations increment it so a reload can be verified.

Release-candidate ZIP provenance, offline verification, the Chrome Web Store signing boundary and monotonic-version rollback rules are documented in [`docs/release-provenance.md`](docs/release-provenance.md). The pinned release Actions and their permissions are reviewed in [`docs/release-actions.md`](docs/release-actions.md).

## Current functionality

- MV3 service worker, Popup, and a code-gated registration Options page
- Authenticated HPKE identity with non-extractable WebCrypto private key persistence
- Persistent replay, durable action-invoke delivery, and pending-result reconciliation ledgers
- Canonical encrypted action sender/result receiver with persistent per-recipient sequence allocation
- Strict code-gated registration and recoverable transport-credential rotation clients with an extension-origin-only dual-slot credential store
- Device Auth Frame v1, mandatory `SNO1` server confirmation, and bounded authentication acknowledgement timeout
- Explicit optional-host permission grant during registration
- Worker-start connection restoration with HPKE identity/transport credential binding verification
- Provisional vendored protocol assets with SHA-256 verification
- Extension-origin IndexedDB Workspace Membership store with an immutable authority pin, exact signed local certificate, canonical highest roster bytes/digest, and fail-closed rollback/fork/epoch-gap handling
- Strict provisional ADR-005 register/prove/state HTTP client with real Base HPKE proof generation, an extension-origin durable pending-enrollment journal, ambiguous-proof recovery, bounded no-redirect responses, sequential roster paging, Worker-start recovery before transport credential loading, and recoverable write-once transport promotion only after the durable active certificate is present

## Protocol

The server repository is the canonical protocol source. This repository vendors a fixed copy under `protocol/vendor` and records its version, upstream reference and SHA-256. Run:

```sh
node protocol/verify-schema.mjs
```

The current `0.1.0-dev` schema is unreleased and provisional.

## Security status

The transport core accepts only HTTPS origins outside loopback, never puts credentials in URLs or `chrome.storage.sync`, rejects silent credential replacement, and refuses to send the first authentication frame if the WebSocket endpoint changes. The bearer credential must remain available as bytes for the browser WebSocket API, so extension-origin IndexedDB and a minimal in-memory lifetime are the practical Chrome boundary; the HPKE private identity remains non-extractable.

Version `0.1.14` adds a durable recipient cursor for Relay Delivery v1. After exact `SNO1`, the Worker resumes from its highest committed delivery ID; it advances and cumulatively ACKs only after authenticated business reconciliation and presentation complete. Exact relay redelivery may reuse an already consumed replay tuple only when the existing durable business binding reconciles successfully. A history gap is persisted as snapshot-required and is never skipped automatically. The Android durable sender and snapshot-required recovery handshake remain incomplete.

Version `0.1.12` adds one atomic `{current, pending, phase}` rotation record. Options durably prepares one client-generated pending credential and marks it attempted before the strict no-redirect HTTPS request can leave the extension. HTTP 200 never replaces current. After interruption or Worker reconstruction, transport probes pending, falls back to current after pre-authentication denial, and retains the exact pending secret for request retry. Only exact pending `SNO1` permits an atomic promotion that removes old current and pending metadata. Device/workspace and HPKE identity bindings remain unchanged.

The Options page can consume an administrator-issued Chrome pairing code, request only the selected server's optional host access, persist the returned credential, and start a connection. `online` is reported only after `SNO1`; a socket open or local `SNA1` enqueue is not sufficient. Missing/replaced HPKE identity state fails closed.

Authenticated inbound binary frames enter a serialized `action.result` dispatcher. It strictly decodes `SNE1`, checks the credential workspace/recipient route, resolves the exact sender device/key ID only from a local immutable approved-peer pin, performs Auth HPKE opening, consumes the persistent replay tuple, validates canonical payload bytes, and reconciles the pending action atomically. Unapproved senders and every decoding/authentication/reconciliation failure close the socket without logging payload or identity data.

Outbound `action.invoke` now persists the exact canonical invoke payload, Android device/key binding, operation digest, idempotency key, retry state, and per-recipient sequence before/around authenticated WebSocket delivery. Only a `SNO1`-authenticated connection generation can send. Fresh delivery attempts use new envelope message IDs/sequences but retain the same business idempotency key and exact operation bytes. Named `chrome.alarms` wake bounded 1/2/4/8-second retries across MV3 Worker suspension; a terminal authenticated result stops delivery, and removing the approved peer stops subsequent encryption. Local `WebSocket.send` acceptance is not treated as Android execution or result acknowledgement.

The Worker retries network/socket failures with jittered exponential backoff from 1 second up to 60 seconds. A single connection generation suppresses duplicate error/close retries, successful `SNO1` authentication resets the sequence, explicit connect/disconnect cancels pending work, and `chrome.alarms` preserves scheduled wakeups across MV3 Worker suspension. Persistent local identity or encrypted-delivery failures stop fail-closed rather than being retried as network failures.

Server directory data can never populate the pin store implicitly. Textual trusted-device approval and Chrome transport-credential rotation are implemented, but camera QR UX, Android dual-slot rotation, E2EE identity rotation, lost-device recovery, snapshot-required recovery, Android durable submission, multi-device offline convergence, and independent security review remain incomplete. No real notification content may use this transport yet.

## License

Current revisions are licensed under [`GPL-3.0-only`](LICENSE). Commercial use is permitted subject to GPLv3. See [`LICENSE-TRANSITION.md`](LICENSE-TRANSITION.md) for the exact non-retroactive MIT-to-GPL boundary; the boundary revision and its ancestors remain available under MIT.

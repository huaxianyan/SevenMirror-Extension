# Chrome sensitive local data

Status: internal security inventory; not an independent review result

Last updated: 2026-08-29

## Purpose and security boundary

SevenMirror must decrypt notification and operation payloads inside an authorized
Chrome extension endpoint. The Chrome profile therefore cannot satisfy a
“zero business plaintext” rule. This inventory separates required endpoint-local
state from data that must not appear in URLs, console output, user-facing errors,
or unrelated stores.

Extension-origin isolation and a non-extractable WebCrypto key reduce accidental
exposure. They do not protect data after arbitrary code execution in the browser,
malicious extension execution with sufficient access, operating-system account
compromise, profile copying while usable, browser debugging, or endpoint memory
capture.

## Data classification

### Bearer credentials and private keys

| Data | Required location and lifetime | Forbidden locations |
| --- | --- | --- |
| Current transport token | Raw 32-byte value in `syncnotifications-transport-v1`; retained while the profile remains registered | URL/query/referrer, `chrome.storage`, console, errors, notification UI, interaction page, unrelated IndexedDB stores |
| Pending transport-rotation token | Same credential record, only while rotation is prepared/attempted; removed by successful promotion | Same as current token |
| Pending-enrollment transport token | Raw value in `syncnotifications-pending-membership-v1` until approval/promotion or explicit cleanup | Same diagnostic and unrelated-store locations |
| Pairing and rotation codes | Options input and bounded request body in process memory only; the input is cleared after submission | IndexedDB, `chrome.storage`, URL, console, errors, notification UI |
| HPKE identity private key | Non-extractable P-256 `CryptoKey` in `syncnotifications-crypto-v1` | Raw scalar, JWK, PKCS#8, Base64 export, console, errors, UI, URLs |

“Non-extractable” is a WebCrypto API property, not a hardware-backed or
profile-compromise guarantee. The extension process can still use the key for
authorized HPKE operations.

### Expected endpoint-local protocol state

The following values are not bearer secrets and may remain as app-private
plaintext because they are required for authorization, replay defense, restart
recovery, or reconciliation:

- canonical Server origin, workspace/device IDs, public keys, key IDs,
  authority certificate/roster and membership epochs;
- routing/replay tuples, outbound sequences, relay delivery cursors, snapshot
  high-water and recovery correlation;
- notification ID, source application ID/name, revision, payload digest,
  action IDs and operation/result status;
- connection state, notification button bindings, shortcut preferences and
  development lifecycle counters in `chrome.storage.local`.

These fields remain sensitive metadata. They must not be described as hidden
from a person who can inspect the extension profile.

### Expected business plaintext

`syncnotifications-notification-state-v1` durably retains the decrypted source
application name, title, body, action titles/descriptors, bounded PNG bytes and
revision state needed to reconstruct presentation after an MV3 Worker restart.
The same presentation fields are intentionally passed to `chrome.notifications`
and to SevenMirror's interaction page.

`syncnotifications-pending-actions-default` may retain exact canonical
`action.invoke` bytes. A free-form reply is inside those bytes, including for the
one-shot online-only reply path, until the pending-action record expires or the
store is cleared. The current action retention bound is 30 days. “Online-only”
means the relay must not durably queue the reply; it does not mean the Chrome
endpoint has no durable correlation or canonical invoke state.

The interaction page URL contains only the opaque Chrome notification ID. Title,
body, reply text, credentials and canonical payload bytes must never be added to
its query string or fragment. Reply text exists in the page DOM/process memory
before submission and then in the canonical pending-action record described
above.

Chrome/OS notification history, screenshots, screen recording, accessibility
services, keyboard/IME history, crash dumps, swap and browser profile backups
are outside extension-origin storage and remain endpoint disclosure surfaces.

## Store inventory

| Store | Sensitive contents |
| --- | --- |
| `syncnotifications-transport-v1` | Current and optional pending raw bearer token; transport/device/key binding |
| `syncnotifications-pending-membership-v1` | Pending raw bearer token, authority/challenge/proof state |
| `syncnotifications-crypto-v1` | Non-extractable HPKE `CryptoKeyPair` |
| `syncnotifications-notification-state-v1` | Decrypted notification presentation and media state |
| `syncnotifications-pending-actions-default` | Canonical invoke/ACK payloads, potentially reply text, result detail and retry state |
| Workspace membership/replay/sequence/cursor stores | Authority-certified public state and durable protocol metadata |
| `chrome.storage.local` | Connection state, shortcut preferences, exact button-to-action binding, synthetic diagnostic selection and lifecycle diagnostics; no bearer token or reply text is expected |

## Diagnostics and user-visible surfaces

Production source currently makes no routine `console.*` calls. Options catches
registration/rotation failures and presents fixed text rather than raw exception
messages. Most service-worker message failures also return fixed states.

The development `run-e2ee-persistence-test` message currently returns an
exception message to Popup. Its current implementation uses fixed internal error
messages, but it remains a diagnostic surface that must be canary-scanned in a
real MV3 runtime and removed from the final ordinary-user UI.

Native notifications and the interaction page intentionally expose decrypted
presentation content to the authorized local user. They must not display bearer
credentials, pairing/rotation codes, private-key material, canonical encrypted
payloads, raw protocol exceptions, or unrelated notification/reply content.

## Retention, clearing and backup behavior

- Transport promotion atomically replaces the current token and removes pending
  rotation metadata. Loaded token copies are overwritten on best effort after
  use; JavaScript garbage collection and internal browser copies prevent a
  guaranteed memory-erasure claim.
- Pending actions are purged on store activity after their 30-day expiry.
- Removed notification records are retained for revision/snapshot convergence;
  there is not yet a product retention/deletion control for historical endpoint
  state.
- Revocation and transport fail-closed behavior stop network use but do not
  currently prove deletion of all local notification/action/membership state.
- Uninstalling the extension or deleting the entire browser profile is the only
  current broad user-controlled deletion boundary. Browser sync, backup, profile
  export, enterprise roaming and filesystem recovery behavior still require a
  real-browser release-baseline assessment.

The missing in-product clear/retention policy is an open release issue, not an
implicit promise that Chrome removes the data automatically.

## Automated canary evidence

`src/security/sensitive-data-canary.test.ts` uses real production stores with
`fake-indexeddb` to verify that:

1. current and pending transport tokens exist only in the dedicated credential
   record, while text/Base64 encodings do not appear in scanned records;
2. an HPKE identity remains non-extractable after store reconstruction and
   PKCS#8 export fails;
3. notification title/body canaries are present in the notification store as
   explicitly expected local plaintext, not in credential/identity stores;
4. induced validation failures and captured console methods contain no token or
   business canary;
5. explicit store clearing removes the tested credential and identity records.

This deterministic test does **not** inspect Chromium's on-disk LevelDB/IndexedDB
encoding, browser console buffers, native notification history, crash dumps,
memory, caches, profile export, sync/backup, or behavior after a real Worker and
browser restart. Those checks remain required with a fresh isolated profile; a
clean unit test must not be reported as a clean browser-profile scan.

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
  current broad user-controlled deletion boundary. The isolated profile-export
  canary below proves current local file placement, but browser sync, backup,
  enterprise roaming and filesystem recovery behavior remain unverified.

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
encoding or behavior after a real browser restart. It remains the fast CI-facing
store-boundary test and must not be substituted for the separate browser scan.

## Isolated real-browser profile canary

`scripts/chrome_profile_canary.py` launches the production `dist/` in headless
Cent Browser with a fresh temporary `--user-data-dir`. It attaches directly to
the production MV3 Worker through CDP and uses real browser WebCrypto,
IndexedDB, `chrome.storage` and `chrome.notifications` APIs. The script:

1. creates random current/pending 32-byte transport tokens and a non-extractable
   P-256 identity inside the Worker;
2. stores exact production-shape credential, identity, notification and
   one-shot pending-action records, with independent title/body/reply canaries;
3. verifies the native notification API accepts the presentation fields;
4. closes and reopens the complete browser, then verifies token digests,
   identity, private-key non-extractability, notification state and reply bytes;
5. captures Worker console, uncaught-exception and browser-log events while
   attached and searches their text for raw/hex/Base64 credential and business
   canaries;
6. closes the browser before recursively scanning the complete temporary
   profile plus browser stdout/stderr, then deletes that profile by default.

Run it only after building the exact extension under review:

```text
python scripts/chrome_profile_canary.py --report <non-sensitive-report.json>
```

The 2026-08-29 run against extension `0.1.15` scanned `17,744,071` closed-profile
bytes after a full browser restart. Each raw current/pending token was found in
one file, exclusively under the extension IndexedDB LevelDB directory. Standard
Base64 and unpadded Base64URL token matches were zero. Title, body and reply each
appeared in one file, also exclusively in that expected IndexedDB directory.
`chrome.storage`, the interaction URL, captured diagnostics and browser logs had
zero forbidden matches. Both runs had zero console calls and zero uncaught
Worker exceptions; one browser log event per run contained no canary. The
restored HPKE private key remained non-extractable, PKCS#8 export failed, and
`chrome.notifications.getAll()` contained the recreated notification.

The JSON report contains counts and limitations only; generated token values,
digests and business canaries are not written to it. The temporary profile is
sensitive evidence until deletion. `--keep-profile` exists only for explicitly
access-controlled investigation and prints its location as a warning.

## Isolated interaction-page DOM canary

`scripts/interaction_dom_canary.py` launches the production `dist/` in an
isolated non-headless Chromium profile. On Windows the browser window is placed
off-screen; Linux environments without a display use Xvfb. It seeds isolated
extension-origin stores with a non-extractable test identity, transport binding,
notification state, and a deterministic authority-signed Chrome／Android roster.
The page then talks to the unmodified production Worker; no runtime-message mock
or production diagnostic endpoint is added. The canary verifies:

1. the URL contains only the opaque Chrome notification ID;
2. the Worker accepts the signed roster and renders only the exact target title,
   body, certified source and source application;
3. reply submission is bound to the exact notification ID, revision and action;
4. the authority-certified Android recipient and identity key are resolved;
5. the exact canonical schema-v2 `ActionInvoke` is durably registered with the
   matching SHA-256, recipient, idempotency key and `once` delivery mode before
   transport acceptance;
6. the textarea is cleared immediately, and reply text does not remain visible
   or enter the URL, console, exception log or browser output;
7. the temporary profile is deleted by default and the JSON report contains
   counts and limitations, not canary values.

`scripts/interaction-worker-fixture.json` contains public deterministic test
material only. It is reproducible with
`node node_modules/vite-node/vite-node.mjs scripts/generate_interaction_worker_fixture.ts`;
the production membership verifier rejects an invalid certificate, signature,
roster digest or role binding. The relay endpoint is deliberately unavailable,
so this check does not claim relay delivery, authenticated Android execution or
result reconciliation. Existing codec, Auth HPKE, transport and cross-device
tests cover those separate boundaries. The Python WebSocket dependency is fixed
in `scripts/security-requirements.txt` with an exact wheel SHA-256 and should be
installed in an isolated environment with `--require-hashes`.

This check currently runs against the read-only local Cent Browser installation.
Stock Google Chrome 137 and newer no longer honor `--load-extension` in official
branded builds, including the current GitHub runner browser, while Chrome for
Testing requires a separately pinned browser artifact and provenance decision.
The existing CI therefore continues to build and test the page but does not
misrepresent a browser in which the unpacked extension never loaded as DOM
evidence. Pinning a CI browser artifact remains open.

### Remaining browser coverage

The profile scan and interaction Worker canary do not replace separate
registration, live relay delivery, authenticated Android execution or result
reconciliation evidence. Process memory, crash dumps, OS notification history,
sync/backup, IME history, screenshots, screen recording and filesystem recovery
also remain open.

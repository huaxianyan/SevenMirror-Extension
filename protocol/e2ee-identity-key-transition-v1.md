# E2EE Identity Key Transition v1

Status: provisional Phase 0 protocol. This protocol rotates one device's RFC 9180 Auth HPKE identity while the old private key is still available. It does not recover a lost identity key.

The transition is end-to-end encrypted. The relay routes Encrypted Envelope v1 frames but MUST NOT parse the transition plaintext or establish peer trust. Transport credential rotation, server admission, and E2EE identity transition are independent lifecycles.

## Payloads

All three messages use canonical `EncryptedPayload` with `schema_version = 2`. Schema version 1 remains reserved for the existing action messages.

### `identity_key_transition`

| Field | Constraint |
| --- | --- |
| `transition_id` | random, non-zero 16 bytes |
| `previous_key_id` | SHA-256 of the exact old 65-byte public key, 32 bytes |
| `new_public_key` | valid uncompressed P-256 point, exactly 65 bytes |
| `new_key_id` | SHA-256 of `new_public_key`, exactly 32 bytes and different from `previous_key_id` |

The envelope MUST authenticate with the old private key, and the routing header's `sender_key_id` MUST equal `previous_key_id`. The recipient MUST already have that exact old key as the active immutable pin for the sender. The recipient rejects a second, different pending successor for the same peer.

### `identity_key_transition_ack`

| Field | Constraint |
| --- | --- |
| `transition_id` | exact transition identifier |
| `previous_key_id` | exact old key identifier |
| `new_key_id` | exact proposed key identifier |
| `transition_sha256` | SHA-256 of the complete canonical `EncryptedPayload` carrying `identity_key_transition` |

The peer sends this acknowledgement with its own currently approved sender key and encrypts it to the proposed new recipient key. The routing header's `recipient_key_id` MUST equal `new_key_id`. Receiving and opening this ACK proves to the rotating device that the peer durably processed the exact transition and that the rotating device still controls the proposed new private key.

### `identity_key_transition_commit`

| Field | Constraint |
| --- | --- |
| `transition_id` | exact transition identifier |
| `previous_key_id` | exact old key identifier |
| `new_key_id` | exact proposed key identifier |
| `transition_sha256` | exact transition digest from the ACK |
| `ack_sha256` | SHA-256 of the complete canonical `EncryptedPayload` carrying the accepted `identity_key_transition_ack` |

The rotating device authenticates this message with the proposed new private key. Before the new key is active, the peer may use the pending new public key only to open an exact commit bound to its own stored ACK. A valid commit atomically promotes the new pin and retires the old pin. No general business payload may use a merely pending key.

A commit has no commit-ACK. The rotating device may durably retry the exact canonical commit under fresh envelope message IDs and sequences. The peer handles a valid duplicate commit idempotently through the committed transition record and normal replay protection.

## Durable state machine

The rotating device MUST durably create the new key without overwriting the old key and snapshot the currently approved peer set before sending a transition.

For each peer:

1. `PENDING_SEND`: old and new private keys are retained; send the exact canonical transition authenticated by old.
2. `AWAITING_ACK`: retry the same canonical transition with fresh envelope tuples.
3. `ACKNOWLEDGED`: after an authenticated exact ACK addressed to new, durably store the canonical commit before relying on network delivery.
4. `COMMIT_QUEUED`: send the exact canonical commit authenticated by new with fresh envelope tuples.
5. `COMPLETED_LOCALLY`: the peer generated an ACK, so it has durably stored the successor. Commit delivery may continue independently.

The receiving peer MUST atomically store the exact canonical transition, old/new key binding, transition digest, and canonical ACK intent before sending the ACK. Until an exact commit arrives, the old key remains the active pin and the new key is accepted only for the bound commit. After commit, the new key becomes active and the old key becomes a bounded tombstone that accepts neither business payloads nor a new transition.

At most one local identity transition and one pending successor per peer are permitted. A different transition, key, digest, workspace, device, or sender tuple fails closed. Removing and re-adding trust requires the normal out-of-band pairing workflow.

The rotating device MUST NOT destroy the old private key until every peer in the transition snapshot has produced an exact valid ACK and every corresponding commit is durably queued. An unavailable peer therefore cannot be silently skipped. The user may explicitly remove that peer from local trust and from the transition snapshot, after which the transition may complete. Before the first accepted ACK, the user may abort and destroy only the proposed new key. After any accepted ACK, silent rollback is forbidden.

A transition session expires after at most seven days. Expiry does not auto-promote, auto-remove a peer, auto-destroy the old key, or generate a replacement key. It enters a user-visible blocked state requiring explicit peer removal, retry, or recovery.

## Envelope, replay, and ordering

Every delivery uses a fresh Encrypted Envelope v1 `message_id` and sender sequence while reusing the exact canonical lifecycle payload. Existing HPKE authentication, routing checks, expiry checks, and replay-ledger ordering remain mandatory.

Payload-state validation occurs only after the envelope sender/recipient device and key tuple is authenticated. Digest comparisons use constant-time equality. Unknown transitions, wrong peers, wrong old/new key IDs, non-canonical payloads, stale commits, and digest mismatches fail closed.

## Lost identity recovery

If the old private key is missing or unusable, this protocol MUST NOT run and the transport credential MUST NOT be rebound to a replacement identity. Recovery requires all of the following:

1. fail closed locally without generating a silent replacement;
2. use the local server administrator to revoke the old device transport membership;
3. explicitly clear the failed local registration;
4. register as a new device with a new device ID, transport credential, and HPKE identity;
5. explicitly remove the old peer pin on every remaining device; and
6. complete a fresh out-of-band Offer/Approval transcript and independently compare the full safety code.

A server directory update, retained device name, old transport membership, or imported pairing payload cannot authorize the new identity. Lost-device recovery never preserves the old device ID or approved-peer pin.

## Security boundary

This protocol provides authenticated continuity only when the old private key remains trusted and uncompromised. It does not provide post-compromise security against an attacker controlling the old key, metadata hiding, delivery availability, or a group-wide atomic epoch. The server may delay or suppress transition traffic but cannot create a valid transition, ACK, or commit.

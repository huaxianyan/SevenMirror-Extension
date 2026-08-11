# Trusted Device Pairing v1

Status: provisional (`0.1.0-dev`)

This protocol establishes local E2EE peer pins. It is independent of server admission and transport authentication. A server directory, registration response, or transport credential MUST NOT call the approved-peer store directly.

## Workflow

1. The device being added creates and displays a short-lived `TrustOffer` QR.
2. An already trusted device scans the exact offer, verifies its local workspace, and displays a `TrustApproval` QR plus the safety code derived from both canonical records.
3. The new device scans the approval, verifies that it binds the exact locally-created offer, and displays the same safety code.
4. The user compares the full safety code on both devices and explicitly confirms on each device.
5. Each device pins the other device ID/public-key tuple only after its own confirmation. Identical approval is idempotent; replacing an existing pin requires explicit removal and a new workflow.

Scanning QR data alone MUST NOT pin a peer. A safety-code mismatch or cancellation pins neither peer on that device. The protocol provides no remote approval and no silent server-assisted trust.

The first device in a workspace uses a separate explicit local TOFU action to mark its own current identity as the trust root. TOFU does not approve later directory entries.

## Encoding

Integers are unsigned 64-bit big-endian milliseconds since Unix epoch. IDs and nonces are non-zero raw bytes. Public keys are canonical 65-byte uncompressed P-256 points. Records have no optional fields or trailing bytes.

QR text is lowercase prefix `sntrust1:` followed by unpadded base64url of the complete canonical binary record. Decoders reject whitespace, padding, alternate base64 alphabets, non-canonical re-encoding, unsupported magic, and incorrect length.

### TrustOffer — 133 bytes

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `SNT1` |
| 4 | 16 | workspace ID |
| 20 | 16 | offerer device ID |
| 36 | 65 | offerer HPKE public key |
| 101 | 16 | random offer nonce |
| 117 | 8 | created-at Unix ms |
| 125 | 8 | expires-at Unix ms |

### TrustApproval — 149 bytes

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `SNT2` |
| 4 | 32 | SHA-256 of the exact 133-byte TrustOffer |
| 36 | 16 | approver device ID |
| 52 | 65 | approver HPKE public key |
| 117 | 16 | random approval nonce |
| 133 | 8 | created-at Unix ms |
| 141 | 8 | expires-at Unix ms |

## Validation

- Each record TTL is in `(0, 10 minutes]`.
- Approval expiry MUST NOT exceed the bound offer expiry.
- Approval `offer_hash` MUST equal SHA-256 of the exact locally-created/scanned offer bytes.
- Offer workspace MUST equal the active local transport workspace before approval is shown.
- Offerer and approver device IDs and public keys MUST differ.
- At use time, expiry must be in the future. Implementations may tolerate at most five minutes of future clock skew for `created_at`; they must not extend expiry.
- Offer and approval nonces use 128 bits from the platform CSPRNG and are never reused.

## Safety code

The safety transcript is:

```text
UTF8("SyncNotifications-Trust-SAS-v1") || TrustOfferBytes || TrustApprovalBytes
```

Compute SHA-256 over that transcript, take the first 60 bits in network bit order, map each consecutive 5-bit value through the Crockford alphabet:

```text
0123456789ABCDEFGHJKMNPQRSTVWXYZ
```

Display the resulting 12 symbols as `XXXX-XXXX-XXXX`. Comparison is case-insensitive for display only; protocol QR text remains canonical and case-sensitive. All 12 symbols must be compared. The safety code authenticates this one offer/approval transcript; it is not a credential and is not stored as a substitute for peer pins.

## Privacy and logging

The records contain public identities and routing IDs but are still sensitive metadata. They must not enter analytics, crash reports, server logs, clipboard history by default, or URL/query parameters. Private keys, transport credentials, notification content, and business idempotency keys never appear in this protocol.

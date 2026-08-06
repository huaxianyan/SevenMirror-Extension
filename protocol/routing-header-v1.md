# Routing Header v1

Status: provisional SPIKE-004 wire candidate; not a compatibility promise until ADR-001 and ADR-002 are accepted.

Every HPKE ciphertext is created for exactly one recipient. The sender encodes
this fixed 160-byte header once and passes those exact bytes as HPKE AAD. The
transport carries the same bytes without parsing and re-encoding them.

All integers use unsigned big-endian encoding. UUID-like identifiers are raw
16-byte opaque random values; key IDs are the complete SHA-256 digest of the
65-byte RFC 9180 P-256 public-key encoding.

| Offset | Bytes | Field | Constraint |
| ---: | ---: | --- | --- |
| 0 | 4 | magic/version | ASCII `SNH1` |
| 4 | 2 | E2EE suite | `1` = HPKE Auth P-256/HKDF-SHA256/AES-128-GCM |
| 6 | 2 | reserved flags | must be zero |
| 8 | 16 | workspace ID | opaque, non-zero |
| 24 | 16 | sender device ID | opaque, non-zero |
| 40 | 16 | recipient device ID | opaque, non-zero |
| 56 | 32 | sender key ID | SHA-256 public-key digest |
| 88 | 32 | recipient key ID | SHA-256 public-key digest |
| 120 | 16 | message ID | cryptographically random, non-zero |
| 136 | 8 | sender sequence | `1..2^63-1`, sender-assigned per sender/recipient key pair |
| 144 | 8 | creation time | Unix milliseconds, `0..2^53-1` |
| 152 | 8 | expiry time | Unix milliseconds, greater than creation |

The expiry interval must not exceed 24 hours. Receivers separately apply a
clock-skew policy; the codec only validates structural time relationships.
Application message type, notification identifiers, action IDs, reply text,
idempotency keys, icons, avatars, and all other business semantics belong in
the encrypted payload, never this header.

Recipients process an envelope in this order:

1. require exactly 160 header bytes and enforce syntax/size/time limits;
2. locate locally pinned sender and recipient key IDs;
3. open Auth HPKE with the original 160 bytes as AAD;
4. atomically record `(sender_key_id, message_id)` in the persistent replay ledger;
5. only after an `accepted` decision, parse payload and apply a side effect.

Unknown magic, suite, flags, invalid lengths, zero IDs, zero sequence, invalid
timestamps, authentication failure, replay, expiry, or storage failure all fail
closed. No implementation may normalize and re-encode a received header before
AAD verification.

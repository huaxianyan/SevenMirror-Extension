# Encrypted Envelope v1

Status: provisional SPIKE-004 transport candidate; not a compatibility promise until ADR-001 and ADR-002 are accepted.

One binary WebSocket message carries exactly one recipient-specific envelope.
The frame is deterministic and does not use protobuf for its clear framing:

| Offset | Bytes | Field | Constraint |
| ---: | ---: | --- | --- |
| 0 | 4 | magic/version | ASCII `SNE1` |
| 4 | 160 | Routing Header v1 | exact original HPKE AAD bytes |
| 164 | 65 | HPKE encapsulated key | uncompressed P-256 point, first byte `0x04` |
| 229 | 4 | ciphertext length | unsigned big-endian, `16..524288` |
| 233 | variable | HPKE ciphertext | exact declared length, includes AEAD tag |

The minimum frame is 249 bytes and the maximum is 524521 bytes. Trailing bytes,
truncation, unknown magic, invalid encapsulated-key encoding, and out-of-range
lengths fail closed. WebSocket/configuration limits must reject a frame larger
than the maximum before allocating payload-sized buffers.

The frame magic and length are structural transport metadata. Routing Header v1
is authenticated as HPKE AAD; HPKE authenticates the encapsulated key and
ciphertext. Any modification therefore either fails structural parsing or HPKE
opening.

Recipient processing order is mandatory:

1. enforce WebSocket frame-size limit;
2. decode frame and Routing Header v1 using strict lengths;
3. verify workspace, recipient device ID/key ID, and pinned sender key ID;
4. open Auth HPKE using the original 160 header bytes as AAD;
5. atomically record `(sender_key_id, message_id)` in the persistent replay ledger;
6. only for `accepted`, parse the encrypted business payload and apply a side effect.

Authentication failure must not consume the replay tuple. Once a tuple is
accepted it remains consumed even if payload parsing or a side effect fails;
result recovery must never execute the same action twice.

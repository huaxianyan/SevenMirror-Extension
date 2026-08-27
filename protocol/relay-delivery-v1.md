# Relay Delivery v1

Status: provisional pre-release protocol.

Relay Delivery v1 adds recipient-specific durable ciphertext history without exposing the encrypted business type. It is independent from Encrypted Envelope replay tuples, notification revisions, snapshot high-water marks, and action result acknowledgements.

## Security and product boundary

The relay never decrypts an Encrypted Envelope. A sender explicitly chooses one of two transport policies:

- a bare canonical `SNE1` frame is online-only and is never stored for later recipient delivery;
- `SNQ1 || envelope` requests durable recipient delivery.

This distinction is required because delayed delivery is unsafe for some encrypted operations, especially one-shot text replies. The relay cannot infer that policy from ciphertext. Clients MUST send one-shot replies as bare online-only `SNE1` frames.

The durable wrapper reveals only that delayed transport is permitted. It does not reveal the business payload type, notification metadata, action, reply text, or result.

## Fixed binary messages

All integers are unsigned 64-bit big-endian values in `1..2^63-1`, except that a client cursor MAY be zero before its first committed delivery.

### Durable submission: client to relay

```text
SNQ1 (4 bytes) || canonical SNE1 envelope
```

The relay validates the embedded canonical Encrypted Envelope and authenticated sender binding, verifies that the recipient remains authorized, assigns the next recipient-specific delivery ID, and commits the exact `SNE1` bytes before making them available to a connected recipient.

### Resume cursor: recipient to relay

```text
SNC1 (4 bytes) || committed_delivery_id (8 bytes)
```

The cursor is the highest contiguous delivery ID whose encrypted business effect and replay state are durably committed by that recipient. Sending `SNC1` also acknowledges that ID if the relay did not receive an earlier ACK.

### Delivery: relay to recipient

```text
SND1 (4 bytes) || delivery_id (8 bytes) || canonical SNE1 envelope
```

Deliveries are sent in strictly increasing recipient-specific delivery ID order. The recipient MUST authenticate and process the embedded envelope using the existing E2EE and replay boundaries.

### Delivery ACK: recipient to relay

```text
SNC2 (4 bytes) || committed_delivery_id (8 bytes)
```

ACK is cumulative. A recipient MUST NOT advance it before the encrypted business effect and replay state are durably committed. An ACK does not prove that a browser or operating system visibly presented a notification.

### Caught-up marker: relay to recipient

```text
SND2 (4 bytes) || high_water_delivery_id (8 bytes)
```

The marker follows all retained deliveries through the reported high-water ID. New deliveries may follow it.

### Snapshot required: relay to recipient

```text
SNR1 (4 bytes) || high_water_delivery_id (8 bytes)
```

The recipient cursor is older than retained history because unacknowledged ciphertext expired or was evicted by a documented capacity bound. The recipient MUST reconcile authoritative source snapshots before resuming from the supplied high-water ID. It MUST NOT interpret the reset as evidence that missing business events were applied.

## Ordering, persistence, and bounds

- Delivery IDs are allocated independently for each `(workspace_id, recipient_device_id)`.
- The relay commits the exact ciphertext before signaling a live recipient.
- Reconnect replay is ascending and may repeat a delivery whose ACK was lost.
- Client E2EE replay protection and business idempotency remain mandatory.
- Envelopes are not delivered after their authenticated Routing Header expiry.
- The provisional Server keeps at most 4,096 unacknowledged deliveries and 64 MiB of ciphertext per recipient. Oldest unacknowledged entries are evicted first and create a snapshot-required gap.
- Revoked recipients cannot enqueue new history or reconnect to read retained history. Device deletion removes its queue through the existing database foreign key.

## Authentication ordering

`SNO1` remains the first server data message. A recipient sends `SNC1` only after validating `SNO1`. Heartbeat `SNH1`／`SNH2` remains independent and is not a cursor or delivery ACK.

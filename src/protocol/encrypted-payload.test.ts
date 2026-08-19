import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/encrypted-payload-v1.json';
import {
  createActionInvokePayload,
  createActionResultPayload,
  createActionResultAckPayload,
  createNotificationRemovedPayload,
  createNotificationSnapshotManifestPayload,
  createNotificationUpsertPayload,
  decodeEncryptedPayloadV1,
  encodeEncryptedPayloadV1,
} from './encrypted-payload';
import { ActionResultStatus } from './generated/notification/v1/payload_pb';

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));

const validPayload = () => createActionInvokePayload({
  notificationId: vector.notificationId,
  notificationRevision: BigInt(vector.notificationRevision),
  actionId: fromHex(vector.actionIdHex),
  idempotencyKey: fromHex(vector.idempotencyKeyHex),
  replyText: vector.replyText,
});

describe('Encrypted Payload v1', () => {
  it('matches the canonical cross-platform action.invoke vector', () => {
    const encoded = encodeEncryptedPayloadV1(validPayload());
    expect(encoded).toEqual(fromHex(vector.encodedHex));
    const decoded = decodeEncryptedPayloadV1(encoded);
    expect(decoded.body.case).toBe('actionInvoke');
    if (decoded.body.case === 'actionInvoke') {
      expect(decoded.body.value.notificationRevision).toBe(7n);
      expect(decoded.body.value.replyText).toBe('acknowledged');
    }
  });

  it('round-trips a canonical action result', () => {
    const encoded = encodeEncryptedPayloadV1(createActionResultPayload({
      idempotencyKey: fromHex(vector.idempotencyKeyHex),
      status: ActionResultStatus.STALE_NOTIFICATION_VERSION,
      detail: 'revision changed',
    }));
    expect(encoded).toEqual(fromHex(vector.actionResultEncodedHex));
    const decoded = decodeEncryptedPayloadV1(encoded);
    expect(decoded.body.case).toBe('actionResult');
    if (decoded.body.case === 'actionResult') {
      expect(decoded.body.value.status).toBe(ActionResultStatus.STALE_NOTIFICATION_VERSION);
      expect(decoded.body.value.detail).toBe('revision changed');
    }
  });

  it('round-trips a canonical action result acknowledgement', () => {
    const digest = fromHex(vector.actionResultSha256Hex);
    const payload = createActionResultAckPayload({
      idempotencyKey: fromHex(vector.idempotencyKeyHex),
      resultSha256: digest,
    });
    const encoded = encodeEncryptedPayloadV1(payload);
    expect(encoded).toEqual(fromHex(vector.actionResultAckEncodedHex));
    const decoded = decodeEncryptedPayloadV1(encoded);
    expect(decoded.body.case).toBe('actionResultAck');
    if (decoded.body.case === 'actionResultAck') {
      expect(decoded.body.value.resultSha256).toEqual(digest);
    }

    if (payload.body.case === 'actionResultAck') {
      payload.body.value.resultSha256 = new Uint8Array(32);
    }
    expect(() => encodeEncryptedPayloadV1(payload)).toThrow(/SHA-256/i);
  });

  it('matches the canonical notification and snapshot vectors', () => {
    const upsert = createNotificationUpsertPayload({
      notificationId: vector.notificationPayloadId,
      notificationRevision: BigInt(vector.notificationUpsertRevision),
      title: vector.notificationTitle,
      body: vector.notificationBody,
    });
    const encodedUpsert = encodeEncryptedPayloadV1(upsert);
    expect(encodedUpsert).toEqual(fromHex(vector.notificationUpsertEncodedHex));
    const decodedUpsert = decodeEncryptedPayloadV1(encodedUpsert);
    expect(decodedUpsert.body.case).toBe('notificationUpsert');

    const removed = createNotificationRemovedPayload({
      notificationId: vector.notificationPayloadId,
      notificationRevision: BigInt(vector.notificationRemovedRevision),
    });
    const encodedRemoved = encodeEncryptedPayloadV1(removed);
    expect(encodedRemoved).toEqual(fromHex(vector.notificationRemovedEncodedHex));
    expect(decodeEncryptedPayloadV1(encodedRemoved).body.case).toBe('notificationRemoved');

    const manifest = createNotificationSnapshotManifestPayload({
      highWaterRevision: BigInt(vector.notificationSnapshotHighWaterRevision),
      activeNotifications: vector.notificationSnapshotEntries.map((entry) => ({
        notificationId: entry.notificationId,
        notificationRevision: BigInt(entry.notificationRevision),
      })),
    });
    const encodedManifest = encodeEncryptedPayloadV1(manifest);
    expect(encodedManifest).toEqual(fromHex(vector.notificationSnapshotManifestEncodedHex));
    expect(decodeEncryptedPayloadV1(encodedManifest).body.case)
      .toBe('notificationSnapshotManifest');
  });

  it('rejects invalid notification snapshot manifests', () => {
    const validManifest = () => createNotificationSnapshotManifestPayload({
      highWaterRevision: 9n,
      activeNotifications: [
        { notificationId: 'synthetic.notification/42', notificationRevision: 7n },
        { notificationId: 'synthetic.notification/99', notificationRevision: 9n },
      ],
    });

    const aboveHighWater = validManifest();
    if (aboveHighWater.body.case === 'notificationSnapshotManifest') {
      aboveHighWater.body.value.highWaterRevision = 6n;
    }
    expect(() => encodeEncryptedPayloadV1(aboveHighWater)).toThrow(/high-water/i);

    const duplicate = validManifest();
    if (duplicate.body.case === 'notificationSnapshotManifest') {
      duplicate.body.value.activeNotifications[1].notificationId = 'synthetic.notification/42';
    }
    expect(() => encodeEncryptedPayloadV1(duplicate)).toThrow(/sorted/i);

    const unsorted = validManifest();
    if (unsorted.body.case === 'notificationSnapshotManifest') {
      unsorted.body.value.activeNotifications[0].notificationId = 'synthetic.notification/zz';
    }
    expect(() => encodeEncryptedPayloadV1(unsorted)).toThrow(/sorted/i);

    const empty = createNotificationSnapshotManifestPayload({
      highWaterRevision: 0n,
      activeNotifications: [],
    });
    expect(decodeEncryptedPayloadV1(encodeEncryptedPayloadV1(empty)).body.case)
      .toBe('notificationSnapshotManifest');
  });

  it('rejects invalid notification fields and schema mismatch', () => {
    const missingText = createNotificationUpsertPayload({
      notificationId: vector.notificationPayloadId,
      notificationRevision: 7n,
    });
    expect(() => encodeEncryptedPayloadV1(missingText)).toThrow(/title or body/i);

    const wrongSchema = createNotificationRemovedPayload({
      notificationId: vector.notificationPayloadId,
      notificationRevision: 8n,
    });
    wrongSchema.schemaVersion = 1;
    expect(() => encodeEncryptedPayloadV1(wrongSchema)).toThrow(/schema version/i);
  });

  it('rejects duplicate, unknown and invalid semantic fields', () => {
    const encoded = fromHex(vector.encodedHex);
    expect(() => decodeEncryptedPayloadV1(Uint8Array.from([8, 1, ...encoded]))).toThrow();
    expect(() => decodeEncryptedPayloadV1(Uint8Array.from([...encoded, 0x78, 1]))).toThrow();

    const invalid = validPayload();
    if (invalid.body.case === 'actionInvoke') {
      invalid.body.value.notificationRevision = 0n;
    }
    expect(() => encodeEncryptedPayloadV1(invalid)).toThrow(/revision/i);
  });
});

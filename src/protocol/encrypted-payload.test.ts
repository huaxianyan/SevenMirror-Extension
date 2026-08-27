import { create, toBinary } from '@bufbuild/protobuf';
import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/encrypted-payload-v1.json';
import {
  createActionInvokePayload,
  createActionResultPayload,
  createActionResultAckPayload,
  createNotificationRemovedPayload,
  createNotificationSnapshotManifestPayload,
  createNotificationSnapshotRequestPayload,
  createNotificationUpsertPayload,
  decodeEncryptedPayloadV1,
  encodeEncryptedPayloadV1,
} from './encrypted-payload';
import {
  ActionResultStatus,
  EncryptedPayloadSchema,
  NotificationActionDescriptorSchema,
  NotificationMediaMimeType,
  NotificationMediaSchema,
} from './generated/notification/v1/payload_pb';

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));

const actionFromVector = (action: typeof vector.notificationActions[number]) =>
  create(NotificationActionDescriptorSchema, {
    actionId: fromHex(action.actionIdHex),
    title: action.title,
    requiresTextInput: action.requiresTextInput,
    allowsFreeFormInput: action.allowsFreeFormInput,
  });

const mediaFromVector = (media: typeof vector.notificationAppIcon) =>
  create(NotificationMediaSchema, {
    contentSha256: fromHex(media.contentSha256Hex),
    mimeType: NotificationMediaMimeType.PNG,
    width: media.width,
    height: media.height,
    encodedBytes: fromHex(media.encodedHex),
  });

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

  it('decodes legacy durable actions but does not emit them or accept legacy dismiss', () => {
    const legacy = validPayload();
    legacy.schemaVersion = 1;
    const encoded = toBinary(EncryptedPayloadSchema, legacy);
    expect(decodeEncryptedPayloadV1(encoded).body.case).toBe('actionInvoke');
    expect(() => encodeEncryptedPayloadV1(legacy)).toThrow(/schema version/i);

    if (legacy.body.case !== 'actionInvoke') throw new Error('unexpected test payload');
    legacy.body.value.actionId = new Uint8Array();
    legacy.body.value.replyText = undefined;
    legacy.body.value.dismissNotification = true;
    expect(() => decodeEncryptedPayloadV1(toBinary(EncryptedPayloadSchema, legacy)))
      .toThrow(/schema version/i);
  });

  it('matches the canonical dismiss operation and rejects mixed operations', () => {
    const dismiss = createActionInvokePayload({
      notificationId: vector.notificationId,
      notificationRevision: BigInt(vector.dismissNotificationRevision),
      idempotencyKey: fromHex(vector.dismissIdempotencyKeyHex),
      dismissNotification: true,
    });
    expect(encodeEncryptedPayloadV1(dismiss)).toEqual(fromHex(vector.dismissEncodedHex));
    const decoded = decodeEncryptedPayloadV1(fromHex(vector.dismissEncodedHex));
    expect(decoded.body.case).toBe('actionInvoke');
    if (decoded.body.case === 'actionInvoke') {
      expect(decoded.body.value.dismissNotification).toBe(true);
    }

    if (dismiss.body.case !== 'actionInvoke') throw new Error('unexpected test payload');
    dismiss.body.value.actionId = new Uint8Array(16).fill(1);
    expect(() => encodeEncryptedPayloadV1(dismiss)).toThrow(/cannot include/i);
    dismiss.body.value.actionId = new Uint8Array();
    dismiss.body.value.replyText = 'reply';
    expect(() => encodeEncryptedPayloadV1(dismiss)).toThrow(/cannot include/i);
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
      sourceApplicationId: vector.notificationSourceApplicationId,
      sourceApplicationName: vector.notificationSourceApplicationName,
      title: vector.notificationTitle,
      body: vector.notificationBody,
      appIcon: mediaFromVector(vector.notificationAppIcon),
      avatar: mediaFromVector(vector.notificationAvatar),
      containsContentImage: vector.notificationContainsContentImage,
      actions: vector.notificationActions.map(actionFromVector),
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

    const recoveryRequestId = fromHex(vector.notificationSnapshotRecoveryRequestIdHex);
    const request = createNotificationSnapshotRequestPayload({
      recoveryRequestId,
      resetHighWaterDeliveryId: BigInt(vector.notificationSnapshotResetHighWaterDeliveryId),
    });
    expect(encodeEncryptedPayloadV1(request))
      .toEqual(fromHex(vector.notificationSnapshotRequestEncodedHex));
    expect(decodeEncryptedPayloadV1(encodeEncryptedPayloadV1(request)).body.case)
      .toBe('notificationSnapshotRequest');

    const manifest = createNotificationSnapshotManifestPayload({
      highWaterRevision: BigInt(vector.notificationSnapshotHighWaterRevision),
      activeNotifications: vector.notificationSnapshotEntries.map((entry) => ({
        notificationId: entry.notificationId,
        notificationRevision: BigInt(entry.notificationRevision),
      })),
      recoveryRequestId,
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

    const zeroRecoveryId = validManifest();
    if (zeroRecoveryId.body.case === 'notificationSnapshotManifest') {
      zeroRecoveryId.body.value.recoveryRequestId = new Uint8Array(16);
    }
    expect(() => encodeEncryptedPayloadV1(zeroRecoveryId)).toThrow(/non-zero/i);

    const invalidRequest = createNotificationSnapshotRequestPayload({
      recoveryRequestId: new Uint8Array(16),
      resetHighWaterDeliveryId: 9n,
    });
    expect(() => encodeEncryptedPayloadV1(invalidRequest)).toThrow(/non-zero/i);

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

  it('rejects invalid notification media', () => {
    const validMediaPayload = () => createNotificationUpsertPayload({
      notificationId: vector.notificationPayloadId,
      notificationRevision: 7n,
      sourceApplicationId: vector.notificationSourceApplicationId,
      sourceApplicationName: vector.notificationSourceApplicationName,
      title: vector.notificationTitle,
      appIcon: mediaFromVector(vector.notificationAppIcon),
    });

    const invalidAction = createNotificationUpsertPayload({
      notificationId: vector.notificationPayloadId,
      notificationRevision: 7n,
      sourceApplicationId: vector.notificationSourceApplicationId,
      sourceApplicationName: vector.notificationSourceApplicationName,
      title: vector.notificationTitle,
      actions: [create(NotificationActionDescriptorSchema, {
        actionId: new Uint8Array(16).fill(1),
        title: 'Reply',
        allowsFreeFormInput: true,
      })],
    });
    expect(() => encodeEncryptedPayloadV1(invalidAction)).toThrow(/requiring text input/i);

    const wrongDigest = validMediaPayload();
    if (wrongDigest.body.case === 'notificationUpsert') {
      wrongDigest.body.value.appIcon!.contentSha256 = new Uint8Array(32);
    }
    expect(() => encodeEncryptedPayloadV1(wrongDigest)).toThrow(/SHA-256/i);

    const unsupportedMime = validMediaPayload();
    if (unsupportedMime.body.case === 'notificationUpsert') {
      unsupportedMime.body.value.appIcon!.mimeType = NotificationMediaMimeType.UNSPECIFIED;
    }
    expect(() => encodeEncryptedPayloadV1(unsupportedMime)).toThrow(/MIME/i);

    const invalidDimension = validMediaPayload();
    if (invalidDimension.body.case === 'notificationUpsert') {
      invalidDimension.body.value.appIcon!.width = 0;
    }
    expect(() => encodeEncryptedPayloadV1(invalidDimension)).toThrow(/dimensions/i);

    const oversized = validMediaPayload();
    if (oversized.body.case === 'notificationUpsert') {
      oversized.body.value.appIcon!.encodedBytes = new Uint8Array(128 * 1_024 + 1);
    }
    expect(() => encodeEncryptedPayloadV1(oversized)).toThrow(/bytes/i);

    const wrongSignature = validMediaPayload();
    if (wrongSignature.body.case === 'notificationUpsert') {
      wrongSignature.body.value.appIcon!.mimeType = NotificationMediaMimeType.WEBP;
    }
    expect(() => encodeEncryptedPayloadV1(wrongSignature)).toThrow(/WebP signature/i);

    const missingPlaceholder = validMediaPayload();
    if (missingPlaceholder.body.case === 'notificationUpsert') {
      missingPlaceholder.body.value.containsContentImage = true;
    }
    expect(() => encodeEncryptedPayloadV1(missingPlaceholder)).toThrow(/placeholder/i);
  });

  it('rejects invalid notification fields and schema mismatch', () => {
    const missingText = createNotificationUpsertPayload({
      notificationId: vector.notificationPayloadId,
      notificationRevision: 7n,
      sourceApplicationId: vector.notificationSourceApplicationId,
      sourceApplicationName: vector.notificationSourceApplicationName,
    });
    expect(() => encodeEncryptedPayloadV1(missingText)).toThrow(/title or body/i);

    const missingApplication = createNotificationUpsertPayload({
      notificationId: vector.notificationPayloadId,
      notificationRevision: 7n,
      title: vector.notificationTitle,
      sourceApplicationId: '',
      sourceApplicationName: vector.notificationSourceApplicationName,
    });
    expect(() => encodeEncryptedPayloadV1(missingApplication)).toThrow(/application id/i);

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

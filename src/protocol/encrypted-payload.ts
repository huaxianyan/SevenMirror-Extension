import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import {
  ActionInvokeSchema,
  ActionResultSchema,
  ActionResultAckSchema,
  ActionResultStatus,
  EncryptedPayloadSchema,
  NotificationRemovedSchema,
  NotificationSnapshotManifestSchema,
  NotificationUpsertSchema,
  type ActionInvoke,
  type ActionResult,
  type ActionResultAck,
  type EncryptedPayload,
  type NotificationRemoved,
  type NotificationSnapshotManifest,
  type NotificationUpsert,
} from './generated/notification/v1/payload_pb';

export const ENCRYPTED_PAYLOAD_LIMITS = {
  schemaVersion: 1,
  notificationSchemaVersion: 3,
  maxPlaintextSize: 524_272,
  maxNotificationIdBytes: 512,
  maxNotificationTitleBytes: 512,
  maxNotificationBodyBytes: 4_000,
  maxSnapshotEntries: 200,
  maxReplyTextBytes: 4_000,
  maxResultDetailBytes: 256,
  identifierSize: 16,
  sha256Size: 32,
  maxNotificationRevision: 0x7fff_ffff_ffff_ffffn,
} as const;

const encoder = new TextEncoder();

export function createNotificationUpsertPayload(
  notification: Omit<NotificationUpsert, '$typeName'>,
): EncryptedPayload {
  return create(EncryptedPayloadSchema, {
    schemaVersion: ENCRYPTED_PAYLOAD_LIMITS.notificationSchemaVersion,
    body: {
      case: 'notificationUpsert',
      value: create(NotificationUpsertSchema, notification),
    },
  });
}

export function createNotificationRemovedPayload(
  notification: Omit<NotificationRemoved, '$typeName'>,
): EncryptedPayload {
  return create(EncryptedPayloadSchema, {
    schemaVersion: ENCRYPTED_PAYLOAD_LIMITS.notificationSchemaVersion,
    body: {
      case: 'notificationRemoved',
      value: create(NotificationRemovedSchema, notification),
    },
  });
}

export function createNotificationSnapshotManifestPayload(
  manifest: {
    highWaterRevision: bigint;
    activeNotifications: Array<{ notificationId: string; notificationRevision: bigint }>;
  },
): EncryptedPayload {
  return create(EncryptedPayloadSchema, {
    schemaVersion: ENCRYPTED_PAYLOAD_LIMITS.notificationSchemaVersion,
    body: {
      case: 'notificationSnapshotManifest',
      value: create(NotificationSnapshotManifestSchema, manifest),
    },
  });
}

export function createActionInvokePayload(
  action: Omit<ActionInvoke, '$typeName'>,
): EncryptedPayload {
  return create(EncryptedPayloadSchema, {
    schemaVersion: ENCRYPTED_PAYLOAD_LIMITS.schemaVersion,
    body: {
      case: 'actionInvoke',
      value: create(ActionInvokeSchema, action),
    },
  });
}

export function createActionResultPayload(
  result: Omit<ActionResult, '$typeName'>,
): EncryptedPayload {
  return create(EncryptedPayloadSchema, {
    schemaVersion: ENCRYPTED_PAYLOAD_LIMITS.schemaVersion,
    body: {
      case: 'actionResult',
      value: create(ActionResultSchema, result),
    },
  });
}

export function createActionResultAckPayload(
  ack: Omit<ActionResultAck, '$typeName'>,
): EncryptedPayload {
  return create(EncryptedPayloadSchema, {
    schemaVersion: ENCRYPTED_PAYLOAD_LIMITS.schemaVersion,
    body: {
      case: 'actionResultAck',
      value: create(ActionResultAckSchema, ack),
    },
  });
}

export function encodeEncryptedPayloadV1(payload: EncryptedPayload): Uint8Array {
  validateEncryptedPayloadV1(payload);
  const encoded = toBinary(EncryptedPayloadSchema, payload);
  validateSize(encoded);
  return encoded;
}

export function decodeEncryptedPayloadV1(encoded: Uint8Array): EncryptedPayload {
  validateSize(encoded);
  const payload = fromBinary(EncryptedPayloadSchema, encoded, {
    readUnknownFields: true,
  });
  validateEncryptedPayloadV1(payload);
  const canonical = toBinary(EncryptedPayloadSchema, payload);
  if (!arraysEqual(encoded, canonical)) {
    throw new Error('Encrypted payload is not canonically encoded');
  }
  return payload;
}

export function validateEncryptedPayloadV1(payload: EncryptedPayload): void {
  if (payload.$unknown?.length) {
    throw new Error('Encrypted payload contains unknown fields');
  }
  switch (payload.body.case) {
    case 'actionInvoke':
      requireSchema(payload, ENCRYPTED_PAYLOAD_LIMITS.schemaVersion);
      validateAction(payload.body.value);
      return;
    case 'actionResult':
      requireSchema(payload, ENCRYPTED_PAYLOAD_LIMITS.schemaVersion);
      validateResult(payload.body.value);
      return;
    case 'actionResultAck':
      requireSchema(payload, ENCRYPTED_PAYLOAD_LIMITS.schemaVersion);
      validateResultAck(payload.body.value);
      return;
    case 'notificationUpsert':
      requireSchema(payload, ENCRYPTED_PAYLOAD_LIMITS.notificationSchemaVersion);
      validateNotificationUpsert(payload.body.value);
      return;
    case 'notificationRemoved':
      requireSchema(payload, ENCRYPTED_PAYLOAD_LIMITS.notificationSchemaVersion);
      validateNotificationRemoved(payload.body.value);
      return;
    case 'notificationSnapshotManifest':
      requireSchema(payload, ENCRYPTED_PAYLOAD_LIMITS.notificationSchemaVersion);
      validateNotificationSnapshotManifest(payload.body.value);
      return;
    default:
      throw new Error('Exactly one supported encrypted payload body is required');
  }
}

function requireSchema(payload: EncryptedPayload, expected: number): void {
  if (payload.schemaVersion !== expected) {
    throw new Error('Encrypted payload schema version does not match body');
  }
}

function validateNotificationUpsert(notification: NotificationUpsert): void {
  if (notification.$unknown?.length) {
    throw new Error('Notification upsert contains unknown fields');
  }
  validateNotificationBinding(notification.notificationId, notification.notificationRevision);
  if (notification.title === undefined && notification.body === undefined) {
    throw new Error('Notification upsert requires title or body');
  }
  if (notification.title !== undefined) {
    validateText(notification.title, ENCRYPTED_PAYLOAD_LIMITS.maxNotificationTitleBytes, 'Notification title');
  }
  if (notification.body !== undefined) {
    validateText(notification.body, ENCRYPTED_PAYLOAD_LIMITS.maxNotificationBodyBytes, 'Notification body');
  }
}

function validateNotificationRemoved(notification: NotificationRemoved): void {
  if (notification.$unknown?.length) {
    throw new Error('Notification removed contains unknown fields');
  }
  validateNotificationBinding(notification.notificationId, notification.notificationRevision);
}

function validateNotificationSnapshotManifest(manifest: NotificationSnapshotManifest): void {
  if (manifest.$unknown?.length) {
    throw new Error('Notification snapshot manifest contains unknown fields');
  }
  if (manifest.highWaterRevision < 0n ||
      manifest.highWaterRevision > ENCRYPTED_PAYLOAD_LIMITS.maxNotificationRevision) {
    throw new Error('Notification snapshot high-water revision is out of range');
  }
  if (manifest.activeNotifications.length > ENCRYPTED_PAYLOAD_LIMITS.maxSnapshotEntries) {
    throw new Error('Notification snapshot has too many active entries');
  }
  let previousId: Uint8Array | undefined;
  for (const entry of manifest.activeNotifications) {
    if (entry.$unknown?.length) {
      throw new Error('Notification snapshot entry contains unknown fields');
    }
    validateNotificationBinding(entry.notificationId, entry.notificationRevision);
    if (entry.notificationRevision > manifest.highWaterRevision) {
      throw new Error('Notification snapshot entry exceeds high-water revision');
    }
    const id = encoder.encode(entry.notificationId);
    if (previousId !== undefined && compareUnsigned(previousId, id) >= 0) {
      throw new Error('Notification snapshot entries are not unique and strictly sorted');
    }
    previousId = id;
  }
}

function compareUnsigned(left: Uint8Array, right: Uint8Array): number {
  const commonLength = Math.min(left.byteLength, right.byteLength);
  for (let index = 0; index < commonLength; index += 1) {
    const difference = left[index] - right[index];
    if (difference !== 0) return difference;
  }
  return left.byteLength - right.byteLength;
}

function validateNotificationBinding(notificationId: string, revision: bigint): void {
  const notificationIdSize = encoder.encode(notificationId).byteLength;
  if (notificationIdSize < 1 || notificationIdSize > ENCRYPTED_PAYLOAD_LIMITS.maxNotificationIdBytes) {
    throw new Error('Notification id is out of range');
  }
  if (revision < 1n || revision > ENCRYPTED_PAYLOAD_LIMITS.maxNotificationRevision) {
    throw new Error('Notification revision is out of range');
  }
}

function validateText(value: string, maximumBytes: number, name: string): void {
  const size = encoder.encode(value).byteLength;
  if (size < 1 || size > maximumBytes) {
    throw new Error(`${name} is out of range`);
  }
}

function validateAction(action: ActionInvoke): void {
  if (action.$unknown?.length) {
    throw new Error('Action invocation contains unknown fields');
  }
  validateNotificationBinding(action.notificationId, action.notificationRevision);
  if (action.actionId.byteLength !== ENCRYPTED_PAYLOAD_LIMITS.identifierSize) {
    throw new Error('Action id must be 16 bytes');
  }
  if (action.idempotencyKey.byteLength !== ENCRYPTED_PAYLOAD_LIMITS.identifierSize ||
      action.idempotencyKey.every((value) => value === 0)) {
    throw new Error('Idempotency key must be a non-zero 16-byte value');
  }
  if (action.replyText !== undefined) {
    const replySize = encoder.encode(action.replyText).byteLength;
    if (replySize < 1 || replySize > ENCRYPTED_PAYLOAD_LIMITS.maxReplyTextBytes) {
      throw new Error('Reply text is out of range');
    }
  }
}

function validateResult(result: ActionResult): void {
  if (result.$unknown?.length) {
    throw new Error('Action result contains unknown fields');
  }
  if (result.idempotencyKey.byteLength !== ENCRYPTED_PAYLOAD_LIMITS.identifierSize ||
      result.idempotencyKey.every((value) => value === 0)) {
    throw new Error('Idempotency key must be a non-zero 16-byte value');
  }
  if (result.status < ActionResultStatus.SUCCEEDED ||
      result.status > ActionResultStatus.OUTCOME_UNKNOWN) {
    throw new Error('Action result status is unsupported');
  }
  if (result.detail !== undefined) {
    const detailSize = encoder.encode(result.detail).byteLength;
    if (detailSize < 1 || detailSize > ENCRYPTED_PAYLOAD_LIMITS.maxResultDetailBytes) {
      throw new Error('Action result detail is out of range');
    }
  }
}

function validateResultAck(ack: ActionResultAck): void {
  if (ack.$unknown?.length) {
    throw new Error('Action result acknowledgement contains unknown fields');
  }
  if (ack.idempotencyKey.byteLength !== ENCRYPTED_PAYLOAD_LIMITS.identifierSize ||
      ack.idempotencyKey.every((value) => value === 0)) {
    throw new Error('Idempotency key must be a non-zero 16-byte value');
  }
  if (ack.resultSha256.byteLength !== ENCRYPTED_PAYLOAD_LIMITS.sha256Size ||
      ack.resultSha256.every((value) => value === 0)) {
    throw new Error('Result SHA-256 must be a non-zero 32-byte value');
  }
}

function validateSize(encoded: Uint8Array): void {
  if (encoded.byteLength < 1 || encoded.byteLength > ENCRYPTED_PAYLOAD_LIMITS.maxPlaintextSize) {
    throw new Error('Encrypted payload size is out of range');
  }
}

function arraysEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength &&
    left.every((value, index) => value === right[index]);
}

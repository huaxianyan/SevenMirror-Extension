import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { sha256 } from '@noble/hashes/sha256';
import {
  ActionInvokeSchema,
  ActionResultSchema,
  ActionResultAckSchema,
  ActionResultStatus,
  EncryptedPayloadSchema,
  NotificationMediaMimeType,
  NotificationRemovedSchema,
  NotificationSnapshotManifestSchema,
  NotificationUpsertSchema,
  type ActionInvoke,
  type ActionResult,
  type ActionResultAck,
  type EncryptedPayload,
  type NotificationActionDescriptor,
  type NotificationMedia,
  type NotificationRemoved,
  type NotificationSnapshotManifest,
  type NotificationUpsert,
} from './generated/notification/v1/payload_pb';

export const ENCRYPTED_PAYLOAD_LIMITS = {
  schemaVersion: 2,
  notificationSchemaVersion: 5,
  maxPlaintextSize: 524_272,
  maxNotificationIdBytes: 512,
  maxNotificationTitleBytes: 512,
  maxNotificationBodyBytes: 4_000,
  maxNotificationActions: 16,
  maxNotificationActionTitleBytes: 256,
  maxNotificationMediaBytes: 128 * 1_024,
  maxNotificationMediaDimension: 256,
  maxSnapshotEntries: 200,
  maxReplyTextBytes: 4_000,
  maxResultDetailBytes: 256,
  identifierSize: 16,
  sha256Size: 32,
  maxNotificationRevision: 0x7fff_ffff_ffff_ffffn,
} as const;

const encoder = new TextEncoder();
const PNG_SIGNATURE = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const RIFF_SIGNATURE = encoder.encode('RIFF');
const WEBP_SIGNATURE = encoder.encode('WEBP');

export function createNotificationUpsertPayload(
  notification: Omit<NotificationUpsert, '$typeName' | 'containsContentImage' | 'actions'> & {
    containsContentImage?: boolean;
    actions?: NotificationUpsert['actions'];
  },
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

export interface ActionInvokeInput {
  notificationId: string;
  notificationRevision: bigint;
  actionId?: Uint8Array;
  idempotencyKey: Uint8Array;
  replyText?: string;
  dismissNotification?: boolean;
}

export function createActionInvokePayload(
  action: ActionInvokeInput,
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
  if (notification.containsContentImage &&
      (notification.body === undefined || !notification.body.includes('[图片]'))) {
    throw new Error('Notification content image requires a body placeholder');
  }
  if (notification.appIcon !== undefined) {
    validateNotificationMedia(notification.appIcon);
  }
  if (notification.avatar !== undefined) {
    validateNotificationMedia(notification.avatar);
  }
  if (notification.actions.length > ENCRYPTED_PAYLOAD_LIMITS.maxNotificationActions) {
    throw new Error('Notification has too many actions');
  }
  const actionIds = new Set<string>();
  for (const action of notification.actions) {
    validateNotificationActionDescriptor(action);
    const actionId = toHex(action.actionId);
    if (actionIds.has(actionId)) {
      throw new Error('Notification action ids must be unique');
    }
    actionIds.add(actionId);
  }
}

function validateNotificationActionDescriptor(action: NotificationActionDescriptor): void {
  if (action.$unknown?.length) {
    throw new Error('Notification action contains unknown fields');
  }
  if (action.actionId.byteLength !== ENCRYPTED_PAYLOAD_LIMITS.identifierSize) {
    throw new Error('Notification action id must be 16 bytes');
  }
  validateText(action.title, ENCRYPTED_PAYLOAD_LIMITS.maxNotificationActionTitleBytes,
    'Notification action title');
  if (action.allowsFreeFormInput && !action.requiresTextInput) {
    throw new Error('Notification action cannot allow text without requiring text input');
  }
}

function validateNotificationMedia(media: NotificationMedia): void {
  if (media.$unknown?.length) {
    throw new Error('Notification media contains unknown fields');
  }
  if (media.encodedBytes.byteLength < 1 ||
      media.encodedBytes.byteLength > ENCRYPTED_PAYLOAD_LIMITS.maxNotificationMediaBytes) {
    throw new Error('Notification media bytes are out of range');
  }
  if (media.width < 1 || media.width > ENCRYPTED_PAYLOAD_LIMITS.maxNotificationMediaDimension ||
      media.height < 1 || media.height > ENCRYPTED_PAYLOAD_LIMITS.maxNotificationMediaDimension) {
    throw new Error('Notification media dimensions are out of range');
  }
  if (!arraysEqual(media.contentSha256, sha256(media.encodedBytes))) {
    throw new Error('Notification media SHA-256 does not match encoded bytes');
  }
  switch (media.mimeType) {
    case NotificationMediaMimeType.PNG:
      if (!hasBytesAt(media.encodedBytes, 0, PNG_SIGNATURE)) {
        throw new Error('Notification media does not have a PNG signature');
      }
      return;
    case NotificationMediaMimeType.WEBP:
      if (media.encodedBytes.byteLength < 12 ||
          !hasBytesAt(media.encodedBytes, 0, RIFF_SIGNATURE) ||
          !hasBytesAt(media.encodedBytes, 8, WEBP_SIGNATURE)) {
        throw new Error('Notification media does not have a WebP signature');
      }
      return;
    default:
      throw new Error('Notification media MIME type is unsupported');
  }
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function hasBytesAt(value: Uint8Array, offset: number, expected: Uint8Array): boolean {
  return value.byteLength >= offset + expected.byteLength &&
    expected.every((byte, index) => value[offset + index] === byte);
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
  if (action.idempotencyKey.byteLength !== ENCRYPTED_PAYLOAD_LIMITS.identifierSize ||
      action.idempotencyKey.every((value) => value === 0)) {
    throw new Error('Idempotency key must be a non-zero 16-byte value');
  }
  if (action.dismissNotification) {
    if (action.actionId.byteLength !== 0 || action.replyText !== undefined) {
      throw new Error('Dismiss invocation cannot include an action id or reply text');
    }
    return;
  }
  if (action.actionId.byteLength !== ENCRYPTED_PAYLOAD_LIMITS.identifierSize) {
    throw new Error('Action id must be 16 bytes');
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

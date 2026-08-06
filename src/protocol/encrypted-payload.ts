import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import {
  ActionInvokeSchema,
  ActionResultSchema,
  ActionResultStatus,
  EncryptedPayloadSchema,
  type ActionInvoke,
  type ActionResult,
  type EncryptedPayload,
} from './generated/notification/v1/payload_pb';

export const ENCRYPTED_PAYLOAD_LIMITS = {
  schemaVersion: 1,
  maxPlaintextSize: 524_272,
  maxNotificationIdBytes: 512,
  maxReplyTextBytes: 4_000,
  maxResultDetailBytes: 256,
  identifierSize: 16,
  maxNotificationRevision: 0x7fff_ffff_ffff_ffffn,
} as const;

const encoder = new TextEncoder();

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
  if (payload.schemaVersion !== ENCRYPTED_PAYLOAD_LIMITS.schemaVersion) {
    throw new Error('Unsupported encrypted payload schema version');
  }
  switch (payload.body.case) {
    case 'actionInvoke':
      validateAction(payload.body.value);
      return;
    case 'actionResult':
      validateResult(payload.body.value);
      return;
    default:
      throw new Error('Exactly one supported encrypted payload body is required');
  }
}

function validateAction(action: ActionInvoke): void {
  if (action.$unknown?.length) {
    throw new Error('Action invocation contains unknown fields');
  }
  const notificationIdSize = encoder.encode(action.notificationId).byteLength;
  if (notificationIdSize < 1 || notificationIdSize > ENCRYPTED_PAYLOAD_LIMITS.maxNotificationIdBytes) {
    throw new Error('Notification id is out of range');
  }
  if (action.notificationRevision < 1n ||
      action.notificationRevision > ENCRYPTED_PAYLOAD_LIMITS.maxNotificationRevision) {
    throw new Error('Notification revision is out of range');
  }
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

function validateSize(encoded: Uint8Array): void {
  if (encoded.byteLength < 1 || encoded.byteLength > ENCRYPTED_PAYLOAD_LIMITS.maxPlaintextSize) {
    throw new Error('Encrypted payload size is out of range');
  }
}

function arraysEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength &&
    left.every((value, index) => value === right[index]);
}

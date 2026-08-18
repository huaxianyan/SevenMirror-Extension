import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import {
  EncryptedPayloadSchema,
  IdentityKeyTransitionSchema,
  IdentityKeyTransitionAckSchema,
  IdentityKeyTransitionCommitSchema,
  type EncryptedPayload,
  type IdentityKeyTransition,
  type IdentityKeyTransitionAck,
  type IdentityKeyTransitionCommit,
} from './generated/notification/v1/payload_pb';

export const IDENTITY_KEY_TRANSITION_LIMITS = {
  schemaVersion: 2,
  maxPlaintextSize: 524_272,
  identifierSize: 16,
  sha256Size: 32,
  p256PublicKeySize: 65,
} as const;

export function createIdentityKeyTransitionPayload(
  transition: Omit<IdentityKeyTransition, '$typeName'>,
): EncryptedPayload {
  return create(EncryptedPayloadSchema, {
    schemaVersion: IDENTITY_KEY_TRANSITION_LIMITS.schemaVersion,
    body: {
      case: 'identityKeyTransition',
      value: create(IdentityKeyTransitionSchema, transition),
    },
  });
}

export function createIdentityKeyTransitionAckPayload(
  ack: Omit<IdentityKeyTransitionAck, '$typeName'>,
): EncryptedPayload {
  return create(EncryptedPayloadSchema, {
    schemaVersion: IDENTITY_KEY_TRANSITION_LIMITS.schemaVersion,
    body: {
      case: 'identityKeyTransitionAck',
      value: create(IdentityKeyTransitionAckSchema, ack),
    },
  });
}

export function createIdentityKeyTransitionCommitPayload(
  commit: Omit<IdentityKeyTransitionCommit, '$typeName'>,
): EncryptedPayload {
  return create(EncryptedPayloadSchema, {
    schemaVersion: IDENTITY_KEY_TRANSITION_LIMITS.schemaVersion,
    body: {
      case: 'identityKeyTransitionCommit',
      value: create(IdentityKeyTransitionCommitSchema, commit),
    },
  });
}

export async function encodeIdentityKeyLifecyclePayload(
  payload: EncryptedPayload,
): Promise<Uint8Array> {
  await validateIdentityKeyLifecyclePayload(payload);
  const encoded = toBinary(EncryptedPayloadSchema, payload);
  validateSize(encoded);
  return encoded;
}

export async function decodeIdentityKeyLifecyclePayload(
  encoded: Uint8Array,
): Promise<EncryptedPayload> {
  validateSize(encoded);
  const payload = fromBinary(EncryptedPayloadSchema, encoded, { readUnknownFields: true });
  await validateIdentityKeyLifecyclePayload(payload);
  const canonical = toBinary(EncryptedPayloadSchema, payload);
  if (!arraysEqual(encoded, canonical)) {
    throw new Error('Encrypted payload is not canonically encoded');
  }
  return payload;
}

export async function validateIdentityKeyLifecyclePayload(
  payload: EncryptedPayload,
): Promise<void> {
  if (payload.$unknown?.length) {
    throw new Error('Encrypted payload contains unknown fields');
  }
  if (payload.schemaVersion !== IDENTITY_KEY_TRANSITION_LIMITS.schemaVersion) {
    throw new Error('Encrypted payload schema version does not match body');
  }
  switch (payload.body.case) {
    case 'identityKeyTransition':
      await validateTransition(payload.body.value);
      return;
    case 'identityKeyTransitionAck':
      validateAck(payload.body.value);
      return;
    case 'identityKeyTransitionCommit':
      validateCommit(payload.body.value);
      return;
    default:
      throw new Error('Exactly one identity lifecycle payload body is required');
  }
}

async function validateTransition(transition: IdentityKeyTransition): Promise<void> {
  rejectUnknown(transition, 'Identity key transition');
  validateTransitionBinding(
    transition.transitionId,
    transition.previousKeyId,
    transition.newKeyId,
  );
  validateP256PublicKey(transition.newPublicKey);
  if (!arraysEqual(await sha256(transition.newPublicKey), transition.newKeyId)) {
    throw new Error('New identity key id must equal SHA-256 of public key');
  }
}

function validateAck(ack: IdentityKeyTransitionAck): void {
  rejectUnknown(ack, 'Identity key transition acknowledgement');
  validateTransitionBinding(ack.transitionId, ack.previousKeyId, ack.newKeyId);
  validateNonZero(ack.transitionSha256, IDENTITY_KEY_TRANSITION_LIMITS.sha256Size,
    'Transition SHA-256');
}

function validateCommit(commit: IdentityKeyTransitionCommit): void {
  rejectUnknown(commit, 'Identity key transition commit');
  validateTransitionBinding(commit.transitionId, commit.previousKeyId, commit.newKeyId);
  validateNonZero(commit.transitionSha256, IDENTITY_KEY_TRANSITION_LIMITS.sha256Size,
    'Transition SHA-256');
  validateNonZero(commit.ackSha256, IDENTITY_KEY_TRANSITION_LIMITS.sha256Size,
    'Transition acknowledgement SHA-256');
}

function validateTransitionBinding(
  transitionId: Uint8Array,
  previousKeyId: Uint8Array,
  newKeyId: Uint8Array,
): void {
  validateNonZero(transitionId, IDENTITY_KEY_TRANSITION_LIMITS.identifierSize, 'Transition id');
  validateNonZero(previousKeyId, IDENTITY_KEY_TRANSITION_LIMITS.sha256Size,
    'Previous identity key id');
  validateNonZero(newKeyId, IDENTITY_KEY_TRANSITION_LIMITS.sha256Size, 'New identity key id');
  if (arraysEqual(previousKeyId, newKeyId)) {
    throw new Error('New identity key must differ from previous key');
  }
}

function validateP256PublicKey(value: Uint8Array): void {
  if (value.byteLength !== IDENTITY_KEY_TRANSITION_LIMITS.p256PublicKeySize || value[0] !== 4) {
    throw new Error('New identity public key must be an uncompressed P-256 point');
  }
  const x = bytesToBigInt(value.subarray(1, 33));
  const y = bytesToBigInt(value.subarray(33, 65));
  if (x >= P256_P || y >= P256_P || mod(y * y) !== mod(x * x * x - 3n * x + P256_B)) {
    throw new Error('New identity public key must be a valid P-256 point');
  }
}

function validateNonZero(value: Uint8Array, size: number, name: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== size ||
      value.every((byte) => byte === 0)) {
    throw new Error(`${name} must be a non-zero ${size}-byte value`);
  }
}

function rejectUnknown(value: { $unknown?: unknown[] }, name: string): void {
  if (value.$unknown?.length) throw new Error(`${name} contains unknown fields`);
}

function validateSize(encoded: Uint8Array): void {
  if (encoded.byteLength < 1 ||
      encoded.byteLength > IDENTITY_KEY_TRANSITION_LIMITS.maxPlaintextSize) {
    throw new Error('Encrypted payload size is out of range');
  }
}

function bytesToBigInt(value: Uint8Array): bigint {
  let result = 0n;
  for (const byte of value) result = (result << 8n) | BigInt(byte);
  return result;
}

function mod(value: bigint): bigint {
  const result = value % P256_P;
  return result < 0n ? result + P256_P : result;
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  const input = new Uint8Array(value.byteLength);
  input.set(value);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input));
}

function arraysEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength &&
    left.every((value, index) => value === right[index]);
}

const P256_P = BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
const P256_B = BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b');

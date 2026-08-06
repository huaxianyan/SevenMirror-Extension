export interface RoutingHeaderV1 {
  workspaceId: Uint8Array;
  senderDeviceId: Uint8Array;
  recipientDeviceId: Uint8Array;
  senderKeyId: Uint8Array;
  recipientKeyId: Uint8Array;
  messageId: Uint8Array;
  sequence: bigint;
  createdAtUnixMs: number;
  expiresAtUnixMs: number;
}

export const ROUTING_HEADER_V1_SIZE = 160;
export const ROUTING_HEADER_V1_SUITE_ID = 1;
export const ROUTING_HEADER_V1_MAX_TTL_MS = 24 * 60 * 60 * 1000;

const magic = Uint8Array.of(0x53, 0x4e, 0x48, 0x31); // SNH1
const MAX_SEQUENCE = 0x7fff_ffff_ffff_ffffn;

/** Encodes the sole canonical 160-byte representation used directly as HPKE AAD. */
export function encodeRoutingHeaderV1(header: RoutingHeaderV1): Uint8Array {
  validateRoutingHeaderV1(header);
  const encoded = new Uint8Array(ROUTING_HEADER_V1_SIZE);
  const view = new DataView(encoded.buffer);
  encoded.set(magic, 0);
  view.setUint16(4, ROUTING_HEADER_V1_SUITE_ID, false);
  view.setUint16(6, 0, false);
  encoded.set(header.workspaceId, 8);
  encoded.set(header.senderDeviceId, 24);
  encoded.set(header.recipientDeviceId, 40);
  encoded.set(header.senderKeyId, 56);
  encoded.set(header.recipientKeyId, 88);
  encoded.set(header.messageId, 120);
  view.setBigUint64(136, header.sequence, false);
  view.setBigUint64(144, BigInt(header.createdAtUnixMs), false);
  view.setBigUint64(152, BigInt(header.expiresAtUnixMs), false);
  return encoded;
}

/**
 * Parses exact received AAD bytes. Callers must authenticate the original input
 * bytes and must never substitute a re-encoded copy for HPKE AAD.
 */
export function decodeRoutingHeaderV1(encoded: Uint8Array): RoutingHeaderV1 {
  if (!(encoded instanceof Uint8Array) || encoded.byteLength !== ROUTING_HEADER_V1_SIZE) {
    throw new Error(`routing header must be ${ROUTING_HEADER_V1_SIZE} bytes`);
  }
  if (!magic.every((value, index) => encoded[index] === value)) {
    throw new Error('unsupported routing header magic/version');
  }
  const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
  if (view.getUint16(4, false) !== ROUTING_HEADER_V1_SUITE_ID) {
    throw new Error('unsupported E2EE suite');
  }
  if (view.getUint16(6, false) !== 0) {
    throw new Error('reserved routing flags must be zero');
  }

  const header: RoutingHeaderV1 = {
    workspaceId: encoded.slice(8, 24),
    senderDeviceId: encoded.slice(24, 40),
    recipientDeviceId: encoded.slice(40, 56),
    senderKeyId: encoded.slice(56, 88),
    recipientKeyId: encoded.slice(88, 120),
    messageId: encoded.slice(120, 136),
    sequence: view.getBigUint64(136, false),
    createdAtUnixMs: safeNumber(view.getBigUint64(144, false), 'createdAtUnixMs'),
    expiresAtUnixMs: safeNumber(view.getBigUint64(152, false), 'expiresAtUnixMs'),
  };
  validateRoutingHeaderV1(header);
  return header;
}

export function validateRoutingHeaderV1(header: RoutingHeaderV1): void {
  validateId(header.workspaceId, 16, 'workspaceId');
  validateId(header.senderDeviceId, 16, 'senderDeviceId');
  validateId(header.recipientDeviceId, 16, 'recipientDeviceId');
  validateId(header.senderKeyId, 32, 'senderKeyId');
  validateId(header.recipientKeyId, 32, 'recipientKeyId');
  validateId(header.messageId, 16, 'messageId');
  if (typeof header.sequence !== 'bigint' || header.sequence < 1n || header.sequence > MAX_SEQUENCE) {
    throw new Error('sequence must be in 1..2^63-1');
  }
  validateTimestamp(header.createdAtUnixMs, 'createdAtUnixMs');
  validateTimestamp(header.expiresAtUnixMs, 'expiresAtUnixMs');
  if (header.expiresAtUnixMs <= header.createdAtUnixMs) {
    throw new Error('expiry must be greater than creation time');
  }
  if (header.expiresAtUnixMs - header.createdAtUnixMs > ROUTING_HEADER_V1_MAX_TTL_MS) {
    throw new Error('routing header TTL exceeds 24 hours');
  }
}

function validateId(value: Uint8Array, size: number, name: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== size) {
    throw new Error(`${name} must be ${size} bytes`);
  }
  if (value.every((byte) => byte === 0)) {
    throw new Error(`${name} must not be zero`);
  }
}

function validateTimestamp(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be in 0..2^53-1`);
  }
}

function safeNumber(value: bigint, name: string): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${name} must be in 0..2^53-1`);
  }
  return Number(value);
}

import { decodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';

const CONTROL_SIZE = 12;
const DELIVERY_PREFIX_SIZE = 12;
const MAX_CURSOR = 0x7fff_ffff_ffff_ffffn;
const textEncoder = new TextEncoder();
const ONLINE_MAGIC = textEncoder.encode('SNE1');
const SUBMISSION_MAGIC = textEncoder.encode('SNQ1');
const RESUME_MAGIC = textEncoder.encode('SNC1');
const ACK_MAGIC = textEncoder.encode('SNC2');
const DELIVERY_MAGIC = textEncoder.encode('SND1');
const CAUGHT_UP_MAGIC = textEncoder.encode('SND2');
const RESET_MAGIC = textEncoder.encode('SNR1');

export type RelayServerMessage =
  | { kind: 'online-envelope'; envelope: Uint8Array }
  | { kind: 'delivery'; deliveryId: bigint; envelope: Uint8Array }
  | { kind: 'caught-up'; highWater: bigint }
  | { kind: 'snapshot-required'; highWater: bigint };

export function encodeDurableSubmission(envelope: Uint8Array): Uint8Array {
  decodeEncryptedEnvelopeV1(envelope);
  const encoded = new Uint8Array(SUBMISSION_MAGIC.byteLength + envelope.byteLength);
  encoded.set(SUBMISSION_MAGIC);
  encoded.set(envelope, SUBMISSION_MAGIC.byteLength);
  return encoded;
}

export function encodeRelayResume(cursor: bigint): Uint8Array {
  return encodeControl(RESUME_MAGIC, cursor, true);
}

export function encodeRelayAcknowledgement(cursor: bigint): Uint8Array {
  return encodeControl(ACK_MAGIC, cursor, false);
}

export function decodeRelayServerMessage(data: ArrayBuffer): RelayServerMessage {
  const encoded = new Uint8Array(data.slice(0));
  if (startsWith(encoded, ONLINE_MAGIC)) {
    decodeEncryptedEnvelopeV1(encoded);
    return { kind: 'online-envelope', envelope: encoded };
  }
  if (startsWith(encoded, DELIVERY_MAGIC)) {
    if (encoded.byteLength <= DELIVERY_PREFIX_SIZE) {
      throw new Error('Relay delivery is missing its encrypted envelope');
    }
    const deliveryId = decodeCursor(encoded, false);
    const envelope = encoded.slice(DELIVERY_PREFIX_SIZE);
    decodeEncryptedEnvelopeV1(envelope);
    return { kind: 'delivery', deliveryId, envelope };
  }
  if (encoded.byteLength !== CONTROL_SIZE) {
    throw new Error('Unsupported relay server message');
  }
  if (startsWith(encoded, CAUGHT_UP_MAGIC)) {
    return { kind: 'caught-up', highWater: decodeCursor(encoded, true) };
  }
  if (startsWith(encoded, RESET_MAGIC)) {
    return { kind: 'snapshot-required', highWater: decodeCursor(encoded, true) };
  }
  throw new Error('Unsupported relay server message');
}

function encodeControl(magic: Uint8Array, cursor: bigint, allowZero: boolean): Uint8Array {
  validateCursor(cursor, allowZero);
  const encoded = new Uint8Array(CONTROL_SIZE);
  encoded.set(magic);
  new DataView(encoded.buffer).setBigUint64(4, cursor, false);
  return encoded;
}

function decodeCursor(encoded: Uint8Array, allowZero: boolean): bigint {
  const cursor = new DataView(
    encoded.buffer,
    encoded.byteOffset,
    encoded.byteLength,
  ).getBigUint64(4, false);
  validateCursor(cursor, allowZero);
  return cursor;
}

function validateCursor(cursor: bigint, allowZero: boolean): void {
  if (cursor > MAX_CURSOR || (!allowZero && cursor === 0n)) {
    throw new Error('Relay delivery cursor is out of range');
  }
}

function startsWith(encoded: Uint8Array, prefix: Uint8Array): boolean {
  if (encoded.byteLength < prefix.byteLength) return false;
  return prefix.every((byte, index) => encoded[index] === byte);
}

import {
  decodeRoutingHeaderV1,
  ROUTING_HEADER_V1_SIZE,
  type RoutingHeaderV1,
} from './routing-header';

export const ENVELOPE_V1_PREFIX_SIZE = 233;
export const ENVELOPE_V1_ENCAPSULATED_KEY_SIZE = 65;
export const ENVELOPE_V1_MIN_CIPHERTEXT_SIZE = 16;
export const ENVELOPE_V1_MAX_CIPHERTEXT_SIZE = 512 * 1024;
export const ENVELOPE_V1_MIN_FRAME_SIZE =
  ENVELOPE_V1_PREFIX_SIZE + ENVELOPE_V1_MIN_CIPHERTEXT_SIZE;
export const ENVELOPE_V1_MAX_FRAME_SIZE =
  ENVELOPE_V1_PREFIX_SIZE + ENVELOPE_V1_MAX_CIPHERTEXT_SIZE;

const magic = Uint8Array.of(0x53, 0x4e, 0x45, 0x31); // SNE1

export interface EncryptedEnvelopeV1 {
  routingHeaderBytes: Uint8Array;
  routingHeader: RoutingHeaderV1;
  encapsulatedKey: Uint8Array;
  ciphertext: Uint8Array;
}

export interface EnvelopeV1Parts {
  routingHeader: Uint8Array;
  encapsulatedKey: Uint8Array;
  ciphertext: Uint8Array;
}

export function encodeEncryptedEnvelopeV1(parts: EnvelopeV1Parts): Uint8Array {
  validateParts(parts);
  const encoded = new Uint8Array(ENVELOPE_V1_PREFIX_SIZE + parts.ciphertext.byteLength);
  const view = new DataView(encoded.buffer);
  encoded.set(magic, 0);
  encoded.set(parts.routingHeader, 4);
  encoded.set(parts.encapsulatedKey, 164);
  view.setUint32(229, parts.ciphertext.byteLength, false);
  encoded.set(parts.ciphertext, ENVELOPE_V1_PREFIX_SIZE);
  return encoded;
}

export function decodeEncryptedEnvelopeV1(encoded: Uint8Array): EncryptedEnvelopeV1 {
  if (
    !(encoded instanceof Uint8Array) ||
    encoded.byteLength < ENVELOPE_V1_MIN_FRAME_SIZE ||
    encoded.byteLength > ENVELOPE_V1_MAX_FRAME_SIZE
  ) {
    throw new Error(
      `encrypted envelope must be ${ENVELOPE_V1_MIN_FRAME_SIZE}..${ENVELOPE_V1_MAX_FRAME_SIZE} bytes`,
    );
  }
  if (!magic.every((value, index) => encoded[index] === value)) {
    throw new Error('unsupported encrypted envelope magic/version');
  }
  const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
  const ciphertextSize = view.getUint32(229, false);
  if (
    ciphertextSize < ENVELOPE_V1_MIN_CIPHERTEXT_SIZE ||
    ciphertextSize > ENVELOPE_V1_MAX_CIPHERTEXT_SIZE
  ) {
    throw new Error('ciphertext length is out of range');
  }
  if (encoded.byteLength !== ENVELOPE_V1_PREFIX_SIZE + ciphertextSize) {
    throw new Error('encrypted envelope length does not match ciphertext length');
  }

  const routingHeaderBytes = encoded.slice(4, 4 + ROUTING_HEADER_V1_SIZE);
  const encapsulatedKey = encoded.slice(164, 229);
  if (encapsulatedKey[0] !== 0x04) {
    throw new Error('encapsulated key must be an uncompressed P-256 point');
  }
  return {
    routingHeaderBytes,
    routingHeader: decodeRoutingHeaderV1(routingHeaderBytes),
    encapsulatedKey,
    ciphertext: encoded.slice(ENVELOPE_V1_PREFIX_SIZE),
  };
}

function validateParts(parts: EnvelopeV1Parts): void {
  if (!(parts.routingHeader instanceof Uint8Array) || parts.routingHeader.byteLength !== ROUTING_HEADER_V1_SIZE) {
    throw new Error(`routing header must be ${ROUTING_HEADER_V1_SIZE} bytes`);
  }
  decodeRoutingHeaderV1(parts.routingHeader);
  if (
    !(parts.encapsulatedKey instanceof Uint8Array) ||
    parts.encapsulatedKey.byteLength !== ENVELOPE_V1_ENCAPSULATED_KEY_SIZE ||
    parts.encapsulatedKey[0] !== 0x04
  ) {
    throw new Error('encapsulated key must be a 65-byte uncompressed P-256 point');
  }
  if (
    !(parts.ciphertext instanceof Uint8Array) ||
    parts.ciphertext.byteLength < ENVELOPE_V1_MIN_CIPHERTEXT_SIZE ||
    parts.ciphertext.byteLength > ENVELOPE_V1_MAX_CIPHERTEXT_SIZE
  ) {
    throw new Error('ciphertext length is out of range');
  }
}

export interface TrustOfferV1 {
  workspaceId: Uint8Array;
  deviceId: Uint8Array;
  publicKey: Uint8Array;
  nonce: Uint8Array;
  createdAtUnixMs: number;
  expiresAtUnixMs: number;
}

export interface TrustApprovalV1 {
  offerHash: Uint8Array;
  deviceId: Uint8Array;
  publicKey: Uint8Array;
  nonce: Uint8Array;
  createdAtUnixMs: number;
  expiresAtUnixMs: number;
}

export const TRUST_OFFER_V1_SIZE = 133;
export const TRUST_APPROVAL_V1_SIZE = 149;
export const TRUST_QR_PREFIX = 'sntrust1:';
export const TRUST_MAX_TTL_MS = 10 * 60 * 1_000;
export const TRUST_MAX_FUTURE_CLOCK_SKEW_MS = 5 * 60 * 1_000;
const SAFETY_DOMAIN = 'SyncNotifications-Trust-SAS-v1';
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const offerMagic = Uint8Array.of(0x53, 0x4e, 0x54, 0x31);
const approvalMagic = Uint8Array.of(0x53, 0x4e, 0x54, 0x32);

export function encodeTrustOfferV1(value: TrustOfferV1): Uint8Array {
  validateOffer(value);
  const encoded = new Uint8Array(TRUST_OFFER_V1_SIZE);
  encoded.set(offerMagic, 0);
  encoded.set(value.workspaceId, 4);
  encoded.set(value.deviceId, 20);
  encoded.set(value.publicKey, 36);
  encoded.set(value.nonce, 101);
  const view = new DataView(encoded.buffer);
  view.setBigUint64(117, BigInt(value.createdAtUnixMs), false);
  view.setBigUint64(125, BigInt(value.expiresAtUnixMs), false);
  return encoded;
}

export function decodeTrustOfferV1(encoded: Uint8Array): TrustOfferV1 {
  requireBytes(encoded, TRUST_OFFER_V1_SIZE, 'trust offer');
  if (!bytesEqual(encoded.subarray(0, 4), offerMagic)) {
    throw new Error('unsupported trust offer magic/version');
  }
  const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
  const value: TrustOfferV1 = {
    workspaceId: encoded.slice(4, 20),
    deviceId: encoded.slice(20, 36),
    publicKey: encoded.slice(36, 101),
    nonce: encoded.slice(101, 117),
    createdAtUnixMs: safeNumber(view.getBigUint64(117, false), 'createdAtUnixMs'),
    expiresAtUnixMs: safeNumber(view.getBigUint64(125, false), 'expiresAtUnixMs'),
  };
  validateOffer(value);
  return value;
}

export function encodeTrustApprovalV1(value: TrustApprovalV1): Uint8Array {
  validateApproval(value);
  const encoded = new Uint8Array(TRUST_APPROVAL_V1_SIZE);
  encoded.set(approvalMagic, 0);
  encoded.set(value.offerHash, 4);
  encoded.set(value.deviceId, 36);
  encoded.set(value.publicKey, 52);
  encoded.set(value.nonce, 117);
  const view = new DataView(encoded.buffer);
  view.setBigUint64(133, BigInt(value.createdAtUnixMs), false);
  view.setBigUint64(141, BigInt(value.expiresAtUnixMs), false);
  return encoded;
}

export function decodeTrustApprovalV1(encoded: Uint8Array): TrustApprovalV1 {
  requireBytes(encoded, TRUST_APPROVAL_V1_SIZE, 'trust approval');
  if (!bytesEqual(encoded.subarray(0, 4), approvalMagic)) {
    throw new Error('unsupported trust approval magic/version');
  }
  const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
  const value: TrustApprovalV1 = {
    offerHash: encoded.slice(4, 36),
    deviceId: encoded.slice(36, 52),
    publicKey: encoded.slice(52, 117),
    nonce: encoded.slice(117, 133),
    createdAtUnixMs: safeNumber(view.getBigUint64(133, false), 'createdAtUnixMs'),
    expiresAtUnixMs: safeNumber(view.getBigUint64(141, false), 'expiresAtUnixMs'),
  };
  validateApproval(value);
  return value;
}

export function encodeTrustQr(record: Uint8Array): string {
  decodeTrustRecord(record);
  let binary = '';
  for (const byte of record) binary += String.fromCharCode(byte);
  return TRUST_QR_PREFIX + btoa(binary)
    .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function decodeTrustQr(text: string): Uint8Array {
  if (text !== text.trim() || !text.startsWith(TRUST_QR_PREFIX)) {
    throw new Error('trust QR prefix or whitespace is invalid');
  }
  const body = text.slice(TRUST_QR_PREFIX.length);
  if (!/^[A-Za-z0-9_-]+$/.test(body) || body.includes('=')) {
    throw new Error('trust QR base64url is not canonical');
  }
  let binary: string;
  try {
    const padded = body.replaceAll('-', '+').replaceAll('_', '/') +
      '='.repeat((4 - (body.length % 4)) % 4);
    binary = atob(padded);
  } catch {
    throw new Error('trust QR base64url is invalid');
  }
  const record = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (encodeTrustQr(record) !== text) throw new Error('trust QR base64url is not canonical');
  return record;
}

export async function trustOfferHash(offerBytes: Uint8Array): Promise<Uint8Array> {
  decodeTrustOfferV1(offerBytes);
  return sha256(offerBytes);
}

export async function validateTrustPair(
  offerBytes: Uint8Array,
  approvalBytes: Uint8Array,
): Promise<void> {
  const offer = decodeTrustOfferV1(offerBytes);
  const approval = decodeTrustApprovalV1(approvalBytes);
  if (!bytesEqual(await sha256(offerBytes), approval.offerHash)) {
    throw new Error('approval does not bind the exact trust offer');
  }
  if (approval.expiresAtUnixMs > offer.expiresAtUnixMs) {
    throw new Error('approval expiry exceeds offer expiry');
  }
  if (bytesEqual(offer.deviceId, approval.deviceId)) {
    throw new Error('offerer and approver device IDs must differ');
  }
  if (bytesEqual(offer.publicKey, approval.publicKey)) {
    throw new Error('offerer and approver public keys must differ');
  }
}

export function validateTrustRecordActive(
  createdAtUnixMs: number,
  expiresAtUnixMs: number,
  nowUnixMs: number,
): void {
  validateTimestamp(nowUnixMs, 'nowUnixMs');
  if (createdAtUnixMs > nowUnixMs + TRUST_MAX_FUTURE_CLOCK_SKEW_MS) {
    throw new Error('trust record creation time exceeds clock-skew allowance');
  }
  if (expiresAtUnixMs <= nowUnixMs) throw new Error('trust record is expired');
}

export async function trustSafetyCode(
  offerBytes: Uint8Array,
  approvalBytes: Uint8Array,
): Promise<string> {
  await validateTrustPair(offerBytes, approvalBytes);
  const domain = new TextEncoder().encode(SAFETY_DOMAIN);
  const transcript = new Uint8Array(domain.length + offerBytes.length + approvalBytes.length);
  transcript.set(domain, 0);
  transcript.set(offerBytes, domain.length);
  transcript.set(approvalBytes, domain.length + offerBytes.length);
  const digest = await sha256(transcript);
  let raw = '';
  for (let index = 0; index < 12; index += 1) {
    const bit = index * 5;
    const byteIndex = Math.floor(bit / 8);
    const shift = 11 - (bit % 8);
    const pair = (digest[byteIndex]! << 8) | (digest[byteIndex + 1] ?? 0);
    raw += CROCKFORD[(pair >>> shift) & 31];
  }
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
}

function decodeTrustRecord(record: Uint8Array): void {
  if (!(record instanceof Uint8Array) || record.byteLength < 4) {
    throw new Error('trust record is truncated');
  }
  if (bytesEqual(record.subarray(0, 4), offerMagic)) decodeTrustOfferV1(record);
  else if (bytesEqual(record.subarray(0, 4), approvalMagic)) decodeTrustApprovalV1(record);
  else throw new Error('unsupported trust record magic/version');
}

function validateOffer(value: TrustOfferV1): void {
  validateNonZero(value.workspaceId, 16, 'workspaceId');
  validateNonZero(value.deviceId, 16, 'deviceId');
  validatePublicKey(value.publicKey);
  validateNonZero(value.nonce, 16, 'nonce');
  validateTtl(value.createdAtUnixMs, value.expiresAtUnixMs);
}

function validateApproval(value: TrustApprovalV1): void {
  validateNonZero(value.offerHash, 32, 'offerHash');
  validateNonZero(value.deviceId, 16, 'deviceId');
  validatePublicKey(value.publicKey);
  validateNonZero(value.nonce, 16, 'nonce');
  validateTtl(value.createdAtUnixMs, value.expiresAtUnixMs);
}

function validateTtl(createdAtUnixMs: number, expiresAtUnixMs: number): void {
  validateTimestamp(createdAtUnixMs, 'createdAtUnixMs');
  validateTimestamp(expiresAtUnixMs, 'expiresAtUnixMs');
  if (expiresAtUnixMs <= createdAtUnixMs ||
      expiresAtUnixMs - createdAtUnixMs > TRUST_MAX_TTL_MS) {
    throw new Error('trust record TTL must be in (0, 10 minutes]');
  }
}

function validatePublicKey(value: Uint8Array): void {
  validateNonZero(value, 65, 'publicKey');
  if (value[0] !== 4) throw new Error('trust public key must be an uncompressed P-256 point');
  const x = bytesToBigInt(value.subarray(1, 33));
  const y = bytesToBigInt(value.subarray(33, 65));
  if (x >= P256_P || y >= P256_P || mod(y * y) !== mod(x * x * x - 3n * x + P256_B)) {
    throw new Error('trust public key is not a valid P-256 point');
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

function requireBytes(value: Uint8Array, size: number, name: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== size) {
    throw new Error(`${name} must be ${size} bytes`);
  }
}

function validateNonZero(value: Uint8Array, size: number, name: string): void {
  requireBytes(value, size, name);
  if (value.every((byte) => byte === 0)) throw new Error(`${name} must not be zero`);
}

function validateTimestamp(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
}

function safeNumber(value: bigint, name: string): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${name} is out of range`);
  return Number(value);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

const P256_P = BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
const P256_B = BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b');

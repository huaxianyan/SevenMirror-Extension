import { create, fromBinary, toBinary, type DescMessage, type MessageShape } from '@bufbuild/protobuf';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { ed25519 } from '@noble/curves/ed25519';
import {
  DeviceCertificateSchema,
  DeviceRole,
  DeviceType,
  IdentityPossessionChallengeSchema,
  PendingIdentityProofSchema,
  SignedDeviceCertificateSchema,
  SignedWorkspaceRosterSchema,
  WorkspaceRosterSchema,
  type DeviceCertificate,
  type IdentityPossessionChallenge,
  type PendingIdentityProof,
  type SignedDeviceCertificate,
  type SignedWorkspaceRoster,
  type WorkspaceRoster,
} from './generated/membership/v1/membership_pb';

const LIMITS = Object.freeze({ version: 1, id: 16, digest: 32, p256: 65, signature: 64, maxName: 100, maxMessage: 1 << 20, maxActive: 256, maxRevocations: 4096, maxInteger: 0x7fff_ffff_ffff_ffffn, maxChallengeMs: 600_000n });
const domains = Object.freeze({
  hpkeInfo: 'SyncNotifications-membership-possession-hpke-info-v1\0',
  challengeDigest: 'SyncNotifications-membership-possession-challenge-digest-v1\0',
  certificateId: 'SyncNotifications-membership-device-certificate-id-v1\0',
  certificateSignature: 'SyncNotifications-membership-device-certificate-signature-v1\0',
  rosterDigest: 'SyncNotifications-membership-workspace-roster-digest-v1\0',
  rosterSignature: 'SyncNotifications-membership-workspace-roster-signature-v1\0',
});
const textEncoder = new TextEncoder();
const hpkeSuite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });

export function decodeIdentityPossessionChallenge(encoded: Uint8Array): IdentityPossessionChallenge {
  return decodeCanonical(IdentityPossessionChallengeSchema, encoded, validateChallenge);
}

export function encodeIdentityPossessionChallenge(value: IdentityPossessionChallenge): Uint8Array {
  validateChallenge(value);
  return encode(IdentityPossessionChallengeSchema, value);
}

export function encodePendingIdentityProof(proof: PendingIdentityProof): Uint8Array {
  validateProof(proof);
  return encode(PendingIdentityProofSchema, proof);
}

export function decodePendingIdentityProof(encoded: Uint8Array): PendingIdentityProof {
  return decodeCanonical(PendingIdentityProofSchema, encoded, validateProof);
}

export async function createPendingIdentityProof(canonicalChallenge: Uint8Array): Promise<Uint8Array> {
  const challenge = decodeIdentityPossessionChallenge(canonicalChallenge);
  return encodePendingIdentityProof(create(PendingIdentityProofSchema, {
    protocolVersion: LIMITS.version,
    workspaceId: challenge.workspaceId,
    deviceId: challenge.deviceId,
    identityKeyId: challenge.identityKeyId,
    challengeDigest: await domainHash(domains.challengeDigest, canonicalChallenge),
    challengeSecret: challenge.challengeSecret,
  }));
}

export async function openIdentityPossessionChallenge(
  recipientPrivateKey: CryptoKey,
  binding: { workspaceId: Uint8Array; deviceId: Uint8Array; identityKeyId: Uint8Array },
  encapsulatedKey: Uint8Array,
  ciphertext: Uint8Array,
): Promise<IdentityPossessionChallenge> {
  validateBinding(binding.workspaceId, binding.deviceId, binding.identityKeyId);
  const context = await hpkeSuite.createRecipientContext({
    recipientKey: recipientPrivateKey,
    enc: encapsulatedKey,
    info: concat(textEncoder.encode(domains.hpkeInfo), binding.workspaceId, binding.deviceId, binding.identityKeyId),
  });
  const plaintext = new Uint8Array(await context.open(ciphertext, new Uint8Array()));
  const challenge = decodeIdentityPossessionChallenge(plaintext);
  if (!equal(challenge.workspaceId, binding.workspaceId) || !equal(challenge.deviceId, binding.deviceId) || !equal(challenge.identityKeyId, binding.identityKeyId)) {
    throw new Error('Identity possession challenge binding does not match');
  }
  return challenge;
}

export function decodeSignedDeviceCertificate(encoded: Uint8Array): SignedDeviceCertificate {
  return decodeCanonical(SignedDeviceCertificateSchema, encoded, validateSignedCertificateStructure);
}

export function encodeSignedDeviceCertificate(value: SignedDeviceCertificate): Uint8Array {
  validateSignedCertificateStructure(value);
  return encode(SignedDeviceCertificateSchema, value);
}

export async function verifySignedDeviceCertificate(value: SignedDeviceCertificate, authorityPublicKey: Uint8Array): Promise<void> {
  validateSignedCertificateStructure(value);
  if (authorityPublicKey.byteLength !== 32) throw new Error('Authority public key must be Ed25519');
  const certificateBytes = encode(DeviceCertificateSchema, value.certificate!);
  const expectedId = await domainHash(domains.certificateId, certificateBytes);
  if (!equal(expectedId, value.certificateId)) throw new Error('Device certificate ID does not match canonical certificate');
  const identityKeyId = new Uint8Array(await crypto.subtle.digest('SHA-256', arrayBuffer(value.certificate!.identityPublicKey)));
  if (!equal(identityKeyId, value.certificate!.identityKeyId)) throw new Error('Device identity key ID does not match public key');
  await hpkeSuite.kem.deserializePublicKey(value.certificate!.identityPublicKey);
  const valid = await verifyEd25519(
    authorityPublicKey,
    value.authoritySignature,
    concat(textEncoder.encode(domains.certificateSignature), certificateBytes),
  );
  if (!valid) throw new Error('Device certificate authority signature is invalid');
}

export async function requireTransportCertificateBinding(
  encoded: Uint8Array,
  authorityPublicKey: Uint8Array,
  binding: { workspaceId: Uint8Array; deviceId: Uint8Array; identityKeyId: Uint8Array },
  nowUnixMs: bigint,
): Promise<void> {
  if (nowUnixMs < 1n || nowUnixMs > LIMITS.maxInteger) throw new Error('Current time is invalid');
  const signed = decodeSignedDeviceCertificate(encoded);
  await verifySignedDeviceCertificate(signed, authorityPublicKey);
  const certificate = signed.certificate!;
  if (!equal(certificate.workspaceId, binding.workspaceId) || !equal(certificate.deviceId, binding.deviceId) ||
      !equal(certificate.identityKeyId, binding.identityKeyId) || certificate.deviceType !== DeviceType.CHROME) {
    throw new Error('Device certificate is not bound to this transport identity');
  }
  if (certificate.issuedAtUnixMs > nowUnixMs) throw new Error('Device certificate is not yet valid');
  if (certificate.expiresAtUnixMs !== 0n && certificate.expiresAtUnixMs <= nowUnixMs) {
    throw new Error('Device certificate has expired');
  }
}

export function decodeSignedWorkspaceRoster(encoded: Uint8Array): SignedWorkspaceRoster {
  return decodeCanonical(SignedWorkspaceRosterSchema, encoded, validateSignedRosterStructure);
}

export async function verifySignedWorkspaceRoster(value: SignedWorkspaceRoster, authorityPublicKey: Uint8Array): Promise<void> {
  validateSignedRosterStructure(value);
  for (const certificate of value.roster!.activeCertificates) await verifySignedDeviceCertificate(certificate, authorityPublicKey);
  const rosterBytes = encode(WorkspaceRosterSchema, value.roster!);
  const expectedDigest = await domainHash(domains.rosterDigest, rosterBytes);
  if (!equal(expectedDigest, value.rosterDigest)) throw new Error('Workspace roster digest does not match canonical roster');
  const valid = await verifyEd25519(
    authorityPublicKey,
    value.authoritySignature,
    concat(textEncoder.encode(domains.rosterSignature), rosterBytes),
  );
  if (!valid) throw new Error('Workspace roster authority signature is invalid');
}

async function verifyEd25519(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      arrayBuffer(publicKey),
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    return await crypto.subtle.verify(
      'Ed25519',
      key,
      arrayBuffer(signature),
      arrayBuffer(message),
    );
  } catch (error) {
    if (!isUnsupportedAlgorithm(error)) throw error;
    try {
      return ed25519.verify(signature, message, publicKey, { zip215: false });
    } catch {
      return false;
    }
  }
}

function isUnsupportedAlgorithm(error: unknown): boolean {
  return typeof error === 'object' && error !== null &&
    'name' in error && error.name === 'NotSupportedError';
}

function validateChallenge(value: IdentityPossessionChallenge): void {
  rejectUnknown(value);
  if (value.protocolVersion !== LIMITS.version) throw new Error('Challenge protocol version is unsupported');
  validateBinding(value.workspaceId, value.deviceId, value.identityKeyId);
  requireNonZero(value.challengeSecret, LIMITS.digest, 'Challenge secret');
  if (value.issuedAtUnixMs < 1n || value.issuedAtUnixMs > LIMITS.maxInteger || value.expiresAtUnixMs <= value.issuedAtUnixMs || value.expiresAtUnixMs > LIMITS.maxInteger || value.expiresAtUnixMs - value.issuedAtUnixMs > LIMITS.maxChallengeMs) throw new Error('Challenge lifetime is invalid');
}

function validateProof(value: PendingIdentityProof): void {
  rejectUnknown(value);
  if (value.protocolVersion !== LIMITS.version) throw new Error('Proof protocol version is unsupported');
  validateBinding(value.workspaceId, value.deviceId, value.identityKeyId);
  requireNonZero(value.challengeDigest, LIMITS.digest, 'Challenge digest');
  requireNonZero(value.challengeSecret, LIMITS.digest, 'Challenge secret');
}

function validateSignedCertificateStructure(value: SignedDeviceCertificate): void {
  rejectUnknown(value);
  if (!value.certificate) throw new Error('Device certificate is required');
  validateCertificate(value.certificate);
  requireNonZero(value.certificateId, LIMITS.digest, 'Certificate ID');
  if (value.authoritySignature.byteLength !== LIMITS.signature) throw new Error('Certificate signature must be 64 bytes');
}

function validateCertificate(value: DeviceCertificate): void {
  rejectUnknown(value);
  if (value.protocolVersion !== LIMITS.version) throw new Error('Certificate protocol version is unsupported');
  validateBinding(value.workspaceId, value.deviceId, value.identityKeyId);
  if (value.deviceType !== DeviceType.ANDROID && value.deviceType !== DeviceType.CHROME) throw new Error('Device type is unsupported');
  const nameSize = textEncoder.encode(value.displayName).byteLength;
  if (value.displayName.trim().length === 0 || nameSize > LIMITS.maxName) throw new Error('Display name is invalid');
  if (value.roles.length === 0) throw new Error('Certificate requires roles');
  let previous = DeviceRole.UNSPECIFIED;
  for (const role of value.roles) {
    if (role < DeviceRole.SEND_NOTIFICATIONS || role > DeviceRole.MANAGE_DEVICES || role <= previous) throw new Error('Certificate roles are not unique and strictly sorted');
    previous = role;
  }
  if (value.identityPublicKey.byteLength !== LIMITS.p256 || value.identityPublicKey[0] !== 4) throw new Error('Identity public key must be uncompressed P-256');
  if (value.issuedAtUnixMs < 1n || value.issuedAtUnixMs > LIMITS.maxInteger || value.expiresAtUnixMs > LIMITS.maxInteger || (value.expiresAtUnixMs !== 0n && value.expiresAtUnixMs <= value.issuedAtUnixMs) || value.membershipEpoch < 1n || value.membershipEpoch > LIMITS.maxInteger) throw new Error('Certificate time or epoch is invalid');
}

function validateSignedRosterStructure(value: SignedWorkspaceRoster): void {
  rejectUnknown(value);
  if (!value.roster) throw new Error('Workspace roster is required');
  validateRoster(value.roster);
  requireNonZero(value.rosterDigest, LIMITS.digest, 'Roster digest');
  if (value.authoritySignature.byteLength !== LIMITS.signature) throw new Error('Roster signature must be 64 bytes');
}

function validateRoster(value: WorkspaceRoster): void {
  rejectUnknown(value);
  if (value.protocolVersion !== LIMITS.version || value.workspaceId.byteLength !== LIMITS.id || allZero(value.workspaceId) || value.rosterEpoch < 1n || value.rosterEpoch > LIMITS.maxInteger) throw new Error('Roster version, workspace, or epoch is invalid');
  if (value.previousRosterDigest.byteLength !== LIMITS.digest || (value.rosterEpoch === 1n ? !allZero(value.previousRosterDigest) : allZero(value.previousRosterDigest))) throw new Error('Previous roster digest is invalid');
  if (value.activeCertificates.length > LIMITS.maxActive || value.revocations.length > LIMITS.maxRevocations) throw new Error('Roster entry limit exceeded');
  let previousDevice: Uint8Array | undefined;
  const activeIds = new Set<string>();
  for (const signed of value.activeCertificates) {
    validateSignedCertificateStructure(signed);
    const certificate = signed.certificate!;
    if (!equal(certificate.workspaceId, value.workspaceId) || certificate.membershipEpoch > value.rosterEpoch || (previousDevice && compare(previousDevice, certificate.deviceId) >= 0)) throw new Error('Active certificate roster binding or order is invalid');
    previousDevice = certificate.deviceId;
    activeIds.add(hex(signed.certificateId));
  }
  let previousId: Uint8Array | undefined;
  for (const revoked of value.revocations) {
    rejectUnknown(revoked);
    requireNonZero(revoked.certificateId, LIMITS.digest, 'Revoked certificate ID');
    requireNonZero(revoked.deviceId, LIMITS.id, 'Revoked device ID');
    if (revoked.revokedAtUnixMs < 1n || revoked.revokedAtUnixMs > LIMITS.maxInteger || (previousId && compare(previousId, revoked.certificateId) >= 0) || activeIds.has(hex(revoked.certificateId))) throw new Error('Roster revocation is invalid');
    previousId = revoked.certificateId;
  }
}

function validateBinding(workspaceId: Uint8Array, deviceId: Uint8Array, identityKeyId: Uint8Array): void {
  requireNonZero(workspaceId, LIMITS.id, 'Workspace ID'); requireNonZero(deviceId, LIMITS.id, 'Device ID'); requireNonZero(identityKeyId, LIMITS.digest, 'Identity key ID');
}
function requireNonZero(value: Uint8Array, size: number, name: string): void { if (value.byteLength !== size || allZero(value)) throw new Error(`${name} is invalid`); }
function rejectUnknown(value: { $unknown?: unknown[] }): void { if (value.$unknown?.length) throw new Error('Membership message contains unknown fields'); }
function allZero(value: Uint8Array): boolean { return value.every((item) => item === 0); }
function equal(left: Uint8Array, right: Uint8Array): boolean { return left.byteLength === right.byteLength && left.every((item, index) => item === right[index]); }
function compare(left: Uint8Array, right: Uint8Array): number { for (let i = 0; i < Math.min(left.length, right.length); i += 1) { if (left[i] !== right[i]) return left[i] - right[i]; } return left.length - right.length; }
function hex(value: Uint8Array): string { return Array.from(value, (item) => item.toString(16).padStart(2, '0')).join(''); }
function concat(...values: Uint8Array[]): Uint8Array { const result = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0)); let offset = 0; for (const value of values) { result.set(value, offset); offset += value.length; } return result; }
function arrayBuffer(value: Uint8Array): ArrayBuffer { return Uint8Array.from(value).buffer; }
async function domainHash(domain: string, value: Uint8Array): Promise<Uint8Array> { return new Uint8Array(await crypto.subtle.digest('SHA-256', arrayBuffer(concat(textEncoder.encode(domain), value)))); }
function encode<T extends DescMessage>(schema: T, value: MessageShape<T>): Uint8Array { const encoded = toBinary(schema, value); if (encoded.length === 0 || encoded.length > LIMITS.maxMessage) throw new Error('Membership message size is invalid'); return encoded; }
function decodeCanonical<T extends DescMessage>(schema: T, encoded: Uint8Array, validate: (value: MessageShape<T>) => void): MessageShape<T> { if (encoded.length === 0 || encoded.length > LIMITS.maxMessage) throw new Error('Membership message size is invalid'); const value = fromBinary(schema, encoded, { readUnknownFields: true }); validate(value); if (!equal(toBinary(schema, value), encoded)) throw new Error('Membership message is not canonically encoded'); return value; }

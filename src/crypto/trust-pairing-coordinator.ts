import { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';
import {
  IndexedDbTrustPairingSessionStore,
  type TrustPairingRole,
} from './indexeddb-trust-pairing-session-store';
import {
  TRUST_MAX_TTL_MS,
  decodeTrustApprovalV1,
  decodeTrustOfferV1,
  decodeTrustQr,
  encodeTrustApprovalV1,
  encodeTrustOfferV1,
  encodeTrustQr,
  trustOfferHash,
  trustSafetyCode,
  validateTrustPair,
  validateTrustRecordActive,
} from '../protocol/trusted-device-pairing';

export interface LocalTrustIdentity {
  workspaceId: Uint8Array;
  deviceId: Uint8Array;
  publicKey: Uint8Array;
}

export type TrustOfferView = {
  stage: 'offer-created'; role: 'offerer'; offerQr: string; expiresAtUnixMs: number;
};
export type TrustComparisonView = {
  stage: 'compare-safety-code';
  role: TrustPairingRole;
  safetyCode: string;
  approvalQr?: string;
  peerDeviceId: Uint8Array;
  expiresAtUnixMs: number;
};
export type TrustPairingView = TrustOfferView | TrustComparisonView;

/** Durable local workflow. QR exchange is out-of-band and never delegates trust to the relay. */
export class TrustPairingCoordinator {
  constructor(
    private readonly sessions: IndexedDbTrustPairingSessionStore,
    private readonly peers: IndexedDbTrustedPeerStore,
    private readonly randomBytes: (size: number) => Uint8Array = secureRandomBytes,
  ) {}

  async createOffer(local: LocalTrustIdentity, nowUnixMs = Date.now()): Promise<TrustOfferView> {
    validateLocal(local);
    validateNow(nowUnixMs);
    const expiresAtUnixMs = nowUnixMs + TRUST_MAX_TTL_MS;
    const offerBytes = encodeTrustOfferV1({
      workspaceId: local.workspaceId,
      deviceId: local.deviceId,
      publicKey: local.publicKey,
      nonce: this.randomNonZero(16),
      createdAtUnixMs: nowUnixMs,
      expiresAtUnixMs,
    });
    await this.sessions.create({ role: 'offerer', offerBytes, expiresAtUnixMs });
    return { stage: 'offer-created', role: 'offerer', offerQr: encodeTrustQr(offerBytes), expiresAtUnixMs };
  }

  async acceptOffer(
    offerQr: string,
    local: LocalTrustIdentity,
    nowUnixMs = Date.now(),
  ): Promise<TrustComparisonView> {
    validateLocal(local);
    validateNow(nowUnixMs);
    const offerBytes = decodeTrustQr(offerQr);
    const offer = decodeTrustOfferV1(offerBytes);
    validateTrustRecordActive(offer.createdAtUnixMs, offer.expiresAtUnixMs, nowUnixMs);
    requireEqual(offer.workspaceId, local.workspaceId, 'Trust offer belongs to a different workspace');
    requireDifferent(offer.deviceId, local.deviceId, 'Cannot approve the local device ID');
    requireDifferent(offer.publicKey, local.publicKey, 'Cannot approve the local identity key');
    const expiresAtUnixMs = Math.min(offer.expiresAtUnixMs, nowUnixMs + TRUST_MAX_TTL_MS);
    const approvalBytes = encodeTrustApprovalV1({
      offerHash: await trustOfferHash(offerBytes),
      deviceId: local.deviceId,
      publicKey: local.publicKey,
      nonce: this.randomNonZero(16),
      createdAtUnixMs: nowUnixMs,
      expiresAtUnixMs,
    });
    await validateTrustPair(offerBytes, approvalBytes);
    await this.sessions.create({ role: 'approver', offerBytes, approvalBytes, expiresAtUnixMs });
    return {
      stage: 'compare-safety-code',
      role: 'approver',
      safetyCode: await trustSafetyCode(offerBytes, approvalBytes),
      approvalQr: encodeTrustQr(approvalBytes),
      peerDeviceId: offer.deviceId.slice(),
      expiresAtUnixMs,
    };
  }

  async acceptApproval(
    approvalQr: string,
    local: LocalTrustIdentity,
    nowUnixMs = Date.now(),
  ): Promise<TrustComparisonView> {
    validateLocal(local);
    validateNow(nowUnixMs);
    const session = await this.sessions.load();
    if (session === undefined || session.role !== 'offerer' || session.approvalBytes !== undefined) {
      throw new Error('No offer is awaiting a trust approval');
    }
    const offer = decodeTrustOfferV1(session.offerBytes);
    requireEqual(offer.workspaceId, local.workspaceId, 'Active offer belongs to a different workspace');
    requireEqual(offer.deviceId, local.deviceId, 'Active offer belongs to a different local device');
    requireEqual(offer.publicKey, local.publicKey, 'Active offer belongs to a different identity key');
    validateTrustRecordActive(offer.createdAtUnixMs, offer.expiresAtUnixMs, nowUnixMs);
    const approvalBytes = decodeTrustQr(approvalQr);
    const approval = decodeTrustApprovalV1(approvalBytes);
    validateTrustRecordActive(approval.createdAtUnixMs, approval.expiresAtUnixMs, nowUnixMs);
    await validateTrustPair(session.offerBytes, approvalBytes);
    await this.sessions.attachApproval(session.offerBytes, approvalBytes);
    return {
      stage: 'compare-safety-code',
      role: 'offerer',
      safetyCode: await trustSafetyCode(session.offerBytes, approvalBytes),
      peerDeviceId: approval.deviceId.slice(),
      expiresAtUnixMs: approval.expiresAtUnixMs,
    };
  }

  async resume(local: LocalTrustIdentity, nowUnixMs = Date.now()): Promise<TrustPairingView | undefined> {
    validateLocal(local);
    validateNow(nowUnixMs);
    const session = await this.sessions.load();
    if (session === undefined) return undefined;
    const offer = decodeTrustOfferV1(session.offerBytes);
    validateTrustRecordActive(offer.createdAtUnixMs, offer.expiresAtUnixMs, nowUnixMs);
    if (session.role === 'offerer') {
      requireEqual(offer.workspaceId, local.workspaceId, 'Active offer belongs to a different workspace');
      requireEqual(offer.deviceId, local.deviceId, 'Active offer belongs to a different local device');
      requireEqual(offer.publicKey, local.publicKey, 'Active offer belongs to a different identity key');
      if (session.approvalBytes === undefined) {
        return {
          stage: 'offer-created', role: 'offerer',
          offerQr: encodeTrustQr(session.offerBytes), expiresAtUnixMs: offer.expiresAtUnixMs,
        };
      }
    } else {
      requireEqual(decodeTrustApprovalV1(session.approvalBytes!).deviceId, local.deviceId,
        'Active approval belongs to a different local device');
      requireEqual(decodeTrustApprovalV1(session.approvalBytes!).publicKey, local.publicKey,
        'Active approval belongs to a different identity key');
    }
    return this.comparisonView(session.role, session.offerBytes, session.approvalBytes!, local, nowUnixMs);
  }

  async confirmSafetyCode(
    displayedSafetyCode: string,
    local: LocalTrustIdentity,
    nowUnixMs = Date.now(),
  ): Promise<'pinned' | 'already-pinned'> {
    validateLocal(local);
    validateNow(nowUnixMs);
    const session = await this.sessions.load();
    if (session?.approvalBytes === undefined) throw new Error('No safety code is awaiting confirmation');
    const view = await this.comparisonView(
      session.role, session.offerBytes, session.approvalBytes, local, nowUnixMs,
    );
    if (view.safetyCode !== displayedSafetyCode) {
      throw new Error('Safety code confirmation does not match the active transcript');
    }
    const offer = decodeTrustOfferV1(session.offerBytes);
    const approval = decodeTrustApprovalV1(session.approvalBytes);
    const peer = session.role === 'offerer'
      ? { deviceId: approval.deviceId, publicKey: approval.publicKey }
      : { deviceId: offer.deviceId, publicKey: offer.publicKey };
    const result = await this.peers.pinApproved(local.workspaceId, peer.deviceId, peer.publicKey);
    await this.sessions.removeExact(session.offerBytes, session.approvalBytes);
    return result;
  }

  async cancel(): Promise<void> {
    await this.sessions.cancel();
  }

  private async comparisonView(
    role: TrustPairingRole,
    offerBytes: Uint8Array,
    approvalBytes: Uint8Array,
    local: LocalTrustIdentity,
    nowUnixMs: number,
  ): Promise<TrustComparisonView> {
    const offer = decodeTrustOfferV1(offerBytes);
    const approval = decodeTrustApprovalV1(approvalBytes);
    validateTrustRecordActive(offer.createdAtUnixMs, offer.expiresAtUnixMs, nowUnixMs);
    validateTrustRecordActive(approval.createdAtUnixMs, approval.expiresAtUnixMs, nowUnixMs);
    await validateTrustPair(offerBytes, approvalBytes);
    requireEqual(offer.workspaceId, local.workspaceId, 'Pairing transcript belongs to a different workspace');
    const expectedLocal = role === 'offerer' ? offer : approval;
    requireEqual(expectedLocal.deviceId, local.deviceId, 'Pairing transcript belongs to another local device');
    requireEqual(expectedLocal.publicKey, local.publicKey, 'Pairing transcript belongs to another identity key');
    return {
      stage: 'compare-safety-code', role,
      safetyCode: await trustSafetyCode(offerBytes, approvalBytes),
      approvalQr: role === 'approver' ? encodeTrustQr(approvalBytes) : undefined,
      peerDeviceId: (role === 'offerer' ? approval.deviceId : offer.deviceId).slice(),
      expiresAtUnixMs: approval.expiresAtUnixMs,
    };
  }

  private randomNonZero(size: number): Uint8Array {
    const value = this.randomBytes(size);
    if (!(value instanceof Uint8Array) || value.byteLength !== size || value.every((byte) => byte === 0)) {
      throw new Error('Secure random source returned an invalid nonce');
    }
    return value.slice();
  }
}

function validateLocal(value: LocalTrustIdentity): void {
  validateNonZero(value.workspaceId, 16, 'workspaceId');
  validateNonZero(value.deviceId, 16, 'deviceId');
  if (!(value.publicKey instanceof Uint8Array) || value.publicKey.byteLength !== 65) {
    throw new Error('publicKey must be a 65-byte P-256 point');
  }
}

function validateNow(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - TRUST_MAX_TTL_MS) {
    throw new Error('nowUnixMs is out of range');
  }
}

function validateNonZero(value: Uint8Array, size: number, name: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== size || value.every((byte) => byte === 0)) {
    throw new Error(`${name} must be a non-zero ${size}-byte value`);
  }
}

function requireEqual(left: Uint8Array, right: Uint8Array, message: string): void {
  if (!bytesEqual(left, right)) throw new Error(message);
}

function requireDifferent(left: Uint8Array, right: Uint8Array, message: string): void {
  if (bytesEqual(left, right)) throw new Error(message);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}

function secureRandomBytes(size: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(size));
}

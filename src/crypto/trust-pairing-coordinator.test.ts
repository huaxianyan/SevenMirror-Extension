import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { deriveKeyPair } from './auth-hpke';
import { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';
import { IndexedDbTrustPairingSessionStore } from './indexeddb-trust-pairing-session-store';
import { TrustPairingCoordinator, type LocalTrustIdentity } from './trust-pairing-coordinator';

const now = 1_800_000_000_000;

describe('TrustPairingCoordinator', () => {
  it('durably resumes both roles and pins only after each explicit matching confirmation', async () => {
    const names = uniqueNames();
    const offerSessions = new IndexedDbTrustPairingSessionStore(names.offerSession);
    const approvalSessions = new IndexedDbTrustPairingSessionStore(names.approvalSession);
    const offerPeers = new IndexedDbTrustedPeerStore(names.offerPeers);
    const approvalPeers = new IndexedDbTrustedPeerStore(names.approvalPeers);
    const offerer = await identity(1, 2, 11);
    const approver = await identity(1, 3, 22);
    try {
      const offerCoordinator = coordinator(offerSessions, offerPeers, 0x41);
      const offerView = await offerCoordinator.createOffer(offerer, now);
      expect(offerView.stage).toBe('offer-created');
      await expect(offerCoordinator.createOffer(offerer, now + 1)).rejects.toThrow('cancel it explicitly');

      const approvalView = await coordinator(approvalSessions, approvalPeers, 0x52)
        .acceptOffer(offerView.offerQr, approver, now + 1_000);
      expect(approvalView.stage).toBe('compare-safety-code');
      expect(approvalView.approvalQr).toBeTypeOf('string');

      const offerCompare = await coordinator(offerSessions, offerPeers, 0x63)
        .acceptApproval(approvalView.approvalQr!, offerer, now + 2_000);
      expect(offerCompare.safetyCode).toBe(approvalView.safetyCode);

      const resumedOffer = await coordinator(offerSessions, offerPeers, 0x74).resume(offerer, now + 3_000);
      const resumedApproval = await coordinator(approvalSessions, approvalPeers, 0x75)
        .resume(approver, now + 3_000);
      expect(resumedOffer).toMatchObject({ stage: 'compare-safety-code', role: 'offerer' });
      expect(resumedApproval).toMatchObject({
        stage: 'compare-safety-code', role: 'approver', approvalQr: approvalView.approvalQr,
      });

      await expect(coordinator(offerSessions, offerPeers, 0x76).confirmSafetyCode(
        '0000-0000-0000', offerer, now + 4_000,
      )).rejects.toThrow('does not match');
      expect(await offerPeers.findApproved(
        offerer.workspaceId, approver.deviceId, await sha256(approver.publicKey),
      )).toBeUndefined();
      expect(await offerSessions.load()).toBeDefined();

      expect(await coordinator(offerSessions, offerPeers, 0x77).confirmSafetyCode(
        offerCompare.safetyCode, offerer, now + 4_000,
      )).toBe('pinned');
      expect(await offerPeers.findApproved(
        offerer.workspaceId, approver.deviceId, await sha256(approver.publicKey),
      )).toEqual(approver.publicKey);
      expect(await offerSessions.load()).toBeUndefined();

      expect(await coordinator(approvalSessions, approvalPeers, 0x78).confirmSafetyCode(
        approvalView.safetyCode, approver, now + 5_000,
      )).toBe('pinned');
      expect(await approvalPeers.findApproved(
        approver.workspaceId, offerer.deviceId, await sha256(offerer.publicKey),
      )).toEqual(offerer.publicKey);
      expect(await approvalSessions.load()).toBeUndefined();
    } finally {
      await Promise.all([
        offerSessions.clear(), approvalSessions.clear(), offerPeers.clear(), approvalPeers.clear(),
      ]);
    }
  });

  it('rejects cross-workspace and expired offers without creating durable sessions', async () => {
    const names = uniqueNames();
    const offerSessions = new IndexedDbTrustPairingSessionStore(names.offerSession);
    const approvalSessions = new IndexedDbTrustPairingSessionStore(names.approvalSession);
    const offerPeers = new IndexedDbTrustedPeerStore(names.offerPeers);
    const approvalPeers = new IndexedDbTrustedPeerStore(names.approvalPeers);
    const offerer = await identity(1, 2, 11);
    const otherWorkspace = await identity(9, 3, 22);
    try {
      const offer = await coordinator(offerSessions, offerPeers, 0x21).createOffer(offerer, now);
      await expect(coordinator(approvalSessions, approvalPeers, 0x22).acceptOffer(
        offer.offerQr, otherWorkspace, now + 1,
      )).rejects.toThrow('different workspace');
      expect(await approvalSessions.load()).toBeUndefined();
      await expect(coordinator(approvalSessions, approvalPeers, 0x23).acceptOffer(
        offer.offerQr, { ...otherWorkspace, workspaceId: offerer.workspaceId }, now + 600_000,
      )).rejects.toThrow('expired');
      expect(await approvalSessions.load()).toBeUndefined();
    } finally {
      await Promise.all([
        offerSessions.clear(), approvalSessions.clear(), offerPeers.clear(), approvalPeers.clear(),
      ]);
    }
  });
});

function coordinator(
  sessions: IndexedDbTrustPairingSessionStore,
  peers: IndexedDbTrustedPeerStore,
  randomByte: number,
): TrustPairingCoordinator {
  return new TrustPairingCoordinator(sessions, peers, (size) => new Uint8Array(size).fill(randomByte));
}

async function identity(workspaceByte: number, deviceByte: number, keyByte: number): Promise<LocalTrustIdentity> {
  const key = await deriveKeyPair(new Uint8Array(32).fill(keyByte));
  return {
    workspaceId: new Uint8Array(16).fill(workspaceByte),
    deviceId: new Uint8Array(16).fill(deviceByte),
    publicKey: key.publicKey,
  };
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

function uniqueNames() {
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return {
    offerSession: `pair-offer-${suffix}`,
    approvalSession: `pair-approval-${suffix}`,
    offerPeers: `pair-offer-peers-${suffix}`,
    approvalPeers: `pair-approval-peers-${suffix}`,
  };
}

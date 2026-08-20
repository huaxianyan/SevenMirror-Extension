import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/workspace-membership-v1.json';
import { IndexedDbWorkspaceMembershipStore } from './indexeddb-workspace-membership-store';

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g) ?? [], (item) => Number.parseInt(item, 16));
const workspaceId = fromHex(vector.workspaceIdHex);
const deviceId = fromHex(vector.deviceIdHex);
const authority = fromHex(vector.authorityPublicKeyHex);
const certificate = fromHex(vector.certificateEncodedHex);
const initialRoster = fromHex(vector.initialRosterEncodedHex);
const revokedRoster = fromHex(vector.revokedRosterEncodedHex);

describe('IndexedDbWorkspaceMembershipStore', () => {
  it('persists an immutable authority pin and contiguous roster rollback floor', async () => {
    const databaseName = `membership-${crypto.randomUUID()}`;
    const store = new IndexedDbWorkspaceMembershipStore(databaseName);
    try {
      await expect(store.pinAuthority(workspaceId, deviceId, authority)).resolves.toBe('pinned');
      await expect(store.pinAuthority(workspaceId, deviceId, authority))
        .resolves.toBe('already-pinned');
      await expect(store.pinAuthority(workspaceId, deviceId, new Uint8Array(32).fill(9)))
        .rejects.toThrow('authenticated transition');

      await expect(store.reconcileApproved(workspaceId, deviceId, certificate, revokedRoster))
        .rejects.toThrow('Bootstrap roster');
      await expect(store.reconcileApproved(workspaceId, deviceId, certificate, initialRoster))
        .resolves.toBe('applied');
      await expect(store.reconcileApproved(workspaceId, deviceId, certificate, initialRoster))
        .resolves.toBe('already-applied');

      const recoveredStore = new IndexedDbWorkspaceMembershipStore(databaseName);
      const initial = await recoveredStore.load(workspaceId, deviceId);
      expect(initial).toMatchObject({ rosterEpoch: 1n, localDeviceActive: true });
      expect(initial?.authorityPublicKey).toEqual(authority);
      expect(initial?.signedCertificate).toEqual(certificate);

      await expect(recoveredStore.reconcileApproved(
        workspaceId,
        deviceId,
        certificate,
        revokedRoster,
      )).resolves.toBe('applied');
      await expect(recoveredStore.load(workspaceId, deviceId)).resolves.toMatchObject({
        rosterEpoch: 2n,
        localDeviceActive: false,
      });
      await expect(recoveredStore.reconcileApproved(
        workspaceId,
        deviceId,
        certificate,
        initialRoster,
      )).rejects.toThrow('stale or non-contiguous');
    } finally {
      await store.clear();
    }
  });

  it('rejects a certificate for a different local device', async () => {
    const store = new IndexedDbWorkspaceMembershipStore(`membership-${crypto.randomUUID()}`);
    const otherDevice = new Uint8Array(16).fill(7);
    try {
      await store.pinAuthority(workspaceId, otherDevice, authority);
      await expect(store.reconcileApproved(workspaceId, otherDevice, certificate, initialRoster))
        .rejects.toThrow('not bound to this local device');
      await expect(store.load(workspaceId, otherDevice)).resolves.toMatchObject({ rosterEpoch: 0n });
    } finally {
      await store.clear();
    }
  });
});

import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/workspace-membership-v1.json';
import {
  decodeSignedDeviceCertificate,
  decodeSignedWorkspaceRoster,
} from '../protocol/workspace-membership';
import { IndexedDbWorkspaceMembershipStore } from './indexeddb-workspace-membership-store';

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g) ?? [], (item) => Number.parseInt(item, 16));
const workspaceId = fromHex(vector.workspaceIdHex);
const deviceId = fromHex(vector.deviceIdHex);
const authority = fromHex(vector.authorityPublicKeyHex);
const certificate = fromHex(vector.certificateEncodedHex);
const initialRoster = fromHex(vector.initialRosterEncodedHex);
const revokedRoster = fromHex(vector.revokedRosterEncodedHex);
const renamedCertificate = fromHex(vector.renamedCertificateEncodedHex);
const renameRoster = fromHex(vector.renameRosterEncodedHex);

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
      const localCertificate = decodeSignedDeviceCertificate(certificate).certificate!;
      const rosterCertificate = decodeSignedWorkspaceRoster(initialRoster)
        .roster!.activeCertificates[0].certificate!;
      await expect(recoveredStore.listAuthorizedDevices(
        workspaceId,
        deviceId,
        rosterCertificate.issuedAtUnixMs,
      )).resolves.toMatchObject([{
        displayName: localCertificate.displayName,
        isCurrentDevice: true,
        accessCurrent: true,
      }]);

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
      await expect(recoveredStore.listAuthorizedDevices(
        workspaceId,
        deviceId,
        localCertificate.issuedAtUnixMs,
      )).resolves.toEqual([]);
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

  it('accepts an exact certified display-name replacement across reconstruction', async () => {
    const databaseName = `membership-${crypto.randomUUID()}`;
    const store = new IndexedDbWorkspaceMembershipStore(databaseName);
    try {
      await store.pinAuthority(workspaceId, deviceId, authority);
      await store.reconcileApproved(workspaceId, deviceId, certificate, initialRoster);
      await expect(store.reconcileApproved(
        workspaceId, deviceId, renamedCertificate, revokedRoster,
      )).rejects.toThrow('not active');
      await expect(store.reconcileApproved(
        workspaceId, deviceId, renamedCertificate, renameRoster,
      )).resolves.toBe('applied');

      const recovered = new IndexedDbWorkspaceMembershipStore(databaseName);
      await expect(recovered.load(workspaceId, deviceId)).resolves.toMatchObject({
        rosterEpoch: 2n,
        localDeviceActive: true,
        signedCertificate: renamedCertificate,
      });
      await expect(recovered.listAuthorizedDevices(
        workspaceId, deviceId, 1_800_000_060_000n,
      )).resolves.toMatchObject([{
        displayName: 'Chrome-Renamed',
        isCurrentDevice: true,
        accessCurrent: true,
      }]);
    } finally {
      await store.clear();
    }
  });

  it('durably upgrades a legacy authority pin before validating it', async () => {
    const databaseName = `membership-${crypto.randomUUID()}`;
    const store = new IndexedDbWorkspaceMembershipStore(databaseName);
    try {
      await store.pinAuthority(workspaceId, deviceId, authority);
      await removeAuthorityFloor(databaseName);

      await expect(store.pinAuthority(workspaceId, deviceId, authority))
        .resolves.toBe('already-pinned');
      await expect(store.load(workspaceId, deviceId)).resolves.toMatchObject({
        authorityEpoch: 1n,
        authorityTransitionDigest: new Uint8Array(32),
      });
      await expect(readAuthorityFloor(databaseName)).resolves.toEqual({
        authorityEpoch: '1',
        authorityTransitionDigest: new Uint8Array(32),
      });
    } finally {
      await store.clear();
    }
  });

  it('atomically advances authority and roster rollback floors', async () => {
    const store = new IndexedDbWorkspaceMembershipStore(`membership-${crypto.randomUUID()}`);
    try {
      await store.pinAuthority(workspaceId, deviceId, authority);
      await store.reconcileApproved(workspaceId, deviceId, certificate, initialRoster);
      const transition = fromHex(vector.authorityTransitionEncodedHex);
      const activation = fromHex(vector.authorityActivationRosterEncodedHex);
      await expect(store.reconcileAuthorityTransition(workspaceId, deviceId, transition, activation))
        .resolves.toBe('applied');
      await expect(store.load(workspaceId, deviceId)).resolves.toMatchObject({
        authorityEpoch: 2n, rosterEpoch: 2n, localDeviceActive: true,
      });
      await expect(store.reconcileAuthorityTransition(workspaceId, deviceId, transition, activation))
        .resolves.toBe('already-applied');
      const differentActivation = activation.slice(); differentActivation[differentActivation.length - 1] ^= 1;
      await expect(store.reconcileAuthorityTransition(workspaceId, deviceId, transition, differentActivation))
        .rejects.toThrow('different transition');
      expect((await store.load(workspaceId, deviceId))?.authorityPublicKey)
        .toEqual(fromHex(vector.newAuthorityPublicKeyHex));
      const tampered = transition.slice(); tampered[tampered.length - 1] ^= 1;
      await expect(store.reconcileAuthorityTransition(workspaceId, deviceId, tampered, activation))
        .rejects.toThrow();
      await expect(store.load(workspaceId, deviceId)).resolves.toMatchObject({ authorityEpoch: 2n, rosterEpoch: 2n });
    } finally { await store.clear(); }
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

async function removeAuthorityFloor(databaseName: string): Promise<void> {
  const database = await openDatabase(databaseName);
  try {
    const transaction = database.transaction('workspace-membership', 'readwrite');
    const store = transaction.objectStore('workspace-membership');
    const value = await requestResult<Record<string, unknown>>(
      store.get(`${vector.workspaceIdHex}:${vector.deviceIdHex}`),
    );
    delete value.authorityEpoch;
    delete value.authorityTransitionDigest;
    await requestResult(store.put(value));
    await transactionCompleted(transaction);
  } finally {
    database.close();
  }
}

async function readAuthorityFloor(databaseName: string): Promise<{
  authorityEpoch: unknown;
  authorityTransitionDigest: unknown;
}> {
  const database = await openDatabase(databaseName);
  try {
    const transaction = database.transaction('workspace-membership', 'readonly');
    const value = await requestResult<Record<string, unknown>>(
      transaction.objectStore('workspace-membership').get(`${vector.workspaceIdHex}:${vector.deviceIdHex}`),
    );
    await transactionCompleted(transaction);
    return {
      authorityEpoch: value.authorityEpoch,
      authorityTransitionDigest: value.authorityTransitionDigest,
    };
  } finally {
    database.close();
  }
}

function openDatabase(databaseName: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function transactionCompleted(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error);
    transaction.onerror = () => reject(transaction.error);
  });
}

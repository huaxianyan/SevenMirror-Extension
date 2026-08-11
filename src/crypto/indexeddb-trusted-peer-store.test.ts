import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { generateNonExtractableIdentity, serializeIdentityPublicKey } from './auth-hpke';
import { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';

const workspaceId = new Uint8Array(16).fill(1);
const deviceId = new Uint8Array(16).fill(2);

describe('IndexedDbTrustedPeerStore', () => {
  it('keeps an approved pin immutable until explicit removal', async () => {
    const store = new IndexedDbTrustedPeerStore(uniqueName());
    const first = await serializeIdentityPublicKey(await generateNonExtractableIdentity());
    const replacement = await serializeIdentityPublicKey(await generateNonExtractableIdentity());
    try {
      expect(await store.pinApproved(workspaceId, deviceId, first)).toBe('pinned');
      expect(await store.pinApproved(workspaceId, deviceId, first)).toBe('already-pinned');
      await expect(store.pinApproved(workspaceId, deviceId, replacement)).rejects.toThrow(
        'explicit removal and approval',
      );

      const firstKeyId = await sha256(first);
      expect(await store.findApproved(workspaceId, deviceId, firstKeyId)).toEqual(first);
      expect(await store.findApproved(
        workspaceId,
        deviceId,
        await sha256(replacement),
      )).toBeUndefined();

      await store.remove(workspaceId, deviceId);
      expect(await store.findApproved(workspaceId, deviceId, firstKeyId)).toBeUndefined();
      expect(await store.pinApproved(workspaceId, deviceId, replacement)).toBe('pinned');
    } finally {
      await store.clear();
    }
  });

  it('fails closed if a persisted key binding is corrupt', async () => {
    const databaseName = uniqueName();
    const store = new IndexedDbTrustedPeerStore(databaseName);
    const publicKey = await serializeIdentityPublicKey(await generateNonExtractableIdentity());
    try {
      await store.pinApproved(workspaceId, deviceId, publicKey);
      await corruptStoredKeyId(databaseName);
      await expect(store.findApproved(workspaceId, deviceId, new Uint8Array(32).fill(9)))
        .rejects.toThrow('key binding is corrupt');
    } finally {
      await store.clear();
    }
  });

  it('rejects malformed P-256 points before persistence', async () => {
    const store = new IndexedDbTrustedPeerStore(uniqueName());
    const invalid = new Uint8Array(65);
    invalid[0] = 4;
    try {
      await expect(store.pinApproved(workspaceId, deviceId, invalid)).rejects.toThrow(
        'valid P-256 point',
      );
    } finally {
      await store.clear();
    }
  });
});

async function corruptStoredKeyId(databaseName: string): Promise<void> {
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(databaseName, 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    const transaction = database.transaction('approved-peer', 'readwrite');
    const store = transaction.objectStore('approved-peer');
    const tuple = `${toHex(workspaceId)}:${toHex(deviceId)}`;
    const record = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const request = store.get(tuple);
      request.onsuccess = () => resolve(request.result as Record<string, unknown>);
      request.onerror = () => reject(request.error);
    });
    await new Promise<void>((resolve, reject) => {
      const request = store.put({ ...record, keyId: new Uint8Array(32).fill(9) });
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } finally {
    database.close();
  }
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function uniqueName(): string {
  return `trusted-peers-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

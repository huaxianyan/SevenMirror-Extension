import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { generateNonExtractableIdentity, serializeIdentityPublicKey } from './auth-hpke';
import {
  createIdentityKeyTransitionPayload,
  decodeIdentityKeyLifecyclePayload,
  encodeIdentityKeyLifecyclePayload,
} from '../protocol/identity-key-transition-payload';
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

  it('migrates a legacy approved pin before accepting a successor', async () => {
    const databaseName = uniqueName();
    const previousPublicKey = await serializeIdentityPublicKey(await generateNonExtractableIdentity());
    const previousKeyId = await sha256(previousPublicKey);
    const newPublicKey = await serializeIdentityPublicKey(await generateNonExtractableIdentity());
    const store = new IndexedDbTrustedPeerStore(databaseName);
    try {
      await createLegacyApprovedPeerDatabase(
        databaseName,
        previousPublicKey,
        previousKeyId,
      );
      expect(await store.findApproved(workspaceId, deviceId, previousKeyId))
        .toEqual(previousPublicKey);
      await expect(store.acceptIdentityTransition(
        workspaceId,
        deviceId,
        await transitionPayload(
          new Uint8Array(16).fill(6),
          previousKeyId,
          newPublicKey,
          await sha256(newPublicKey),
        ),
        1_800_000_000_000,
      )).resolves.toMatchObject({ disposition: 'accepted' });
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

  it('durably binds one exact successor and deterministic acknowledgement intent', async () => {
    const databaseName = uniqueName();
    const store = new IndexedDbTrustedPeerStore(databaseName);
    const previousPublicKey = await serializeIdentityPublicKey(await generateNonExtractableIdentity());
    const newPublicKey = await serializeIdentityPublicKey(await generateNonExtractableIdentity());
    const previousKeyId = await sha256(previousPublicKey);
    const newKeyId = await sha256(newPublicKey);
    const canonicalTransition = await transitionPayload(
      new Uint8Array(16).fill(3),
      previousKeyId,
      newPublicKey,
      newKeyId,
    );
    const now = 1_800_000_000_000;
    try {
      await store.pinApproved(workspaceId, deviceId, previousPublicKey);
      const accepted = await store.acceptIdentityTransition(
        workspaceId,
        deviceId,
        canonicalTransition,
        now,
      );
      expect(accepted.disposition).toBe('accepted');
      expect(accepted.state.canonicalTransition).toEqual(canonicalTransition);
      const ack = await decodeIdentityKeyLifecyclePayload(accepted.state.canonicalAck);
      expect(ack.body.case).toBe('identityKeyTransitionAck');
      if (ack.body.case !== 'identityKeyTransitionAck') throw new Error('wrong ACK body');
      expect(ack.body.value.transitionSha256).toEqual(await sha256(canonicalTransition));

      const duplicate = await new IndexedDbTrustedPeerStore(databaseName)
        .acceptIdentityTransition(workspaceId, deviceId, canonicalTransition, now + 1);
      expect(duplicate.disposition).toBe('already-accepted');
      expect(duplicate.state.canonicalAck).toEqual(accepted.state.canonicalAck);
      expect(await new IndexedDbTrustedPeerStore(databaseName)
        .loadIdentityTransition(workspaceId, deviceId, now + 2)).toEqual(accepted.state);

      const otherPublicKey = await serializeIdentityPublicKey(await generateNonExtractableIdentity());
      await expect(store.acceptIdentityTransition(
        workspaceId,
        deviceId,
        await transitionPayload(
          new Uint8Array(16).fill(4),
          previousKeyId,
          otherPublicKey,
          await sha256(otherPublicKey),
        ),
        now + 3,
      )).rejects.toThrow('different identity successor');
    } finally {
      await store.clear();
    }
  });

  it('blocks an expired successor without changing either approved pin', async () => {
    const store = new IndexedDbTrustedPeerStore(uniqueName());
    const previousPublicKey = await serializeIdentityPublicKey(await generateNonExtractableIdentity());
    const newPublicKey = await serializeIdentityPublicKey(await generateNonExtractableIdentity());
    const previousKeyId = await sha256(previousPublicKey);
    const newKeyId = await sha256(newPublicKey);
    const canonicalTransition = await transitionPayload(
      new Uint8Array(16).fill(5),
      previousKeyId,
      newPublicKey,
      newKeyId,
    );
    const now = 1_800_000_000_000;
    try {
      await store.pinApproved(workspaceId, deviceId, previousPublicKey);
      const accepted = await store.acceptIdentityTransition(
        workspaceId,
        deviceId,
        canonicalTransition,
        now,
      );
      const blocked = await store.loadIdentityTransition(
        workspaceId,
        deviceId,
        accepted.state.expiresAtUnixMs,
      );
      expect(blocked?.phase).toBe('blocked');
      expect(await store.dueIdentityTransitionAcks(
        workspaceId,
        accepted.state.expiresAtUnixMs,
      )).toEqual([]);
      expect(await store.findApproved(workspaceId, deviceId, previousKeyId))
        .toEqual(previousPublicKey);
      expect(await store.findApproved(workspaceId, deviceId, newKeyId)).toBeUndefined();
      await expect(store.acceptIdentityTransition(
        workspaceId,
        deviceId,
        canonicalTransition,
        accepted.state.expiresAtUnixMs,
      )).rejects.toThrow('blocked after expiry');

      await store.remove(workspaceId, deviceId);
      expect(await store.loadIdentityTransition(
        workspaceId,
        deviceId,
        accepted.state.expiresAtUnixMs + 1,
      )).toBeUndefined();
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

async function createLegacyApprovedPeerDatabase(
  databaseName: string,
  publicKey: Uint8Array,
  keyId: Uint8Array,
): Promise<void> {
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(databaseName, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore('approved-peer', { keyPath: 'tuple' });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    const transaction = database.transaction('approved-peer', 'readwrite');
    const completed = transactionCompleted(transaction);
    await requestCompleted(transaction.objectStore('approved-peer').add({
      tuple: `${toHex(workspaceId)}:${toHex(deviceId)}`,
      workspaceId,
      deviceId,
      keyId,
      publicKey,
    }));
    await completed;
  } finally {
    database.close();
  }
}

async function corruptStoredKeyId(databaseName: string): Promise<void> {
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(databaseName, 3);
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

function requestCompleted(request: IDBRequest): Promise<void> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve();
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

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function uniqueName(): string {
  return `trusted-peers-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

async function transitionPayload(
  transitionId: Uint8Array,
  previousKeyId: Uint8Array,
  newPublicKey: Uint8Array,
  newKeyId: Uint8Array,
): Promise<Uint8Array> {
  return encodeIdentityKeyLifecyclePayload(createIdentityKeyTransitionPayload({
    transitionId,
    previousKeyId,
    newPublicKey,
    newKeyId,
  }));
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

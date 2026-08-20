import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/workspace-membership-v1.json';
import { IndexedDbPendingMembershipStore } from './indexeddb-pending-membership-store';

const fromHex = (value: string): Uint8Array => Uint8Array.from(value.match(/../g) ?? [], (item) => Number.parseInt(item, 16));
const pending = {
  serverOrigin: 'https://membership.example',
  workspaceId: fromHex(vector.workspaceIdHex),
  deviceId: fromHex(vector.deviceIdHex),
  authToken: new Uint8Array(32).fill(3),
  identityKeyId: fromHex(vector.identityKeyIdHex),
};
const proof = fromHex(vector.proofEncodedHex);

describe('IndexedDbPendingMembershipStore', () => {
  it('restores one exact enrollment intent and monotonic proof phase', async () => {
    const name = `pending-membership-${crypto.randomUUID()}`;
    const store = new IndexedDbPendingMembershipStore(name);
    try {
      const registered = await store.prepareRegistration(
        pending, new Uint8Array(32).fill(6), new Uint8Array(65).fill(7), new Uint8Array(48).fill(8),
      );
      expect(registered.phase).toBe('registered');
      expect(registered.canonicalProof).toBeUndefined();
      await store.bindProof(pending, proof);
      await store.markProofAttempted(pending, proof);
      expect(await new IndexedDbPendingMembershipStore(name).load())
        .toMatchObject({ phase: 'proof-attempted', authToken: pending.authToken, canonicalProof: proof });
      await store.markPendingApproval(pending);
      expect(await store.load()).toMatchObject({ phase: 'pending-approval' });
      await store.markProofAttempted(pending, proof);
      expect((await store.load())?.phase).toBe('pending-approval');

      await expect(store.prepareRegistration(
        { ...pending, authToken: new Uint8Array(32).fill(9) },
        new Uint8Array(32).fill(6), new Uint8Array(65).fill(7), new Uint8Array(48).fill(8),
      )).rejects.toThrow('different membership enrollment');
    } finally {
      await store.clear();
    }
  });
});

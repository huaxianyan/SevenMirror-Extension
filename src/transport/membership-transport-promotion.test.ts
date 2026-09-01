import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/workspace-membership-v1.json';
import { IndexedDbWorkspaceMembershipStore } from '../crypto/indexeddb-workspace-membership-store';
import { IndexedDbPendingMembershipStore } from './indexeddb-pending-membership-store';
import { IndexedDbTransportCredentialStore } from './indexeddb-transport-credential-store';
import { promoteApprovedMembership } from './membership-transport-promotion';

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g) ?? [], (item) => Number.parseInt(item, 16));
const workspaceId = fromHex(vector.workspaceIdHex);
const deviceId = fromHex(vector.deviceIdHex);
const identityKeyId = fromHex(vector.identityKeyIdHex);
const authority = fromHex(vector.authorityPublicKeyHex);
const proof = fromHex(vector.proofEncodedHex);
const certificate = fromHex(vector.certificateEncodedHex);
const roster = fromHex(vector.initialRosterEncodedHex);

async function prepared() {
  const suffix = crypto.randomUUID();
  const pending = new IndexedDbPendingMembershipStore(`promotion-pending-${suffix}`);
  const membership = new IndexedDbWorkspaceMembershipStore(`promotion-membership-${suffix}`);
  const transport = new IndexedDbTransportCredentialStore(`promotion-transport-${suffix}`);
  const enrollment = {
    serverOrigin: 'https://notify.example', workspaceId, deviceId,
    authToken: new Uint8Array(32).fill(9), identityKeyId,
  };
  await pending.prepareRegistration(enrollment, authority, new Uint8Array(65).fill(7), new Uint8Array(48).fill(8));
  await pending.bindProof(enrollment, proof);
  await pending.markPendingApproval(enrollment);
  await membership.pinAuthority(workspaceId, deviceId, authority);
  await membership.reconcileApproved(workspaceId, deviceId, certificate, roster);
  return { pending, membership, transport, enrollment };
}

describe('promoteApprovedMembership', () => {
  it('writes exact current credential before clearing the enrollment journal', async () => {
    const state = await prepared();
    try {
      const promoted = await promoteApprovedMembership(
        state.pending, state.membership, state.transport, 1_800_000_000_001n,
      );
      expect(promoted).toMatchObject({ serverOrigin: state.enrollment.serverOrigin });
      expect(promoted.authToken).toEqual(state.enrollment.authToken);
      await expect(state.pending.load()).resolves.toBeUndefined();
      await expect(state.transport.load()).resolves.toEqual(promoted);
    } finally {
      await state.pending.clear(); await state.membership.clear(); await state.transport.clear();
    }
  });

  it('finishes cleanup after a crash following the exact transport write', async () => {
    const state = await prepared();
    try {
      await state.transport.saveNew(state.enrollment);
      await expect(promoteApprovedMembership(
        state.pending, state.membership, state.transport, 1_800_000_000_001n,
      )).resolves.toEqual(state.enrollment);
      await expect(state.pending.load()).resolves.toBeUndefined();
    } finally {
      await state.pending.clear(); await state.membership.clear(); await state.transport.clear();
    }
  });

  it('fails closed without clearing the journal when transport current conflicts', async () => {
    const state = await prepared();
    try {
      await state.transport.saveNew({ ...state.enrollment, authToken: new Uint8Array(32).fill(4) });
      await expect(promoteApprovedMembership(
        state.pending, state.membership, state.transport, 1_800_000_000_001n,
      )).rejects.toThrow('explicit clear');
      await expect(state.pending.load()).resolves.toMatchObject({ phase: 'pending-approval' });
    } finally {
      await state.pending.clear(); await state.membership.clear(); await state.transport.clear();
    }
  });
});

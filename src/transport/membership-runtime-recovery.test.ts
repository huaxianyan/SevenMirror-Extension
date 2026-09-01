import 'fake-indexeddb/auto';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/workspace-membership-v1.json';
import type { IndexedDbIdentityStore } from '../crypto/indexeddb-identity-store';
import { IndexedDbWorkspaceMembershipStore } from '../crypto/indexeddb-workspace-membership-store';
import { IndexedDbPendingMembershipStore } from './indexeddb-pending-membership-store';
import { IndexedDbTransportCredentialStore } from './indexeddb-transport-credential-store';
import {
  recoverPendingMembership,
  refreshActiveMembership,
} from './membership-runtime-recovery';

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g) ?? [], (item) => Number.parseInt(item, 16));
const toBase64Url = (value: Uint8Array): string => Buffer.from(value).toString('base64url');

it('resumes approved membership and promotes before returning to transport', async () => {
  const suffix = crypto.randomUUID();
  const pendingStore = new IndexedDbPendingMembershipStore(`runtime-pending-${suffix}`);
  const membershipStore = new IndexedDbWorkspaceMembershipStore(`runtime-membership-${suffix}`);
  const transportStore = new IndexedDbTransportCredentialStore(`runtime-transport-${suffix}`);
  const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
  const identity = {
    privateKey: await suite.kem.deserializePrivateKey(fromHex(vector.identityPrivateScalarHex)),
    publicKey: await suite.kem.deserializePublicKey(fromHex(vector.identityPublicKeyHex)),
  };
  const enrollment = {
    serverOrigin: 'https://notify.example',
    workspaceId: fromHex(vector.workspaceIdHex), deviceId: fromHex(vector.deviceIdHex),
    authToken: new Uint8Array(32).fill(9), identityKeyId: fromHex(vector.identityKeyIdHex),
  };
  const authority = fromHex(vector.authorityPublicKeyHex);
  try {
    await pendingStore.prepareRegistration(
      enrollment, authority, fromHex(vector.possessionHpkeEncapsulatedKeyHex),
      fromHex(vector.possessionHpkeCiphertextHex),
    );
    const proof = fromHex(vector.proofEncodedHex);
    await pendingStore.bindProof(enrollment, proof);
    await pendingStore.markPendingApproval(enrollment);
    const fetcher = async () => new Response(JSON.stringify({
      state: 'approved', authority_public_key: toBase64Url(authority), authority_transitions: [],
      signed_certificate: toBase64Url(fromHex(vector.certificateEncodedHex)),
      rosters: [toBase64Url(fromHex(vector.initialRosterEncodedHex))],
      latest_roster_epoch: '1',
    }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    const identityStore = { loadExisting: async () => identity } as IndexedDbIdentityStore;

    await expect(recoverPendingMembership(
      pendingStore, membershipStore, transportStore, identityStore,
      fetcher as typeof fetch, 1_800_000_000_001n,
    )).resolves.toBe('promoted');
    await expect(pendingStore.load()).resolves.toBeUndefined();
    await expect(transportStore.load()).resolves.toEqual(enrollment);
  } finally {
    await pendingStore.clear(); await membershipStore.clear(); await transportStore.clear();
  }
});

it('refreshes a promoted member and persists a signed revocation roster', async () => {
  const suffix = crypto.randomUUID();
  const membershipStore = new IndexedDbWorkspaceMembershipStore(`active-membership-${suffix}`);
  const transportStore = new IndexedDbTransportCredentialStore(`active-transport-${suffix}`);
  const authority = fromHex(vector.authorityPublicKeyHex);
  const credential = {
    serverOrigin: 'https://notify.example',
    workspaceId: fromHex(vector.workspaceIdHex),
    deviceId: fromHex(vector.deviceIdHex),
    authToken: new Uint8Array(32).fill(7),
    identityKeyId: fromHex(vector.identityKeyIdHex),
  };
  try {
    await membershipStore.pinAuthority(credential.workspaceId, credential.deviceId, authority);
    await membershipStore.reconcileApproved(
      credential.workspaceId,
      credential.deviceId,
      fromHex(vector.certificateEncodedHex),
      fromHex(vector.initialRosterEncodedHex),
    );
    await transportStore.saveNew(credential);
    const fetcher = async () => new Response(JSON.stringify({
      state: 'approved', authority_public_key: toBase64Url(authority), authority_transitions: [],
      signed_certificate: toBase64Url(fromHex(vector.certificateEncodedHex)),
      rosters: [toBase64Url(fromHex(vector.revokedRosterEncodedHex))],
      latest_roster_epoch: '2',
    }), { status: 200, headers: { 'Content-Type': 'application/json' } });

    await expect(refreshActiveMembership(
      credential,
      membershipStore,
      fetcher as typeof fetch,
    )).resolves.toBe('inactive');
    await expect(membershipStore.load(credential.workspaceId, credential.deviceId))
      .resolves.toMatchObject({ rosterEpoch: 2n, localDeviceActive: false });
    await expect(transportStore.load()).resolves.toEqual(credential);
  } finally {
    credential.authToken.fill(0);
    await membershipStore.clear();
    await transportStore.clear();
  }
});

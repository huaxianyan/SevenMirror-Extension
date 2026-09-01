import 'fake-indexeddb/auto';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/workspace-membership-v1.json';
import { IndexedDbWorkspaceMembershipStore } from '../crypto/indexeddb-workspace-membership-store';
import { IndexedDbPendingMembershipStore } from './indexeddb-pending-membership-store';
import { beginChromeMembership, refreshChromeMembership, resumeChromeMembership } from './workspace-membership-client';

const fromHex = (value: string): Uint8Array => Uint8Array.from(value.match(/../g) ?? [], (item) => Number.parseInt(item, 16));
const b64 = (value: Uint8Array): string => { let binary = ''; for (const byte of value) binary += String.fromCharCode(byte); return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, ''); };

async function vectorIdentity(): Promise<CryptoKeyPair> {
  const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
  return {
    privateKey: await suite.kem.deserializePrivateKey(fromHex(vector.identityPrivateScalarHex)),
    publicKey: await suite.kem.deserializePublicKey(fromHex(vector.identityPublicKeyHex)),
  };
}

describe('Workspace Membership HTTP client', () => {
  it('proves identity possession and durably reconciles approval before transport eligibility', async () => {
    const databaseName = `membership-http-${crypto.randomUUID()}`;
    const store = new IndexedDbWorkspaceMembershipStore(databaseName);
    const journal = new IndexedDbPendingMembershipStore(`${databaseName}-journal`);
    const token = new Uint8Array(32).fill(8);
    const requests: Array<{ url: string; body: Record<string, unknown> }> = [];
    const responses: unknown[] = [
      {
        workspace_id: b64(fromHex(vector.workspaceIdHex)), device_id: b64(fromHex(vector.deviceIdHex)),
        auth_token: b64(token), authority_public_key: b64(fromHex(vector.authorityPublicKeyHex)),
        challenge_enc: b64(fromHex(vector.possessionHpkeEncapsulatedKeyHex)),
        challenge_ciphertext: b64(fromHex(vector.possessionHpkeCiphertextHex)),
      },
      { state: 'pending_approval' },
      {
        state: 'approved', authority_public_key: b64(fromHex(vector.authorityPublicKeyHex)),
        authority_transitions: [], signed_certificate: b64(fromHex(vector.certificateEncodedHex)),
        rosters: [b64(fromHex(vector.initialRosterEncodedHex))], latest_roster_epoch: '1',
      },
      {
        state: 'approved', authority_public_key: b64(fromHex(vector.newAuthorityPublicKeyHex)),
        authority_transitions: [b64(fromHex(vector.authorityTransitionEncodedHex))],
        signed_certificate: b64(fromHex(vector.authorityActivationCertificateEncodedHex)),
        rosters: [b64(fromHex(vector.authorityActivationRosterEncodedHex))], latest_roster_epoch: '2',
      },
    ];
    const fetcher = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      requests.push({ url: String(input), body: JSON.parse(String(init?.body)) as Record<string, unknown> });
      return Response.json(responses.shift(), { status: requests.length === 1 ? 201 : 200 });
    };
    try {
      const pending = await beginChromeMembership({
        serverOrigin: 'https://membership.example', pairingCode: 'A'.repeat(32),
        deviceName: 'Browser', identity: await vectorIdentity(),
      }, store, journal, fetcher);
      expect(requests.map((item) => item.url)).toEqual([
        'https://membership.example/v1/membership/register',
        'https://membership.example/v1/membership/prove',
      ]);
      expect(requests[1]?.body.proof).toBe(b64(fromHex(vector.proofEncodedHex)));
      expect(await journal.load()).toMatchObject({ phase: 'pending-approval' });
      expect((await store.load(pending.workspaceId, pending.deviceId))?.rosterEpoch).toBe(0n);

      const approved = await refreshChromeMembership(pending, store, fetcher);
      expect(approved).toMatchObject({ serverState: 'approved', transportEligible: true });
      expect(approved.state.rosterEpoch).toBe(1n);
      expect(requests[2]?.body.after_roster_epoch).toBe('0');

      const rotated = await refreshChromeMembership(pending, store, fetcher);
      expect(rotated).toMatchObject({ serverState: 'approved', transportEligible: true });
      expect(rotated.state).toMatchObject({ authorityEpoch: 2n, rosterEpoch: 2n });
      expect(rotated.state.authorityPublicKey).toEqual(fromHex(vector.newAuthorityPublicKeyHex));
      expect(requests[3]?.body.after_roster_epoch).toBe('1');
    } finally {
      await store.clear();
      await journal.clear();
    }
  });

  it('resumes the exact durable proof after an ambiguous attempt', async () => {
    const databaseName = `membership-resume-${crypto.randomUUID()}`;
    const store = new IndexedDbWorkspaceMembershipStore(databaseName);
    const journal = new IndexedDbPendingMembershipStore(`${databaseName}-journal`);
    const workspace = fromHex(vector.workspaceIdHex); const device = fromHex(vector.deviceIdHex);
    const pending = {
      serverOrigin: 'https://membership.example', workspaceId: workspace, deviceId: device,
      authToken: new Uint8Array(32).fill(8), identityKeyId: fromHex(vector.identityKeyIdHex),
    };
    const proof = fromHex(vector.proofEncodedHex);
    await store.pinAuthority(workspace, device, fromHex(vector.authorityPublicKeyHex));
    await journal.prepareRegistration(
      pending, fromHex(vector.authorityPublicKeyHex),
      fromHex(vector.possessionHpkeEncapsulatedKeyHex), fromHex(vector.possessionHpkeCiphertextHex),
    );
    await journal.bindProof(pending, proof);
    await journal.markProofAttempted(pending, proof);
    const responses = [
      { state: 'pending_proof', authority_public_key: b64(fromHex(vector.authorityPublicKeyHex)), authority_transitions: [], rosters: [], latest_roster_epoch: '0' },
      { state: 'pending_approval' },
      { state: 'pending_approval', authority_public_key: b64(fromHex(vector.authorityPublicKeyHex)), authority_transitions: [], rosters: [], latest_roster_epoch: '0' },
    ];
    const bodies: Record<string, unknown>[] = [];
    try {
      const result = await resumeChromeMembership(journal, store, await vectorIdentity(), async (_input, init) => {
        bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
        return Response.json(responses.shift());
      });
      expect(result).toMatchObject({ serverState: 'pending_approval', transportEligible: false });
      expect(bodies[1]?.proof).toBe(b64(proof));
      expect((await journal.load())?.phase).toBe('pending-approval');
    } finally {
      await store.clear(); await journal.clear();
    }
  });

  it('does not expose transport eligibility while administrator approval is pending', async () => {
    const store = new IndexedDbWorkspaceMembershipStore(`membership-http-${crypto.randomUUID()}`);
    const workspace = fromHex(vector.workspaceIdHex); const device = fromHex(vector.deviceIdHex);
    await store.pinAuthority(workspace, device, fromHex(vector.authorityPublicKeyHex));
    try {
      const result = await refreshChromeMembership({
        serverOrigin: 'https://membership.example', workspaceId: workspace, deviceId: device,
        authToken: new Uint8Array(32).fill(8), identityKeyId: fromHex(vector.identityKeyIdHex),
      }, store, async () => Response.json({
        state: 'pending_approval', authority_public_key: b64(fromHex(vector.authorityPublicKeyHex)),
        authority_transitions: [], rosters: [], latest_roster_epoch: '0',
      }));
      expect(result).toMatchObject({ serverState: 'pending_approval', transportEligible: false });
    } finally {
      await store.clear();
    }
  });
});

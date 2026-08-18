import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { IndexedDbTransportCredentialStore } from '../transport/indexeddb-transport-credential-store';
import { deriveIdentityKeyId, generateNonExtractableIdentity, serializeIdentityPublicKey } from './auth-hpke';
import { IndexedDbIdentityStore } from './indexeddb-identity-store';
import { IndexedDbLocalIdentityTransitionStore } from './indexeddb-local-identity-transition-store';
import { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';
import { IdentityTransitionInitiator } from './identity-transition-initiator';

const now = 1_800_000_000_000;

describe('IdentityTransitionInitiator', () => {
  it('reuses exact pending/session state after Worker-style reconstruction', async () => {
    const suffix = `${Date.now()}-${Math.random()}`;
    const identities = new IndexedDbIdentityStore(`initiator-identity-${suffix}`);
    const credentials = new IndexedDbTransportCredentialStore(`initiator-credential-${suffix}`);
    const peers = new IndexedDbTrustedPeerStore(`initiator-peers-${suffix}`);
    const local = new IndexedDbLocalIdentityTransitionStore(`initiator-local-${suffix}`);
    const workspaceId = new Uint8Array(16).fill(1);
    const deviceId = new Uint8Array(16).fill(2);
    try {
      const current = await identities.loadOrCreate();
      const currentKeyId = await deriveIdentityKeyId(await serializeIdentityPublicKey(current));
      await credentials.saveNew({
        serverOrigin: 'https://relay.example',
        workspaceId,
        deviceId,
        authToken: new Uint8Array(32).fill(9),
        identityKeyId: currentKeyId,
      });
      const peer = await generateNonExtractableIdentity();
      await peers.pinApproved(
        workspaceId,
        new Uint8Array(16).fill(3),
        await serializeIdentityPublicKey(peer),
      );
      let next = 4;
      const first = await new IdentityTransitionInitiator(
        credentials,
        identities,
        peers,
        local,
        () => now,
        (target) => target.fill(next++),
      ).prepare();
      const recovered = await new IdentityTransitionInitiator(
        new IndexedDbTransportCredentialStore(`initiator-credential-${suffix}`),
        new IndexedDbIdentityStore(`initiator-identity-${suffix}`),
        new IndexedDbTrustedPeerStore(`initiator-peers-${suffix}`),
        new IndexedDbLocalIdentityTransitionStore(`initiator-local-${suffix}`),
        () => now + 1,
        (target) => target.fill(next++),
      ).prepare();
      expect(recovered.transitionId).toEqual(first.transitionId);
      expect(recovered.canonicalTransition).toEqual(first.canonicalTransition);
      expect(recovered.newKeyId).toEqual(first.newKeyId);
      expect(next).toBe(5);
    } finally {
      await local.clear();
      await peers.clear();
      await credentials.clear();
      await identities.clear();
    }
  });
});

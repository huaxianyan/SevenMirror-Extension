import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { IndexedDbTransportCredentialStore } from '../transport/indexeddb-transport-credential-store';
import { deriveIdentityKeyId, generateNonExtractableIdentity, serializeIdentityPublicKey } from './auth-hpke';
import { IndexedDbIdentityStore } from './indexeddb-identity-store';
import { IndexedDbLocalIdentityTransitionStore } from './indexeddb-local-identity-transition-store';
import { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';
import { IdentityTransitionInitiator } from './identity-transition-initiator';
import { IdentityTransitionPeerRemovalCoordinator } from './identity-transition-peer-removal';

const now = 1_800_000_000_000;

describe('IdentityTransitionPeerRemovalCoordinator', () => {
  it('recovers after trust removal committed before snapshot exclusion', async () => {
    const suffix = `${Date.now()}-${Math.random()}`;
    const identities = new IndexedDbIdentityStore(`removal-identity-${suffix}`);
    const credentials = new IndexedDbTransportCredentialStore(`removal-credential-${suffix}`);
    const peers = new IndexedDbTrustedPeerStore(`removal-peers-${suffix}`);
    const local = new IndexedDbLocalIdentityTransitionStore(`removal-local-${suffix}`);
    const workspaceId = new Uint8Array(16).fill(1);
    const localDeviceId = new Uint8Array(16).fill(2);
    const peerDeviceId = new Uint8Array(16).fill(3);
    try {
      const current = await identities.loadOrCreate();
      await credentials.saveNew({
        serverOrigin: 'https://relay.example',
        workspaceId,
        deviceId: localDeviceId,
        authToken: new Uint8Array(32).fill(9),
        identityKeyId: await deriveIdentityKeyId(await serializeIdentityPublicKey(current)),
      });
      const peer = await generateNonExtractableIdentity();
      await peers.pinApproved(workspaceId, peerDeviceId, await serializeIdentityPublicKey(peer));
      await new IdentityTransitionInitiator(
        credentials,
        identities,
        peers,
        local,
        () => now,
        (target) => target.fill(4),
      ).prepare();

      await peers.remove(workspaceId, peerDeviceId);
      expect(await new IdentityTransitionPeerRemovalCoordinator(
        credentials,
        peers,
        local,
        () => now + 1,
      ).remove(peerDeviceId)).toBe('recovered');
      expect(await local.loadPeer(peerDeviceId, now + 1)).toBeUndefined();
      expect((await local.loadSession(now + 1))?.phase).toBe('blocked');
    } finally {
      await local.clear();
      await peers.clear();
      await credentials.clear();
      await identities.clear();
    }
  });
});

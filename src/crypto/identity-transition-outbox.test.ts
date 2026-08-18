import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import {
  createIdentityKeyTransitionPayload,
  encodeIdentityKeyLifecyclePayload,
} from '../protocol/identity-key-transition-payload';
import { IndexedDbTransportCredentialStore } from '../transport/indexeddb-transport-credential-store';
import { serializeIdentityPublicKey } from './auth-hpke';
import { receiveIdentityTransitionOnce, type ReplayLedgerWriter } from './envelope-receiver';
import { IndexedDbIdentityStore } from './indexeddb-identity-store';
import { IndexedDbLocalIdentityTransitionStore } from './indexeddb-local-identity-transition-store';
import { IndexedDbOutboundSequenceStore } from './indexeddb-outbound-sequence-store';
import { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';
import { IdentityTransitionOutbox } from './identity-transition-outbox';

const now = 1_800_000_000_000;
const workspaceId = new Uint8Array(16).fill(1);
const senderDeviceId = new Uint8Array(16).fill(2);
const peerDeviceId = new Uint8Array(16).fill(3);

class MemoryReplayLedger implements ReplayLedgerWriter {
  async checkAndRecord(): Promise<'accepted'> { return 'accepted'; }
}

describe('IdentityTransitionOutbox', () => {
  it('retries exact transition plaintext under fresh envelopes without advancing on send false', async () => {
    const suffix = `${Date.now()}-${Math.random()}`;
    const identities = new IndexedDbIdentityStore(`transition-outbox-identity-${suffix}`);
    const credentials = new IndexedDbTransportCredentialStore(`transition-outbox-credential-${suffix}`);
    const local = new IndexedDbLocalIdentityTransitionStore(`transition-outbox-local-${suffix}`);
    const senderPeers = new IndexedDbTrustedPeerStore(`transition-outbox-sender-peers-${suffix}`);
    const receiverPeers = new IndexedDbTrustedPeerStore(`transition-outbox-receiver-peers-${suffix}`);
    const sequences = new IndexedDbOutboundSequenceStore(`transition-outbox-sequence-${suffix}`);
    try {
      const current = await identities.loadOrCreate();
      const rotation = await identities.prepareRotation();
      const currentPublic = await serializeIdentityPublicKey(current);
      const pendingPublic = await serializeIdentityPublicKey(rotation.pending);
      const peerIdentityStore = new IndexedDbIdentityStore(`transition-outbox-peer-identity-${suffix}`);
      try {
        const peer = await peerIdentityStore.loadOrCreate();
        const peerPublic = await serializeIdentityPublicKey(peer);
        const currentKeyId = await sha256(currentPublic);
        const peerKeyId = await sha256(peerPublic);
        const canonicalTransition = await encodeIdentityKeyLifecyclePayload(
          createIdentityKeyTransitionPayload({
            transitionId: new Uint8Array(16).fill(4),
            previousKeyId: currentKeyId,
            newPublicKey: pendingPublic,
            newKeyId: await sha256(pendingPublic),
          }),
        );
        await credentials.saveNew({
          serverOrigin: 'https://relay.example',
          workspaceId,
          deviceId: senderDeviceId,
          authToken: new Uint8Array(32).fill(9),
          identityKeyId: currentKeyId,
        });
        await senderPeers.pinApproved(workspaceId, peerDeviceId, peerPublic);
        await receiverPeers.pinApproved(workspaceId, senderDeviceId, currentPublic);
        await local.create(
          workspaceId,
          senderDeviceId,
          canonicalTransition,
          [{ deviceId: peerDeviceId, keyId: peerKeyId }],
          now,
        );
        const sent: Uint8Array[] = [];
        let random = 5;
        const rejected = await new IdentityTransitionOutbox(
          credentials,
          identities,
          local,
          senderPeers,
          sequences,
          (frame) => { sent.push(frame.slice()); return false; },
          () => now + 1,
          (target) => target.fill(random++),
        ).drainDue();
        expect(rejected).toMatchObject({ acceptedSends: 0, attemptedEntries: 1 });
        expect((await local.loadPeer(peerDeviceId, now + 1))?.commitAttemptCount).toBe(0);

        const accepted = await new IdentityTransitionOutbox(
          credentials,
          identities,
          local,
          senderPeers,
          sequences,
          (frame) => { sent.push(frame.slice()); return true; },
          () => now + 1,
          (target) => target.fill(random++),
        ).drainDue();
        expect(accepted).toMatchObject({ acceptedSends: 1, attemptedEntries: 1 });
        expect(sent[1]).not.toEqual(sent[0]);
        const received = await receiveIdentityTransitionOnce(sent[1]!, {
          workspaceId,
          recipientDeviceId: peerDeviceId,
          recipientIdentity: peer,
          pinnedSenderPublicKey: currentPublic,
        }, receiverPeers, new MemoryReplayLedger(), now + 2);
        expect(received.accepted.state.canonicalTransition).toEqual(canonicalTransition);
      } finally {
        await peerIdentityStore.clear();
      }
    } finally {
      await sequences.clear();
      await receiverPeers.clear();
      await senderPeers.clear();
      await local.clear();
      await credentials.clear();
      await identities.clear();
    }
  });
});

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

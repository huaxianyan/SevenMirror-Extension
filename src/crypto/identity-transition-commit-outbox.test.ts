import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import {
  createIdentityKeyTransitionCommitPayload,
  createIdentityKeyTransitionPayload,
  encodeIdentityKeyLifecyclePayload,
} from '../protocol/identity-key-transition-payload';
import type { StoredTransportCredential } from '../transport/indexeddb-transport-credential-store';
import {
  generateNonExtractableIdentity,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import {
  receiveIdentityTransitionCommitOnce,
  type ReplayLedgerWriter,
} from './envelope-receiver';
import { IdentityTransitionCommitOutbox } from './identity-transition-commit-outbox';
import { IndexedDbLocalIdentityTransitionStore } from './indexeddb-local-identity-transition-store';
import { IndexedDbOutboundSequenceStore } from './indexeddb-outbound-sequence-store';
import { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';

const now = 1_800_000_000_000;
const workspaceId = new Uint8Array(16).fill(1);
const rotatingDeviceId = new Uint8Array(16).fill(2);
const peerDeviceId = new Uint8Array(16).fill(3);
const transitionId = new Uint8Array(16).fill(4);

class MemoryReplayLedger implements ReplayLedgerWriter {
  constructor(private failNext = false) {}
  async checkAndRecord(): Promise<'accepted' | 'capacity-exceeded'> {
    if (this.failNext) {
      this.failNext = false;
      return 'capacity-exceeded';
    }
    return 'accepted';
  }
}

describe('IdentityTransitionCommitOutbox', () => {
  it('sends with the pending identity and peer atomically promotes before replay recovery', async () => {
    const current = await generateNonExtractableIdentity();
    const pending = await generateNonExtractableIdentity();
    const peer = await generateNonExtractableIdentity();
    const currentPublic = await serializeIdentityPublicKey(current);
    const pendingPublic = await serializeIdentityPublicKey(pending);
    const peerPublic = await serializeIdentityPublicKey(peer);
    const previousKeyId = await sha256(currentPublic);
    const newKeyId = await sha256(pendingPublic);
    const peerKeyId = await sha256(peerPublic);
    const canonicalTransition = await encodeIdentityKeyLifecyclePayload(
      createIdentityKeyTransitionPayload({
        transitionId,
        previousKeyId,
        newPublicKey: pendingPublic,
        newKeyId,
      }),
    );
    const receiverPeerDatabase = uniqueName('receiver-peers');
    const senderPeerDatabase = uniqueName('sender-peers');
    const localDatabase = uniqueName('local');
    const sequenceDatabase = uniqueName('sequences');
    const receiverPeers = new IndexedDbTrustedPeerStore(receiverPeerDatabase);
    const senderPeers = new IndexedDbTrustedPeerStore(senderPeerDatabase);
    const localTransitions = new IndexedDbLocalIdentityTransitionStore(localDatabase);
    const sequences = new IndexedDbOutboundSequenceStore(sequenceDatabase);
    try {
      await receiverPeers.pinApproved(workspaceId, rotatingDeviceId, currentPublic);
      const acceptedTransition = await receiverPeers.acceptIdentityTransition(
        workspaceId,
        rotatingDeviceId,
        canonicalTransition,
        now,
      );
      const wrongCommit = await encodeIdentityKeyLifecyclePayload(
        createIdentityKeyTransitionCommitPayload({
          transitionId,
          previousKeyId,
          newKeyId,
          transitionSha256: acceptedTransition.state.transitionSha256,
          ackSha256: new Uint8Array(32).fill(9),
        }),
      );
      await expect(receiverPeers.commitIdentityTransition(
        workspaceId,
        rotatingDeviceId,
        newKeyId,
        wrongCommit,
        now + 1,
      )).rejects.toThrow('binding does not match');
      expect(await receiverPeers.findApproved(workspaceId, rotatingDeviceId, previousKeyId))
        .toEqual(currentPublic);

      await senderPeers.pinApproved(workspaceId, peerDeviceId, peerPublic);
      await localTransitions.create(
        workspaceId,
        rotatingDeviceId,
        canonicalTransition,
        [{ deviceId: peerDeviceId, keyId: peerKeyId }],
        now,
      );
      await localTransitions.acceptAck(
        peerDeviceId,
        peerKeyId,
        acceptedTransition.state.canonicalAck,
        now + 1,
      );

      const sent: Uint8Array[] = [];
      let randomByte = 10;
      const rejectedDrain = await new IdentityTransitionCommitOutbox(
        { load: async () => credential(previousKeyId) },
        { loadExisting: async () => current, loadRotation: async () => ({ current, pending }) },
        localTransitions,
        senderPeers,
        sequences,
        (frame) => { sent.push(frame.slice()); return false; },
        () => now + 2,
        (target) => target.fill(randomByte++),
      ).drainDue();
      expect(rejectedDrain).toMatchObject({ acceptedSends: 0, attemptedEntries: 1 });
      expect((await localTransitions.loadPeer(peerDeviceId, now + 2))?.commitAttemptCount).toBe(0);

      const outbox = new IdentityTransitionCommitOutbox(
        { load: async () => credential(previousKeyId) },
        { loadExisting: async () => current, loadRotation: async () => ({ current, pending }) },
        localTransitions,
        senderPeers,
        sequences,
        (frame) => { sent.push(frame.slice()); return true; },
        () => now + 2,
        (target) => target.fill(randomByte++),
      );
      const firstDrain = await outbox.drainDue();
      expect(firstDrain).toMatchObject({ acceptedSends: 1, attemptedEntries: 1 });
      expect(sent[1]).not.toEqual(sent[0]);

      await expect(receiveIdentityTransitionCommitOnce(
        sent[1]!,
        {
          workspaceId,
          recipientDeviceId: peerDeviceId,
          recipientIdentity: peer,
        },
        receiverPeers,
        new MemoryReplayLedger(true),
        now + 3,
      )).rejects.toMatchObject({ code: 'REPLAY_CAPACITY_EXCEEDED' });
      expect(await receiverPeers.findApproved(workspaceId, rotatingDeviceId, previousKeyId))
        .toBeUndefined();
      expect(await receiverPeers.findApproved(workspaceId, rotatingDeviceId, newKeyId))
        .toEqual(pendingPublic);

      await localTransitions.acceptAck(
        peerDeviceId,
        peerKeyId,
        acceptedTransition.state.canonicalAck,
        now + 4,
      );
      const secondDrain = await new IdentityTransitionCommitOutbox(
        { load: async () => credential(previousKeyId) },
        { loadExisting: async () => current, loadRotation: async () => ({ current, pending }) },
        new IndexedDbLocalIdentityTransitionStore(localDatabase),
        senderPeers,
        new IndexedDbOutboundSequenceStore(sequenceDatabase),
        (frame) => { sent.push(frame.slice()); return true; },
        () => now + 5,
        (target) => target.fill(randomByte++),
      ).drainDue();
      expect(secondDrain.acceptedSends).toBe(1);
      expect(sent[2]).not.toEqual(sent[1]);
      const duplicate = await receiveIdentityTransitionCommitOnce(
        sent[2]!,
        {
          workspaceId,
          recipientDeviceId: peerDeviceId,
          recipientIdentity: peer,
        },
        new IndexedDbTrustedPeerStore(receiverPeerDatabase),
        new MemoryReplayLedger(),
        now + 6,
      );
      expect(duplicate.committed.disposition).toBe('already-committed');
      expect(await receiverPeers.findApproved(workspaceId, rotatingDeviceId, newKeyId))
        .toEqual(pendingPublic);
    } finally {
      await localTransitions.clear();
      await sequences.clear();
      await senderPeers.clear();
      await receiverPeers.clear();
    }
  });
});

function credential(identityKeyId: Uint8Array): StoredTransportCredential {
  return {
    serverOrigin: 'https://relay.example',
    workspaceId: workspaceId.slice(),
    deviceId: rotatingDeviceId.slice(),
    authToken: new Uint8Array(32).fill(8),
    identityKeyId: identityKeyId.slice(),
  };
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

function uniqueName(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random()}`;
}

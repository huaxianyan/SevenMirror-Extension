import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import {
  createIdentityKeyTransitionPayload,
  encodeIdentityKeyLifecyclePayload,
} from '../protocol/identity-key-transition-payload';
import type { StoredTransportCredential } from '../transport/indexeddb-transport-credential-store';
import { generateNonExtractableIdentity, serializeIdentityPublicKey } from './auth-hpke';
import { openPendingIdentityAckOnce, type ReplayLedgerWriter } from './envelope-receiver';
import { IdentityTransitionAckOutbox } from './identity-transition-ack-outbox';
import { IndexedDbOutboundSequenceStore } from './indexeddb-outbound-sequence-store';
import { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';

class MemoryReplayLedger implements ReplayLedgerWriter {
  async checkAndRecord(): Promise<'accepted'> { return 'accepted'; }
}

const nowBase = 1_800_000_000_000;

function uniqueName(): string {
  return `transition-ack-${Date.now()}-${Math.random()}`;
}

describe('IdentityTransitionAckOutbox', () => {
  it('restores exact intent and uses fresh envelopes without deleting it on send acceptance', async () => {
    const name = uniqueName();
    const peerStoreName = `peers-${name}`;
    const sequenceStoreName = `sequences-${name}`;
    const localIdentity = await generateNonExtractableIdentity();
    const peerOldIdentity = await generateNonExtractableIdentity();
    const peerNewIdentity = await generateNonExtractableIdentity();
    const localPublicKey = await serializeIdentityPublicKey(localIdentity);
    const peerOldPublicKey = await serializeIdentityPublicKey(peerOldIdentity);
    const peerNewPublicKey = await serializeIdentityPublicKey(peerNewIdentity);
    const workspaceId = new Uint8Array(16).fill(1);
    const localDeviceId = new Uint8Array(16).fill(2);
    const peerDeviceId = new Uint8Array(16).fill(3);
    const transitionId = new Uint8Array(16).fill(4);
    const previousKeyId = await sha256(peerOldPublicKey);
    const newKeyId = await sha256(peerNewPublicKey);
    const canonicalTransition = await encodeIdentityKeyLifecyclePayload(
      createIdentityKeyTransitionPayload({
        transitionId,
        previousKeyId,
        newPublicKey: peerNewPublicKey,
        newKeyId,
      }),
    );
    const credential: StoredTransportCredential = {
      serverOrigin: 'https://notify.example',
      workspaceId,
      deviceId: localDeviceId,
      authToken: new Uint8Array(32).fill(5),
      identityKeyId: await sha256(localPublicKey),
    };
    let peers = new IndexedDbTrustedPeerStore(peerStoreName);
    let sequences = new IndexedDbOutboundSequenceStore(sequenceStoreName);
    let socketAccepted = false;
    let now = nowBase;
    const attemptedFrames: Uint8Array[] = [];
    const sentFrames: Uint8Array[] = [];
    const createOutbox = () => new IdentityTransitionAckOutbox(
      { load: async () => copyCredential(credential) },
      { loadExisting: async () => localIdentity },
      peers,
      sequences,
      (frame) => {
        attemptedFrames.push(frame.slice());
        if (!socketAccepted) return false;
        sentFrames.push(frame.slice());
        return true;
      },
      () => now,
      (target) => target.fill(attemptedFrames.length + 6),
    );
    try {
      await peers.pinApproved(workspaceId, peerDeviceId, peerOldPublicKey);
      const accepted = await peers.acceptIdentityTransition(
        workspaceId,
        peerDeviceId,
        canonicalTransition,
        now,
      );
      let outbox = createOutbox();

      expect(await outbox.drainDue()).toEqual({ acceptedSends: 0, attemptedEntries: 1 });
      expect((await peers.loadIdentityTransition(workspaceId, peerDeviceId, now))?.ackAttemptCount)
        .toBe(0);

      peers = new IndexedDbTrustedPeerStore(peerStoreName);
      sequences = new IndexedDbOutboundSequenceStore(sequenceStoreName);
      outbox = createOutbox();
      socketAccepted = true;
      expect(await outbox.drainDue()).toEqual({
        acceptedSends: 1,
        attemptedEntries: 1,
        nextWakeDelayMs: 1_000,
      });
      const binding = {
        senderDeviceId: localDeviceId,
        transitionId,
        previousKeyId,
        newKeyId,
        transitionSha256: accepted.state.transitionSha256,
      };
      const firstAttempt = await openPendingIdentityAckOnce(
        attemptedFrames[0]!,
        {
          workspaceId,
          recipientDeviceId: peerDeviceId,
          recipientIdentity: peerNewIdentity,
          pinnedSenderPublicKey: localPublicKey,
        },
        binding,
        new MemoryReplayLedger(),
        now,
      );
      const acceptedAttempt = await openPendingIdentityAckOnce(
        sentFrames[0]!,
        {
          workspaceId,
          recipientDeviceId: peerDeviceId,
          recipientIdentity: peerNewIdentity,
          pinnedSenderPublicKey: localPublicKey,
        },
        binding,
        new MemoryReplayLedger(),
        now,
      );
      expect(firstAttempt.canonicalPayload).toEqual(accepted.state.canonicalAck);
      expect(acceptedAttempt.canonicalPayload).toEqual(accepted.state.canonicalAck);
      expect(firstAttempt.header.messageId).not.toEqual(acceptedAttempt.header.messageId);
      expect(firstAttempt.header.sequence).toBe(1n);
      expect(acceptedAttempt.header.sequence).toBe(2n);
      expect((await peers.loadIdentityTransition(workspaceId, peerDeviceId, now))?.ackAttemptCount)
        .toBe(1);

      now += 1_000;
      expect((await outbox.drainDue()).acceptedSends).toBe(1);
      expect(sentFrames).toHaveLength(2);
      expect((await peers.loadIdentityTransition(workspaceId, peerDeviceId, now))?.phase)
        .toBe('pending-commit');
    } finally {
      await Promise.all([peers.clear(), sequences.clear()]);
    }
  });
});

function copyCredential(value: StoredTransportCredential): StoredTransportCredential {
  return {
    serverOrigin: value.serverOrigin,
    workspaceId: value.workspaceId.slice(),
    deviceId: value.deviceId.slice(),
    authToken: value.authToken.slice(),
    identityKeyId: value.identityKeyId.slice(),
  };
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { encodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import {
  createIdentityKeyTransitionAckPayload,
  createIdentityKeyTransitionPayload,
  decodeIdentityKeyLifecyclePayload,
  encodeIdentityKeyLifecyclePayload,
} from '../protocol/identity-key-transition-payload';
import { encodeRoutingHeaderV1 } from '../protocol/routing-header';
import {
  generateNonExtractableIdentity,
  sealWithIdentity,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import { receivePendingIdentityAckOnce, type ReplayLedgerWriter } from './envelope-receiver';
import { IndexedDbLocalIdentityTransitionStore } from './indexeddb-local-identity-transition-store';

const now = 1_800_000_000_000;
const workspaceId = new Uint8Array(16).fill(1);
const localDeviceId = new Uint8Array(16).fill(2);
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

describe('IndexedDbLocalIdentityTransitionStore', () => {
  it('persists exact ACK and commit bytes across Worker reconstruction', async () => {
    const fixture = await createFixture();
    const databaseName = uniqueName();
    const store = new IndexedDbLocalIdentityTransitionStore(databaseName);
    try {
      await store.create(
        workspaceId,
        localDeviceId,
        fixture.canonicalTransition,
        [{ deviceId: peerDeviceId, keyId: fixture.peerKeyId }],
        now,
      );
      const accepted = await store.acceptAck(
        peerDeviceId,
        fixture.peerKeyId,
        fixture.canonicalAck,
        now + 1,
      );
      expect(accepted.disposition).toBe('accepted');
      expect(accepted.peer.canonicalAck).toEqual(fixture.canonicalAck);
      const commit = await decodeIdentityKeyLifecyclePayload(accepted.peer.canonicalCommit!);
      expect(commit.body.case).toBe('identityKeyTransitionCommit');
      if (commit.body.case !== 'identityKeyTransitionCommit') throw new Error('wrong commit body');
      expect(commit.body.value.ackSha256).toEqual(await sha256(fixture.canonicalAck));

      const reconstructed = new IndexedDbLocalIdentityTransitionStore(databaseName);
      const duplicate = await reconstructed.acceptAck(
        peerDeviceId,
        fixture.peerKeyId,
        fixture.canonicalAck,
        now + 2,
      );
      expect(duplicate.disposition).toBe('already-accepted');
      expect(duplicate.peer.canonicalCommit).toEqual(accepted.peer.canonicalCommit);

      const wrongAck = await encodeIdentityKeyLifecyclePayload(
        createIdentityKeyTransitionAckPayload({
          transitionId,
          previousKeyId: fixture.previousKeyId,
          newKeyId: fixture.newKeyId,
          transitionSha256: new Uint8Array(32).fill(9),
        }),
      );
      await expect(reconstructed.acceptAck(
        peerDeviceId,
        fixture.peerKeyId,
        wrongAck,
        now + 3,
      )).rejects.toThrow('binding does not match');
      expect((await reconstructed.loadPeer(peerDeviceId, now + 4))?.canonicalCommit)
        .toEqual(accepted.peer.canonicalCommit);
    } finally {
      await store.clear();
    }
  });

  it('blocks expired sessions without accepting or generating a commit', async () => {
    const fixture = await createFixture();
    const store = new IndexedDbLocalIdentityTransitionStore(uniqueName());
    try {
      const session = await store.create(
        workspaceId,
        localDeviceId,
        fixture.canonicalTransition,
        [{ deviceId: peerDeviceId, keyId: fixture.peerKeyId }],
        now,
      );
      await expect(store.acceptAck(
        peerDeviceId,
        fixture.peerKeyId,
        fixture.canonicalAck,
        session.expiresAtUnixMs,
      )).rejects.toThrow('blocked after expiry');
      expect((await store.loadPeer(peerDeviceId, session.expiresAtUnixMs + 1))?.phase)
        .toBe('awaiting-ack');
    } finally {
      await store.clear();
    }
  });

  it('persists ACK and commit before replay consumption', async () => {
    const fixture = await createFixture();
    const databaseName = uniqueName();
    const store = new IndexedDbLocalIdentityTransitionStore(databaseName);
    try {
      await store.create(
        workspaceId,
        localDeviceId,
        fixture.canonicalTransition,
        [{ deviceId: peerDeviceId, keyId: fixture.peerKeyId }],
        now,
      );
      const firstFrame = await ackFrame(fixture, new Uint8Array(16).fill(6));
      await expect(receivePendingIdentityAckOnce(
        firstFrame,
        fixture.recipientContext,
        store,
        new MemoryReplayLedger(true),
        now + 1,
      )).rejects.toMatchObject({ code: 'REPLAY_CAPACITY_EXCEEDED' });
      const durable = await new IndexedDbLocalIdentityTransitionStore(databaseName)
        .loadPeer(peerDeviceId, now + 2);
      expect(durable?.canonicalAck).toEqual(fixture.canonicalAck);
      expect(durable?.canonicalCommit).toBeDefined();

      const recovered = await receivePendingIdentityAckOnce(
        await ackFrame(fixture, new Uint8Array(16).fill(7)),
        fixture.recipientContext,
        store,
        new MemoryReplayLedger(),
        now + 2,
      );
      expect(recovered.accepted.disposition).toBe('already-accepted');
      expect(recovered.accepted.peer.canonicalCommit).toEqual(durable?.canonicalCommit);
    } finally {
      await store.clear();
    }
  });
});

interface Fixture {
  peer: HpkeIdentity;
  peerPublicKey: Uint8Array;
  peerKeyId: Uint8Array;
  pendingPublicKey: Uint8Array;
  previousKeyId: Uint8Array;
  newKeyId: Uint8Array;
  canonicalTransition: Uint8Array;
  canonicalAck: Uint8Array;
  recipientContext: {
    workspaceId: Uint8Array;
    recipientDeviceId: Uint8Array;
    recipientIdentity: HpkeIdentity;
    pinnedSenderPublicKey: Uint8Array;
  };
}

async function createFixture(): Promise<Fixture> {
  const current = await generateNonExtractableIdentity();
  const pending = await generateNonExtractableIdentity();
  const peer = await generateNonExtractableIdentity();
  const currentPublicKey = await serializeIdentityPublicKey(current);
  const pendingPublicKey = await serializeIdentityPublicKey(pending);
  const peerPublicKey = await serializeIdentityPublicKey(peer);
  const previousKeyId = await sha256(currentPublicKey);
  const newKeyId = await sha256(pendingPublicKey);
  const canonicalTransition = await encodeIdentityKeyLifecyclePayload(
    createIdentityKeyTransitionPayload({
      transitionId,
      previousKeyId,
      newPublicKey: pendingPublicKey,
      newKeyId,
    }),
  );
  const canonicalAck = await encodeIdentityKeyLifecyclePayload(
    createIdentityKeyTransitionAckPayload({
      transitionId,
      previousKeyId,
      newKeyId,
      transitionSha256: await sha256(canonicalTransition),
    }),
  );
  return {
    peer,
    peerPublicKey,
    peerKeyId: await sha256(peerPublicKey),
    pendingPublicKey,
    previousKeyId,
    newKeyId,
    canonicalTransition,
    canonicalAck,
    recipientContext: {
      workspaceId,
      recipientDeviceId: localDeviceId,
      recipientIdentity: pending,
      pinnedSenderPublicKey: peerPublicKey,
    },
  };
}

async function ackFrame(fixture: Fixture, messageId: Uint8Array): Promise<Uint8Array> {
  const routingHeader = encodeRoutingHeaderV1({
    workspaceId,
    senderDeviceId: peerDeviceId,
    recipientDeviceId: localDeviceId,
    senderKeyId: fixture.peerKeyId,
    recipientKeyId: fixture.newKeyId,
    messageId,
    sequence: BigInt(messageId[0] ?? 1),
    createdAtUnixMs: now,
    expiresAtUnixMs: now + 60_000,
  });
  const encrypted = await sealWithIdentity(
    fixture.pendingPublicKey,
    fixture.peer,
    fixture.canonicalAck,
    routingHeader,
  );
  return encodeEncryptedEnvelopeV1({
    routingHeader,
    encapsulatedKey: encrypted.encapsulatedKey,
    ciphertext: encrypted.ciphertext,
  });
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

function uniqueName(): string {
  return `local-transition-${Date.now()}-${Math.random()}`;
}

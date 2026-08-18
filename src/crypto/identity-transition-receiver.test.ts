import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { encodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import { createActionResultPayload, encodeEncryptedPayloadV1 } from '../protocol/encrypted-payload';
import {
  createIdentityKeyTransitionPayload,
  encodeIdentityKeyLifecyclePayload,
} from '../protocol/identity-key-transition-payload';
import { ActionResultStatus } from '../protocol/generated/notification/v1/payload_pb';
import { encodeRoutingHeaderV1 } from '../protocol/routing-header';
import {
  generateNonExtractableIdentity,
  sealWithIdentity,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import {
  receiveIdentityTransitionOnce,
  type ReplayLedgerWriter,
} from './envelope-receiver';
import { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';

const now = 1_800_000_000_000;
const workspaceId = new Uint8Array(16).fill(1);
const senderDeviceId = new Uint8Array(16).fill(2);
const recipientDeviceId = new Uint8Array(16).fill(3);

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

describe('identity transition receiver', () => {
  it('persists the exact ACK intent before replay consumption', async () => {
    const fixture = await createFixture();
    const databaseName = uniqueName();
    const store = new IndexedDbTrustedPeerStore(databaseName);
    try {
      await store.pinApproved(workspaceId, senderDeviceId, fixture.senderPublicKey);
      const firstFrame = await frame(
        fixture,
        fixture.canonicalTransition,
        new Uint8Array(16).fill(6),
      );
      await expect(receiveIdentityTransitionOnce(
        firstFrame,
        fixture.context,
        store,
        new MemoryReplayLedger(true),
        now,
      )).rejects.toMatchObject({ code: 'REPLAY_CAPACITY_EXCEEDED' });

      const durable = await new IndexedDbTrustedPeerStore(databaseName)
        .loadIdentityTransition(workspaceId, senderDeviceId, now + 1);
      expect(durable?.canonicalTransition).toEqual(fixture.canonicalTransition);
      expect(durable?.canonicalAck.byteLength).toBeGreaterThan(0);

      const recovered = await receiveIdentityTransitionOnce(
        await frame(fixture, fixture.canonicalTransition, new Uint8Array(16).fill(7)),
        fixture.context,
        store,
        new MemoryReplayLedger(),
        now + 1,
      );
      expect(recovered.accepted.disposition).toBe('already-accepted');
      expect(recovered.accepted.state.canonicalAck).toEqual(durable?.canonicalAck);
    } finally {
      await store.clear();
    }
  });

  it('rejects authenticated business plaintext without creating successor state', async () => {
    const fixture = await createFixture();
    const store = new IndexedDbTrustedPeerStore(uniqueName());
    const business = encodeEncryptedPayloadV1(createActionResultPayload({
      idempotencyKey: new Uint8Array(16).fill(8),
      status: ActionResultStatus.SUCCEEDED,
    }));
    try {
      await store.pinApproved(workspaceId, senderDeviceId, fixture.senderPublicKey);
      await expect(receiveIdentityTransitionOnce(
        await frame(fixture, business, new Uint8Array(16).fill(9)),
        fixture.context,
        store,
        new MemoryReplayLedger(),
        now,
      )).rejects.toMatchObject({ code: 'IDENTITY_TRANSITION_PAYLOAD_MISMATCH' });
      expect(await store.loadIdentityTransition(workspaceId, senderDeviceId, now))
        .toBeUndefined();
    } finally {
      await store.clear();
    }
  });
});

interface Fixture {
  sender: HpkeIdentity;
  senderPublicKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  canonicalTransition: Uint8Array;
  context: {
    workspaceId: Uint8Array;
    recipientDeviceId: Uint8Array;
    recipientIdentity: HpkeIdentity;
    pinnedSenderPublicKey: Uint8Array;
  };
}

async function createFixture(): Promise<Fixture> {
  const sender = await generateNonExtractableIdentity();
  const recipient = await generateNonExtractableIdentity();
  const successor = await generateNonExtractableIdentity();
  const senderPublicKey = await serializeIdentityPublicKey(sender);
  const recipientPublicKey = await serializeIdentityPublicKey(recipient);
  const successorPublicKey = await serializeIdentityPublicKey(successor);
  return {
    sender,
    senderPublicKey,
    recipientPublicKey,
    canonicalTransition: await encodeIdentityKeyLifecyclePayload(
      createIdentityKeyTransitionPayload({
        transitionId: new Uint8Array(16).fill(4),
        previousKeyId: await sha256(senderPublicKey),
        newPublicKey: successorPublicKey,
        newKeyId: await sha256(successorPublicKey),
      }),
    ),
    context: {
      workspaceId,
      recipientDeviceId,
      recipientIdentity: recipient,
      pinnedSenderPublicKey: senderPublicKey,
    },
  };
}

async function frame(
  fixture: Fixture,
  plaintext: Uint8Array,
  messageId: Uint8Array,
): Promise<Uint8Array> {
  const routingHeader = encodeRoutingHeaderV1({
    workspaceId,
    senderDeviceId,
    recipientDeviceId,
    senderKeyId: await sha256(fixture.senderPublicKey),
    recipientKeyId: await sha256(fixture.recipientPublicKey),
    messageId,
    sequence: BigInt(messageId[0] ?? 1),
    createdAtUnixMs: now,
    expiresAtUnixMs: now + 60_000,
  });
  const encrypted = await sealWithIdentity(
    fixture.recipientPublicKey,
    fixture.sender,
    plaintext,
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
  return `identity-transition-receiver-${Date.now()}-${Math.random()}`;
}

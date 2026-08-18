import { describe, expect, it } from 'vitest';
import { encodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import { createActionResultPayload, encodeEncryptedPayloadV1 } from '../protocol/encrypted-payload';
import {
  createIdentityKeyTransitionAckPayload,
  createIdentityKeyTransitionCommitPayload,
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
  openPendingIdentityAckOnce,
  type PendingIdentityAckBinding,
  type ReplayLedgerWriter,
} from './envelope-receiver';

class MemoryReplayLedger implements ReplayLedgerWriter {
  readonly seen = new Set<string>();

  async checkAndRecord(sender: Uint8Array, message: Uint8Array): Promise<'accepted' | 'duplicate'> {
    const tuple = `${hex(sender)}:${hex(message)}`;
    if (this.seen.has(tuple)) return 'duplicate';
    this.seen.add(tuple);
    return 'accepted';
  }
}

const now = 1_800_000_000_000;
const workspaceId = new Uint8Array(16).fill(1);
const peerDeviceId = new Uint8Array(16).fill(2);
const localDeviceId = new Uint8Array(16).fill(3);
const transitionId = new Uint8Array(16).fill(4);
const transitionSha256 = new Uint8Array(32).fill(5);

describe('pending identity acknowledgement receiver', () => {
  it('opens only the exact acknowledgement addressed to the proposed identity', async () => {
    const fixture = await createFixture();
    const ledger = new MemoryReplayLedger();
    const canonicalAck = await encodeIdentityKeyLifecyclePayload(
      createIdentityKeyTransitionAckPayload({
        transitionId,
        previousKeyId: fixture.previousKeyId,
        newKeyId: fixture.newKeyId,
        transitionSha256,
      }),
    );
    const frame = await encryptedFrame(fixture, canonicalAck, new Uint8Array(16).fill(6));

    const opened = await openPendingIdentityAckOnce(
      frame,
      fixture.context,
      fixture.binding,
      ledger,
      now,
    );
    expect(opened.acknowledgement.transitionId).toEqual(transitionId);
    expect(opened.canonicalPayload).toEqual(canonicalAck);
    await expect(openPendingIdentityAckOnce(
      frame,
      fixture.context,
      fixture.binding,
      ledger,
      now,
    )).rejects.toMatchObject({ code: 'DUPLICATE' });
  });

  it('rejects business plaintext before consuming the replay tuple', async () => {
    const fixture = await createFixture();
    const ledger = new MemoryReplayLedger();
    const businessPayload = encodeEncryptedPayloadV1(createActionResultPayload({
      idempotencyKey: new Uint8Array(16).fill(7),
      status: ActionResultStatus.SUCCEEDED,
    }));
    const frame = await encryptedFrame(fixture, businessPayload, new Uint8Array(16).fill(8));

    await expect(openPendingIdentityAckOnce(
      frame,
      fixture.context,
      fixture.binding,
      ledger,
      now,
    )).rejects.toMatchObject({ code: 'PENDING_IDENTITY_PAYLOAD_MISMATCH' });
    expect(ledger.seen.size).toBe(0);

    const commitPayload = await encodeIdentityKeyLifecyclePayload(
      createIdentityKeyTransitionCommitPayload({
        transitionId,
        previousKeyId: fixture.previousKeyId,
        newKeyId: fixture.newKeyId,
        transitionSha256,
        ackSha256: new Uint8Array(32).fill(12),
      }),
    );
    const commitFrame = await encryptedFrame(
      fixture,
      commitPayload,
      new Uint8Array(16).fill(13),
    );
    await expect(openPendingIdentityAckOnce(
      commitFrame,
      fixture.context,
      fixture.binding,
      ledger,
      now,
    )).rejects.toMatchObject({ code: 'PENDING_IDENTITY_PAYLOAD_MISMATCH' });
    expect(ledger.seen.size).toBe(0);
  });

  it('rejects a valid acknowledgement with the wrong durable binding or peer device', async () => {
    const fixture = await createFixture();
    const canonicalAck = await encodeIdentityKeyLifecyclePayload(
      createIdentityKeyTransitionAckPayload({
        transitionId,
        previousKeyId: fixture.previousKeyId,
        newKeyId: fixture.newKeyId,
        transitionSha256,
      }),
    );
    const frame = await encryptedFrame(fixture, canonicalAck, new Uint8Array(16).fill(9));

    await expect(openPendingIdentityAckOnce(
      frame,
      fixture.context,
      { ...fixture.binding, transitionSha256: new Uint8Array(32).fill(10) },
      new MemoryReplayLedger(),
      now,
    )).rejects.toMatchObject({ code: 'TRANSITION_BINDING_MISMATCH' });
    await expect(openPendingIdentityAckOnce(
      frame,
      fixture.context,
      { ...fixture.binding, senderDeviceId: new Uint8Array(16).fill(11) },
      new MemoryReplayLedger(),
      now,
    )).rejects.toMatchObject({ code: 'WRONG_SENDER' });
  });
});

interface Fixture {
  sender: HpkeIdentity;
  senderPublicKey: Uint8Array;
  pending: HpkeIdentity;
  pendingPublicKey: Uint8Array;
  previousKeyId: Uint8Array;
  newKeyId: Uint8Array;
  context: {
    workspaceId: Uint8Array;
    recipientDeviceId: Uint8Array;
    recipientIdentity: HpkeIdentity;
    pinnedSenderPublicKey: Uint8Array;
  };
  binding: PendingIdentityAckBinding;
}

async function createFixture(): Promise<Fixture> {
  const sender = await generateNonExtractableIdentity();
  const current = await generateNonExtractableIdentity();
  const pending = await generateNonExtractableIdentity();
  const senderPublicKey = await serializeIdentityPublicKey(sender);
  const currentPublicKey = await serializeIdentityPublicKey(current);
  const pendingPublicKey = await serializeIdentityPublicKey(pending);
  const previousKeyId = await sha256(currentPublicKey);
  const newKeyId = await sha256(pendingPublicKey);
  return {
    sender,
    senderPublicKey,
    pending,
    pendingPublicKey,
    previousKeyId,
    newKeyId,
    context: {
      workspaceId,
      recipientDeviceId: localDeviceId,
      recipientIdentity: pending,
      pinnedSenderPublicKey: senderPublicKey,
    },
    binding: {
      senderDeviceId: peerDeviceId,
      transitionId,
      previousKeyId,
      newKeyId,
      transitionSha256,
    },
  };
}

async function encryptedFrame(
  fixture: Fixture,
  plaintext: Uint8Array,
  messageId: Uint8Array,
): Promise<Uint8Array> {
  const routingHeader = encodeRoutingHeaderV1({
    workspaceId,
    senderDeviceId: peerDeviceId,
    recipientDeviceId: localDeviceId,
    senderKeyId: await sha256(fixture.senderPublicKey),
    recipientKeyId: fixture.newKeyId,
    messageId,
    sequence: BigInt(messageId[0] ?? 1),
    createdAtUnixMs: now,
    expiresAtUnixMs: now + 60_000,
  });
  const encrypted = await sealWithIdentity(
    fixture.pendingPublicKey,
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
  const input = new Uint8Array(value.byteLength);
  input.set(value);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input));
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

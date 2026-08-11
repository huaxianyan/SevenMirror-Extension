import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { decodeEncryptedPayloadV1 } from '../protocol/encrypted-payload';
import type { StoredTransportCredential } from '../transport/indexeddb-transport-credential-store';
import { ActionInvokeOutbox } from './action-invoke-outbox';
import {
  deriveIdentityKeyId,
  generateNonExtractableIdentity,
  serializeIdentityPublicKey,
} from './auth-hpke';
import { openEnvelopeOnce, type ReplayLedgerWriter } from './envelope-receiver';
import { IndexedDbOutboundSequenceStore } from './indexeddb-outbound-sequence-store';
import { IndexedDbPendingActionStore } from './indexeddb-pending-action-store';
import { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';

const nowBase = 1_800_000_000_000;

class MemoryReplayLedger implements ReplayLedgerWriter {
  async checkAndRecord(): Promise<'accepted'> { return 'accepted'; }
}

function uniqueName(): string {
  return `test-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

describe('ActionInvokeOutbox', () => {
  it('persists before send, encrypts retries with durable sequences, and obeys revocation', async () => {
    const name = uniqueName();
    const senderIdentity = await generateNonExtractableIdentity();
    const recipientIdentity = await generateNonExtractableIdentity();
    const recipientPublicKey = await serializeIdentityPublicKey(recipientIdentity);
    const senderPublicKey = await serializeIdentityPublicKey(senderIdentity);
    const workspaceId = new Uint8Array(16).fill(1);
    const senderDeviceId = new Uint8Array(16).fill(2);
    const recipientDeviceId = new Uint8Array(16).fill(3);
    const recipientKeyId = await deriveIdentityKeyId(recipientPublicKey);
    const credential: StoredTransportCredential = {
      serverOrigin: 'https://notify.example',
      workspaceId,
      deviceId: senderDeviceId,
      authToken: new Uint8Array(32).fill(4),
      identityKeyId: await deriveIdentityKeyId(senderPublicKey),
    };
    const pending = new IndexedDbPendingActionStore(name);
    const peers = new IndexedDbTrustedPeerStore(`trusted-${name}`);
    const sequences = new IndexedDbOutboundSequenceStore(`sequences-${name}`);
    let now = nowBase;
    const sent: Uint8Array[] = [];
    const outbox = new ActionInvokeOutbox(
      { load: async () => copyCredential(credential) },
      { loadExisting: async () => senderIdentity },
      peers,
      pending,
      sequences,
      (frame) => { sent.push(frame.slice()); return true; },
      () => now,
      (target) => target.fill(sent.length + 5),
    );
    const idempotencyKey = new Uint8Array(16).fill(8);
    try {
      await peers.pinApproved(workspaceId, recipientDeviceId, recipientPublicKey);
      const queued = await outbox.queueAndSend({
        deviceId: recipientDeviceId,
        keyId: recipientKeyId,
      }, {
        notificationId: 'synthetic.notification/42',
        notificationRevision: 7n,
        actionId: new Uint8Array(16).fill(9),
        idempotencyKey,
        replyText: 'synthetic reply',
      });
      expect(queued).toEqual({ accepted: true, nextWakeDelayMs: 1_000 });
      expect((await pending.get(idempotencyKey))?.invokeAttemptCount).toBe(1);

      const firstOpened = await openEnvelopeOnce(sent[0]!, {
        workspaceId,
        recipientDeviceId,
        recipientIdentity,
        pinnedSenderPublicKey: senderPublicKey,
      }, new MemoryReplayLedger(), now);
      const payload = decodeEncryptedPayloadV1(firstOpened.plaintext);
      expect(payload.body.case).toBe('actionInvoke');
      if (payload.body.case === 'actionInvoke') {
        expect(payload.body.value.idempotencyKey).toEqual(idempotencyKey);
      }
      expect(firstOpened.header.sequence).toBe(1n);

      now += 1_000;
      expect(await outbox.drainDue()).toEqual({
        acceptedSends: 1,
        attemptedEntries: 1,
        nextWakeDelayMs: 2_000,
      });
      const secondOpened = await openEnvelopeOnce(sent[1]!, {
        workspaceId,
        recipientDeviceId,
        recipientIdentity,
        pinnedSenderPublicKey: senderPublicKey,
      }, new MemoryReplayLedger(), now);
      expect(secondOpened.header.sequence).toBe(2n);

      await peers.remove(workspaceId, recipientDeviceId);
      now += 2_000;
      expect(await outbox.drainDue()).toEqual({ acceptedSends: 0, attemptedEntries: 0 });
      expect(sent).toHaveLength(2);
    } finally {
      await Promise.all([pending.clear(), peers.clear(), sequences.clear()]);
    }
  });

  it('recovers an unsent invoke after reconstruction without changing its idempotency key', async () => {
    const name = uniqueName();
    const senderIdentity = await generateNonExtractableIdentity();
    const recipientIdentity = await generateNonExtractableIdentity();
    const recipientPublicKey = await serializeIdentityPublicKey(recipientIdentity);
    const senderPublicKey = await serializeIdentityPublicKey(senderIdentity);
    const workspaceId = new Uint8Array(16).fill(1);
    const senderDeviceId = new Uint8Array(16).fill(2);
    const recipientDeviceId = new Uint8Array(16).fill(3);
    const recipientKeyId = await deriveIdentityKeyId(recipientPublicKey);
    const credential: StoredTransportCredential = {
      serverOrigin: 'https://notify.example',
      workspaceId,
      deviceId: senderDeviceId,
      authToken: new Uint8Array(32).fill(4),
      identityKeyId: await deriveIdentityKeyId(senderPublicKey),
    };
    const pending = new IndexedDbPendingActionStore(name);
    const peers = new IndexedDbTrustedPeerStore(`trusted-${name}`);
    const sequences = new IndexedDbOutboundSequenceStore(`sequences-${name}`);
    const idempotencyKey = new Uint8Array(16).fill(8);
    const common = [
      { load: async () => copyCredential(credential) },
      { loadExisting: async () => senderIdentity },
      peers,
      pending,
      sequences,
    ] as const;
    try {
      await peers.pinApproved(workspaceId, recipientDeviceId, recipientPublicKey);
      const offline = new ActionInvokeOutbox(...common, () => false, () => nowBase);
      expect((await offline.queueAndSend({
        deviceId: recipientDeviceId,
        keyId: recipientKeyId,
      }, {
        notificationId: 'synthetic.notification/42',
        notificationRevision: 7n,
        actionId: new Uint8Array(16).fill(9),
        idempotencyKey,
      })).accepted).toBe(false);
      expect((await pending.get(idempotencyKey))?.invokeAttemptCount).toBe(0);

      let recoveredFrame: Uint8Array | undefined;
      const reconstructed = new ActionInvokeOutbox(
        ...common,
        (frame) => { recoveredFrame = frame.slice(); return true; },
        () => nowBase + 1,
      );
      expect((await reconstructed.drainDue()).acceptedSends).toBe(1);
      const opened = await openEnvelopeOnce(recoveredFrame!, {
        workspaceId,
        recipientDeviceId,
        recipientIdentity,
        pinnedSenderPublicKey: senderPublicKey,
      }, new MemoryReplayLedger(), nowBase + 1);
      const payload = decodeEncryptedPayloadV1(opened.plaintext);
      expect(payload.body.case === 'actionInvoke' && payload.body.value.idempotencyKey)
        .toEqual(idempotencyKey);
    } finally {
      await Promise.all([pending.clear(), peers.clear(), sequences.clear()]);
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

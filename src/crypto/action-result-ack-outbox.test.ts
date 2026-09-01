import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { ActionResultStatus } from '../protocol/generated/notification/v1/payload_pb';
import {
  createActionInvokePayload,
  createActionResultAckPayload,
  decodeEncryptedPayloadV1,
  encodeEncryptedPayloadV1,
} from '../protocol/encrypted-payload';
import type { StoredTransportCredential } from '../transport/indexeddb-transport-credential-store';
import { ActionResultAckOutbox } from './action-result-ack-outbox';
import {
  deriveIdentityKeyId,
  generateNonExtractableIdentity,
  serializeIdentityPublicKey,
} from './auth-hpke';
import { openEnvelopeOnce, type ReplayLedgerWriter } from './envelope-receiver';
import { IndexedDbOutboundSequenceStore } from './indexeddb-outbound-sequence-store';
import { IndexedDbPendingActionStore } from './indexeddb-pending-action-store';

class MemoryReplayLedger implements ReplayLedgerWriter {
  async checkAndRecord(): Promise<'accepted'> { return 'accepted'; }
}

const nowBase = 1_800_000_000_000;

function uniqueName(): string {
  return `test-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

describe('ActionResultAckOutbox', () => {
  it('restores exact ACK intent, uses fresh sequences, and obeys authorization revocation', async () => {
    const name = uniqueName();
    const chromeIdentity = await generateNonExtractableIdentity();
    const androidIdentity = await generateNonExtractableIdentity();
    const chromePublicKey = await serializeIdentityPublicKey(chromeIdentity);
    const androidPublicKey = await serializeIdentityPublicKey(androidIdentity);
    const workspaceId = new Uint8Array(16).fill(1);
    const chromeDeviceId = new Uint8Array(16).fill(2);
    const androidDeviceId = new Uint8Array(16).fill(3);
    const androidKeyId = await deriveIdentityKeyId(androidPublicKey);
    const idempotencyKey = new Uint8Array(16).fill(4);
    const credential: StoredTransportCredential = {
      serverOrigin: 'https://notify.example',
      workspaceId,
      deviceId: chromeDeviceId,
      authToken: new Uint8Array(32).fill(5),
      identityKeyId: await deriveIdentityKeyId(chromePublicKey),
    };
    let pending = new IndexedDbPendingActionStore(name);
    const recipients = new TestActionRecipientDirectory();
    let sequences = new IndexedDbOutboundSequenceStore(`sequences-${name}`);
    const canonicalInvoke = encodeEncryptedPayloadV1(createActionInvokePayload({
      notificationId: 'synthetic.notification/42',
      notificationRevision: 1n,
      actionId: new Uint8Array(16).fill(6),
      idempotencyKey,
    }));
    const canonicalAck = encodeEncryptedPayloadV1(createActionResultAckPayload({
      idempotencyKey,
      resultSha256: new Uint8Array(32).fill(7),
    }));
    let now = nowBase;
    let socketAccepted = false;
    const attemptedFrames: Uint8Array[] = [];
    const sent: Uint8Array[] = [];
    const createOutbox = () => new ActionResultAckOutbox(
      { load: async () => copyCredential(credential) },
      { loadExisting: async () => chromeIdentity },
      {
        resolveActionRecipient: (
          resolvedWorkspace: Uint8Array,
          _localDevice: Uint8Array,
          recipientDevice: Uint8Array,
          recipientKey: Uint8Array,
        ) => recipients.resolve(resolvedWorkspace, recipientDevice, recipientKey),
      },
      pending,
      sequences,
      (frame) => {
        attemptedFrames.push(frame.slice());
        if (!socketAccepted) return false;
        sent.push(frame.slice());
        return true;
      },
      () => now,
      (target) => target.fill(attemptedFrames.length + 8),
    );
    let outbox = createOutbox();
    try {
      recipients.authorize(workspaceId, androidDeviceId, androidPublicKey);
      await pending.register(
        idempotencyKey,
        androidDeviceId,
        await sha256(canonicalInvoke),
        now,
        now + 60_000,
        canonicalInvoke,
        androidKeyId,
      );
      await pending.reconcile(
        idempotencyKey,
        androidDeviceId,
        ActionResultStatus.SUCCEEDED,
        undefined,
        now,
        canonicalAck,
      );

      expect(await outbox.drainDue(idempotencyKey)).toEqual({
        acceptedSends: 0,
        attemptedEntries: 0,
      });
      expect(attemptedFrames).toHaveLength(0);
      expect((await pending.dueAcks(now)).at(0)?.attemptCount).toBe(0);

      expect(await outbox.drainDue()).toEqual({
        acceptedSends: 0,
        attemptedEntries: 1,
      });
      expect((await pending.dueAcks(now)).at(0)?.attemptCount).toBe(0);

      // Simulate an MV3 Worker being discarded while the authenticated socket is unavailable.
      pending = new IndexedDbPendingActionStore(name);
      sequences = new IndexedDbOutboundSequenceStore(`sequences-${name}`);
      outbox = createOutbox();
      expect((await pending.dueAcks(now)).at(0)?.canonicalAckPayload).toEqual(canonicalAck);

      socketAccepted = true;
      expect(await outbox.drainDue()).toEqual({
        acceptedSends: 1,
        attemptedEntries: 1,
        nextWakeDelayMs: 1_000,
      });
      const first = await openEnvelopeOnce(sent[0]!, {
        workspaceId,
        recipientDeviceId: androidDeviceId,
        recipientIdentity: androidIdentity,
        pinnedSenderPublicKey: chromePublicKey,
      }, new MemoryReplayLedger(), now);
      expect(first.header.sequence).toBe(2n);
      expect(decodeEncryptedPayloadV1(first.plaintext).body.case).toBe('actionResultAck');
      const refused = await openEnvelopeOnce(attemptedFrames[0]!, {
        workspaceId,
        recipientDeviceId: androidDeviceId,
        recipientIdentity: androidIdentity,
        pinnedSenderPublicKey: chromePublicKey,
      }, new MemoryReplayLedger(), now);
      expect(first.header.messageId).not.toEqual(refused.header.messageId);

      now += 1_000;
      expect((await outbox.drainDue()).acceptedSends).toBe(1);
      const second = await openEnvelopeOnce(sent[1]!, {
        workspaceId,
        recipientDeviceId: androidDeviceId,
        recipientIdentity: androidIdentity,
        pinnedSenderPublicKey: chromePublicKey,
      }, new MemoryReplayLedger(), now);
      expect(second.header.sequence).toBe(3n);
      expect(second.header.messageId).not.toEqual(first.header.messageId);

      recipients.revoke();
      await pending.reconcile(
        idempotencyKey,
        androidDeviceId,
        ActionResultStatus.SUCCEEDED,
        undefined,
        now + 1,
        canonicalAck,
      );
      expect(await outbox.drainDue()).toEqual({ acceptedSends: 0, attemptedEntries: 0 });
      expect(sent).toHaveLength(2);
    } finally {
      await Promise.all([pending.clear(), sequences.clear()]);
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
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice()));
}

class TestActionRecipientDirectory {
  private recipient?: { workspaceId: Uint8Array; deviceId: Uint8Array; publicKey: Uint8Array };

  authorize(workspaceId: Uint8Array, deviceId: Uint8Array, publicKey: Uint8Array): void {
    this.recipient = {
      workspaceId: workspaceId.slice(),
      deviceId: deviceId.slice(),
      publicKey: publicKey.slice(),
    };
  }

  revoke(): void {
    this.recipient = undefined;
  }

  async resolve(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    keyId: Uint8Array,
  ): Promise<Uint8Array | undefined> {
    const recipient = this.recipient;
    if (recipient === undefined ||
        !bytesEqual(recipient.workspaceId, workspaceId) ||
        !bytesEqual(recipient.deviceId, deviceId) ||
        !bytesEqual(await deriveIdentityKeyId(recipient.publicKey), keyId)) {
      return undefined;
    }
    return recipient.publicKey.slice();
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength &&
    left.every((value, index) => value === right[index]);
}

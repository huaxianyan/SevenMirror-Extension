import { toBinary } from '@bufbuild/protobuf';
import { describe, expect, it } from 'vitest';
import {
  createActionInvokeEnvelope,
  createActionInvokeEnvelopeFromPayload,
  prepareActionInvokeEnvelope,
} from './action-envelope-sender';
import {
  generateNonExtractableIdentity,
  serializeIdentityPublicKey,
} from './auth-hpke';
import { openEnvelopeOnce, type ReplayLedgerWriter } from './envelope-receiver';
import {
  createActionInvokePayload,
  decodeEncryptedPayloadV1,
} from '../protocol/encrypted-payload';
import { EncryptedPayloadSchema } from '../protocol/generated/notification/v1/payload_pb';

class MemoryReplayLedger implements ReplayLedgerWriter {
  private readonly seen = new Set<string>();

  async checkAndRecord(sender: Uint8Array, message: Uint8Array): Promise<'accepted' | 'duplicate'> {
    const key = [...sender, ...message].join(',');
    if (this.seen.has(key)) return 'duplicate';
    this.seen.add(key);
    return 'accepted';
  }
}

describe('action envelope sender', () => {
  it('persists pending correlation before creating a sendable frame', async () => {
    const sender = await generateNonExtractableIdentity();
    const recipient = await generateNonExtractableIdentity();
    const recipientPublicKey = await serializeIdentityPublicKey(recipient);
    const events: string[] = [];
    let registeredDigest: Uint8Array | undefined;
    let registeredPayload: Uint8Array | undefined;
    let registeredRecipientKey: Uint8Array | undefined;
    const frame = await prepareActionInvokeEnvelope({
      workspaceId: new Uint8Array(16).fill(1),
      senderDeviceId: new Uint8Array(16).fill(2),
      recipientDeviceId: new Uint8Array(16).fill(3),
      senderIdentity: sender,
      recipientPublicKey,
      messageId: new Uint8Array(16).fill(4),
      sequence: 1n,
      createdAtUnixMs: 1_800_000_000_000,
      expiresAtUnixMs: 1_800_000_060_000,
    }, {
      notificationId: 'private.notification/42',
      notificationRevision: 9n,
      actionId: new Uint8Array(16).fill(0xa1),
      idempotencyKey: new Uint8Array(16).fill(0xb2),
    }, {
      async register(_key, _device, operationDigest, _created, _expires, payload, recipientKey) {
        events.push('registered');
        registeredDigest = operationDigest;
        registeredPayload = payload;
        registeredRecipientKey = recipientKey;
        return 'registered';
      },
    });
    expect(events).toEqual(['registered']);
    expect(registeredDigest).toHaveLength(32);
    expect(registeredPayload).toBeInstanceOf(Uint8Array);
    expect(registeredRecipientKey).toHaveLength(32);
    expect(frame.byteLength).toBeGreaterThan(0);
  });

  it('encrypts message type and action fields for one authenticated recipient', async () => {
    const sender = await generateNonExtractableIdentity();
    const recipient = await generateNonExtractableIdentity();
    const senderPublicKey = await serializeIdentityPublicKey(sender);
    const recipientPublicKey = await serializeIdentityPublicKey(recipient);
    const workspaceId = new Uint8Array(16).fill(1);
    const recipientDeviceId = new Uint8Array(16).fill(3);
    const now = 1_800_000_000_000;
    const frame = await createActionInvokeEnvelope({
      workspaceId,
      senderDeviceId: new Uint8Array(16).fill(2),
      recipientDeviceId,
      senderIdentity: sender,
      recipientPublicKey,
      messageId: new Uint8Array(16).fill(4),
      sequence: 1n,
      createdAtUnixMs: now,
      expiresAtUnixMs: now + 60_000,
    }, {
      notificationId: 'private.notification/42',
      notificationRevision: 9n,
      actionId: new Uint8Array(16).fill(0xa1),
      idempotencyKey: new Uint8Array(16).fill(0xb2),
      replyText: 'private reply',
    });

    expect(new TextDecoder().decode(frame)).not.toContain('private.notification/42');
    expect(new TextDecoder().decode(frame)).not.toContain('private reply');

    const ledger = new MemoryReplayLedger();
    const opened = await openEnvelopeOnce(frame, {
      workspaceId,
      recipientDeviceId,
      recipientIdentity: recipient,
      pinnedSenderPublicKey: senderPublicKey,
    }, ledger, now);
    const payload = decodeEncryptedPayloadV1(opened.plaintext);
    expect(payload.body.case).toBe('actionInvoke');
    if (payload.body.case === 'actionInvoke') {
      expect(payload.body.value.notificationId).toBe('private.notification/42');
      expect(payload.body.value.notificationRevision).toBe(9n);
      expect(payload.body.value.replyText).toBe('private reply');
    }
    await expect(openEnvelopeOnce(frame, {
      workspaceId,
      recipientDeviceId,
      recipientIdentity: recipient,
      pinnedSenderPublicKey: senderPublicKey,
    }, ledger, now)).rejects.toMatchObject({ code: 'DUPLICATE' });

    const legacyPayload = createActionInvokePayload({
      notificationId: 'private.notification/legacy',
      notificationRevision: 8n,
      actionId: new Uint8Array(16).fill(0xa2),
      idempotencyKey: new Uint8Array(16).fill(0xb3),
    });
    legacyPayload.schemaVersion = 1;
    const legacyFrame = await createActionInvokeEnvelopeFromPayload({
      workspaceId,
      senderDeviceId: new Uint8Array(16).fill(2),
      recipientDeviceId,
      senderIdentity: sender,
      recipientPublicKey,
      messageId: new Uint8Array(16).fill(5),
      sequence: 2n,
      createdAtUnixMs: now,
      expiresAtUnixMs: now + 60_000,
    }, toBinary(EncryptedPayloadSchema, legacyPayload));
    const legacyOpened = await openEnvelopeOnce(legacyFrame, {
      workspaceId,
      recipientDeviceId,
      recipientIdentity: recipient,
      pinnedSenderPublicKey: senderPublicKey,
    }, new MemoryReplayLedger(), now);
    expect(decodeEncryptedPayloadV1(legacyOpened.plaintext).schemaVersion).toBe(1);
  });
});

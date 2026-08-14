import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { ActionResultStatus } from '../protocol/generated/notification/v1/payload_pb';
import { encodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import {
  createActionInvokePayload,
  createActionResultPayload,
  decodeEncryptedPayloadV1,
  encodeEncryptedPayloadV1,
} from '../protocol/encrypted-payload';
import { encodeRoutingHeaderV1 } from '../protocol/routing-header';
import { receiveActionResultOnce } from './action-result-receiver';
import {
  generateNonExtractableIdentity,
  sealWithIdentity,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import { type ReplayLedgerWriter } from './envelope-receiver';
import { IndexedDbPendingActionStore } from './indexeddb-pending-action-store';

class MemoryReplayLedger implements ReplayLedgerWriter {
  private readonly seen = new Set<string>();
  async checkAndRecord(sender: Uint8Array, message: Uint8Array): Promise<'accepted' | 'duplicate'> {
    const tuple = `${hex(sender)}:${hex(message)}`;
    if (this.seen.has(tuple)) return 'duplicate';
    this.seen.add(tuple);
    return 'accepted';
  }
}

const now = 1_800_000_000_000;
const workspaceId = new Uint8Array(16).fill(1);
const androidDeviceId = new Uint8Array(16).fill(2);
const chromeDeviceId = new Uint8Array(16).fill(3);
const idempotencyKey = new Uint8Array(16).fill(4);

describe('action result receiver', () => {
  it('authenticates and persistently reconciles a result without reopening the operation', async () => {
    const androidIdentity = await generateNonExtractableIdentity();
    const chromeIdentity = await generateNonExtractableIdentity();
    const androidPublicKey = await serializeIdentityPublicKey(androidIdentity);
    const chromePublicKey = await serializeIdentityPublicKey(chromeIdentity);
    const storeName = `receiver-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const pending = new IndexedDbPendingActionStore(storeName);
    const replay = new MemoryReplayLedger();
    try {
      const canonicalInvoke = encodeEncryptedPayloadV1(createActionInvokePayload({
        notificationId: 'synthetic.notification/42',
        notificationRevision: 1n,
        actionId: new Uint8Array(16).fill(8),
        idempotencyKey,
      }));
      await pending.register(
        idempotencyKey,
        androidDeviceId,
        await sha256(canonicalInvoke),
        now,
        now + 60_000,
        canonicalInvoke,
        await sha256(androidPublicKey),
      );
      const firstFrame = await resultFrame(
        androidIdentity,
        androidPublicKey,
        chromePublicKey,
        new Uint8Array(16).fill(5),
        ActionResultStatus.SUCCEEDED,
      );
      const context = {
        workspaceId,
        recipientDeviceId: chromeDeviceId,
        recipientIdentity: chromeIdentity,
        pinnedSenderPublicKey: androidPublicKey,
      };

      const first = await receiveActionResultOnce(firstFrame, context, replay, pending, now);
      expect(first.reconciliation).toBe('completed');
      expect(first.result.status).toBe(ActionResultStatus.SUCCEEDED);
      const ack = decodeEncryptedPayloadV1(
        (await pending.dueAcks(now)).at(0)!.canonicalAckPayload,
      );
      expect(ack.body.case).toBe('actionResultAck');

      const recoveredFrame = await resultFrame(
        androidIdentity,
        androidPublicKey,
        chromePublicKey,
        new Uint8Array(16).fill(6),
        ActionResultStatus.SUCCEEDED,
      );
      expect((await receiveActionResultOnce(
        recoveredFrame,
        context,
        replay,
        new IndexedDbPendingActionStore(storeName),
        now + 1,
      )).reconciliation).toBe('already-completed');
    } finally {
      await pending.clear();
    }
  });
});

async function resultFrame(
  senderIdentity: HpkeIdentity,
  senderPublicKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  messageId: Uint8Array,
  status: ActionResultStatus,
): Promise<Uint8Array> {
  const routingHeader = encodeRoutingHeaderV1({
    workspaceId,
    senderDeviceId: androidDeviceId,
    recipientDeviceId: chromeDeviceId,
    senderKeyId: await sha256(senderPublicKey),
    recipientKeyId: await sha256(recipientPublicKey),
    messageId,
    sequence: BigInt(messageId[0] ?? 1),
    createdAtUnixMs: now,
    expiresAtUnixMs: now + 60_000,
  });
  const plaintext = encodeEncryptedPayloadV1(createActionResultPayload({
    idempotencyKey,
    status,
  }));
  const encrypted = await sealWithIdentity(
    recipientPublicKey,
    senderIdentity,
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

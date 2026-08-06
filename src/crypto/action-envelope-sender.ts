import {
  sealWithIdentity,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import { encodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import {
  createActionInvokePayload,
  encodeEncryptedPayloadV1,
} from '../protocol/encrypted-payload';
import { encodeRoutingHeaderV1 } from '../protocol/routing-header';

export interface ActionEnvelopeContext {
  workspaceId: Uint8Array;
  senderDeviceId: Uint8Array;
  recipientDeviceId: Uint8Array;
  senderIdentity: HpkeIdentity;
  recipientPublicKey: Uint8Array;
  messageId: Uint8Array;
  sequence: bigint;
  createdAtUnixMs: number;
  expiresAtUnixMs: number;
}

export interface ActionInvokeRequest {
  notificationId: string;
  notificationRevision: bigint;
  actionId: Uint8Array;
  idempotencyKey: Uint8Array;
  replyText?: string;
}

/** Creates one recipient-specific action frame; all business semantics are encrypted. */
export async function createActionInvokeEnvelope(
  context: ActionEnvelopeContext,
  request: ActionInvokeRequest,
): Promise<Uint8Array> {
  const senderPublicKey = await serializeIdentityPublicKey(context.senderIdentity);
  const routingHeader = encodeRoutingHeaderV1({
    workspaceId: context.workspaceId,
    senderDeviceId: context.senderDeviceId,
    recipientDeviceId: context.recipientDeviceId,
    senderKeyId: await sha256(senderPublicKey),
    recipientKeyId: await sha256(context.recipientPublicKey),
    messageId: context.messageId,
    sequence: context.sequence,
    createdAtUnixMs: context.createdAtUnixMs,
    expiresAtUnixMs: context.expiresAtUnixMs,
  });
  const plaintext = encodeEncryptedPayloadV1(createActionInvokePayload(request));
  const encrypted = await sealWithIdentity(
    context.recipientPublicKey,
    context.senderIdentity,
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

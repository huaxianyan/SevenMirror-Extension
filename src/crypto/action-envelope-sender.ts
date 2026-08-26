import {
  sealWithIdentity,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import { encodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import {
  createActionInvokePayload,
  decodeEncryptedPayloadV1,
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

export interface PendingActionRegistrar {
  register(
    idempotencyKey: Uint8Array,
    senderDeviceId: Uint8Array,
    operationDigest: Uint8Array,
    createdAtUnixMs: number,
    expiresAtUnixMs: number,
    canonicalInvokePayload?: Uint8Array,
    recipientKeyId?: Uint8Array,
  ): Promise<'registered' | 'already-registered' | 'capacity-exceeded'>;
}

interface ActionInvokeRequestBase {
  notificationId: string;
  notificationRevision: bigint;
  idempotencyKey: Uint8Array;
}

export type ActionInvokeRequest = ActionInvokeRequestBase & (
  | {
    actionId: Uint8Array;
    replyText?: string;
    dismissNotification?: false;
  }
  | {
    actionId?: never;
    replyText?: never;
    dismissNotification: true;
  }
);

export const PENDING_ACTION_RETENTION_MS = 30 * 24 * 60 * 60 * 1_000;

/**
 * Durably registers correlation state before producing a frame that may be sent.
 * Retrying uses the same idempotency key and never replaces the pending record.
 */
export async function prepareActionInvokeEnvelope(
  context: ActionEnvelopeContext,
  request: ActionInvokeRequest,
  pendingActions: PendingActionRegistrar,
): Promise<Uint8Array> {
  const canonicalRequest = encodeEncryptedPayloadV1(createActionInvokePayload(request));
  const registration = await pendingActions.register(
    request.idempotencyKey,
    context.recipientDeviceId,
    await sha256(canonicalRequest),
    context.createdAtUnixMs,
    context.createdAtUnixMs + PENDING_ACTION_RETENTION_MS,
    canonicalRequest,
    await sha256(context.recipientPublicKey),
  );
  if (registration === 'capacity-exceeded') {
    throw new Error('Pending action capacity exceeded');
  }
  return createActionInvokeEnvelopeFromPayload(context, canonicalRequest);
}

/** Low-level codec helper; production callers should use prepareActionInvokeEnvelope. */
export async function createActionInvokeEnvelope(
  context: ActionEnvelopeContext,
  request: ActionInvokeRequest,
): Promise<Uint8Array> {
  const canonicalPayload = encodeEncryptedPayloadV1(createActionInvokePayload(request));
  return createActionInvokeEnvelopeFromPayload(context, canonicalPayload);
}

/** Encrypts an already persisted canonical action.invoke payload for a fresh delivery attempt. */
export async function createActionInvokeEnvelopeFromPayload(
  context: ActionEnvelopeContext,
  canonicalPayload: Uint8Array,
): Promise<Uint8Array> {
  return createEnvelopeFromCanonicalPayload(context, canonicalPayload, 'actionInvoke');
}

export async function createActionResultAckEnvelopeFromPayload(
  context: ActionEnvelopeContext,
  canonicalPayload: Uint8Array,
): Promise<Uint8Array> {
  return createEnvelopeFromCanonicalPayload(context, canonicalPayload, 'actionResultAck');
}

async function createEnvelopeFromCanonicalPayload(
  context: ActionEnvelopeContext,
  canonicalPayload: Uint8Array,
  expectedBody: 'actionInvoke' | 'actionResultAck',
): Promise<Uint8Array> {
  const decoded = createPayloadFromCanonical(canonicalPayload, expectedBody);
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
  const encrypted = await sealWithIdentity(
    context.recipientPublicKey,
    context.senderIdentity,
    decoded,
    routingHeader,
  );
  return encodeEncryptedEnvelopeV1({
    routingHeader,
    encapsulatedKey: encrypted.encapsulatedKey,
    ciphertext: encrypted.ciphertext,
  });
}

function createPayloadFromCanonical(
  value: Uint8Array,
  expectedBody: 'actionInvoke' | 'actionResultAck',
): Uint8Array {
  const decoded = decodeEncryptedPayloadV1(value);
  if (decoded.body.case !== expectedBody) {
    throw new Error(`Expected canonical ${expectedBody} payload`);
  }
  const canonical = encodeEncryptedPayloadV1(decoded);
  if (!bytesEqual(canonical, value)) {
    throw new Error('Stored encrypted payload is not canonical');
  }
  return canonical;
}

export async function actionInvokeOperationDigest(request: ActionInvokeRequest): Promise<{
  canonicalPayload: Uint8Array;
  digest: Uint8Array;
}> {
  const canonicalPayload = encodeEncryptedPayloadV1(createActionInvokePayload(request));
  return { canonicalPayload, digest: await sha256(canonicalPayload) };
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  const input = new Uint8Array(value.byteLength);
  input.set(value);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input));
}

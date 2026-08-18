import { encodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import {
  decodeIdentityKeyLifecyclePayload,
  encodeIdentityKeyLifecyclePayload,
} from '../protocol/identity-key-transition-payload';
import { encodeRoutingHeaderV1 } from '../protocol/routing-header';
import {
  sealWithIdentity,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';

export interface IdentityTransitionEnvelopeContext {
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

/** Encrypts one exact durable old-key-authenticated transition under a fresh envelope tuple. */
export async function createIdentityTransitionEnvelopeFromPayload(
  context: IdentityTransitionEnvelopeContext,
  canonicalTransition: Uint8Array,
): Promise<Uint8Array> {
  return createIdentityTransitionEnvelope(context, canonicalTransition, 'identityKeyTransition');
}

/** Encrypts one exact durable identity-transition ACK under a fresh envelope tuple. */
export async function createIdentityTransitionAckEnvelopeFromPayload(
  context: IdentityTransitionEnvelopeContext,
  canonicalAck: Uint8Array,
): Promise<Uint8Array> {
  return createIdentityTransitionEnvelope(context, canonicalAck, 'identityKeyTransitionAck');
}

/** Encrypts one exact durable identity-transition commit under a fresh envelope tuple. */
export async function createIdentityTransitionCommitEnvelopeFromPayload(
  context: IdentityTransitionEnvelopeContext,
  canonicalCommit: Uint8Array,
): Promise<Uint8Array> {
  return createIdentityTransitionEnvelope(context, canonicalCommit, 'identityKeyTransitionCommit');
}

async function createIdentityTransitionEnvelope(
  context: IdentityTransitionEnvelopeContext,
  canonicalPayload: Uint8Array,
  expectedBody:
    'identityKeyTransition' | 'identityKeyTransitionAck' | 'identityKeyTransitionCommit',
): Promise<Uint8Array> {
  const payload = await decodeIdentityKeyLifecyclePayload(canonicalPayload);
  if (payload.body.case !== expectedBody) {
    throw new Error(`Expected canonical ${expectedBody} payload`);
  }
  const canonical = await encodeIdentityKeyLifecyclePayload(payload);
  if (!bytesEqual(canonical, canonicalPayload)) {
    throw new Error('Stored identity transition payload is not canonical');
  }
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
    canonical,
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

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

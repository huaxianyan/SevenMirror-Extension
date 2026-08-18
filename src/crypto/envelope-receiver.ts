import {
  openWithIdentity,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import type { PersistentReplayDecision } from './indexeddb-replay-ledger';
import { decodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import { decodeIdentityKeyLifecyclePayload } from '../protocol/identity-key-transition-payload';
import type { IdentityKeyTransitionAck } from '../protocol/generated/notification/v1/payload_pb';
import type { RoutingHeaderV1 } from '../protocol/routing-header';
import type {
  AcceptedLocalIdentityAck,
  IndexedDbLocalIdentityTransitionStore,
} from './indexeddb-local-identity-transition-store';
import type {
  AcceptPeerIdentityTransitionResult,
  IndexedDbTrustedPeerStore,
} from './indexeddb-trusted-peer-store';

export interface ReplayLedgerWriter {
  checkAndRecord(
    senderKeyId: Uint8Array,
    messageId: Uint8Array,
    expiresAtUnixMs: number,
    nowUnixMs: number,
  ): Promise<PersistentReplayDecision>;
}

export interface EnvelopeRecipientContext {
  workspaceId: Uint8Array;
  recipientDeviceId: Uint8Array;
  recipientIdentity: HpkeIdentity;
  pinnedSenderPublicKey: Uint8Array;
}

export interface OpenedEnvelope {
  header: RoutingHeaderV1;
  plaintext: Uint8Array;
}

export interface PendingIdentityAckBinding {
  senderDeviceId: Uint8Array;
  transitionId: Uint8Array;
  previousKeyId: Uint8Array;
  newKeyId: Uint8Array;
  transitionSha256: Uint8Array;
}

export interface OpenedPendingIdentityAck {
  header: RoutingHeaderV1;
  acknowledgement: IdentityKeyTransitionAck;
  canonicalPayload: Uint8Array;
}

export interface AcceptedPeerIdentityTransitionEnvelope {
  header: RoutingHeaderV1;
  accepted: AcceptPeerIdentityTransitionResult;
}

export interface AcceptedLocalIdentityAckEnvelope {
  header: RoutingHeaderV1;
  accepted: AcceptedLocalIdentityAck;
}

export class EnvelopeRejectedError extends Error {
  constructor(
    readonly code:
      | 'WRONG_WORKSPACE'
      | 'WRONG_RECIPIENT'
      | 'WRONG_SENDER'
      | 'RECIPIENT_KEY_MISMATCH'
      | 'SENDER_KEY_MISMATCH'
      | 'PENDING_IDENTITY_PAYLOAD_MISMATCH'
      | 'IDENTITY_TRANSITION_PAYLOAD_MISMATCH'
      | 'TRANSITION_BINDING_MISMATCH'
      | 'DUPLICATE'
      | 'EXPIRED'
      | 'REPLAY_CAPACITY_EXCEEDED',
  ) {
    super(code);
    this.name = 'EnvelopeRejectedError';
  }
}

/**
 * Opens and consumes one envelope. A caller can only receive plaintext after
 * successful HPKE authentication and an atomic accepted replay-ledger write.
 */
export async function openEnvelopeOnce(
  frameBytes: Uint8Array,
  context: EnvelopeRecipientContext,
  replayLedger: ReplayLedgerWriter,
  nowUnixMs: number,
): Promise<OpenedEnvelope> {
  const opened = await authenticateAndOpen(frameBytes, context, nowUnixMs);
  await consumeReplay(opened.header, replayLedger, nowUnixMs);
  return opened;
}

/**
 * Persists the successor and exact ACK intent before replay consumption. A
 * crash or replay failure therefore cannot lose an authenticated transition.
 */
export async function receiveIdentityTransitionOnce(
  frameBytes: Uint8Array,
  context: EnvelopeRecipientContext,
  trustedPeers: IndexedDbTrustedPeerStore,
  replayLedger: ReplayLedgerWriter,
  nowUnixMs: number,
): Promise<AcceptedPeerIdentityTransitionEnvelope> {
  const opened = await authenticateAndOpen(frameBytes, context, nowUnixMs);
  let payload;
  try {
    payload = await decodeIdentityKeyLifecyclePayload(opened.plaintext);
  } catch {
    throw new EnvelopeRejectedError('IDENTITY_TRANSITION_PAYLOAD_MISMATCH');
  }
  if (payload.body.case !== 'identityKeyTransition') {
    throw new EnvelopeRejectedError('IDENTITY_TRANSITION_PAYLOAD_MISMATCH');
  }
  if (!arraysEqual(payload.body.value.previousKeyId, opened.header.senderKeyId)) {
    throw new EnvelopeRejectedError('TRANSITION_BINDING_MISMATCH');
  }
  const accepted = await trustedPeers.acceptIdentityTransition(
    opened.header.workspaceId,
    opened.header.senderDeviceId,
    opened.plaintext,
    nowUnixMs,
  );
  await consumeReplay(opened.header, replayLedger, nowUnixMs);
  return { header: opened.header, accepted };
}

/**
 * Persists an exact ACK and its derived commit before replay consumption.
 */
export async function receivePendingIdentityAckOnce(
  frameBytes: Uint8Array,
  context: EnvelopeRecipientContext,
  localTransitions: IndexedDbLocalIdentityTransitionStore,
  replayLedger: ReplayLedgerWriter,
  nowUnixMs: number,
): Promise<AcceptedLocalIdentityAckEnvelope> {
  const opened = await authenticateAndOpen(frameBytes, context, nowUnixMs);
  const binding = await localTransitions.expectedAckBinding(
    opened.header.senderDeviceId,
    nowUnixMs,
  );
  if (binding === undefined) throw new EnvelopeRejectedError('TRANSITION_BINDING_MISMATCH');
  if (!arraysEqual(binding.workspaceId, opened.header.workspaceId) ||
      !arraysEqual(binding.localDeviceId, opened.header.recipientDeviceId) ||
      !arraysEqual(binding.senderKeyId, opened.header.senderKeyId) ||
      !arraysEqual(binding.newKeyId, opened.header.recipientKeyId)) {
    throw new EnvelopeRejectedError('TRANSITION_BINDING_MISMATCH');
  }
  const acknowledgement = await decodePendingIdentityAck(opened.plaintext, {
    senderDeviceId: binding.senderDeviceId,
    transitionId: binding.transitionId,
    previousKeyId: binding.previousKeyId,
    newKeyId: binding.newKeyId,
    transitionSha256: binding.transitionSha256,
  }, opened.header);
  const accepted = await localTransitions.acceptAck(
    opened.header.senderDeviceId,
    opened.header.senderKeyId,
    opened.plaintext,
    nowUnixMs,
  );
  if (!arraysEqual(acknowledgement.transitionId, accepted.peer.transitionId)) {
    throw new EnvelopeRejectedError('TRANSITION_BINDING_MISMATCH');
  }
  await consumeReplay(opened.header, replayLedger, nowUnixMs);
  return { header: opened.header, accepted };
}

/**
 * The proposed local identity is not an active business recipient. It may only
 * open the exact peer acknowledgement bound to caller-validated state.
 */
export async function openPendingIdentityAckOnce(
  frameBytes: Uint8Array,
  context: EnvelopeRecipientContext,
  binding: PendingIdentityAckBinding,
  replayLedger: ReplayLedgerWriter,
  nowUnixMs: number,
): Promise<OpenedPendingIdentityAck> {
  const opened = await authenticateAndOpen(frameBytes, context, nowUnixMs);
  if (!arraysEqual(opened.header.senderDeviceId, binding.senderDeviceId)) {
    throw new EnvelopeRejectedError('WRONG_SENDER');
  }
  if (!arraysEqual(opened.header.recipientKeyId, binding.newKeyId)) {
    throw new EnvelopeRejectedError('TRANSITION_BINDING_MISMATCH');
  }

  const acknowledgement = await decodePendingIdentityAck(
    opened.plaintext,
    binding,
    opened.header,
  );
  await consumeReplay(opened.header, replayLedger, nowUnixMs);
  return { header: opened.header, acknowledgement, canonicalPayload: opened.plaintext };
}

async function decodePendingIdentityAck(
  plaintext: Uint8Array,
  binding: PendingIdentityAckBinding,
  header: RoutingHeaderV1,
): Promise<IdentityKeyTransitionAck> {
  if (!arraysEqual(header.senderDeviceId, binding.senderDeviceId) ||
      !arraysEqual(header.recipientKeyId, binding.newKeyId)) {
    throw new EnvelopeRejectedError('TRANSITION_BINDING_MISMATCH');
  }
  let payload;
  try {
    payload = await decodeIdentityKeyLifecyclePayload(plaintext);
  } catch {
    throw new EnvelopeRejectedError('PENDING_IDENTITY_PAYLOAD_MISMATCH');
  }
  if (payload.body.case !== 'identityKeyTransitionAck') {
    throw new EnvelopeRejectedError('PENDING_IDENTITY_PAYLOAD_MISMATCH');
  }
  const acknowledgement = payload.body.value;
  if (!arraysEqual(acknowledgement.transitionId, binding.transitionId) ||
      !arraysEqual(acknowledgement.previousKeyId, binding.previousKeyId) ||
      !arraysEqual(acknowledgement.newKeyId, binding.newKeyId) ||
      !arraysEqual(acknowledgement.transitionSha256, binding.transitionSha256)) {
    throw new EnvelopeRejectedError('TRANSITION_BINDING_MISMATCH');
  }
  return acknowledgement;
}

async function authenticateAndOpen(
  frameBytes: Uint8Array,
  context: EnvelopeRecipientContext,
  nowUnixMs: number,
): Promise<OpenedEnvelope> {
  const envelope = decodeEncryptedEnvelopeV1(frameBytes);
  const { routingHeader: header } = envelope;
  if (!arraysEqual(header.workspaceId, context.workspaceId)) {
    throw new EnvelopeRejectedError('WRONG_WORKSPACE');
  }
  if (!arraysEqual(header.recipientDeviceId, context.recipientDeviceId)) {
    throw new EnvelopeRejectedError('WRONG_RECIPIENT');
  }
  if (header.expiresAtUnixMs <= nowUnixMs) {
    throw new EnvelopeRejectedError('EXPIRED');
  }

  const recipientKeyId = await sha256(
    await serializeIdentityPublicKey(context.recipientIdentity),
  );
  if (!arraysEqual(header.recipientKeyId, recipientKeyId)) {
    throw new EnvelopeRejectedError('RECIPIENT_KEY_MISMATCH');
  }
  const senderKeyId = await sha256(context.pinnedSenderPublicKey);
  if (!arraysEqual(header.senderKeyId, senderKeyId)) {
    throw new EnvelopeRejectedError('SENDER_KEY_MISMATCH');
  }

  const plaintext = await openWithIdentity(
    context.recipientIdentity,
    context.pinnedSenderPublicKey,
    {
      encapsulatedKey: envelope.encapsulatedKey,
      ciphertext: envelope.ciphertext,
    },
    envelope.routingHeaderBytes,
  );
  return { header, plaintext };
}

async function consumeReplay(
  header: RoutingHeaderV1,
  replayLedger: ReplayLedgerWriter,
  nowUnixMs: number,
): Promise<void> {
  const replayDecision = await replayLedger.checkAndRecord(
    header.senderKeyId,
    header.messageId,
    header.expiresAtUnixMs,
    nowUnixMs,
  );
  switch (replayDecision) {
    case 'accepted':
      return;
    case 'duplicate':
      throw new EnvelopeRejectedError('DUPLICATE');
    case 'expired':
      throw new EnvelopeRejectedError('EXPIRED');
    case 'capacity-exceeded':
      throw new EnvelopeRejectedError('REPLAY_CAPACITY_EXCEEDED');
  }
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  const input = new Uint8Array(value.byteLength);
  input.set(value);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input));
}

function arraysEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

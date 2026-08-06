import {
  openWithIdentity,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import type { PersistentReplayDecision } from './indexeddb-replay-ledger';
import { decodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import type { RoutingHeaderV1 } from '../protocol/routing-header';

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

export class EnvelopeRejectedError extends Error {
  constructor(
    readonly code:
      | 'WRONG_WORKSPACE'
      | 'WRONG_RECIPIENT'
      | 'RECIPIENT_KEY_MISMATCH'
      | 'SENDER_KEY_MISMATCH'
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
  const replayDecision = await replayLedger.checkAndRecord(
    header.senderKeyId,
    header.messageId,
    header.expiresAtUnixMs,
    nowUnixMs,
  );
  switch (replayDecision) {
    case 'accepted':
      return { header, plaintext };
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
  return left.byteLength === right.byteLength &&
    left.every((value, index) => value === right[index]);
}

import type { ActionResult } from '../protocol/generated/notification/v1/payload_pb';
import {
  createActionResultAckPayload,
  decodeEncryptedPayloadV1,
  encodeEncryptedPayloadV1,
} from '../protocol/encrypted-payload';
import {
  openEnvelopeOnce,
  type EnvelopeRecipientContext,
  type ReplayLedgerWriter,
} from './envelope-receiver';
import type { ActionResultReconciliation } from './indexeddb-pending-action-store';

export interface PendingActionReconciler {
  reconcile(
    idempotencyKey: Uint8Array,
    senderDeviceId: Uint8Array,
    status: ActionResult['status'],
    detail: string | undefined,
    nowUnixMs: number,
    canonicalResultAckPayload?: Uint8Array,
  ): Promise<ActionResultReconciliation>;
}

export interface ActionResultReceipt {
  result: ActionResult;
  reconciliation: 'completed' | 'already-completed';
}

export class ActionResultRejectedError extends Error {
  constructor(readonly code: 'UNEXPECTED_PAYLOAD' | 'OPERATION_NOT_FOUND' | 'SENDER_MISMATCH' | 'RESULT_CONFLICT') {
    super(code);
    this.name = 'ActionResultRejectedError';
  }
}

/** Authenticates, consumes replay state, then atomically correlates action.result. */
export async function receiveActionResultOnce(
  frameBytes: Uint8Array,
  context: EnvelopeRecipientContext,
  replayLedger: ReplayLedgerWriter,
  pendingActions: PendingActionReconciler,
  nowUnixMs: number,
): Promise<ActionResultReceipt> {
  const opened = await openEnvelopeOnce(frameBytes, context, replayLedger, nowUnixMs);
  const payload = decodeEncryptedPayloadV1(opened.plaintext);
  if (payload.body.case !== 'actionResult') {
    throw new ActionResultRejectedError('UNEXPECTED_PAYLOAD');
  }
  const result = payload.body.value;
  const canonicalAck = encodeEncryptedPayloadV1(createActionResultAckPayload({
    idempotencyKey: result.idempotencyKey,
    resultSha256: await sha256(opened.plaintext),
  }));
  const reconciliation = await pendingActions.reconcile(
    result.idempotencyKey,
    opened.header.senderDeviceId,
    result.status,
    result.detail,
    nowUnixMs,
    canonicalAck,
  );
  switch (reconciliation) {
    case 'completed':
    case 'already-completed':
      return { result, reconciliation };
    case 'not-found':
      throw new ActionResultRejectedError('OPERATION_NOT_FOUND');
    case 'sender-mismatch':
      throw new ActionResultRejectedError('SENDER_MISMATCH');
    case 'conflict':
      throw new ActionResultRejectedError('RESULT_CONFLICT');
  }
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  const copy = value.slice();
  try {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', copy));
  } finally {
    copy.fill(0);
  }
}

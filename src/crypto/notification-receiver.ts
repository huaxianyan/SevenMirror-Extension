import { decodeEncryptedPayloadV1 } from '../protocol/encrypted-payload';
import {
  authenticateAndOpen,
  consumeReplay,
  EnvelopeRejectedError,
  type EnvelopeRecipientContext,
  type ReplayLedgerWriter,
} from './envelope-receiver';
import type {
  IndexedDbNotificationStateStore,
  NotificationSnapshotReconciliation,
  NotificationStateReconciliation,
} from './indexeddb-notification-state-store';

export type NotificationReceipt =
  | { kind: 'item'; reconciliation: NotificationStateReconciliation }
  | {
    kind: 'snapshot';
    sourceDeviceId: Uint8Array;
    sourceKeyId: Uint8Array;
    recoveryRequestId?: Uint8Array;
    reconciliation: NotificationSnapshotReconciliation;
  };

export class NotificationRejectedError extends Error {
  constructor(readonly code: 'UNEXPECTED_PAYLOAD') {
    super(code);
    this.name = 'NotificationRejectedError';
  }
}

/** Persists notification revision state before consuming the cross-database replay tuple. */
export async function receiveNotificationOnce(
  frameBytes: Uint8Array,
  context: EnvelopeRecipientContext,
  replayLedger: ReplayLedgerWriter,
  notifications: IndexedDbNotificationStateStore,
  nowUnixMs: number,
  allowReplayDuplicate = false,
): Promise<NotificationReceipt> {
  const opened = await authenticateAndOpen(frameBytes, context, nowUnixMs);
  const payload = decodeEncryptedPayloadV1(opened.plaintext);
  let receipt: NotificationReceipt;
  switch (payload.body.case) {
    case 'notificationUpsert':
      receipt = { kind: 'item', reconciliation: await notifications.reconcileUpsert(
        opened.header.senderDeviceId,
        payload.body.value,
        opened.plaintext,
      ) };
      break;
    case 'notificationRemoved':
      receipt = { kind: 'item', reconciliation: await notifications.reconcileRemoved(
        opened.header.senderDeviceId,
        payload.body.value,
        opened.plaintext,
      ) };
      break;
    case 'notificationSnapshotManifest':
      receipt = {
        kind: 'snapshot',
        sourceDeviceId: opened.header.senderDeviceId.slice(),
        sourceKeyId: opened.header.senderKeyId.slice(),
        ...(payload.body.value.recoveryRequestId === undefined
          ? {}
          : { recoveryRequestId: payload.body.value.recoveryRequestId.slice() }),
        reconciliation: await notifications.reconcileSnapshot(
          opened.header.senderDeviceId,
          payload.body.value,
          opened.plaintext,
        ),
      };
      break;
    default:
      throw new NotificationRejectedError('UNEXPECTED_PAYLOAD');
  }
  try {
    await consumeReplay(opened.header, replayLedger, nowUnixMs);
  } catch (error) {
    if (!allowReplayDuplicate || !(error instanceof EnvelopeRejectedError) ||
        error.code !== 'DUPLICATE') throw error;
  }
  return receipt;
}

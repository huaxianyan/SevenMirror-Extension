import { decodeEncryptedPayloadV1 } from '../protocol/encrypted-payload';
import {
  authenticateAndOpen,
  consumeReplay,
  type EnvelopeRecipientContext,
  type ReplayLedgerWriter,
} from './envelope-receiver';
import type {
  IndexedDbNotificationStateStore,
  NotificationStateReconciliation,
} from './indexeddb-notification-state-store';

export interface NotificationReceipt {
  reconciliation: NotificationStateReconciliation;
}

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
): Promise<NotificationReceipt> {
  const opened = await authenticateAndOpen(frameBytes, context, nowUnixMs);
  const payload = decodeEncryptedPayloadV1(opened.plaintext);
  let reconciliation: NotificationStateReconciliation;
  switch (payload.body.case) {
    case 'notificationUpsert':
      reconciliation = await notifications.reconcileUpsert(
        opened.header.senderDeviceId,
        payload.body.value,
        opened.plaintext,
      );
      break;
    case 'notificationRemoved':
      reconciliation = await notifications.reconcileRemoved(
        opened.header.senderDeviceId,
        payload.body.value,
        opened.plaintext,
      );
      break;
    default:
      throw new NotificationRejectedError('UNEXPECTED_PAYLOAD');
  }
  await consumeReplay(opened.header, replayLedger, nowUnixMs);
  return { reconciliation };
}

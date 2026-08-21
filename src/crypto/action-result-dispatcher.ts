import { decodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import type { HpkeIdentity } from './auth-hpke';
import {
  ActionResultRejectedError,
  receiveActionResultOnce,
  type ActionResultReceipt,
  type PendingActionReconciler,
} from './action-result-receiver';
import type { EnvelopeRecipientContext, ReplayLedgerWriter } from './envelope-receiver';
import type { IndexedDbNotificationStateStore } from './indexeddb-notification-state-store';
import {
  NotificationRejectedError,
  receiveNotificationOnce,
  type NotificationReceipt,
} from './notification-receiver';
import type { StoredTransportCredential } from '../transport/indexeddb-transport-credential-store';
import type {
  BusinessSenderAuthorization,
  BusinessSenderResolver,
} from './workspace-business-peer-resolver';

export interface DispatcherCredentialStore {
  load(): Promise<StoredTransportCredential | undefined>;
}

export interface DispatcherIdentityStore {
  loadExisting(): Promise<HpkeIdentity | undefined>;
}

export type BusinessDispatchReceipt =
  | { kind: 'action-result'; receipt: ActionResultReceipt }
  | { kind: 'notification'; receipt: NotificationReceipt };

export class ActionResultDispatchError extends Error {
  constructor(readonly code: 'NOT_CONFIGURED' | 'IDENTITY_UNAVAILABLE' | 'WRONG_ROUTE' | 'UNAUTHORIZED_SENDER' | 'UNAUTHORIZED_ROLE') {
    super(code);
    this.name = 'ActionResultDispatchError';
  }
}

/** Resolves an authority-certified sender before HPKE opening and reconciliation. */
export class ActionResultDispatcher {
  constructor(
    private readonly credentialStore: DispatcherCredentialStore,
    private readonly identityStore: DispatcherIdentityStore,
    private readonly senders: BusinessSenderResolver,
    private readonly replayLedger: ReplayLedgerWriter,
    private readonly pendingActions: PendingActionReconciler,
    private readonly now: () => number = Date.now,
    private readonly notifications?: IndexedDbNotificationStateStore,
  ) {}

  async receive(frame: ArrayBuffer): Promise<ActionResultReceipt> {
    const resolved = await this.resolve(frame);
    if (!resolved.authorization.mayReceiveActionResults) {
      throw new ActionResultDispatchError('UNAUTHORIZED_ROLE');
    }
    return receiveActionResultOnce(
      resolved.frameBytes,
      resolved.context,
      this.replayLedger,
      this.pendingActions,
      this.now(),
    );
  }

  async receiveBusiness(frame: ArrayBuffer): Promise<BusinessDispatchReceipt> {
    const resolved = await this.resolve(frame);
    if (resolved.authorization.mayReceiveNotifications && this.notifications !== undefined) {
      try {
        const receipt = await receiveNotificationOnce(
          resolved.frameBytes,
          resolved.context,
          this.replayLedger,
          this.notifications,
          this.now(),
        );
        return { kind: 'notification', receipt };
      } catch (error) {
        if (!(error instanceof NotificationRejectedError) ||
            error.code !== 'UNEXPECTED_PAYLOAD') throw error;
      }
    }
    if (!resolved.authorization.mayReceiveActionResults) {
      throw new ActionResultDispatchError('UNAUTHORIZED_ROLE');
    }
    try {
      const receipt = await receiveActionResultOnce(
        resolved.frameBytes,
        resolved.context,
        this.replayLedger,
        this.pendingActions,
        this.now(),
      );
      return { kind: 'action-result', receipt };
    } catch (error) {
      if (error instanceof ActionResultRejectedError && error.code === 'UNEXPECTED_PAYLOAD') {
        throw new ActionResultDispatchError('UNAUTHORIZED_ROLE');
      }
      throw error;
    }
  }

  private async resolve(frame: ArrayBuffer): Promise<{
    frameBytes: Uint8Array;
    context: EnvelopeRecipientContext;
    authorization: BusinessSenderAuthorization;
  }> {
    const frameBytes = new Uint8Array(frame.slice(0));
    // Strictly decode the public routing header before consulting the local pin directory.
    const envelope = decodeEncryptedEnvelopeV1(frameBytes);
    const credential = await this.credentialStore.load();
    if (credential === undefined) {
      throw new ActionResultDispatchError('NOT_CONFIGURED');
    }
    credential.authToken.fill(0);

    const header = envelope.routingHeader;
    if (!bytesEqual(header.workspaceId, credential.workspaceId) ||
        !bytesEqual(header.recipientDeviceId, credential.deviceId)) {
      throw new ActionResultDispatchError('WRONG_ROUTE');
    }
    const identity = await this.identityStore.loadExisting();
    if (identity === undefined) {
      throw new ActionResultDispatchError('IDENTITY_UNAVAILABLE');
    }
    const authorization = await this.senders.resolve(
      header.workspaceId,
      credential.deviceId,
      header.senderDeviceId,
      header.senderKeyId,
      this.now(),
    );
    if (authorization === undefined) {
      throw new ActionResultDispatchError('UNAUTHORIZED_SENDER');
    }

    return {
      frameBytes,
      context: {
        workspaceId: credential.workspaceId,
        recipientDeviceId: credential.deviceId,
        recipientIdentity: identity,
        pinnedSenderPublicKey: authorization.senderPublicKey,
      },
      authorization,
    };
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

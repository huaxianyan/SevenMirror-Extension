import { decodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import type { HpkeIdentity } from './auth-hpke';
import {
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

export interface DispatcherCredentialStore {
  load(): Promise<StoredTransportCredential | undefined>;
}

export interface DispatcherIdentityStore {
  loadExisting(): Promise<HpkeIdentity | undefined>;
}

export interface ApprovedPeerResolver {
  findApproved(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    keyId: Uint8Array,
  ): Promise<Uint8Array | undefined>;
}

export type BusinessDispatchReceipt =
  | { kind: 'action-result'; receipt: ActionResultReceipt }
  | { kind: 'notification'; receipt: NotificationReceipt };

export class ActionResultDispatchError extends Error {
  constructor(readonly code: 'NOT_CONFIGURED' | 'IDENTITY_UNAVAILABLE' | 'WRONG_ROUTE' | 'UNAPPROVED_SENDER') {
    super(code);
    this.name = 'ActionResultDispatchError';
  }
}

/** Resolves only a locally approved sender pin before HPKE opening and reconciliation. */
export class ActionResultDispatcher {
  constructor(
    private readonly credentialStore: DispatcherCredentialStore,
    private readonly identityStore: DispatcherIdentityStore,
    private readonly approvedPeers: ApprovedPeerResolver,
    private readonly replayLedger: ReplayLedgerWriter,
    private readonly pendingActions: PendingActionReconciler,
    private readonly now: () => number = Date.now,
    private readonly notifications?: IndexedDbNotificationStateStore,
  ) {}

  async receive(frame: ArrayBuffer): Promise<ActionResultReceipt> {
    const resolved = await this.resolve(frame);
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
    if (this.notifications !== undefined) {
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
    const receipt = await receiveActionResultOnce(
      resolved.frameBytes,
      resolved.context,
      this.replayLedger,
      this.pendingActions,
      this.now(),
    );
    return { kind: 'action-result', receipt };
  }

  private async resolve(frame: ArrayBuffer): Promise<{
    frameBytes: Uint8Array;
    context: EnvelopeRecipientContext;
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
    const pinnedSenderPublicKey = await this.approvedPeers.findApproved(
      header.workspaceId,
      header.senderDeviceId,
      header.senderKeyId,
    );
    if (pinnedSenderPublicKey === undefined) {
      throw new ActionResultDispatchError('UNAPPROVED_SENDER');
    }

    return {
      frameBytes,
      context: {
        workspaceId: credential.workspaceId,
        recipientDeviceId: credential.deviceId,
        recipientIdentity: identity,
        pinnedSenderPublicKey,
      },
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

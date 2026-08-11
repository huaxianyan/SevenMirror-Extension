import { decodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import type { HpkeIdentity } from './auth-hpke';
import {
  receiveActionResultOnce,
  type ActionResultReceipt,
  type PendingActionReconciler,
} from './action-result-receiver';
import type { ReplayLedgerWriter } from './envelope-receiver';
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
  ) {}

  async receive(frame: ArrayBuffer): Promise<ActionResultReceipt> {
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

    return receiveActionResultOnce(
      frameBytes,
      {
        workspaceId: credential.workspaceId,
        recipientDeviceId: credential.deviceId,
        recipientIdentity: identity,
        pinnedSenderPublicKey,
      },
      this.replayLedger,
      this.pendingActions,
      this.now(),
    );
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

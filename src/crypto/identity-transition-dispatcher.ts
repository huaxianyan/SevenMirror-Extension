import {
  deriveIdentityKeyId,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import {
  EnvelopeRejectedError,
  receiveIdentityTransitionCommitOnce,
  receiveIdentityTransitionOnce,
  receivePendingIdentityAckOnce,
  type ReplayLedgerWriter,
} from './envelope-receiver';
import type { IndexedDbIdentityStore } from './indexeddb-identity-store';
import type { IndexedDbLocalIdentityTransitionStore } from './indexeddb-local-identity-transition-store';
import type { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';
import { decodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import type {
  IndexedDbTransportCredentialStore,
  StoredTransportCredential,
} from '../transport/indexeddb-transport-credential-store';

export type IdentityTransitionDispatchResult =
  'peer-transition' | 'local-ack' | 'peer-commit' | 'business-fallback';

/** Routes lifecycle frames without ever admitting pending identities to business dispatch. */
export class IdentityTransitionDispatcher {
  constructor(
    private readonly credentials: IndexedDbTransportCredentialStore,
    private readonly identities: IndexedDbIdentityStore,
    private readonly trustedPeers: IndexedDbTrustedPeerStore,
    private readonly localTransitions: IndexedDbLocalIdentityTransitionStore,
    private readonly replayLedger: ReplayLedgerWriter,
    private readonly businessFallback: (frame: Uint8Array) => Promise<void>,
    private readonly now: () => number = Date.now,
  ) {}

  async receive(frame: Uint8Array): Promise<IdentityTransitionDispatchResult> {
    const nowUnixMs = this.now();
    const envelope = decodeEncryptedEnvelopeV1(frame);
    const credential = await this.credentials.load();
    if (credential === undefined) throw new Error('Transport is not configured');
    try {
      this.requireTransportTuple(envelope.routingHeader, credential);
      const rotation = await this.identities.loadRotation();
      const current = rotation?.current ?? await this.identities.loadExisting();
      if (current === undefined) throw new Error('E2EE identity is not configured');
      const currentKeyId = await keyId(current);
      if (!bytesEqual(currentKeyId, credential.identityKeyId)) {
        throw new Error('Transport credential E2EE identity binding does not match');
      }
      const recipientKeyId = envelope.routingHeader.recipientKeyId;
      if (rotation !== undefined) {
        const pendingKeyId = await keyId(rotation.pending);
        if (bytesEqual(recipientKeyId, pendingKeyId)) {
          const senderPublicKey = await this.requireApprovedSender(envelope.routingHeader);
          try {
            await receivePendingIdentityAckOnce(frame, {
              workspaceId: credential.workspaceId,
              recipientDeviceId: credential.deviceId,
              recipientIdentity: rotation.pending,
              pinnedSenderPublicKey: senderPublicKey,
            }, this.localTransitions, this.replayLedger, nowUnixMs);
          } finally {
            senderPublicKey.fill(0);
          }
          return 'local-ack';
        }
      }
      if (!bytesEqual(recipientKeyId, currentKeyId)) {
        throw new EnvelopeRejectedError('RECIPIENT_KEY_MISMATCH');
      }

      const commitBinding = await this.trustedPeers.resolveIdentityCommitSender(
        credential.workspaceId,
        envelope.routingHeader.senderDeviceId,
        envelope.routingHeader.senderKeyId,
        nowUnixMs,
      );
      if (commitBinding !== undefined) {
        commitBinding.senderPublicKey.fill(0);
        await receiveIdentityTransitionCommitOnce(frame, {
          workspaceId: credential.workspaceId,
          recipientDeviceId: credential.deviceId,
          recipientIdentity: current,
        }, this.trustedPeers, this.replayLedger, nowUnixMs);
        return 'peer-commit';
      }

      const senderPublicKey = await this.requireApprovedSender(envelope.routingHeader);
      try {
        await receiveIdentityTransitionOnce(frame, {
          workspaceId: credential.workspaceId,
          recipientDeviceId: credential.deviceId,
          recipientIdentity: current,
          pinnedSenderPublicKey: senderPublicKey,
        }, this.trustedPeers, this.replayLedger, nowUnixMs);
        return 'peer-transition';
      } catch (error) {
        if (!(error instanceof EnvelopeRejectedError) ||
            error.code !== 'IDENTITY_TRANSITION_PAYLOAD_MISMATCH') throw error;
      } finally {
        senderPublicKey.fill(0);
      }
      await this.businessFallback(frame);
      return 'business-fallback';
    } finally {
      credential.authToken.fill(0);
    }
  }

  private async requireApprovedSender(
    header: ReturnType<typeof decodeEncryptedEnvelopeV1>['routingHeader'],
  ): Promise<Uint8Array> {
    const sender = await this.trustedPeers.findApproved(
      header.workspaceId,
      header.senderDeviceId,
      header.senderKeyId,
    );
    if (sender === undefined) throw new EnvelopeRejectedError('WRONG_SENDER');
    return sender;
  }

  private requireTransportTuple(
    header: ReturnType<typeof decodeEncryptedEnvelopeV1>['routingHeader'],
    credential: StoredTransportCredential,
  ): void {
    if (!bytesEqual(header.workspaceId, credential.workspaceId)) {
      throw new EnvelopeRejectedError('WRONG_WORKSPACE');
    }
    if (!bytesEqual(header.recipientDeviceId, credential.deviceId)) {
      throw new EnvelopeRejectedError('WRONG_RECIPIENT');
    }
  }
}

async function keyId(identity: HpkeIdentity): Promise<Uint8Array> {
  return deriveIdentityKeyId(await serializeIdentityPublicKey(identity));
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

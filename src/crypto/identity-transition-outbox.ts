import type { IndexedDbTransportCredentialStore } from '../transport/indexeddb-transport-credential-store';
import { deriveIdentityKeyId, serializeIdentityPublicKey } from './auth-hpke';
import { createIdentityTransitionEnvelopeFromPayload } from './identity-transition-envelope-sender';
import type { IndexedDbIdentityStore } from './indexeddb-identity-store';
import type { IndexedDbLocalIdentityTransitionStore } from './indexeddb-local-identity-transition-store';
import type { IndexedDbOutboundSequenceStore } from './indexeddb-outbound-sequence-store';
import type { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';

export interface IdentityTransitionDrainResult {
  acceptedSends: number;
  attemptedEntries: number;
  nextWakeDelayMs?: number;
}

/** Sends the exact canonical transition with the still-active old identity. */
export class IdentityTransitionOutbox {
  private exclusive = Promise.resolve();

  constructor(
    private readonly credentials: IndexedDbTransportCredentialStore,
    private readonly identities: IndexedDbIdentityStore,
    private readonly localTransitions: IndexedDbLocalIdentityTransitionStore,
    private readonly trustedPeers: IndexedDbTrustedPeerStore,
    private readonly sequences: IndexedDbOutboundSequenceStore,
    private readonly send: (frame: Uint8Array) => boolean,
    private readonly now: () => number = Date.now,
    private readonly random: (target: Uint8Array) => void = (target) => crypto.getRandomValues(target),
  ) {}

  drainDue(): Promise<IdentityTransitionDrainResult> {
    return this.runExclusive(async () => {
      const nowUnixMs = this.now();
      const credential = await this.credentials.load();
      if (credential === undefined) throw new Error('Transport is not configured');
      try {
        const due = await this.localTransitions.dueTransitions(
          credential.workspaceId,
          nowUnixMs,
        );
        if (due.length === 0) return { acceptedSends: 0, attemptedEntries: 0 };
        const rotation = await this.identities.loadRotation();
        if (rotation === undefined) throw new Error('Pending E2EE identity is not configured');
        const currentKeyId = await deriveIdentityKeyId(
          await serializeIdentityPublicKey(rotation.current),
        );
        const pendingKeyId = await deriveIdentityKeyId(
          await serializeIdentityPublicKey(rotation.pending),
        );
        if (!bytesEqual(currentKeyId, credential.identityKeyId)) {
          throw new Error('Transport credential E2EE identity binding does not match current identity');
        }
        let acceptedSends = 0;
        let attemptedEntries = 0;
        let nextWakeDelayMs: number | undefined;
        for (const entry of due) {
          attemptedEntries += 1;
          if (!bytesEqual(entry.session.localDeviceId, credential.deviceId) ||
              !bytesEqual(entry.session.previousKeyId, currentKeyId) ||
              !bytesEqual(entry.session.newKeyId, pendingKeyId)) {
            throw new Error('Local identity transition does not match current/pending identity slots');
          }
          const recipient = await this.trustedPeers.findApproved(
            credential.workspaceId,
            entry.peer.deviceId,
            entry.peer.keyId,
          );
          if (recipient === undefined) {
            throw new Error('Identity transition recipient is no longer approved');
          }
          let frame: Uint8Array;
          try {
            frame = await createIdentityTransitionEnvelopeFromPayload({
              workspaceId: credential.workspaceId,
              senderDeviceId: credential.deviceId,
              recipientDeviceId: entry.peer.deviceId,
              senderIdentity: rotation.current,
              recipientPublicKey: recipient,
              messageId: this.nextMessageId(),
              sequence: await this.sequences.allocate(entry.peer.keyId),
              createdAtUnixMs: nowUnixMs,
              expiresAtUnixMs: nowUnixMs + 60_000,
            }, entry.session.canonicalTransition);
          } finally {
            recipient.fill(0);
          }
          let accepted: boolean;
          try {
            accepted = this.send(frame);
          } finally {
            frame.fill(0);
          }
          if (!accepted) break;
          acceptedSends += 1;
          const delayMs = Math.min(1_000 * 2 ** entry.peer.commitAttemptCount, 8_000);
          await this.localTransitions.recordTransitionSendAttempt(
            entry.peer.deviceId,
            entry.session.transitionId,
            entry.session.transitionSha256,
            nowUnixMs + delayMs,
            5,
          );
          if (entry.peer.commitAttemptCount + 1 < 5) {
            nextWakeDelayMs = Math.min(nextWakeDelayMs ?? delayMs, delayMs);
          }
        }
        return {
          acceptedSends,
          attemptedEntries,
          ...(nextWakeDelayMs === undefined ? {} : { nextWakeDelayMs }),
        };
      } finally {
        credential.authToken.fill(0);
      }
    });
  }

  private nextMessageId(): Uint8Array {
    const value = new Uint8Array(16);
    do this.random(value); while (value.every((byte) => byte === 0));
    return value;
  }

  private runExclusive<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.exclusive.then(operation, operation);
    this.exclusive = result.then(() => undefined, () => undefined);
    return result;
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

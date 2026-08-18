import type { StoredTransportCredential } from '../transport/indexeddb-transport-credential-store';
import {
  deriveIdentityKeyId,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import { createIdentityTransitionCommitEnvelopeFromPayload } from './identity-transition-envelope-sender';
import type {
  DueLocalIdentityCommit,
  IndexedDbLocalIdentityTransitionStore,
} from './indexeddb-local-identity-transition-store';
import type { IndexedDbOutboundSequenceStore } from './indexeddb-outbound-sequence-store';
import type { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';

interface CredentialStore {
  load(): Promise<StoredTransportCredential | undefined>;
}

interface IdentityRotationStore {
  loadExisting(): Promise<HpkeIdentity | undefined>;
  loadRotation(): Promise<{ current: HpkeIdentity; pending: HpkeIdentity } | undefined>;
}

export interface IdentityTransitionCommitDrainResult {
  acceptedSends: number;
  attemptedEntries: number;
  nextWakeDelayMs?: number;
}

/** Sends exact commits with the proposed identity; acceptance never implies peer promotion. */
export class IdentityTransitionCommitOutbox {
  private exclusive = Promise.resolve();

  constructor(
    private readonly credentialStore: CredentialStore,
    private readonly identityStore: IdentityRotationStore,
    private readonly localTransitions: IndexedDbLocalIdentityTransitionStore,
    private readonly trustedPeers: IndexedDbTrustedPeerStore,
    private readonly sequences: IndexedDbOutboundSequenceStore,
    private readonly send: (frame: Uint8Array) => boolean,
    private readonly now: () => number = Date.now,
    private readonly random: (target: Uint8Array) => void = (target) => crypto.getRandomValues(target),
  ) {}

  drainDue(): Promise<IdentityTransitionCommitDrainResult> {
    return this.runExclusive(async () => {
      const nowUnixMs = this.now();
      const credential = await this.credentialStore.load();
      if (credential === undefined) throw new Error('Transport is not configured');
      try {
        const rotation = await this.requireBoundRotation(credential);
        const due = await this.localTransitions.dueCommits(credential.workspaceId, nowUnixMs);
        let acceptedSends = 0;
        let attemptedEntries = 0;
        let nextWakeDelayMs: number | undefined;
        for (const entry of due) {
          attemptedEntries += 1;
          const recipientPublicKey = await this.trustedPeers.findApproved(
            credential.workspaceId,
            entry.peer.deviceId,
            entry.peer.keyId,
          );
          if (recipientPublicKey === undefined) {
            throw new Error('Identity transition commit recipient is no longer approved');
          }
          let frame: Uint8Array;
          try {
            frame = await this.createFrame(
              credential,
              rotation,
              entry,
              recipientPublicKey,
              nowUnixMs,
            );
          } finally {
            recipientPublicKey.fill(0);
          }
          let accepted: boolean;
          try {
            accepted = this.send(frame);
          } finally {
            frame.fill(0);
          }
          if (!accepted) break;
          acceptedSends += 1;
          const delayMs = retryDelayMs(entry.peer.commitAttemptCount);
          await this.localTransitions.recordCommitSendAttempt(
            entry.peer.deviceId,
            entry.peer.transitionId,
            requireBytes(entry.peer.ackSha256, 'acknowledgement digest'),
            nowUnixMs + delayMs,
            MAXIMUM_ATTEMPTS,
          );
          if (entry.peer.commitAttemptCount + 1 < MAXIMUM_ATTEMPTS) {
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

  private async createFrame(
    credential: StoredTransportCredential,
    rotation: BoundIdentityRotation,
    entry: DueLocalIdentityCommit,
    recipientPublicKey: Uint8Array,
    nowUnixMs: number,
  ): Promise<Uint8Array> {
    if (!bytesEqual(entry.session.localDeviceId, credential.deviceId) ||
        !bytesEqual(entry.session.workspaceId, credential.workspaceId)) {
      throw new Error('Local identity transition transport tuple does not match');
    }
    if (rotation.mode === 'dual' &&
        (!bytesEqual(entry.session.previousKeyId, rotation.currentKeyId) ||
         !bytesEqual(entry.session.newKeyId, rotation.senderKeyId)) ||
        rotation.mode === 'promoted' &&
        !bytesEqual(entry.session.newKeyId, rotation.senderKeyId)) {
      throw new Error('Local identity transition does not match current/pending identity slots');
    }
    return createIdentityTransitionCommitEnvelopeFromPayload({
      workspaceId: credential.workspaceId,
      senderDeviceId: credential.deviceId,
      recipientDeviceId: entry.peer.deviceId,
      senderIdentity: rotation.senderIdentity,
      recipientPublicKey,
      messageId: this.nextMessageId(),
      sequence: await this.sequences.allocate(entry.peer.keyId),
      createdAtUnixMs: nowUnixMs,
      expiresAtUnixMs: nowUnixMs + ENVELOPE_TTL_MS,
    }, requireBytes(entry.peer.canonicalCommit, 'canonical commit'));
  }

  private async requireBoundRotation(
    credential: StoredTransportCredential,
  ): Promise<BoundIdentityRotation> {
    const rotation = await this.identityStore.loadRotation();
    if (rotation !== undefined) {
      const currentKeyId = await deriveIdentityKeyId(
        await serializeIdentityPublicKey(rotation.current),
      );
      const pendingKeyId = await deriveIdentityKeyId(
        await serializeIdentityPublicKey(rotation.pending),
      );
      if (!bytesEqual(currentKeyId, credential.identityKeyId)) {
        throw new Error('Transport credential E2EE identity binding does not match current identity');
      }
      return {
        mode: 'dual',
        senderIdentity: rotation.pending,
        currentKeyId,
        senderKeyId: pendingKeyId,
      };
    }
    const current = await this.identityStore.loadExisting();
    if (current === undefined) throw new Error('E2EE identity is not configured');
    const currentKeyId = await deriveIdentityKeyId(await serializeIdentityPublicKey(current));
    if (!bytesEqual(currentKeyId, credential.identityKeyId)) {
      throw new Error('Transport credential E2EE identity binding does not match current identity');
    }
    return {
      mode: 'promoted',
      senderIdentity: current,
      currentKeyId,
      senderKeyId: currentKeyId,
    };
  }

  private nextMessageId(): Uint8Array {
    const value = new Uint8Array(16);
    do {
      this.random(value);
    } while (value.every((byte) => byte === 0));
    return value;
  }

  private runExclusive<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.exclusive.then(operation, operation);
    this.exclusive = result.then(() => undefined, () => undefined);
    return result;
  }
}

interface BoundIdentityRotation {
  mode: 'dual' | 'promoted';
  senderIdentity: HpkeIdentity;
  currentKeyId: Uint8Array;
  senderKeyId: Uint8Array;
}

const ENVELOPE_TTL_MS = 60_000;
const MAXIMUM_ATTEMPTS = 5;

function retryDelayMs(attemptCount: number): number {
  return Math.min(1_000 * 2 ** attemptCount, 8_000);
}

function requireBytes(value: Uint8Array | undefined, name: string): Uint8Array {
  if (value === undefined) throw new Error(`Identity transition ${name} is missing`);
  return value;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

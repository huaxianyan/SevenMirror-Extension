import type { StoredTransportCredential } from '../transport/indexeddb-transport-credential-store';
import {
  deriveIdentityKeyId,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import { createIdentityTransitionAckEnvelopeFromPayload } from './identity-transition-envelope-sender';
import type { IndexedDbOutboundSequenceStore } from './indexeddb-outbound-sequence-store';
import type { IndexedDbTrustedPeerStore, PeerIdentityTransitionState } from './indexeddb-trusted-peer-store';

interface CredentialStore {
  load(): Promise<StoredTransportCredential | undefined>;
}

interface IdentityStore {
  loadExisting(): Promise<HpkeIdentity | undefined>;
}

export interface IdentityTransitionAckDrainResult {
  acceptedSends: number;
  attemptedEntries: number;
  nextWakeDelayMs?: number;
}

/** Sends exact durable transition ACK intents; socket acceptance never deletes them. */
export class IdentityTransitionAckOutbox {
  private exclusive = Promise.resolve();

  constructor(
    private readonly credentialStore: CredentialStore,
    private readonly identityStore: IdentityStore,
    private readonly trustedPeers: IndexedDbTrustedPeerStore,
    private readonly sequences: IndexedDbOutboundSequenceStore,
    private readonly send: (frame: Uint8Array) => boolean,
    private readonly now: () => number = Date.now,
    private readonly random: (target: Uint8Array) => void = (target) => crypto.getRandomValues(target),
  ) {}

  drainDue(): Promise<IdentityTransitionAckDrainResult> {
    return this.runExclusive(async () => {
      const nowUnixMs = this.now();
      const credential = await this.credentialStore.load();
      if (credential === undefined) throw new Error('Transport is not configured');
      try {
        const identity = await this.requireBoundIdentity(credential);
        const due = await this.trustedPeers.dueIdentityTransitionAcks(
          credential.workspaceId,
          nowUnixMs,
        );
        let acceptedSends = 0;
        let attemptedEntries = 0;
        let nextWakeDelayMs: number | undefined;
        for (const entry of due) {
          attemptedEntries += 1;
          const frame = await this.createFrame(credential, identity, entry, nowUnixMs);
          let accepted: boolean;
          try {
            accepted = this.send(frame);
          } finally {
            frame.fill(0);
          }
          if (!accepted) break;
          acceptedSends += 1;
          const delayMs = retryDelayMs(entry.ackAttemptCount);
          await this.trustedPeers.recordIdentityTransitionAckSendAttempt(
            credential.workspaceId,
            entry.peerDeviceId,
            entry.transitionId,
            entry.ackSha256,
            nowUnixMs + delayMs,
            MAXIMUM_ATTEMPTS,
          );
          if (entry.ackAttemptCount + 1 < MAXIMUM_ATTEMPTS) {
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
    identity: HpkeIdentity,
    entry: PeerIdentityTransitionState,
    nowUnixMs: number,
  ): Promise<Uint8Array> {
    return createIdentityTransitionAckEnvelopeFromPayload({
      workspaceId: credential.workspaceId,
      senderDeviceId: credential.deviceId,
      recipientDeviceId: entry.peerDeviceId,
      senderIdentity: identity,
      recipientPublicKey: entry.newPublicKey,
      messageId: this.nextMessageId(),
      sequence: await this.sequences.allocate(entry.newKeyId),
      createdAtUnixMs: nowUnixMs,
      expiresAtUnixMs: nowUnixMs + ENVELOPE_TTL_MS,
    }, entry.canonicalAck);
  }

  private async requireBoundIdentity(credential: StoredTransportCredential): Promise<HpkeIdentity> {
    const identity = await this.identityStore.loadExisting();
    if (identity === undefined) {
      throw new Error('Transport credential exists without its bound E2EE identity');
    }
    const publicKey = await serializeIdentityPublicKey(identity);
    if (!bytesEqual(await deriveIdentityKeyId(publicKey), credential.identityKeyId)) {
      throw new Error('Transport credential E2EE identity binding does not match');
    }
    return identity;
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

const ENVELOPE_TTL_MS = 60_000;
const MAXIMUM_ATTEMPTS = 5;

function retryDelayMs(attemptCount: number): number {
  return Math.min(1_000 * 2 ** attemptCount, 8_000);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

import { createActionResultAckEnvelopeFromPayload } from './action-envelope-sender';
import {
  deriveIdentityKeyId,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import type {
  IndexedDbPendingActionStore,
  PendingAckDelivery,
} from './indexeddb-pending-action-store';
import type { IndexedDbOutboundSequenceStore } from './indexeddb-outbound-sequence-store';
import type { StoredTransportCredential } from '../transport/indexeddb-transport-credential-store';

interface CredentialStore {
  load(): Promise<StoredTransportCredential | undefined>;
}

interface IdentityStore {
  loadExisting(): Promise<HpkeIdentity | undefined>;
}

interface TrustedPeerStore {
  findApproved(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    keyId: Uint8Array,
  ): Promise<Uint8Array | undefined>;
}

export interface ActionResultAckDrainResult {
  acceptedSends: number;
  attemptedEntries: number;
  nextWakeDelayMs?: number;
}

/** Durable delivery of ACK intents created atomically with result reconciliation. */
export class ActionResultAckOutbox {
  private exclusive = Promise.resolve();

  constructor(
    private readonly credentialStore: CredentialStore,
    private readonly identityStore: IdentityStore,
    private readonly trustedPeers: TrustedPeerStore,
    private readonly pendingActions: IndexedDbPendingActionStore,
    private readonly sequences: IndexedDbOutboundSequenceStore,
    private readonly send: (frame: Uint8Array) => boolean,
    private readonly now: () => number = Date.now,
    private readonly random: (target: Uint8Array) => void = (target) => crypto.getRandomValues(target),
  ) {}

  drainDue(): Promise<ActionResultAckDrainResult> {
    return this.runExclusive(async () => {
      const nowUnixMs = this.now();
      const credential = await this.credentialStore.load();
      if (credential === undefined) throw new Error('Transport is not configured');
      try {
        const identity = await this.requireBoundIdentity(credential);
        const due = await this.pendingActions.dueAcks(nowUnixMs);
        let acceptedSends = 0;
        let attemptedEntries = 0;
        let nextWakeDelayMs: number | undefined;
        for (const entry of due) {
          const recipientPublicKey = await this.trustedPeers.findApproved(
            credential.workspaceId,
            entry.recipientDeviceId,
            entry.recipientKeyId,
          );
          if (recipientPublicKey === undefined) continue;
          attemptedEntries += 1;
          let accepted: boolean;
          try {
            accepted = await this.sendDelivery(
              credential,
              identity,
              recipientPublicKey,
              entry,
              nowUnixMs,
            );
          } finally {
            recipientPublicKey.fill(0);
          }
          if (!accepted) break;
          acceptedSends += 1;
          const delayMs = retryDelayMs(entry.attemptCount);
          await this.pendingActions.recordAckSendAttempt(
            entry.idempotencyKey,
            nowUnixMs + delayMs,
            MAXIMUM_ATTEMPTS,
          );
          if (entry.attemptCount + 1 < MAXIMUM_ATTEMPTS) {
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

  private async sendDelivery(
    credential: StoredTransportCredential,
    identity: HpkeIdentity,
    recipientPublicKey: Uint8Array,
    entry: PendingAckDelivery,
    nowUnixMs: number,
  ): Promise<boolean> {
    const frame = await createActionResultAckEnvelopeFromPayload({
      workspaceId: credential.workspaceId,
      senderDeviceId: credential.deviceId,
      recipientDeviceId: entry.recipientDeviceId,
      senderIdentity: identity,
      recipientPublicKey,
      messageId: this.nextMessageId(),
      sequence: await this.sequences.allocate(entry.recipientKeyId),
      createdAtUnixMs: nowUnixMs,
      expiresAtUnixMs: nowUnixMs + ENVELOPE_TTL_MS,
    }, entry.canonicalAckPayload);
    try {
      return this.send(frame);
    } finally {
      frame.fill(0);
    }
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

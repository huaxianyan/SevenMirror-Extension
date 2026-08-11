import {
  actionInvokeOperationDigest,
  createActionInvokeEnvelopeFromPayload,
  prepareActionInvokeEnvelope,
  PENDING_ACTION_RETENTION_MS,
  type ActionInvokeRequest,
} from './action-envelope-sender';
import {
  deriveIdentityKeyId,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import type {
  IndexedDbPendingActionStore,
  PendingInvokeDelivery,
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

export interface ActionInvokeTarget {
  deviceId: Uint8Array;
  keyId: Uint8Array;
}

export interface ActionInvokeDrainResult {
  acceptedSends: number;
  attemptedEntries: number;
  nextWakeDelayMs?: number;
}

/** Durable Chrome action.invoke queue and authenticated WebSocket delivery boundary. */
export class ActionInvokeOutbox {
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

  queueAndSend(target: ActionInvokeTarget, request: ActionInvokeRequest): Promise<{
    accepted: boolean;
    nextWakeDelayMs?: number;
  }> {
    return this.runExclusive(async () => {
      const active = await this.loadActiveContext(target);
      try {
        const nowUnixMs = this.now();
        const sequence = await this.sequences.allocate(target.keyId);
        const frame = await prepareActionInvokeEnvelope({
          workspaceId: active.credential.workspaceId,
          senderDeviceId: active.credential.deviceId,
          recipientDeviceId: target.deviceId,
          senderIdentity: active.identity,
          recipientPublicKey: active.recipientPublicKey,
          messageId: this.nextMessageId(),
          sequence,
          createdAtUnixMs: nowUnixMs,
          expiresAtUnixMs: nowUnixMs + ENVELOPE_TTL_MS,
        }, request, this.pendingActions);
        const accepted = this.sendFrame(frame);
        if (accepted) {
          await this.pendingActions.recordInvokeSendAttempt(
            request.idempotencyKey,
            nowUnixMs + BASE_RETRY_MS,
            MAXIMUM_ATTEMPTS,
          );
        }
        return { accepted, ...(accepted ? { nextWakeDelayMs: BASE_RETRY_MS } : {}) };
      } finally {
        active.credential.authToken.fill(0);
        active.recipientPublicKey.fill(0);
      }
    });
  }

  drainDue(): Promise<ActionInvokeDrainResult> {
    return this.runExclusive(async () => {
      const nowUnixMs = this.now();
      const credential = await this.credentialStore.load();
      if (credential === undefined) throw new Error('Transport is not configured');
      try {
        const identity = await this.requireBoundIdentity(credential);
        const due = await this.pendingActions.dueInvokes(nowUnixMs);
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
          await this.pendingActions.recordInvokeSendAttempt(
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

  /** Persists without sending; useful when UI queues while transport is offline. */
  queue(target: ActionInvokeTarget, request: ActionInvokeRequest): Promise<void> {
    return this.runExclusive(async () => {
      const credential = await this.credentialStore.load();
      if (credential === undefined) throw new Error('Transport is not configured');
      try {
        const recipientPublicKey = await this.trustedPeers.findApproved(
          credential.workspaceId,
          target.deviceId,
          target.keyId,
        );
        if (recipientPublicKey === undefined) throw new Error('Action recipient is not approved');
        recipientPublicKey.fill(0);
        const operation = await actionInvokeOperationDigest(request);
        const nowUnixMs = this.now();
        const registration = await this.pendingActions.register(
          request.idempotencyKey,
          target.deviceId,
          operation.digest,
          nowUnixMs,
          nowUnixMs + PENDING_ACTION_RETENTION_MS,
          operation.canonicalPayload,
          target.keyId,
        );
        if (registration === 'capacity-exceeded') {
          throw new Error('Pending action capacity exceeded');
        }
      } finally {
        credential.authToken.fill(0);
      }
    });
  }

  private async sendDelivery(
    credential: StoredTransportCredential,
    identity: HpkeIdentity,
    recipientPublicKey: Uint8Array,
    entry: PendingInvokeDelivery,
    nowUnixMs: number,
  ): Promise<boolean> {
    const frame = await createActionInvokeEnvelopeFromPayload({
      workspaceId: credential.workspaceId,
      senderDeviceId: credential.deviceId,
      recipientDeviceId: entry.recipientDeviceId,
      senderIdentity: identity,
      recipientPublicKey,
      messageId: this.nextMessageId(),
      sequence: await this.sequences.allocate(entry.recipientKeyId),
      createdAtUnixMs: nowUnixMs,
      expiresAtUnixMs: nowUnixMs + ENVELOPE_TTL_MS,
    }, entry.canonicalInvokePayload);
    return this.sendFrame(frame);
  }

  private sendFrame(frame: Uint8Array): boolean {
    try {
      return this.send(frame);
    } finally {
      frame.fill(0);
    }
  }

  private async loadActiveContext(target: ActionInvokeTarget): Promise<{
    credential: StoredTransportCredential;
    identity: HpkeIdentity;
    recipientPublicKey: Uint8Array;
  }> {
    const credential = await this.credentialStore.load();
    if (credential === undefined) throw new Error('Transport is not configured');
    try {
      const identity = await this.requireBoundIdentity(credential);
      const recipientPublicKey = await this.trustedPeers.findApproved(
        credential.workspaceId,
        target.deviceId,
        target.keyId,
      );
      if (recipientPublicKey === undefined) throw new Error('Action recipient is not approved');
      return { credential, identity, recipientPublicKey };
    } catch (error) {
      credential.authToken.fill(0);
      throw error;
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

  private runExclusive<T>(work: () => Promise<T>): Promise<T> {
    const result = this.exclusive.then(work, work);
    this.exclusive = result.then(() => undefined, () => undefined);
    return result;
  }
}

function retryDelayMs(completedAttempts: number): number {
  return Math.min(MAX_RETRY_MS, BASE_RETRY_MS * (2 ** Math.min(completedAttempts, 6)));
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

const ENVELOPE_TTL_MS = 5 * 60 * 1_000;
const BASE_RETRY_MS = 1_000;
const MAX_RETRY_MS = 60_000;
const MAXIMUM_ATTEMPTS = 5;

import {
  deriveIdentityKeyId,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from '../crypto/auth-hpke';
import type { ConnectionState } from '../shared/status';
import {
  openAuthenticatedWebSocket,
  type TransportDiagnosticEvent,
} from './authenticated-websocket';
import type {
  StoredTransportCredential,
  TransportCredentialCandidate,
} from './indexeddb-transport-credential-store';
import { FAIL_CLOSED_WEBSOCKET_CODE } from './websocket-close-policy';
import {
  decodeRelayServerMessage,
  encodeDurableSubmission,
  encodeRelayAcknowledgement,
  encodeRelayResume,
} from './relay-delivery';

interface CredentialStore {
  load(): Promise<StoredTransportCredential | undefined>;
  loadConnectionCandidate?(preferCurrentFallback?: boolean): Promise<TransportCredentialCandidate | undefined>;
  promotePending?(): Promise<StoredTransportCredential>;
}

interface IdentityStore {
  loadExisting(): Promise<HpkeIdentity | undefined>;
}

type StateWriter = (state: ConnectionState) => Promise<void>;
type SocketOpener = (
  credential: StoredTransportCredential,
  observe: (event: TransportDiagnosticEvent) => void,
) => WebSocket;

type TimerHandle = ReturnType<typeof setTimeout>;

export interface DeliveryCursorStore {
  load(workspaceId: Uint8Array, deviceId: Uint8Array): Promise<{
    committedDeliveryId: bigint;
    snapshotRequiredHighWater?: bigint;
  }>;
  commitDelivery(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    deliveryId: bigint,
  ): Promise<unknown>;
  requireSnapshot(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    highWater: bigint,
  ): Promise<unknown>;
  acceptSnapshotRecovery?(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    requestId: Uint8Array,
  ): Promise<{ committedDeliveryId: bigint }>;
}

export interface TransportReconnectOptions {
  initialDelayMs?: number;
  maximumDelayMs?: number;
  multiplier?: number;
  jitterRatio?: number;
  random?: () => number;
  setTimer?: (callback: () => void, delayMs: number) => TimerHandle;
  clearTimer?: (handle: TimerHandle) => void;
  onAuthenticated?: () => void;
  beforeConnect?: () => Promise<void>;
  beforeAuthenticate?: (credential: StoredTransportCredential) => Promise<void>;
  deliveryCursorStore?: DeliveryCursorStore;
  onHistoryGap?: (highWater: bigint) => void;
}

interface ReconnectPolicy {
  initialDelayMs: number;
  maximumDelayMs: number;
  multiplier: number;
  jitterRatio: number;
  random: () => number;
  setTimer: (callback: () => void, delayMs: number) => TimerHandle;
  clearTimer: (handle: TimerHandle) => void;
}

const DEFAULT_RECONNECT_POLICY: ReconnectPolicy = {
  initialDelayMs: 1_000,
  maximumDelayMs: 60_000,
  multiplier: 2,
  jitterRatio: 0.2,
  random: Math.random,
  setTimer: (callback, delayMs) => setTimeout(callback, delayMs),
  clearTimer: (handle) => clearTimeout(handle),
};

/** Owns one authenticated socket without creating identities or replacing credentials. */
export class TransportRuntime {
  private generation = 0;
  private terminalGeneration?: number;
  private socket?: WebSocket;
  private reconnectTimer?: TimerHandle;
  private reconnectAttempt = 0;
  private authenticatedGeneration?: number;
  private sno1Generation?: number;
  private preferCurrentFallback = false;
  private readonly onAuthenticated: () => void;
  private readonly beforeConnect: () => Promise<void>;
  private readonly beforeAuthenticate: (credential: StoredTransportCredential) => Promise<void>;
  private readonly deliveryCursorStore?: DeliveryCursorStore;
  private readonly onHistoryGap: (highWater: bigint) => void;
  private readonly reconnectPolicy: ReconnectPolicy;

  constructor(
    private readonly credentialStore: CredentialStore,
    private readonly identityStore: IdentityStore,
    private readonly writeState: StateWriter,
    private readonly onEnvelope: ((
      frame: ArrayBuffer,
      options?: { allowReplayDuplicate: boolean },
    ) => Promise<void>) | undefined,
    private readonly openSocket: SocketOpener = openAuthenticatedWebSocket,
    reconnectOptions: TransportReconnectOptions = {},
  ) {
    this.onAuthenticated = reconnectOptions.onAuthenticated ?? (() => undefined);
    this.beforeConnect = reconnectOptions.beforeConnect ?? (async () => undefined);
    this.beforeAuthenticate = reconnectOptions.beforeAuthenticate ?? (async () => undefined);
    this.deliveryCursorStore = reconnectOptions.deliveryCursorStore;
    this.onHistoryGap = reconnectOptions.onHistoryGap ?? (() => undefined);
    const {
      onAuthenticated: _onAuthenticated,
      beforeConnect: _beforeConnect,
      beforeAuthenticate: _beforeAuthenticate,
      deliveryCursorStore: _deliveryCursorStore,
      onHistoryGap: _onHistoryGap,
      ...policyOptions
    } = reconnectOptions;
    this.reconnectPolicy = validateReconnectPolicy({
      ...DEFAULT_RECONNECT_POLICY,
      ...policyOptions,
    });
  }

  /** Starts immediately and resets the retry sequence for an explicit user/startup request. */
  async connect(): Promise<void> {
    this.cancelReconnect();
    this.reconnectAttempt = 0;
    await this.startConnection();
  }

  /** Handles a durable scheduler wake without resetting the exponential retry sequence. */
  async retryScheduledConnection(): Promise<void> {
    this.reconnectTimer = undefined;
    if (this.isAuthenticated()) return;
    await this.startConnection();
  }

  hasAuthenticatedConnection(): boolean {
    return this.isAuthenticated();
  }

  /**
   * Re-establishes a suspended MV3 transport and waits for SNO1 before an explicit user resend.
   * Durable background queues continue to use their normal alarm-driven recovery path.
   */
  async ensureAuthenticated(timeoutMs = 5_000): Promise<boolean> {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new Error('timeoutMs must be positive');
    }
    if (this.isAuthenticated()) return true;
    try {
      await this.connect();
    } catch {
      return false;
    }
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (this.isAuthenticated()) return true;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    return this.isAuthenticated();
  }

  /** Sends only after this connection generation has authenticated SNO1. */
  sendEnvelope(frame: Uint8Array): boolean {
    const socket = this.socket;
    if (socket === undefined || !this.isAuthenticated()) return false;
    try {
      socket.send(frame);
      return true;
    } catch {
      return false;
    }
  }

  /** Requests durable relay delivery for a business message that is safe to delay. */
  sendDurableEnvelope(frame: Uint8Array): boolean {
    return this.sendEnvelope(encodeDurableSubmission(frame));
  }

  /** Atomically accepts a fully reconciled history reset and resumes after its high-water. */
  async acceptSnapshotRecovery(requestId: Uint8Array): Promise<boolean> {
    const cursorStore = this.deliveryCursorStore;
    if (cursorStore?.acceptSnapshotRecovery === undefined || !this.isAuthenticated()) return false;
    const credential = await this.credentialStore.load();
    if (credential === undefined) return false;
    try {
      const accepted = await cursorStore.acceptSnapshotRecovery(
        credential.workspaceId,
        credential.deviceId,
        requestId,
      );
      if (!this.isAuthenticated()) return false;
      return this.sendEnvelope(encodeRelayResume(accepted.committedDeliveryId));
    } finally {
      credential.authToken.fill(0);
    }
  }

  /** Stops without network retry after a local encrypted-message security failure. */
  async failClosed(): Promise<void> {
    this.cancelReconnect();
    ++this.generation;
    this.terminalGeneration = undefined;
    this.authenticatedGeneration = undefined;
    this.sno1Generation = undefined;
    this.socket?.close(FAIL_CLOSED_WEBSOCKET_CODE, 'encrypted message processing failed');
    this.socket = undefined;
    await this.writeState('offline');
  }

  async disconnect(): Promise<void> {
    this.cancelReconnect();
    this.reconnectAttempt = 0;
    ++this.generation;
    this.terminalGeneration = undefined;
    this.authenticatedGeneration = undefined;
    this.sno1Generation = undefined;
    this.socket?.close(1000, 'local disconnect');
    this.socket = undefined;
    await this.writeState('offline');
  }

  private async startConnection(): Promise<void> {
    const generation = ++this.generation;
    this.terminalGeneration = undefined;
    this.authenticatedGeneration = undefined;
    this.sno1Generation = undefined;
    this.socket?.close(1000, 'replaced by new connection');
    this.socket = undefined;

    try {
      await this.beforeConnect();
    } catch (error) {
      if (generation === this.generation) await this.writeState('offline');
      throw error;
    }
    if (generation !== this.generation) return;

    const candidate = this.credentialStore.loadConnectionCandidate === undefined
      ? await this.loadCurrentCandidate()
      : await this.credentialStore.loadConnectionCandidate(this.preferCurrentFallback);
    const credential = candidate?.credential;
    const credentialSource = candidate?.source ?? 'current';
    if (generation !== this.generation) {
      credential?.authToken.fill(0);
      return;
    }
    if (credential === undefined) {
      this.reconnectAttempt = 0;
      await this.writeState('not-configured');
      return;
    }

    try {
      await this.beforeAuthenticate(credential);
      await this.requireBoundIdentity(credential);
    } catch (error) {
      credential.authToken.fill(0);
      if (generation === this.generation) await this.writeState('offline');
      // Persistent local identity failures are security failures, not network retries.
      throw error;
    }
    if (generation !== this.generation) {
      credential.authToken.fill(0);
      return;
    }

    await this.writeState('connecting');
    let socket: WebSocket;
    try {
      socket = this.openSocket(credential, (event) => {
        if (generation !== this.generation) return;
        if (event === 'authenticated') {
          this.sno1Generation = generation;
          void this.completeAuthentication(generation, socket, credentialSource, credential);
        } else if (event === 'socket-error' || event === 'socket-closed') {
          this.handleSocketTermination(generation, socket, credentialSource);
        }
      });
    } catch (error) {
      credential.authToken.fill(0);
      if (generation === this.generation) {
        await this.writeState('offline');
        this.scheduleReconnect(generation);
      }
      throw error;
    }
    credential.authToken.fill(0);
    if (generation !== this.generation) {
      socket.close(1000, 'superseded connection');
      return;
    }
    let acceptingFrames = true;
    let inboundQueue = Promise.resolve();
    socket.addEventListener('message', (event) => {
      if (generation !== this.generation || !acceptingFrames) return;
      if (!(event.data instanceof ArrayBuffer)) {
        acceptingFrames = false;
        socket.close(FAIL_CLOSED_WEBSOCKET_CODE, 'relay messages must be binary');
        return;
      }
      if (this.onEnvelope === undefined) {
        acceptingFrames = false;
        socket.close(FAIL_CLOSED_WEBSOCKET_CODE, 'encrypted envelope handler unavailable');
        return;
      }
      const frame = event.data.slice(0);
      inboundQueue = inboundQueue.then(async () => {
        if (generation !== this.generation || !acceptingFrames) return;
        await this.receiveRelayMessage(generation, socket, credential, frame);
      }).catch(() => {
        if (generation !== this.generation) return;
        acceptingFrames = false;
        socket.close(FAIL_CLOSED_WEBSOCKET_CODE, 'encrypted envelope rejected');
      });
    });
    this.socket = socket;
  }

  private async receiveRelayMessage(
    generation: number,
    socket: WebSocket,
    credential: StoredTransportCredential,
    encoded: ArrayBuffer,
  ): Promise<void> {
    const message = decodeRelayServerMessage(encoded);
    if (message.kind === 'online-envelope') {
      await this.onEnvelope?.(
        message.envelope.slice().buffer,
        { allowReplayDuplicate: false },
      );
      return;
    }
    const cursorStore = this.deliveryCursorStore;
    if (cursorStore === undefined) {
      throw new Error('Durable relay delivery cursor is unavailable');
    }
    if (message.kind === 'delivery') {
      await this.onEnvelope?.(
        message.envelope.slice().buffer,
        { allowReplayDuplicate: true },
      );
      await cursorStore.commitDelivery(
        credential.workspaceId,
        credential.deviceId,
        message.deliveryId,
      );
      if (generation !== this.generation || this.socket !== socket || !this.isAuthenticated()) {
        return;
      }
      socket.send(encodeRelayAcknowledgement(message.deliveryId));
      return;
    }
    if (message.kind === 'caught-up') {
      const state = await cursorStore.load(credential.workspaceId, credential.deviceId);
      if (state.snapshotRequiredHighWater !== undefined ||
          state.committedDeliveryId !== message.highWater) {
        throw new Error('Relay caught-up marker does not match the committed cursor');
      }
      return;
    }
    await cursorStore.requireSnapshot(
      credential.workspaceId,
      credential.deviceId,
      message.highWater,
    );
    this.onHistoryGap(message.highWater);
  }

  private async loadCurrentCandidate(): Promise<TransportCredentialCandidate | undefined> {
    const credential = await this.credentialStore.load();
    return credential === undefined ? undefined : { credential, source: 'current' };
  }

  private async completeAuthentication(
    generation: number,
    socket: WebSocket,
    credentialSource: 'current' | 'pending',
    credential: StoredTransportCredential,
  ): Promise<void> {
    try {
      if (credentialSource === 'pending') {
        if (this.credentialStore.promotePending === undefined) {
          throw new Error('Pending credential promotion is unavailable');
        }
        const promoted = await this.credentialStore.promotePending();
        promoted.authToken.fill(0);
      }
    } catch {
      if (generation === this.generation) {
        this.cancelReconnect();
        ++this.generation;
        this.authenticatedGeneration = undefined;
        this.sno1Generation = undefined;
        if (this.socket === socket) this.socket = undefined;
        socket.close(FAIL_CLOSED_WEBSOCKET_CODE, 'pending credential promotion failed');
        await this.writeState('offline');
      }
      return;
    }
    if (generation !== this.generation || this.socket !== socket) return;
    this.preferCurrentFallback = false;
    this.reconnectAttempt = 0;
    try {
      if (this.deliveryCursorStore !== undefined) {
        const cursor = await this.deliveryCursorStore.load(
          credential.workspaceId,
          credential.deviceId,
        );
        socket.send(encodeRelayResume(cursor.committedDeliveryId));
      }
    } catch {
      if (generation === this.generation) {
        this.cancelReconnect();
        ++this.generation;
        this.authenticatedGeneration = undefined;
        this.sno1Generation = undefined;
        if (this.socket === socket) this.socket = undefined;
        socket.close(FAIL_CLOSED_WEBSOCKET_CODE, 'relay delivery cursor initialization failed');
        await this.writeState('offline');
      }
      return;
    }
    if (generation !== this.generation || this.socket !== socket) return;
    this.authenticatedGeneration = generation;
    await this.writeState('online');
    this.onAuthenticated();
  }

  private isAuthenticated(): boolean {
    return this.socket !== undefined && this.authenticatedGeneration === this.generation &&
      this.socket.readyState === 1;
  }

  private async requireBoundIdentity(credential: StoredTransportCredential): Promise<void> {
    const identity = await this.identityStore.loadExisting();
    if (identity === undefined) {
      throw new Error('Transport credential exists without its bound E2EE identity');
    }
    const publicKey = await serializeIdentityPublicKey(identity);
    const keyId = await deriveIdentityKeyId(publicKey);
    if (!bytesEqual(keyId, credential.identityKeyId)) {
      throw new Error('Transport credential E2EE identity binding does not match');
    }
  }

  private handleSocketTermination(
    generation: number,
    socket: WebSocket,
    credentialSource: 'current' | 'pending',
  ): void {
    if (generation !== this.generation || this.terminalGeneration === generation) return;
    this.terminalGeneration = generation;
    if (this.sno1Generation !== generation) {
      this.preferCurrentFallback = credentialSource === 'pending';
    }
    this.authenticatedGeneration = undefined;
    this.sno1Generation = undefined;
    if (this.socket === socket) this.socket = undefined;
    void this.writeState('offline');
    this.scheduleReconnect(generation);
  }

  private scheduleReconnect(generation: number): void {
    if (generation !== this.generation || this.reconnectTimer !== undefined) return;
    const exponent = Math.pow(this.reconnectPolicy.multiplier, this.reconnectAttempt);
    const baseDelay = Math.min(
      this.reconnectPolicy.maximumDelayMs,
      this.reconnectPolicy.initialDelayMs * exponent,
    );
    this.reconnectAttempt += 1;
    const jitter = baseDelay * this.reconnectPolicy.jitterRatio *
      ((this.reconnectPolicy.random() * 2) - 1);
    const delay = Math.max(0, Math.min(this.reconnectPolicy.maximumDelayMs, baseDelay + jitter));
    this.reconnectTimer = this.reconnectPolicy.setTimer(() => {
      this.reconnectTimer = undefined;
      if (generation !== this.generation) return;
      void this.startConnection().catch(() => undefined);
    }, delay);
  }

  private cancelReconnect(): void {
    if (this.reconnectTimer === undefined) return;
    this.reconnectPolicy.clearTimer(this.reconnectTimer);
    this.reconnectTimer = undefined;
  }
}

function validateReconnectPolicy(policy: ReconnectPolicy): ReconnectPolicy {
  if (!Number.isFinite(policy.initialDelayMs) || policy.initialDelayMs <= 0 ||
      !Number.isFinite(policy.maximumDelayMs) || policy.maximumDelayMs < policy.initialDelayMs ||
      !Number.isFinite(policy.multiplier) || policy.multiplier < 1 ||
      !Number.isFinite(policy.jitterRatio) || policy.jitterRatio < 0 || policy.jitterRatio > 1) {
    throw new Error('Invalid transport reconnect policy');
  }
  return policy;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

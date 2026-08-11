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
import type { StoredTransportCredential } from './indexeddb-transport-credential-store';

interface CredentialStore {
  load(): Promise<StoredTransportCredential | undefined>;
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

export interface TransportReconnectOptions {
  initialDelayMs?: number;
  maximumDelayMs?: number;
  multiplier?: number;
  jitterRatio?: number;
  random?: () => number;
  setTimer?: (callback: () => void, delayMs: number) => TimerHandle;
  clearTimer?: (handle: TimerHandle) => void;
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
  private readonly reconnectPolicy: ReconnectPolicy;

  constructor(
    private readonly credentialStore: CredentialStore,
    private readonly identityStore: IdentityStore,
    private readonly writeState: StateWriter,
    private readonly onEnvelope: ((frame: ArrayBuffer) => Promise<void>) | undefined,
    private readonly openSocket: SocketOpener = openAuthenticatedWebSocket,
    reconnectOptions: TransportReconnectOptions = {},
  ) {
    this.reconnectPolicy = validateReconnectPolicy({
      ...DEFAULT_RECONNECT_POLICY,
      ...reconnectOptions,
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
    if (this.socket !== undefined) return;
    await this.startConnection();
  }

  async disconnect(): Promise<void> {
    this.cancelReconnect();
    this.reconnectAttempt = 0;
    ++this.generation;
    this.terminalGeneration = undefined;
    this.socket?.close(1000, 'local disconnect');
    this.socket = undefined;
    await this.writeState('offline');
  }

  private async startConnection(): Promise<void> {
    const generation = ++this.generation;
    this.terminalGeneration = undefined;
    this.socket?.close(1000, 'replaced by new connection');
    this.socket = undefined;

    const credential = await this.credentialStore.load();
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
          this.reconnectAttempt = 0;
          void this.writeState('online');
        } else if (event === 'socket-error' || event === 'socket-closed') {
          this.handleSocketTermination(generation, socket);
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
        socket.close(1008, 'relay messages must be binary');
        return;
      }
      if (this.onEnvelope === undefined) {
        acceptingFrames = false;
        socket.close(1008, 'encrypted envelope handler unavailable');
        return;
      }
      const frame = event.data.slice(0);
      inboundQueue = inboundQueue.then(async () => {
        if (generation !== this.generation || !acceptingFrames) return;
        await this.onEnvelope?.(frame);
      }).catch(() => {
        if (generation !== this.generation) return;
        acceptingFrames = false;
        socket.close(1008, 'encrypted envelope rejected');
      });
    });
    this.socket = socket;
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

  private handleSocketTermination(generation: number, socket: WebSocket): void {
    if (generation !== this.generation || this.terminalGeneration === generation) return;
    this.terminalGeneration = generation;
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

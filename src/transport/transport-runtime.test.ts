import { describe, expect, it } from 'vitest';
import {
  deriveIdentityKeyId,
  generateNonExtractableIdentity,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from '../crypto/auth-hpke';
import type { ConnectionState } from '../shared/status';
import type { TransportDiagnosticEvent } from './authenticated-websocket';
import type { StoredTransportCredential } from './indexeddb-transport-credential-store';
import { TransportRuntime } from './transport-runtime';

class FakeSocket extends EventTarget {
  closed = false;
  readyState = 1;
  sent: Uint8Array[] = [];
  closeCode?: number;
  closeReason?: string;
  send(data: Uint8Array): void {
    this.sent.push(data.slice());
  }
  close(code?: number, reason?: string): void {
    this.closed = true;
    this.closeCode = code;
    this.closeReason = reason;
  }
}

describe('TransportRuntime', () => {
  it('reports online only after SNO1 authentication confirmation', async () => {
    const identity = await generateNonExtractableIdentity();
    const credential = await credentialFor(identity);
    const states: ConnectionState[] = [];
    const socket = new FakeSocket();
    let observer: ((event: TransportDiagnosticEvent) => void) | undefined;
    let loadedCredential: StoredTransportCredential | undefined;
    const runtime = new TransportRuntime(
      { load: async () => copyCredential(credential) },
      { loadExisting: async () => identity },
      async (state) => { states.push(state); },
      undefined,
      (loaded, observe) => {
        expect(loaded.authToken.some((byte) => byte !== 0)).toBe(true);
        loadedCredential = loaded;
        observer = observe;
        return socket as unknown as WebSocket;
      },
    );

    await runtime.connect();
    expect(states).toEqual(['connecting']);
    expect(loadedCredential?.authToken.every((byte) => byte === 0)).toBe(true);
    observer?.('auth-frame-sent');
    expect(states).toEqual(['connecting']);
    expect(runtime.sendEnvelope(new Uint8Array([1]))).toBe(false);
    observer?.('authenticated');
    await Promise.resolve();
    expect(states).toEqual(['connecting', 'online']);
    const frame = new Uint8Array([1, 2, 3]);
    expect(runtime.sendEnvelope(frame)).toBe(true);
    frame.fill(0);
    expect(socket.sent).toEqual([new Uint8Array([1, 2, 3])]);
    await runtime.failClosed();
    expect(runtime.sendEnvelope(new Uint8Array([4]))).toBe(false);
    expect(socket.closeCode).toBe(1008);
    expect(states.at(-1)).toBe('offline');
  });

  it('waits for SNO1 when an explicit resend wakes a suspended Worker', async () => {
    const identity = await generateNonExtractableIdentity();
    const credential = await credentialFor(identity);
    const socket = new FakeSocket();
    let observer: ((event: TransportDiagnosticEvent) => void) | undefined;
    const runtime = new TransportRuntime(
      { load: async () => copyCredential(credential) },
      { loadExisting: async () => identity },
      async () => undefined,
      undefined,
      (_loaded, observe) => {
        observer = observe;
        return socket as unknown as WebSocket;
      },
    );

    const authenticated = runtime.ensureAuthenticated(1_000);
    await waitFor(() => observer !== undefined);
    expect(runtime.sendEnvelope(new Uint8Array([1]))).toBe(false);
    observer?.('authenticated');
    await expect(authenticated).resolves.toBe(true);
    expect(runtime.sendEnvelope(new Uint8Array([2]))).toBe(true);
  });

  it('fails closed without creating a replacement for a missing identity', async () => {
    const credential: StoredTransportCredential = {
      serverOrigin: 'https://notify.example',
      workspaceId: new Uint8Array(16).fill(1),
      deviceId: new Uint8Array(16).fill(2),
      authToken: new Uint8Array(32).fill(3),
      identityKeyId: new Uint8Array(32).fill(4),
    };
    const states: ConnectionState[] = [];
    let opened = false;
    const runtime = new TransportRuntime(
      { load: async () => copyCredential(credential) },
      { loadExisting: async () => undefined },
      async (state) => { states.push(state); },
      undefined,
      () => {
        opened = true;
        return new FakeSocket() as unknown as WebSocket;
      },
    );

    await expect(runtime.connect()).rejects.toThrow('without its bound E2EE identity');
    expect(opened).toBe(false);
    expect(states).toEqual(['offline']);
  });

  it('reconnects once for duplicate terminal events and resets backoff after authentication', async () => {
    const identity = await generateNonExtractableIdentity();
    const credential = await credentialFor(identity);
    const states: ConnectionState[] = [];
    const sockets: FakeSocket[] = [];
    const observers: Array<(event: TransportDiagnosticEvent) => void> = [];
    const scheduler = new FakeScheduler();
    const runtime = new TransportRuntime(
      { load: async () => copyCredential(credential) },
      { loadExisting: async () => identity },
      async (state) => { states.push(state); },
      undefined,
      (_loaded, observe) => {
        const socket = new FakeSocket();
        sockets.push(socket);
        observers.push(observe);
        return socket as unknown as WebSocket;
      },
      scheduler.options(),
    );

    await runtime.connect();
    observers[0]?.('socket-error');
    observers[0]?.('socket-closed');
    await flushPromises();
    expect(states).toEqual(['connecting', 'offline']);
    expect(scheduler.activeDelays()).toEqual([1_000]);

    scheduler.runNext();
    await waitFor(() => sockets.length === 2);
    expect(states).toEqual(['connecting', 'offline', 'connecting']);
    observers[1]?.('authenticated');
    await flushPromises();
    observers[1]?.('socket-closed');
    await flushPromises();
    expect(states.at(-2)).toBe('online');
    expect(states.at(-1)).toBe('offline');
    expect(scheduler.activeDelays()).toEqual([1_000]);
  });

  it('accepts a durable scheduler wake and ignores its stale in-memory callback', async () => {
    const identity = await generateNonExtractableIdentity();
    const credential = await credentialFor(identity);
    const scheduler = new FakeScheduler();
    const observers: Array<(event: TransportDiagnosticEvent) => void> = [];
    let sockets = 0;
    const runtime = new TransportRuntime(
      { load: async () => copyCredential(credential) },
      { loadExisting: async () => identity },
      async () => undefined,
      undefined,
      (_loaded, observe) => {
        sockets += 1;
        observers.push(observe);
        return new FakeSocket() as unknown as WebSocket;
      },
      scheduler.options(),
    );

    await runtime.connect();
    observers[0]?.('socket-closed');
    await flushPromises();
    expect(scheduler.activeDelays()).toEqual([1_000]);

    await runtime.retryScheduledConnection();
    expect(sockets).toBe(2);
    scheduler.runNext();
    await flushPromises();
    expect(sockets).toBe(2);
  });

  it('replaces a pre-authentication socket when a durable watchdog alarm wakes', async () => {
    const identity = await generateNonExtractableIdentity();
    const credential = await credentialFor(identity);
    const sockets: FakeSocket[] = [];
    const runtime = new TransportRuntime(
      { load: async () => copyCredential(credential) },
      { loadExisting: async () => identity },
      async () => undefined,
      undefined,
      () => {
        const socket = new FakeSocket();
        sockets.push(socket);
        return socket as unknown as WebSocket;
      },
    );

    await runtime.connect();
    expect(runtime.hasAuthenticatedConnection()).toBe(false);
    await runtime.retryScheduledConnection();
    expect(sockets).toHaveLength(2);
    expect(sockets[0]?.closed).toBe(true);
  });

  it('bounds exponential retries and cancels them on explicit disconnect', async () => {
    const identity = await generateNonExtractableIdentity();
    const credential = await credentialFor(identity);
    const scheduler = new FakeScheduler();
    let attempts = 0;
    const runtime = new TransportRuntime(
      { load: async () => copyCredential(credential) },
      { loadExisting: async () => identity },
      async () => undefined,
      undefined,
      () => {
        attempts += 1;
        throw new Error('synthetic network failure');
      },
      scheduler.options({ maximumDelayMs: 2_500 }),
    );

    await expect(runtime.connect()).rejects.toThrow('synthetic network failure');
    expect(attempts).toBe(1);
    expect(scheduler.activeDelays()).toEqual([1_000]);

    scheduler.runNext();
    await waitFor(() => attempts === 2);
    expect(scheduler.activeDelays()).toEqual([2_000]);
    scheduler.runNext();
    await waitFor(() => attempts === 3);
    expect(scheduler.activeDelays()).toEqual([2_500]);

    await runtime.disconnect();
    expect(scheduler.activeDelays()).toEqual([]);
    scheduler.runAll();
    await flushPromises();
    expect(attempts).toBe(3);
  });

  it('does not retry a persistent identity security failure', async () => {
    const credential: StoredTransportCredential = {
      serverOrigin: 'https://notify.example',
      workspaceId: new Uint8Array(16).fill(1),
      deviceId: new Uint8Array(16).fill(2),
      authToken: new Uint8Array(32).fill(3),
      identityKeyId: new Uint8Array(32).fill(4),
    };
    const scheduler = new FakeScheduler();
    const runtime = new TransportRuntime(
      { load: async () => copyCredential(credential) },
      { loadExisting: async () => undefined },
      async () => undefined,
      undefined,
      () => { throw new Error('must not open'); },
      scheduler.options(),
    );

    await expect(runtime.connect()).rejects.toThrow('without its bound E2EE identity');
    expect(scheduler.activeDelays()).toEqual([]);
  });

  it('closes fail-closed when the asynchronous envelope dispatcher rejects a frame', async () => {
    const identity = await generateNonExtractableIdentity();
    const credential = await credentialFor(identity);
    const socket = new FakeSocket();
    let rejectFrame: ((error: Error) => void) | undefined;
    const runtime = new TransportRuntime(
      { load: async () => copyCredential(credential) },
      { loadExisting: async () => identity },
      async () => undefined,
      async () => new Promise<void>((_resolve, reject) => { rejectFrame = reject; }),
      () => socket as unknown as WebSocket,
    );

    await runtime.connect();
    socket.dispatchEvent(new MessageEvent('message', { data: new ArrayBuffer(32) }));
    await flushPromises();
    rejectFrame?.(new Error('synthetic rejected envelope'));
    await waitFor(() => socket.closed);
    expect(socket.closeCode).toBe(1008);
    expect(socket.closeReason).toBe('encrypted envelope rejected');
  });

  it('reports not configured without opening a socket', async () => {
    const states: ConnectionState[] = [];
    const runtime = new TransportRuntime(
      { load: async () => undefined },
      { loadExisting: async () => undefined },
      async (state) => { states.push(state); },
      undefined,
      () => { throw new Error('must not open'); },
    );
    await runtime.connect();
    expect(states).toEqual(['not-configured']);
  });
});

async function credentialFor(identity: HpkeIdentity): Promise<StoredTransportCredential> {
  const publicKey = await serializeIdentityPublicKey(identity);
  return {
    serverOrigin: 'https://notify.example',
    workspaceId: new Uint8Array(16).fill(1),
    deviceId: new Uint8Array(16).fill(2),
    authToken: new Uint8Array(32).fill(3),
    identityKeyId: await deriveIdentityKeyId(publicKey),
  };
}

class FakeScheduler {
  private tasks: Array<{ callback: () => void; delay: number; cancelled: boolean }> = [];

  options(overrides: { maximumDelayMs?: number } = {}) {
    return {
      initialDelayMs: 1_000,
      maximumDelayMs: overrides.maximumDelayMs ?? 60_000,
      multiplier: 2,
      jitterRatio: 0,
      random: () => 0.5,
      setTimer: (callback: () => void, delay: number) => {
        this.tasks.push({ callback, delay, cancelled: false });
        return (this.tasks.length - 1) as unknown as ReturnType<typeof setTimeout>;
      },
      clearTimer: (handle: ReturnType<typeof setTimeout>) => {
        const task = this.tasks[handle as unknown as number];
        if (task !== undefined) task.cancelled = true;
      },
    };
  }

  activeDelays(): number[] {
    return this.tasks.filter((task) => !task.cancelled).map((task) => task.delay);
  }

  runNext(): void {
    const task = this.tasks.find((candidate) => !candidate.cancelled);
    if (task === undefined) throw new Error('No active scheduled task');
    task.cancelled = true;
    task.callback();
  }

  runAll(): void {
    for (const task of this.tasks) {
      if (!task.cancelled) {
        task.cancelled = true;
        task.callback();
      }
    }
  }
}

async function flushPromises(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error('Condition was not reached');
}

function copyCredential(value: StoredTransportCredential): StoredTransportCredential {
  return {
    serverOrigin: value.serverOrigin,
    workspaceId: value.workspaceId.slice(),
    deviceId: value.deviceId.slice(),
    authToken: value.authToken.slice(),
    identityKeyId: value.identityKeyId.slice(),
  };
}

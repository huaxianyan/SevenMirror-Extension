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
  close(): void { this.closed = true; }
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
    observer?.('authenticated');
    await Promise.resolve();
    expect(states).toEqual(['connecting', 'online']);
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

function copyCredential(value: StoredTransportCredential): StoredTransportCredential {
  return {
    serverOrigin: value.serverOrigin,
    workspaceId: value.workspaceId.slice(),
    deviceId: value.deviceId.slice(),
    authToken: value.authToken.slice(),
    identityKeyId: value.identityKeyId.slice(),
  };
}

import { describe, expect, it, vi } from 'vitest';
import type { StoredTransportCredential } from './indexeddb-transport-credential-store';
import { openAuthenticatedWebSocket } from './authenticated-websocket';
import { encodeTransportAuthenticationSuccessV1 } from './device-auth-frame';

class FakeSocket extends EventTarget {
  binaryType: BinaryType = 'blob';
  url = 'wss://notify.example/v1/relay';
  readonly sent: Uint8Array[] = [];
  closed = false;
  close(): void { this.closed = true; }
  send(data: ArrayBufferView): void {
    this.sent.push(new Uint8Array(data.buffer, data.byteOffset, data.byteLength).slice());
  }
}

const credential: StoredTransportCredential = {
  serverOrigin: 'https://notify.example',
  workspaceId: new Uint8Array(16).fill(1),
  deviceId: new Uint8Array(16).fill(2),
  authToken: new Uint8Array(32).fill(3),
  identityKeyId: new Uint8Array(32).fill(4),
};

describe('authenticated WebSocket', () => {
  it('sends SNA1 first and emits only content-free diagnostic events', () => {
    const fake = new FakeSocket();
    const events: string[] = [];
    let requestedUrl = '';
    const socket = openAuthenticatedWebSocket(
      credential,
      (event) => events.push(event),
      (url) => {
        requestedUrl = url;
        return fake as unknown as WebSocket;
      },
    );
    fake.dispatchEvent(new Event('open'));

    expect(socket).toBe(fake);
    expect(requestedUrl).toBe('wss://notify.example/v1/relay');
    expect(fake.sent).toHaveLength(1);
    expect(new TextDecoder().decode(fake.sent[0]?.slice(0, 4))).toBe('SNA1');
    expect(fake.sent[0]?.slice(36)).toEqual(credential.authToken);
    expect(events).toEqual(['socket-open', 'auth-frame-sent']);

    let acknowledgementReachedApplication = false;
    fake.addEventListener('message', () => { acknowledgementReachedApplication = true; });
    fake.dispatchEvent(new MessageEvent('message', {
      data: encodeTransportAuthenticationSuccessV1().buffer,
    }));
    expect(events).toEqual(['socket-open', 'auth-frame-sent', 'authenticated']);
    expect(acknowledgementReachedApplication).toBe(false);
    fake.dispatchEvent(new Event('close'));
  });

  it('keeps the Worker active with SNH1 and consumes exact SNH2 responses', () => {
    vi.useFakeTimers();
    try {
      const fake = new FakeSocket();
      const events: string[] = [];
      openAuthenticatedWebSocket(
        credential,
        (event) => events.push(event),
        () => fake as unknown as WebSocket,
      );
      fake.dispatchEvent(new Event('open'));
      fake.dispatchEvent(new MessageEvent('message', {
        data: encodeTransportAuthenticationSuccessV1().buffer,
      }));

      let heartbeatReachedApplication = false;
      fake.addEventListener('message', () => { heartbeatReachedApplication = true; });
      vi.advanceTimersByTime(20_000);
      expect(new TextDecoder().decode(fake.sent[1])).toBe('SNH1');
      fake.dispatchEvent(new MessageEvent('message', {
        data: Uint8Array.of(0x53, 0x4e, 0x48, 0x32).buffer,
      }));
      expect(heartbeatReachedApplication).toBe(false);

      vi.advanceTimersByTime(20_000);
      expect(new TextDecoder().decode(fake.sent[2])).toBe('SNH1');
      vi.advanceTimersByTime(10_000);
      expect(fake.closed).toBe(true);
      expect(events.at(-1)).toBe('socket-error');
      fake.dispatchEvent(new Event('close'));
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects a malformed authentication acknowledgement', () => {
    const fake = new FakeSocket();
    const events: string[] = [];
    openAuthenticatedWebSocket(
      credential,
      (event) => events.push(event),
      () => fake as unknown as WebSocket,
    );
    fake.dispatchEvent(new Event('open'));
    fake.dispatchEvent(new MessageEvent('message', { data: Uint8Array.of(1, 2, 3, 4).buffer }));

    expect(fake.closed).toBe(true);
    expect(events).toEqual(['socket-open', 'auth-frame-sent', 'socket-error']);
  });

  it('closes when SNO1 is not received within five seconds', () => {
    vi.useFakeTimers();
    try {
      const fake = new FakeSocket();
      const events: string[] = [];
      openAuthenticatedWebSocket(
        credential,
        (event) => events.push(event),
        () => fake as unknown as WebSocket,
      );
      fake.dispatchEvent(new Event('open'));
      vi.advanceTimersByTime(5_000);
      expect(fake.closed).toBe(true);
      expect(events).toEqual(['socket-open', 'auth-frame-sent', 'socket-error']);
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not disclose the credential after an endpoint change', () => {
    const fake = new FakeSocket();
    fake.url = 'wss://attacker.example/v1/relay';
    const events: string[] = [];
    openAuthenticatedWebSocket(
      credential,
      (event) => events.push(event),
      () => fake as unknown as WebSocket,
    );
    fake.dispatchEvent(new Event('open'));
    expect(fake.sent).toHaveLength(0);
    expect(fake.closed).toBe(true);
    expect(events).toEqual(['socket-open', 'socket-error']);
  });
});

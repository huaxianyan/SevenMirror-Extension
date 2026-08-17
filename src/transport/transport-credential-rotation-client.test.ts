import 'fake-indexeddb/auto';
import { describe, expect, it, vi } from 'vitest';
import {
  IndexedDbTransportCredentialStore,
  type StoredTransportCredential,
} from './indexeddb-transport-credential-store';
import { rotateChromeTransportCredential } from './transport-credential-rotation-client';

const endpoint = 'https://notify.example/v1/devices/rotate';
const rotationCode = 'A'.repeat(32);

function credential(): StoredTransportCredential {
  return {
    serverOrigin: 'https://notify.example',
    workspaceId: new Uint8Array(16).fill(1),
    deviceId: new Uint8Array(16).fill(2),
    authToken: new Uint8Array(32).fill(3),
    identityKeyId: new Uint8Array(32).fill(4),
  };
}

function uniqueStore(): IndexedDbTransportCredentialStore {
  return new IndexedDbTransportCredentialStore(
    `rotation-${Date.now()}-${Math.random().toString(16).slice(2)}`,
  );
}

function response(body = '{"status":"rotated"}', url = endpoint): Response {
  const value = new Response(body, {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
  Object.defineProperty(value, 'url', { value: url });
  return value;
}

describe('rotateChromeTransportCredential', () => {
  it('durably marks one pending credential attempted before sending and never promotes on HTTP 200', async () => {
    const store = uniqueStore();
    const current = credential();
    await store.saveNew(current);
    let observedBody: Record<string, string> | undefined;
    const fetcher = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toBe(endpoint);
      expect(String(url)).not.toContain(rotationCode);
      expect(init?.redirect).toBe('error');
      expect(init?.credentials).toBe('omit');
      expect((await store.loadRotation())?.phase).toBe('attempted');
      observedBody = JSON.parse(String(init?.body)) as Record<string, string>;
      return response();
    }) as unknown as typeof fetch;

    await expect(rotateChromeTransportCredential(
      rotationCode,
      store,
      fetcher,
      (target) => target.fill(9),
    )).resolves.toEqual({ status: 'awaiting-pending-authentication', phase: 'attempted' });

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(observedBody?.rotation_code).toBe(rotationCode);
    expect(observedBody?.current_auth_token).toBe(toBase64Url(new Uint8Array(32).fill(3)));
    expect(observedBody?.pending_auth_token).toBe(toBase64Url(new Uint8Array(32).fill(9)));
    expect((await store.load())?.authToken).toEqual(current.authToken);
    expect((await store.loadRotation())?.pendingAuthToken).toEqual(new Uint8Array(32).fill(9));
  });

  it('retains and reuses exact pending after an ambiguous response loss', async () => {
    const store = uniqueStore();
    await store.saveNew(credential());
    const bodies: string[] = [];
    const lostResponse = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      bodies.push(String(init?.body));
      throw new TypeError('synthetic connection reset');
    }) as unknown as typeof fetch;
    await expect(rotateChromeTransportCredential(
      rotationCode, store, lostResponse, (target) => target.fill(7),
    )).rejects.toThrow('synthetic connection reset');
    expect((await store.loadRotation())?.phase).toBe('attempted');

    let randomCalled = false;
    const retry = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      bodies.push(String(init?.body));
      return response();
    }) as unknown as typeof fetch;
    await rotateChromeTransportCredential(rotationCode, store, retry, (target) => {
      randomCalled = true;
      return target.fill(8);
    });
    expect(randomCalled).toBe(false);
    expect(bodies[1]).toBe(bodies[0]);
  });

  it('fails closed on endpoint changes and malformed success', async () => {
    const missingContentType = new Response('{"status":"rotated"}', { status: 200 });
    Object.defineProperty(missingContentType, 'url', { value: endpoint });
    const cases: Array<[string, Response, string]> = [
      ['endpoint', response(undefined, 'https://other.example/v1/devices/rotate'), 'endpoint changed'],
      ['content type', missingContentType, 'content type'],
      ['fields', response('{"status":"rotated","extra":true}'), 'unexpected fields'],
    ];
    for (const [name, result, message] of cases) {
      const store = uniqueStore();
      await store.saveNew(credential());
      const fetcher = vi.fn(async () => result) as unknown as typeof fetch;
      await expect(rotateChromeTransportCredential(
        rotationCode, store, fetcher, (target) => target.fill(6),
      ), name).rejects.toThrow(message);
      expect((await store.loadRotation())?.phase).toBe('attempted');
      expect((await store.load())?.authToken).toEqual(new Uint8Array(32).fill(3));
    }
  });

  it('rejects malformed code before creating pending state', async () => {
    const store = uniqueStore();
    await store.saveNew(credential());
    await expect(rotateChromeTransportCredential('not a code', store)).rejects.toThrow('192-bit');
    expect(await store.loadRotation()).toBeUndefined();
  });
});

function toBase64Url(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

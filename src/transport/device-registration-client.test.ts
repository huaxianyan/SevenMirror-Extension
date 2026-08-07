import 'fake-indexeddb/auto';
import { describe, expect, it, vi } from 'vitest';
import { registerChromeDevice } from './device-registration-client';
import { IndexedDbTransportCredentialStore } from './indexeddb-transport-credential-store';

const pairingCode = 'A'.repeat(32);
const workspaceId = new Uint8Array(16).fill(1);
const deviceId = new Uint8Array(16).fill(2);
const authToken = new Uint8Array(32).fill(3);

function uniqueName(): string {
  return `registration-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function uniqueStore(): IndexedDbTransportCredentialStore {
  return new IndexedDbTransportCredentialStore(uniqueName());
}

function request() {
  const publicKey = new Uint8Array(65).fill(7);
  publicKey[0] = 0x04;
  return {
    serverOrigin: 'https://notify.example/',
    pairingCode,
    deviceName: 'Chrome workstation',
    e2eePublicKey: publicKey,
    identityKeyId: new Uint8Array(32).fill(4),
  };
}

describe('Chrome device registration', () => {
  it('uses a strict request and persists the one-time credential before success', async () => {
    const name = uniqueName();
    const store = new IndexedDbTransportCredentialStore(name);
    const fetcher = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(_input).toBe('https://notify.example/v1/devices/register');
      expect(init).toMatchObject({
        method: 'POST', cache: 'no-store', credentials: 'omit', redirect: 'error',
      });
      expect(JSON.parse(String(init?.body))).toMatchObject({
        pairing_code: pairingCode,
        device_type: 'chrome',
        device_name: 'Chrome workstation',
      });
      return jsonResponse({
        workspace_id: base64Url(workspaceId),
        device_id: base64Url(deviceId),
        auth_token: base64Url(authToken),
      });
    });

    const registered = await registerChromeDevice(request(), store, fetcher);
    expect(registered.authToken).toEqual(authToken);
    expect((await new IndexedDbTransportCredentialStore(name).load())?.deviceId).toEqual(deviceId);
    expect(fetcher).toHaveBeenCalledOnce();
    await store.clear();
  });

  it('fails closed without persistence on malformed or oversized responses', async () => {
    const malformedStore = uniqueStore();
    await expect(registerChromeDevice(request(), malformedStore, async () =>
      jsonResponse({ workspace_id: base64Url(workspaceId), unexpected: true }),
    )).rejects.toThrow('unexpected fields');
    expect(await malformedStore.load()).toBeUndefined();
    await malformedStore.clear();

    const oversizedStore = uniqueStore();
    await expect(registerChromeDevice(request(), oversizedStore, async () => new Response(
      'x'.repeat(4097), { status: 201, headers: { 'Content-Type': 'application/json' } },
    ))).rejects.toThrow('exceeds 4096 bytes');
    expect(await oversizedStore.load()).toBeUndefined();
    await oversizedStore.clear();
  });

  it('does not contact the server when a credential already exists', async () => {
    const store = uniqueStore();
    await store.saveNew({
      serverOrigin: 'https://notify.example', workspaceId, deviceId, authToken,
      identityKeyId: new Uint8Array(32).fill(4),
    });
    const fetcher = vi.fn();
    await expect(registerChromeDevice(request(), store, fetcher as typeof fetch))
      .rejects.toThrow('already exists');
    expect(fetcher).not.toHaveBeenCalled();
    await store.clear();
  });
});

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 201,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

function base64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

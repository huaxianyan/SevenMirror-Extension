import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import {
  IndexedDbTransportCredentialStore,
  normalizeServerOrigin,
  type StoredTransportCredential,
} from './indexeddb-transport-credential-store';

function credential(seed = 1): StoredTransportCredential {
  return {
    serverOrigin: 'https://notify.example',
    workspaceId: new Uint8Array(16).fill(seed),
    deviceId: new Uint8Array(16).fill(seed + 1),
    authToken: new Uint8Array(32).fill(seed + 2),
    identityKeyId: new Uint8Array(32).fill(seed + 3),
  };
}

function storeName(): string {
  return `transport-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

describe('IndexedDbTransportCredentialStore', () => {
  it('survives reconstruction and returns defensive byte copies', async () => {
    const name = storeName();
    const store = new IndexedDbTransportCredentialStore(name);
    const expected = credential();
    await store.saveNew(expected);
    expected.authToken.fill(0);

    const restored = await new IndexedDbTransportCredentialStore(name).load();
    expect(restored?.authToken).toEqual(new Uint8Array(32).fill(3));
    restored?.authToken.fill(9);
    expect((await store.load())?.authToken).toEqual(new Uint8Array(32).fill(3));
    await store.clear();
  });

  it('allows the same record idempotently but rejects silent replacement', async () => {
    const store = new IndexedDbTransportCredentialStore(storeName());
    const first = credential();
    await store.saveNew(first);
    await store.saveNew(first);
    await expect(store.saveNew(credential(7))).rejects.toThrow('explicit clear');
    expect(await store.load()).toEqual(first);
    await store.clear();
  });

  it('normalizes secure origins and only permits loopback HTTP', () => {
    expect(normalizeServerOrigin('https://notify.example/')).toBe('https://notify.example');
    expect(normalizeServerOrigin('http://127.0.0.1:8080')).toBe('http://127.0.0.1:8080');
    expect(() => normalizeServerOrigin('http://notify.example')).toThrow('HTTPS');
    expect(() => normalizeServerOrigin('https://notify.example/path')).toThrow('only an origin');
    expect(() => normalizeServerOrigin('https://user:secret@notify.example')).toThrow('only an origin');
  });
});

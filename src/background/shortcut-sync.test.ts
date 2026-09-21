import { describe, expect, it } from 'vitest';
import {
  ShortcutSyncStore,
  WrongShortcutPassphraseError,
  defaultShortcutSyncIterations,
  deriveShortcutSyncKey,
  describeShortcutSyncStatus,
  newShortcutSyncSalt,
  openShortcutPreferences,
  readShortcutSyncKdf,
  sealShortcutPreferences,
  type ShortcutSyncState,
  type ShortcutSyncStorage,
} from './shortcut-sync';
import type { NotificationShortcutPreferences } from './notification-shortcuts';
import { toBase64Url } from '../transport/workspace-preferences-client';

const WORKSPACE = new Uint8Array(16).fill(0x11);
const OTHER_WORKSPACE = new Uint8Array(16).fill(0x22);
/** The cheapest iteration count the module accepts; the default is far too slow for tests. */
const FAST_ITERATIONS = 100_000;

const PREFERENCES: NotificationShortcutPreferences = {
  pinDismiss: true,
  rules: [
    { id: '0'.repeat(32), match: { kind: 'reply' } },
    {
      id: '1'.repeat(32),
      match: { kind: 'title-contains', value: '验证码' },
      sourceApplicationId: 'vip.mystery0.pixel.text',
      sourceApplicationName: 'Pixel Text',
    },
  ],
};

async function stateFor(passphrase: string, iterations = FAST_ITERATIONS): Promise<ShortcutSyncState> {
  const salt = newShortcutSyncSalt();
  return { salt, iterations, key: await deriveShortcutSyncKey(passphrase, salt, iterations), revision: 0 };
}

function fakeStorage(): ShortcutSyncStorage & { data: Record<string, unknown> } {
  const data: Record<string, unknown> = {};
  return {
    data,
    get: async (key) => ({ [key]: data[key] }),
    set: async (items) => { Object.assign(data, items); },
    remove: async (key) => { delete data[key]; },
  };
}

describe('shortcut sync sealing', () => {
  it('opens exactly what it sealed', async () => {
    const state = await stateFor('correct horse battery staple');
    const sealed = await sealShortcutPreferences(state, WORKSPACE, PREFERENCES);
    await expect(openShortcutPreferences(state, WORKSPACE, sealed)).resolves.toEqual(PREFERENCES);
  });

  it('binds the sealed rules to one workspace', async () => {
    const state = await stateFor('correct horse battery staple');
    const sealed = await sealShortcutPreferences(state, WORKSPACE, PREFERENCES);
    await expect(openShortcutPreferences(state, OTHER_WORKSPACE, sealed))
      .rejects.toBeInstanceOf(WrongShortcutPassphraseError);
  });

  it('reports a wrong passphrase instead of returning rules', async () => {
    const publisher = await stateFor('correct horse battery staple');
    const sealed = await sealShortcutPreferences(publisher, WORKSPACE, PREFERENCES);
    const wrongKey = await deriveShortcutSyncKey('not the passphrase', publisher.salt, FAST_ITERATIONS);
    await expect(openShortcutPreferences({ ...publisher, key: wrongKey }, WORKSPACE, sealed))
      .rejects.toBeInstanceOf(WrongShortcutPassphraseError);
  });

  it('reports a reset passphrase whose salt no longer matches', async () => {
    const publisher = await stateFor('correct horse battery staple');
    const sealed = await sealShortcutPreferences(publisher, WORKSPACE, PREFERENCES);
    const other = await stateFor('correct horse battery staple');
    await expect(openShortcutPreferences(other, WORKSPACE, sealed))
      .rejects.toBeInstanceOf(WrongShortcutPassphraseError);
  });

  it('lets a second device derive the same key from the published salt', async () => {
    const publisher = await stateFor('shared passphrase');
    const sealed = await sealShortcutPreferences(publisher, WORKSPACE, PREFERENCES);
    const kdf = readShortcutSyncKdf(sealed);
    expect(kdf.iterations).toBe(FAST_ITERATIONS);
    expect([...kdf.salt]).toEqual([...publisher.salt]);
    const joiner: ShortcutSyncState = {
      salt: kdf.salt,
      iterations: kdf.iterations,
      key: await deriveShortcutSyncKey('shared passphrase', kdf.salt, kdf.iterations),
      revision: 1,
    };
    await expect(openShortcutPreferences(joiner, WORKSPACE, sealed)).resolves.toEqual(PREFERENCES);
  });

  it('rejects an envelope that asks for an unreasonable amount of work', async () => {
    const state = await stateFor('shared passphrase');
    const sealed = await sealShortcutPreferences(state, WORKSPACE, PREFERENCES);
    const altered = JSON.parse(new TextDecoder().decode(sealed)) as { iterations: number };
    altered.iterations = 1_000_000_000;
    const encoded = new TextEncoder().encode(JSON.stringify(altered));
    await expect(openShortcutPreferences(state, WORKSPACE, encoded)).rejects.toThrow(/iteration count/);
  });

  it('keeps the default iteration count inside the accepted range', () => {
    expect(defaultShortcutSyncIterations()).toBeGreaterThanOrEqual(FAST_ITERATIONS);
  });
});

describe('shortcut sync state storage', () => {
  it('round-trips the derived key and forgets it when synchronization is turned off', async () => {
    const storage = fakeStorage();
    const store = new ShortcutSyncStore(storage);
    const state = await stateFor('shared passphrase');
    await store.save({ ...state, revision: 7, lastSyncedAtMs: 1_800_000_000_000 });
    const loaded = await store.load();
    expect(loaded?.revision).toBe(7);
    expect(loaded?.iterations).toBe(FAST_ITERATIONS);
    expect(loaded?.lastSyncedAtMs).toBe(1_800_000_000_000);
    expect([...loaded!.salt]).toEqual([...state.salt]);
    expect([...loaded!.key]).toEqual([...state.key]);
    expect(describeShortcutSyncStatus(loaded)).toEqual({
      enabled: true,
      revision: 7,
      lastSyncedAtMs: 1_800_000_000_000,
    });

    await store.clear();
    await expect(store.load()).resolves.toBeUndefined();
    expect(describeShortcutSyncStatus(undefined)).toEqual({ enabled: false, revision: 0 });
  });

  it('refuses a stored state whose key is not a 256-bit value', async () => {
    const storage = fakeStorage();
    const store = new ShortcutSyncStore(storage);
    await storage.set({
      notificationShortcutSyncV1: {
        v: 1,
        salt: toBase64Url(new Uint8Array(16).fill(1)),
        iterations: FAST_ITERATIONS,
        key: toBase64Url(new Uint8Array(8).fill(2)),
        revision: 1,
      },
    });
    await expect(store.load()).rejects.toThrow(/invalid key/);
  });
});

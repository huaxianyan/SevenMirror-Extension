import { describe, expect, it } from 'vitest';
import {
  ShortcutSyncCoordinator,
  ShortcutSyncNotEnrolledError,
} from './shortcut-sync-coordinator';
import {
  WrongShortcutPassphraseError,
  openShortcutPreferences,
  sealShortcutPreferences,
  type ShortcutSyncState,
  type ShortcutSyncStore,
} from './shortcut-sync';
import type {
  NotificationShortcutPreferences,
  NotificationShortcutPreferencesStore,
} from './notification-shortcuts';
import type { IndexedDbTransportCredentialStore } from '../transport/indexeddb-transport-credential-store';
import {
  WorkspacePreferenceConflictError,
  fromBase64Url,
  toBase64Url,
  writeWorkspacePreference,
} from '../transport/workspace-preferences-client';

const WORKSPACE = new Uint8Array(16).fill(0x11);
const NOW = 1_800_000_000_000;

const CREDENTIAL = {
  serverOrigin: 'https://relay.test',
  workspaceId: WORKSPACE,
  deviceId: new Uint8Array(16).fill(0x22),
  authToken: new Uint8Array(32).fill(0x33),
  identityKeyId: new Uint8Array(32).fill(0x44),
};

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

/** Rules a second browser already had of its own before it joined the shared set. */
const OTHER_PREFERENCES: NotificationShortcutPreferences = { pinDismiss: false, rules: [] };

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Stands in for the deployed server. The empty-key response is copied verbatim
 * from what Go marshals for `preferenceReadResponse{Revision: "0"}`: the struct's
 * other fields stay zero, so `payload` and `updated_at_ms` arrive as empty
 * strings rather than canonical decimals.
 */
function fakeServer(): {
  server: { revision: number; payload?: Uint8Array };
  fetcher: typeof fetch;
} {
  const server: { revision: number; payload?: Uint8Array } = { revision: 0 };
  const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const body = JSON.parse(String(init?.body)) as Record<string, string>;
    if (url.endsWith('/v1/workspace/preferences/read')) {
      if (server.revision === 0) return jsonResponse({ revision: '0', payload: '', updated_at_ms: '' });
      return jsonResponse({
        revision: String(server.revision),
        payload: toBase64Url(server.payload!),
        updated_at_ms: String(NOW),
      });
    }
    if (Number(body.expected_revision) !== server.revision) {
      return new Response('preference revision conflict', { status: 409 });
    }
    server.revision += 1;
    server.payload = fromBase64Url(body.payload);
    return jsonResponse({ revision: String(server.revision) });
  }) as unknown as typeof fetch;
  return { server, fetcher };
}

function fakeCredentialStore(): IndexedDbTransportCredentialStore {
  return { load: async () => CREDENTIAL } as unknown as IndexedDbTransportCredentialStore;
}

function fakeSyncStore(): { store: ShortcutSyncStore; state: () => ShortcutSyncState | undefined } {
  let current: ShortcutSyncState | undefined;
  const store = {
    load: async () => current,
    save: async (state: ShortcutSyncState) => { current = state; },
    clear: async () => { current = undefined; },
  } as unknown as ShortcutSyncStore;
  return { store, state: () => current };
}

function fakePreferencesStore(initial: NotificationShortcutPreferences): {
  store: NotificationShortcutPreferencesStore;
  value: () => NotificationShortcutPreferences;
} {
  let current = initial;
  const store = {
    load: async () => current,
    save: async (value: unknown) => { current = value as NotificationShortcutPreferences; },
  } as unknown as NotificationShortcutPreferencesStore;
  return { store, value: () => current };
}

function coordinatorFor(
  fetcher: typeof fetch,
  sync = fakeSyncStore(),
  preferences = fakePreferencesStore(PREFERENCES),
): {
  coordinator: ShortcutSyncCoordinator;
  sync: ReturnType<typeof fakeSyncStore>;
  preferences: ReturnType<typeof fakePreferencesStore>;
} {
  return {
    coordinator: new ShortcutSyncCoordinator(
      fakeCredentialStore(),
      sync.store,
      preferences.store,
      fetcher,
      () => NOW,
    ),
    sync,
    preferences,
  };
}

describe('shortcut sync coordinator', () => {
  it('publishes the local rules when the workspace holds nothing yet', async () => {
    const { server, fetcher } = fakeServer();
    const { coordinator, sync, preferences } = coordinatorFor(fetcher);

    const result = await coordinator.enable('shared passphrase');

    expect(result).toEqual({ preferences: PREFERENCES, pulled: false });
    expect(server.revision).toBe(1);
    expect(preferences.value()).toEqual(PREFERENCES);
    // The published bytes must open with the state that was persisted locally.
    await expect(openShortcutPreferences(sync.state()!, WORKSPACE, server.payload!))
      .resolves.toEqual(PREFERENCES);
    expect(sync.state()?.revision).toBe(1);
    expect(sync.state()?.lastSyncedAtMs).toBe(NOW);
  });

  it('adopts the published rules on a second browser using the same passphrase', async () => {
    const { server, fetcher } = fakeServer();
    await coordinatorFor(fetcher).coordinator.enable('shared passphrase');

    const second = coordinatorFor(fetcher, fakeSyncStore(), fakePreferencesStore(OTHER_PREFERENCES));
    const result = await second.coordinator.enable('shared passphrase');

    expect(result.pulled).toBe(true);
    expect(second.preferences.value()).toEqual(PREFERENCES);
    expect(second.sync.state()?.revision).toBe(server.revision);
  });

  it('changes nothing when the passphrase cannot open the stored rules', async () => {
    const { fetcher } = fakeServer();
    await coordinatorFor(fetcher).coordinator.enable('shared passphrase');

    const second = coordinatorFor(fetcher, fakeSyncStore(), fakePreferencesStore(OTHER_PREFERENCES));
    await expect(second.coordinator.enable('the wrong passphrase'))
      .rejects.toBeInstanceOf(WrongShortcutPassphraseError);
    expect(second.sync.state()).toBeUndefined();
    expect(second.preferences.value()).toEqual(OTHER_PREFERENCES);
  });

  it('refuses to join without a transport credential', async () => {
    const { fetcher } = fakeServer();
    const credentialStore = {
      load: async () => undefined,
    } as unknown as IndexedDbTransportCredentialStore;
    const coordinator = new ShortcutSyncCoordinator(
      credentialStore,
      fakeSyncStore().store,
      fakePreferencesStore(PREFERENCES).store,
      fetcher,
    );
    await expect(coordinator.enable('shared passphrase'))
      .rejects.toBeInstanceOf(ShortcutSyncNotEnrolledError);
  });

  it('reports a conflict instead of overwriting another browser', async () => {
    const { server, fetcher } = fakeServer();
    const { coordinator } = coordinatorFor(fetcher);
    await coordinator.enable('shared passphrase');

    server.revision += 1;
    await expect(coordinator.push(PREFERENCES)).rejects
      .toBeInstanceOf(WorkspacePreferenceConflictError);
  });

  it('applies a newer revision without uploading during a pull', async () => {
    const { server, fetcher } = fakeServer();
    const first = coordinatorFor(fetcher);
    await first.coordinator.enable('shared passphrase');

    // Another browser publishes different rules from the same shared key.
    const newer = await sealShortcutPreferences(
      first.sync.state()!, WORKSPACE, OTHER_PREFERENCES,
    );
    const revision = await writeWorkspacePreference(
      CREDENTIAL, 'notification-shortcuts', server.revision, newer, fetcher,
    );

    const result = await first.coordinator.pull();

    expect(result.changed).toBe(true);
    expect(first.preferences.value()).toEqual(OTHER_PREFERENCES);
    expect(first.sync.state()?.revision).toBe(revision);
    expect(server.revision).toBe(revision);
  });
});

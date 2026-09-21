import {
  SHORTCUT_PREFERENCE_SERVER_KEY,
  ShortcutSyncStore,
  defaultShortcutSyncIterations,
  deriveShortcutSyncKey,
  describeShortcutSyncStatus,
  newShortcutSyncSalt,
  openShortcutPreferences,
  readShortcutSyncKdf,
  sealShortcutPreferences,
  type ShortcutSyncState,
  type ShortcutSyncStatus,
} from './shortcut-sync';
import type {
  NotificationShortcutPreferences,
  NotificationShortcutPreferencesStore,
} from './notification-shortcuts';
import type {
  IndexedDbTransportCredentialStore,
  StoredTransportCredential,
} from '../transport/indexeddb-transport-credential-store';
import { readWorkspacePreference, writeWorkspacePreference } from '../transport/workspace-preferences-client';

/** Synchronization was never enabled on this device, or it was turned off again. */
export class ShortcutSyncDisabledError extends Error {
  constructor() {
    super('Notification shortcut synchronization is not enabled');
    this.name = 'ShortcutSyncDisabledError';
  }
}

/** This browser has no transport credential, so it cannot reach workspace preferences. */
export class ShortcutSyncNotEnrolledError extends Error {
  constructor() {
    super('This browser has not joined the workspace yet');
    this.name = 'ShortcutSyncNotEnrolledError';
  }
}

/**
 * Keeps the local shortcut rules and the workspace-scoped sealed copy in step.
 *
 * The local `chrome.storage.local` record stays the value the notification path
 * reads, so synchronization never sits between an arriving notification and the
 * rules it needs. The server holds the cross-device copy and its revision; a pull
 * applies it locally and a push publishes the local rules.
 */
export class ShortcutSyncCoordinator {
  constructor(
    private readonly credentialStore: IndexedDbTransportCredentialStore,
    private readonly syncStore: ShortcutSyncStore,
    private readonly preferencesStore: NotificationShortcutPreferencesStore,
    private readonly fetcher: typeof fetch = fetch,
    private readonly now: () => number = Date.now,
  ) {}

  async status(): Promise<ShortcutSyncStatus> {
    return describeShortcutSyncStatus(await this.syncStore.load());
  }

  /**
   * Enables synchronization. When the workspace already holds sealed rules they
   * win and are applied locally; otherwise this device seals its current rules
   * and publishes them under the passphrase it just derived.
   */
  async enable(passphrase: string): Promise<{ preferences: NotificationShortcutPreferences; pulled: boolean }> {
    const credential = await this.requireCredential();
    const remote = await readWorkspacePreference(credential, SHORTCUT_PREFERENCE_SERVER_KEY, this.fetcher);
    if (remote.revision === 0 || remote.payload === undefined) {
      const local = await this.preferencesStore.load();
      const salt = newShortcutSyncSalt();
      const iterations = defaultShortcutSyncIterations();
      const key = await deriveShortcutSyncKey(passphrase, salt, iterations);
      const state: ShortcutSyncState = { salt, iterations, key, revision: 0 };
      const payload = await sealShortcutPreferences(state, credential.workspaceId, local);
      state.revision = await writeWorkspacePreference(
        credential, SHORTCUT_PREFERENCE_SERVER_KEY, 0, payload, this.fetcher);
      state.lastSyncedAtMs = this.now();
      await this.syncStore.save(state);
      return { preferences: local, pulled: false };
    }
    // Adopt the salt the publishing device chose, then verify the passphrase by
    // opening the value. A failure here must leave nothing persisted.
    const kdf = readShortcutSyncKdf(remote.payload);
    const key = await deriveShortcutSyncKey(passphrase, kdf.salt, kdf.iterations);
    const state: ShortcutSyncState = {
      salt: kdf.salt,
      iterations: kdf.iterations,
      key,
      revision: remote.revision,
    };
    const preferences = await openShortcutPreferences(state, credential.workspaceId, remote.payload);
    state.lastSyncedAtMs = this.now();
    await this.preferencesStore.save(preferences);
    await this.syncStore.save(state);
    return { preferences, pulled: true };
  }

  /** Turns synchronization off. The local rules and the server copy both remain. */
  async disable(): Promise<void> {
    await this.syncStore.clear();
  }

  /** Applies a newer server revision locally. A local revision is never uploaded here. */
  async pull(): Promise<{ changed: boolean; preferences?: NotificationShortcutPreferences }> {
    const state = await this.requireState();
    const credential = await this.requireCredential();
    const remote = await readWorkspacePreference(credential, SHORTCUT_PREFERENCE_SERVER_KEY, this.fetcher);
    // A server revision at or below the local one carries nothing newer. That also
    // covers a server whose value was cleared behind this device's back.
    if (remote.revision <= state.revision || remote.payload === undefined) {
      state.lastSyncedAtMs = this.now();
      await this.syncStore.save(state);
      return { changed: false };
    }
    const preferences = await openShortcutPreferences(state, credential.workspaceId, remote.payload);
    await this.preferencesStore.save(preferences);
    state.revision = remote.revision;
    state.lastSyncedAtMs = this.now();
    await this.syncStore.save(state);
    return { changed: true, preferences };
  }

  /** Publishes the current rules. A revision conflict is reported, never overwritten. */
  async push(preferences: NotificationShortcutPreferences): Promise<number> {
    const state = await this.requireState();
    const credential = await this.requireCredential();
    const payload = await sealShortcutPreferences(state, credential.workspaceId, preferences);
    const revision = await writeWorkspacePreference(
      credential, SHORTCUT_PREFERENCE_SERVER_KEY, state.revision, payload, this.fetcher);
    state.revision = revision;
    state.lastSyncedAtMs = this.now();
    await this.syncStore.save(state);
    return revision;
  }

  private async requireState(): Promise<ShortcutSyncState> {
    const state = await this.syncStore.load();
    if (state === undefined) throw new ShortcutSyncDisabledError();
    return state;
  }

  private async requireCredential(): Promise<StoredTransportCredential> {
    const credential = await this.credentialStore.load();
    if (credential === undefined) throw new ShortcutSyncNotEnrolledError();
    return credential;
  }
}

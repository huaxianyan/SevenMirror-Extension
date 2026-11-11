import 'fake-indexeddb/auto';
import { sha256 } from '@noble/hashes/sha256';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createNotificationRemovedPayload,
  createNotificationSnapshotManifestPayload,
  createNotificationUpsertPayload,
  encodeEncryptedPayloadV1,
} from '../protocol/encrypted-payload';
import type { NotificationUpsert } from '../protocol/generated/notification/v1/payload_pb';
import { NotificationMediaMimeType } from '../protocol/generated/notification/v1/payload_pb';
import { IndexedDbNotificationStateStore } from './indexeddb-notification-state-store';

const databaseNames = new Set<string>();

afterEach(async () => {
  await Promise.all([...databaseNames].map((name) => new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  })));
  databaseNames.clear();
});

describe('Popup notification presentation state', () => {
  it('counts a visible revision as new until that exact Popup item is viewed', async () => {
    const databaseName = `popup-notifications-${Date.now()}-${Math.random()}`;
    databaseNames.add(databaseName);
    let now = 1_000;
    const store = new IndexedDbNotificationStateStore(databaseName, () => now);
    const sourceDeviceId = new Uint8Array(16).fill(1);

    const revisionOne = upsert(1n, 'First body');
    await store.reconcileUpsert(sourceDeviceId, revisionOne.value, revisionOne.canonical);
    const first = await store.listVisibleForPresentation();
    expect(first).toHaveLength(1);
    expect(first[0]).toMatchObject({ isNew: true, updatedAtUnixMs: 1_000 });
    expect(await store.unseenCount()).toBe(1);

    await store.markViewed([{
      tuple: first[0].state.tuple,
      revision: first[0].state.revision,
    }]);
    expect((await store.listVisibleForPresentation())[0].isNew).toBe(false);
    expect(await store.unseenCount()).toBe(0);

    await store.reconcileUpsert(sourceDeviceId, revisionOne.value, revisionOne.canonical);
    expect(await store.unseenCount()).toBe(0);

    await store.hideVisibleForPresentation();
    expect(await store.listVisibleForPresentation()).toEqual([]);
    expect(await store.unseenCount()).toBe(0);
    expect(await store.listVisible()).toHaveLength(1);
    await store.reconcileUpsert(sourceDeviceId, revisionOne.value, revisionOne.canonical);
    expect(await store.listVisibleForPresentation()).toEqual([]);

    now = 2_000;
    const revisionTwo = upsert(2n, 'Visible update');
    await store.reconcileUpsert(sourceDeviceId, revisionTwo.value, revisionTwo.canonical);
    const reconstructed = new IndexedDbNotificationStateStore(databaseName, () => 3_000);
    expect((await reconstructed.listVisibleForPresentation())[0]).toMatchObject({
      isNew: true,
      updatedAtUnixMs: 2_000,
    });
  });
});

describe('Notification source applications', () => {
  it('keeps an application selectable after its notification is removed', async () => {
    const databaseName = `source-applications-${Date.now()}-${Math.random()}`;
    databaseNames.add(databaseName);
    const store = new IndexedDbNotificationStateStore(databaseName, () => 1_000);
    const sourceDeviceId = new Uint8Array(16).fill(9);

    const first = upsert(1n, 'First body');
    const second = upsert(1n, 'Second body', { notificationId: 'notification-2' });
    await store.reconcileUpsert(sourceDeviceId, first.value, first.canonical);
    await store.reconcileUpsert(sourceDeviceId, second.value, second.canonical);
    expect(await store.listSourceApplications()).toEqual([
      { id: 'example.app', name: 'Example' },
    ]);

    await remove(store, sourceDeviceId, 'notification-1', 2n);
    await remove(store, sourceDeviceId, 'notification-2', 2n);

    expect(await store.listVisible()).toEqual([]);
    expect(await store.listSourceApplications()).toEqual([
      { id: 'example.app', name: 'Example' },
    ]);
  });

  it('keeps an application selectable after a snapshot closes its notification', async () => {
    const databaseName = `source-applications-snapshot-${Date.now()}-${Math.random()}`;
    databaseNames.add(databaseName);
    const store = new IndexedDbNotificationStateStore(databaseName, () => 1_000);
    const sourceDeviceId = new Uint8Array(16).fill(11);

    const first = upsert(1n, 'First body');
    await store.reconcileUpsert(sourceDeviceId, first.value, first.canonical);

    const manifest = createNotificationSnapshotManifestPayload({
      highWaterRevision: 2n,
      activeNotifications: [],
    });
    if (manifest.body.case !== 'notificationSnapshotManifest') {
      throw new Error('Unexpected payload');
    }
    const closed = await store.reconcileSnapshot(
      sourceDeviceId,
      manifest.body.value,
      encodeEncryptedPayloadV1(manifest),
    );

    expect(closed.disposition).toBe('applied');
    expect(closed.closedStates).toHaveLength(1);
    expect(await store.listVisible()).toEqual([]);
    expect(await store.listSourceApplications()).toEqual([
      { id: 'example.app', name: 'Example' },
    ]);
  });
});

describe('Notification history', () => {
  it('moves a read notification into history and keeps the unread count separate', async () => {
    const databaseName = `history-${Date.now()}-${Math.random()}`;
    databaseNames.add(databaseName);
    let now = 5_000;
    const store = new IndexedDbNotificationStateStore(databaseName, () => now);
    const sourceDeviceId = new Uint8Array(16).fill(2);

    const first = upsert(1n, 'Dinner tonight?', { notificationId: 'a' });
    await store.reconcileUpsert(sourceDeviceId, first.value, first.canonical);
    now = 6_000;
    const second = upsert(1n, 'Build finished', { notificationId: 'b' });
    await store.reconcileUpsert(sourceDeviceId, second.value, second.canonical);

    const unread = (await store.listHistory(200)).filter((entry) => !entry.read);
    expect(unread.map((entry) => entry.body)).toEqual(['Build finished', 'Dinner tonight?']);

    expect(await store.markAllViewed()).toBe(2);
    expect((await store.listHistory(200)).filter((entry) => !entry.read)).toEqual([]);
  });

  it('keeps the text and icon of a notification the phone already cleared', async () => {
    const databaseName = `history-removed-${Date.now()}-${Math.random()}`;
    databaseNames.add(databaseName);
    let now = 7_000;
    const store = new IndexedDbNotificationStateStore(databaseName, () => now);
    const sourceDeviceId = new Uint8Array(16).fill(3);
    const iconBytes = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]);
    const appIcon: NonNullable<NotificationUpsert['appIcon']> = {
      $typeName: 'notification.mirroring.v1.NotificationMedia',
      encodedBytes: iconBytes,
      mimeType: NotificationMediaMimeType.PNG,
      width: 1,
      height: 1,
      contentSha256: sha256(iconBytes),
    };

    const visible = upsert(1n, 'Dinner tonight?', { notificationId: 'a', appIcon });
    await store.reconcileUpsert(sourceDeviceId, visible.value, visible.canonical);

    now = 8_000;
    await remove(store, sourceDeviceId, 'a', 2n);

    const [entry] = await store.listHistory(200);
    expect(entry).toMatchObject({ title: 'Title', body: 'Dinner tonight?', read: true, live: false });
    expect(entry?.appIcon?.contentSha256).toEqual(appIcon.contentSha256);
    // A removal states when the mirror ended, not when the notification arrived.
    expect(entry?.receivedAtUnixMs).toBe(7_000);
  });

  it('keeps only the newest 200 records', async () => {
    const databaseName = `history-cap-${Date.now()}-${Math.random()}`;
    databaseNames.add(databaseName);
    let now = 1_000;
    const store = new IndexedDbNotificationStateStore(databaseName, () => now);
    const sourceDeviceId = new Uint8Array(16).fill(3);

    for (let index = 0; index < 205; index += 1) {
      now += 1_000;
      const entry = upsert(1n, `Body ${index}`, { notificationId: `n${index}` });
      await store.reconcileUpsert(sourceDeviceId, entry.value, entry.canonical);
    }

    const history = await store.listHistory(1_000);
    expect(history).toHaveLength(200);
    expect(history[0].body).toBe('Body 204');
    expect(history.at(-1)?.body).toBe('Body 5');
  });

  it('drops removed records when history is switched off, keeping live ones', async () => {
    const databaseName = `history-off-${Date.now()}-${Math.random()}`;
    databaseNames.add(databaseName);
    const store = new IndexedDbNotificationStateStore(databaseName, () => 1_000);
    const sourceDeviceId = new Uint8Array(16).fill(4);

    const live = upsert(1n, 'Still on the phone', { notificationId: 'live' });
    await store.reconcileUpsert(sourceDeviceId, live.value, live.canonical);
    const gone = upsert(1n, 'Already cleared', { notificationId: 'gone' });
    await store.reconcileUpsert(sourceDeviceId, gone.value, gone.canonical);
    await remove(store, sourceDeviceId, 'gone', 2n);

    await store.pruneHistory(200, false);
    const history = await store.listHistory(200);
    expect(history.map((entry) => entry.body)).toEqual(['Still on the phone']);
  });

  it('treats a notification the phone removed as history rather than unread', async () => {
    const databaseName = `history-removed-${Date.now()}-${Math.random()}`;
    databaseNames.add(databaseName);
    const store = new IndexedDbNotificationStateStore(databaseName, () => 1_000);
    const sourceDeviceId = new Uint8Array(16).fill(5);

    const entry = upsert(1n, 'Never opened', { notificationId: 'x' });
    await store.reconcileUpsert(sourceDeviceId, entry.value, entry.canonical);
    await remove(store, sourceDeviceId, 'x', 2n);

    const history = await store.listHistory(200);
    expect(history).toHaveLength(1);
    expect(history[0]).toMatchObject({ read: true, live: false });
  });

  it('clears history without dropping a notification that is still on the phone', async () => {
    const databaseName = `history-clear-${Date.now()}-${Math.random()}`;
    databaseNames.add(databaseName);
    const store = new IndexedDbNotificationStateStore(databaseName, () => 1_000);
    const sourceDeviceId = new Uint8Array(16).fill(6);

    const live = upsert(1n, 'Still here', { notificationId: 'keep' });
    await store.reconcileUpsert(sourceDeviceId, live.value, live.canonical);
    const gone = upsert(1n, 'Gone', { notificationId: 'drop' });
    await store.reconcileUpsert(sourceDeviceId, gone.value, gone.canonical);
    await remove(store, sourceDeviceId, 'drop', 2n);

    expect(await store.clearRemovedHistory()).toBe(1);
    expect((await store.listHistory(200)).map((entry) => entry.body)).toEqual(['Still here']);
  });
});

function remove(
  store: IndexedDbNotificationStateStore,
  sourceDeviceId: Uint8Array,
  notificationId: string,
  revision: bigint,
): Promise<unknown> {
  const payload = createNotificationRemovedPayload({
    notificationId,
    notificationRevision: revision,
  });
  if (payload.body.case !== 'notificationRemoved') throw new Error('Unexpected payload');
  return store.reconcileRemoved(
    sourceDeviceId,
    payload.body.value,
    encodeEncryptedPayloadV1(payload),
  );
}

function upsert(revision: bigint, body: string, overrides: {
  notificationId?: string;
  sourceApplicationId?: string;
  sourceApplicationName?: string;
  appIcon?: NotificationUpsert['appIcon'];
} = {}): {
  value: NotificationUpsert;
  canonical: Uint8Array;
} {
  const payload = createNotificationUpsertPayload({
    notificationId: overrides.notificationId ?? 'notification-1',
    notificationRevision: revision,
    sourceApplicationId: overrides.sourceApplicationId ?? 'example.app',
    sourceApplicationName: overrides.sourceApplicationName ?? 'Example',
    title: 'Title',
    body,
    ...(overrides.appIcon === undefined ? {} : { appIcon: overrides.appIcon }),
    containsContentImage: false,
    actions: [],
  });
  if (payload.body.case !== 'notificationUpsert') throw new Error('Unexpected payload');
  return { value: payload.body.value, canonical: encodeEncryptedPayloadV1(payload) };
}

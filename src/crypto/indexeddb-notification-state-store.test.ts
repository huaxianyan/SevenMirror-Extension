import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createNotificationRemovedPayload,
  createNotificationSnapshotManifestPayload,
  createNotificationUpsertPayload,
  encodeEncryptedPayloadV1,
} from '../protocol/encrypted-payload';
import type { NotificationUpsert } from '../protocol/generated/notification/v1/payload_pb';
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
    containsContentImage: false,
    actions: [],
  });
  if (payload.body.case !== 'notificationUpsert') throw new Error('Unexpected payload');
  return { value: payload.body.value, canonical: encodeEncryptedPayloadV1(payload) };
}

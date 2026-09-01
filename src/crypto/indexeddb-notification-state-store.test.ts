import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it } from 'vitest';
import {
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

function upsert(revision: bigint, body: string): {
  value: NotificationUpsert;
  canonical: Uint8Array;
} {
  const payload = createNotificationUpsertPayload({
    notificationId: 'notification-1',
    notificationRevision: revision,
    sourceApplicationId: 'example.app',
    sourceApplicationName: 'Example',
    title: 'Title',
    body,
    containsContentImage: false,
    actions: [],
  });
  if (payload.body.case !== 'notificationUpsert') throw new Error('Unexpected payload');
  return { value: payload.body.value, canonical: encodeEncryptedPayloadV1(payload) };
}

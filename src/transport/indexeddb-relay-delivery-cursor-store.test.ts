import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { IndexedDbRelayDeliveryCursorStore } from './indexeddb-relay-delivery-cursor-store';

describe('IndexedDbRelayDeliveryCursorStore', () => {
  it('restores one contiguous committed cursor and retains snapshot-required state', async () => {
    const databaseName = `relay-cursor-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const workspaceId = new Uint8Array(16).fill(1);
    const deviceId = new Uint8Array(16).fill(2);
    const store = new IndexedDbRelayDeliveryCursorStore(databaseName);

    expect(await store.load(workspaceId, deviceId)).toEqual({ committedDeliveryId: 0n });
    await store.commitDelivery(workspaceId, deviceId, 1n);
    await expect(store.commitDelivery(workspaceId, deviceId, 3n))
      .rejects.toThrow('not contiguous');

    const reconstructed = new IndexedDbRelayDeliveryCursorStore(databaseName);
    expect(await reconstructed.load(workspaceId, deviceId)).toEqual({
      committedDeliveryId: 1n,
    });
    await reconstructed.requireSnapshot(workspaceId, deviceId, 9n);
    expect(await store.load(workspaceId, deviceId)).toEqual({
      committedDeliveryId: 1n,
      snapshotRequiredHighWater: 9n,
    });
    await expect(store.commitDelivery(workspaceId, deviceId, 2n))
      .rejects.toThrow('requires snapshot reconciliation');
  });

  it('accepts a history reset only after every persisted source snapshot completes', async () => {
    const databaseName = `relay-recovery-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const workspaceId = new Uint8Array(16).fill(1);
    const deviceId = new Uint8Array(16).fill(2);
    const requestId = new Uint8Array(16).fill(3);
    const firstSource = new Uint8Array(16).fill(4);
    const secondSource = new Uint8Array(16).fill(5);
    const firstSourceKey = new Uint8Array(32).fill(6);
    const secondSourceKey = new Uint8Array(32).fill(7);
    const store = new IndexedDbRelayDeliveryCursorStore(databaseName);

    await store.commitDelivery(workspaceId, deviceId, 1n);
    await store.requireSnapshot(workspaceId, deviceId, 9n);
    await store.beginSnapshotRecovery(
      workspaceId, deviceId, 9n, requestId, [
        { deviceId: secondSource, keyId: secondSourceKey },
        { deviceId: firstSource, keyId: firstSourceKey },
      ],
    );
    await expect(store.recordSnapshotRecoverySource(
      workspaceId, deviceId, requestId, firstSource, secondSourceKey,
    )).rejects.toThrow('identity');
    await store.recordSnapshotRecoverySource(
      workspaceId, deviceId, requestId, firstSource, firstSourceKey,
    );
    await expect(store.acceptSnapshotRecovery(workspaceId, deviceId, requestId))
      .rejects.toThrow('incomplete');

    const reconstructed = new IndexedDbRelayDeliveryCursorStore(databaseName);
    await reconstructed.recordSnapshotRecoverySource(
      workspaceId, deviceId, requestId, secondSource, secondSourceKey,
    );
    expect(await reconstructed.acceptSnapshotRecovery(workspaceId, deviceId, requestId))
      .toEqual({ committedDeliveryId: 9n });
    expect(await store.load(workspaceId, deviceId)).toEqual({ committedDeliveryId: 9n });
  });

  it('isolates cursor state by exact workspace and local device tuple', async () => {
    const store = new IndexedDbRelayDeliveryCursorStore(
      `relay-cursor-isolation-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    );
    const workspaceId = new Uint8Array(16).fill(1);
    const first = new Uint8Array(16).fill(2);
    const second = new Uint8Array(16).fill(3);
    await store.commitDelivery(workspaceId, first, 1n);
    expect((await store.load(workspaceId, first)).committedDeliveryId).toBe(1n);
    expect((await store.load(workspaceId, second)).committedDeliveryId).toBe(0n);
  });
});

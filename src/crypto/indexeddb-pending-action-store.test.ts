import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { ActionResultStatus } from '../protocol/generated/notification/v1/payload_pb';
import { IndexedDbPendingActionStore } from './indexeddb-pending-action-store';

const now = 1_800_000_000_000;
const key = new Uint8Array(16).fill(1);
const sender = new Uint8Array(16).fill(2);
const digest = new Uint8Array(32).fill(9);

function uniqueName(): string {
  return `test-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

describe('IndexedDbPendingActionStore', () => {
  it('persists a pending operation and reconciles it after reconstruction', async () => {
    const name = uniqueName();
    const store = new IndexedDbPendingActionStore(name);
    try {
      expect(await store.register(key, sender, digest, now, now + 60_000)).toBe('registered');
      const reconstructed = new IndexedDbPendingActionStore(name);
      expect(await reconstructed.reconcile(
        key,
        sender,
        ActionResultStatus.SUCCEEDED,
        undefined,
        now + 1,
      )).toBe('completed');
      expect((await reconstructed.get(key))?.resultStatus).toBe(ActionResultStatus.SUCCEEDED);
    } finally {
      await store.clear();
    }
  });

  it('accepts an identical recovered result and rejects conflicting results', async () => {
    const store = new IndexedDbPendingActionStore(uniqueName());
    try {
      await store.register(key, sender, digest, now, now + 60_000);
      expect(await store.reconcile(
        key, sender, ActionResultStatus.STALE_NOTIFICATION_VERSION, 'revision changed', now + 1,
      )).toBe('completed');
      expect(await store.reconcile(
        key, sender, ActionResultStatus.STALE_NOTIFICATION_VERSION, 'revision changed', now + 2,
      )).toBe('already-completed');
      expect(await store.reconcile(
        key, sender, ActionResultStatus.SUCCEEDED, undefined, now + 3,
      )).toBe('conflict');
    } finally {
      await store.clear();
    }
  });

  it('binds an operation to its Android sender and fails closed at capacity', async () => {
    const store = new IndexedDbPendingActionStore(uniqueName(), 1);
    const otherKey = new Uint8Array(16).fill(3);
    try {
      expect(await store.register(key, sender, digest, now, now + 60_000)).toBe('registered');
      await expect(store.register(
        key,
        sender,
        new Uint8Array(32).fill(8),
        now,
        now + 60_000,
      )).rejects.toThrow('already bound to another operation');
      expect(await store.register(otherKey, sender, digest, now, now + 60_000)).toBe('capacity-exceeded');
      expect(await store.reconcile(
        key,
        new Uint8Array(16).fill(4),
        ActionResultStatus.SUCCEEDED,
        undefined,
        now + 1,
      )).toBe('sender-mismatch');
      expect(await store.reconcile(
        otherKey, sender, ActionResultStatus.SUCCEEDED, undefined, now + 1,
      )).toBe('not-found');
    } finally {
      await store.clear();
    }
  });

  it('serializes concurrent registration for one idempotency key', async () => {
    const store = new IndexedDbPendingActionStore(uniqueName());
    try {
      expect((await Promise.all([
        store.register(key, sender, digest, now, now + 60_000),
        store.register(key, sender, digest, now, now + 60_000),
      ])).sort()).toEqual(['already-registered', 'registered']);
    } finally {
      await store.clear();
    }
  });
});

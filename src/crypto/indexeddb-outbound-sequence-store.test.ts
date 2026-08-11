import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { IndexedDbOutboundSequenceStore } from './indexeddb-outbound-sequence-store';

function uniqueName(): string {
  return `test-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

describe('IndexedDbOutboundSequenceStore', () => {
  it('allocates atomically and persists per-recipient sequences', async () => {
    const name = uniqueName();
    const store = new IndexedDbOutboundSequenceStore(name);
    const firstRecipient = new Uint8Array(32).fill(1);
    const secondRecipient = new Uint8Array(32).fill(2);
    try {
      expect((await Promise.all([
        store.allocate(firstRecipient),
        store.allocate(firstRecipient),
      ])).sort()).toEqual([1n, 2n]);
      const reconstructed = new IndexedDbOutboundSequenceStore(name);
      expect(await reconstructed.allocate(firstRecipient)).toBe(3n);
      expect(await reconstructed.allocate(secondRecipient)).toBe(1n);
    } finally {
      await store.clear();
    }
  });
});

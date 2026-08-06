import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { IndexedDbReplayLedger } from './indexeddb-replay-ledger';

const now = 1_800_000_000_000;
const senderKeyId = Uint8Array.from({ length: 32 }, (_, index) => index);
const messageId = Uint8Array.from({ length: 16 }, (_, index) => index + 32);

function uniqueLedgerName(): string {
  return `test-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

describe('IndexedDbReplayLedger', () => {
  it('rejects a duplicate after ledger reconstruction', async () => {
    const ledgerName = uniqueLedgerName();
    const first = new IndexedDbReplayLedger(ledgerName);

    try {
      expect(
        await first.checkAndRecord(senderKeyId, messageId, now + 60_000, now),
      ).toBe('accepted');
      expect(
        await new IndexedDbReplayLedger(ledgerName).checkAndRecord(
          senderKeyId,
          messageId,
          now + 60_000,
          now,
        ),
      ).toBe('duplicate');
    } finally {
      await first.clear();
    }
  });

  it('serializes concurrent attempts for the same tuple', async () => {
    const ledger = new IndexedDbReplayLedger(uniqueLedgerName());

    try {
      const decisions = await Promise.all([
        ledger.checkAndRecord(senderKeyId, messageId, now + 60_000, now),
        ledger.checkAndRecord(senderKeyId, messageId, now + 60_000, now),
      ]);
      expect(decisions.sort()).toEqual(['accepted', 'duplicate']);
    } finally {
      await ledger.clear();
    }
  });

  it('rejects expired input and fails closed at capacity', async () => {
    const ledger = new IndexedDbReplayLedger(uniqueLedgerName(), 1);
    const secondMessageId = new Uint8Array(16).fill(9);

    try {
      expect(
        await ledger.checkAndRecord(senderKeyId, messageId, now, now),
      ).toBe('expired');
      expect(
        await ledger.checkAndRecord(senderKeyId, messageId, now + 10, now),
      ).toBe('accepted');
      expect(
        await ledger.checkAndRecord(senderKeyId, secondMessageId, now + 20, now),
      ).toBe('capacity-exceeded');
      expect(
        await ledger.checkAndRecord(senderKeyId, secondMessageId, now + 20, now + 10),
      ).toBe('accepted');
    } finally {
      await ledger.clear();
    }
  });

  it('validates cryptographic identifier lengths', async () => {
    const ledger = new IndexedDbReplayLedger(uniqueLedgerName());
    await expect(
      ledger.checkAndRecord(new Uint8Array(31), messageId, now + 1, now),
    ).rejects.toThrow('senderKeyId must be 32 bytes');
    await ledger.clear();
  });
});

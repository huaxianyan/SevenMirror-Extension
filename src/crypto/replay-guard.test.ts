import { describe, expect, it } from 'vitest';
import { ReplayGuard } from './replay-guard';

const now = 1_800_000_000_000;

describe('ReplayGuard', () => {
  it('accepts once and rejects the same sender-key/message tuple', () => {
    const guard = new ReplayGuard();
    const token = {
      senderKeyId: 'sender-key-1',
      messageId: 'message-1',
      expiresAtUnixMs: now + 60_000,
    };

    expect(guard.checkAndRecord(token, now)).toBe('accepted');
    expect(guard.checkAndRecord(token, now)).toBe('duplicate');
    expect(
      guard.checkAndRecord({ ...token, senderKeyId: 'sender-key-2' }, now),
    ).toBe('accepted');
  });

  it('rejects expired tokens and bounds retained state', () => {
    const guard = new ReplayGuard(1);
    expect(
      guard.checkAndRecord(
        { senderKeyId: 'sender', messageId: 'expired', expiresAtUnixMs: now },
        now,
      ),
    ).toBe('expired');
    expect(
      guard.checkAndRecord(
        { senderKeyId: 'sender', messageId: 'one', expiresAtUnixMs: now + 10 },
        now,
      ),
    ).toBe('accepted');
    expect(
      guard.checkAndRecord(
        { senderKeyId: 'sender', messageId: 'two', expiresAtUnixMs: now + 20 },
        now,
      ),
    ).toBe('accepted');
  });
});

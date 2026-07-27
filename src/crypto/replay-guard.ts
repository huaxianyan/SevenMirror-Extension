export type ReplayDecision = 'accepted' | 'duplicate' | 'expired';

export interface ReplayToken {
  senderKeyId: string;
  messageId: string;
  expiresAtUnixMs: number;
}

/**
 * Bounded SPIKE-004 replay ledger. Production callers must persist equivalent
 * state before applying a decrypted side effect so MV3 worker restarts cannot
 * reopen the replay window.
 */
export class ReplayGuard {
  private readonly seen = new Map<string, number>();

  constructor(private readonly maxEntries = 4096) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new Error('maxEntries must be a positive safe integer');
    }
  }

  checkAndRecord(token: ReplayToken, nowUnixMs: number): ReplayDecision {
    this.purgeExpired(nowUnixMs);
    if (token.expiresAtUnixMs <= nowUnixMs) {
      return 'expired';
    }

    const key = `${token.senderKeyId.length}:${token.senderKeyId}${token.messageId}`;
    if (this.seen.has(key)) {
      return 'duplicate';
    }

    while (this.seen.size >= this.maxEntries) {
      const oldest = this.seen.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.seen.delete(oldest);
    }
    this.seen.set(key, token.expiresAtUnixMs);
    return 'accepted';
  }

  private purgeExpired(nowUnixMs: number): void {
    for (const [key, expiresAt] of this.seen) {
      if (expiresAt <= nowUnixMs) this.seen.delete(key);
    }
  }
}

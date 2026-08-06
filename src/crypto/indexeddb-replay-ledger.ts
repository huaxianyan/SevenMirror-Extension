export type PersistentReplayDecision =
  | 'accepted'
  | 'duplicate'
  | 'expired'
  | 'capacity-exceeded';

interface ReplayRecord {
  tuple: string;
  expiresAtUnixMs: number;
}

const STORE_NAME = 'replay-entry';
const EXPIRY_INDEX = 'by-expiry';
const DATABASE_VERSION = 1;
const SENDER_KEY_ID_BYTES = 32;
const MESSAGE_ID_BYTES = 16;

/**
 * Persistent replay ledger for authenticated envelopes.
 *
 * Call this after HPKE authentication and before applying a side effect. Any
 * IndexedDB error is propagated deliberately so callers fail closed.
 */
export class IndexedDbReplayLedger {
  private readonly databaseName: string;

  constructor(
    ledgerName = 'default',
    private readonly maxEntries = 4096,
  ) {
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(ledgerName)) {
      throw new Error('ledgerName must be 1-64 URL-safe characters');
    }
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new Error('maxEntries must be a positive safe integer');
    }
    this.databaseName = `syncnotifications-replay-${ledgerName}`;
  }

  /**
   * Atomically purges expired entries and records a new sender/message tuple.
   * Accepted tuples remain consumed even if the later side effect fails.
   */
  async checkAndRecord(
    senderKeyId: Uint8Array,
    messageId: Uint8Array,
    expiresAtUnixMs: number,
    nowUnixMs: number,
  ): Promise<PersistentReplayDecision> {
    validateIdentifier(senderKeyId, SENDER_KEY_ID_BYTES, 'senderKeyId');
    validateIdentifier(messageId, MESSAGE_ID_BYTES, 'messageId');
    validateTimestamp(expiresAtUnixMs, 'expiresAtUnixMs');
    validateTimestamp(nowUnixMs, 'nowUnixMs');
    if (expiresAtUnixMs <= nowUnixMs) return 'expired';

    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);

      try {
        const expiredKeys = await requestResult<IDBValidKey[]>(
          store.index(EXPIRY_INDEX).getAllKeys(IDBKeyRange.upperBound(nowUnixMs)),
        );
        await Promise.all(expiredKeys.map((key) => requestResult(store.delete(key))));

        const tuple = `${toHex(senderKeyId)}:${toHex(messageId)}`;
        const existing = await requestResult<ReplayRecord | undefined>(store.get(tuple));
        if (existing !== undefined) {
          await completed;
          return 'duplicate';
        }

        const count = await requestResult<number>(store.count());
        if (count >= this.maxEntries) {
          await completed;
          return 'capacity-exceeded';
        }

        await requestResult(
          store.add({ tuple, expiresAtUnixMs } satisfies ReplayRecord),
        );
        await completed;
        return 'accepted';
      } catch (error: unknown) {
        await completed.catch(() => undefined);
        throw error;
      }
    } finally {
      database.close();
    }
  }

  async clear(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.databaseName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error ?? new Error('Unable to delete replay ledger'));
      request.onblocked = () => reject(new Error('Replay ledger deletion was blocked'));
    });
  }

  private async openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        const database = request.result;
        const store = database.createObjectStore(STORE_NAME, { keyPath: 'tuple' });
        store.createIndex(EXPIRY_INDEX, 'expiresAtUnixMs', { unique: false });
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Unable to open replay ledger'));
      request.onblocked = () => reject(new Error('Replay ledger open was blocked'));
    });
  }
}

function validateIdentifier(value: Uint8Array, expectedBytes: number, name: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== expectedBytes) {
    throw new Error(`${name} must be ${expectedBytes} bytes`);
  }
}

function validateTimestamp(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed'));
  });
}

function transactionCompleted(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB transaction aborted'));
    transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB transaction failed'));
  });
}

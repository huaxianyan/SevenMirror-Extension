const STORE_NAME = 'outbound-sequence';
const DATABASE_VERSION = 1;
const KEY_ID_BYTES = 32;
const MAX_SEQUENCE = 0x7fff_ffff_ffff_ffffn;

interface SequenceRecord {
  recipientKeyId: string;
  nextSequence: string;
}

/** Atomically allocates positive per-recipient routing sequences across MV3 restarts. */
export class IndexedDbOutboundSequenceStore {
  constructor(private readonly databaseName = 'syncnotifications-outbound-sequences-v1') {}

  async allocate(recipientKeyId: Uint8Array): Promise<bigint> {
    validateKeyId(recipientKeyId);
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const key = toHex(recipientKeyId);
      const existing = await requestResult<SequenceRecord | undefined>(store.get(key));
      const current = existing === undefined ? 1n : parseSequence(existing.nextSequence);
      if (current < 1n || current > MAX_SEQUENCE) {
        transaction.abort();
        await completed.catch(() => undefined);
        throw new Error('Outbound sequence exhausted or corrupt');
      }
      await requestResult(store.put({
        recipientKeyId: key,
        nextSequence: (current + 1n).toString(10),
      } satisfies SequenceRecord));
      await completed;
      return current;
    } finally {
      database.close();
    }
  }

  async clear(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.databaseName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error ?? new Error('Unable to delete sequence store'));
      request.onblocked = () => reject(new Error('Sequence store deletion was blocked'));
    });
  }

  private openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        request.result.createObjectStore(STORE_NAME, { keyPath: 'recipientKeyId' });
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Unable to open sequence store'));
      request.onblocked = () => reject(new Error('Sequence store open was blocked'));
    });
  }
}

function parseSequence(value: string): bigint {
  if (!/^[1-9][0-9]*$/.test(value)) throw new Error('Stored outbound sequence is corrupt');
  return BigInt(value);
}

function validateKeyId(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== KEY_ID_BYTES ||
      value.every((byte) => byte === 0)) {
    throw new Error(`recipientKeyId must be a non-zero ${KEY_ID_BYTES}-byte value`);
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

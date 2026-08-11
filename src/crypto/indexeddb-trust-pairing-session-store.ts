export type TrustPairingRole = 'offerer' | 'approver';

export interface TrustPairingSession {
  role: TrustPairingRole;
  offerBytes: Uint8Array;
  approvalBytes?: Uint8Array;
  expiresAtUnixMs: number;
}

interface StoredSession extends TrustPairingSession {
  id: string;
}

const STORE_NAME = 'session';
const RECORD_ID = 'active-trust-pairing-v1';
const DATABASE_VERSION = 1;

/** One durable active pairing transcript. Replacement always requires explicit cancel(). */
export class IndexedDbTrustPairingSessionStore {
  constructor(private readonly databaseName = 'syncnotifications-trust-pairing-v1') {}

  async load(): Promise<TrustPairingSession | undefined> {
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readonly');
      const completed = transactionCompleted(transaction);
      const record = await requestResult<StoredSession | undefined>(
        transaction.objectStore(STORE_NAME).get(RECORD_ID),
      );
      await completed;
      if (record === undefined) return undefined;
      validateSession(record);
      return copySession(record);
    } finally {
      database.close();
    }
  }

  async create(session: TrustPairingSession): Promise<void> {
    validateSession(session);
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const existing = await requestResult<StoredSession | undefined>(store.get(RECORD_ID));
      if (existing !== undefined) {
        await completed;
        validateSession(existing);
        throw new Error('An active trust pairing session already exists; cancel it explicitly');
      }
      await requestResult(store.add({
        id: RECORD_ID,
        ...copySession(session),
      } satisfies StoredSession));
      await completed;
    } finally {
      database.close();
    }
  }

  async attachApproval(expectedOffer: Uint8Array, approvalBytes: Uint8Array): Promise<void> {
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const record = await requestResult<StoredSession | undefined>(store.get(RECORD_ID));
      if (record === undefined) throw new Error('No active trust pairing offer exists');
      validateSession(record);
      if (record.role !== 'offerer' || record.approvalBytes !== undefined ||
          !bytesEqual(record.offerBytes, expectedOffer)) {
        throw new Error('Active trust pairing session does not match this approval');
      }
      await requestResult(store.put({ ...record, approvalBytes: approvalBytes.slice() }));
      await completed;
    } finally {
      database.close();
    }
  }

  async removeExact(offerBytes: Uint8Array, approvalBytes?: Uint8Array): Promise<void> {
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const record = await requestResult<StoredSession | undefined>(store.get(RECORD_ID));
      if (record === undefined) throw new Error('Trust pairing session disappeared');
      validateSession(record);
      if (!bytesEqual(record.offerBytes, offerBytes) ||
          !optionalBytesEqual(record.approvalBytes, approvalBytes)) {
        throw new Error('Trust pairing session changed before completion');
      }
      await requestResult(store.delete(RECORD_ID));
      await completed;
    } finally {
      database.close();
    }
  }

  async cancel(): Promise<void> {
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      await requestResult(transaction.objectStore(STORE_NAME).delete(RECORD_ID));
      await completed;
    } finally {
      database.close();
    }
  }

  async clear(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.databaseName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error ?? new Error('Unable to delete trust pairing store'));
      request.onblocked = () => reject(new Error('Trust pairing store deletion was blocked'));
    });
  }

  private openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) {
          request.result.createObjectStore(STORE_NAME, { keyPath: 'id' });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Unable to open trust pairing store'));
      request.onblocked = () => reject(new Error('Trust pairing store open was blocked'));
    });
  }
}

function validateSession(value: TrustPairingSession): void {
  if (value.role !== 'offerer' && value.role !== 'approver') throw new Error('Invalid pairing role');
  if (!(value.offerBytes instanceof Uint8Array) || value.offerBytes.byteLength !== 133) {
    throw new Error('Stored trust offer has invalid length');
  }
  if (value.approvalBytes !== undefined &&
      (!(value.approvalBytes instanceof Uint8Array) || value.approvalBytes.byteLength !== 149)) {
    throw new Error('Stored trust approval has invalid length');
  }
  if (value.role === 'approver' && value.approvalBytes === undefined) {
    throw new Error('Approver session must contain an approval');
  }
  if (!Number.isSafeInteger(value.expiresAtUnixMs) || value.expiresAtUnixMs < 0) {
    throw new Error('Stored trust pairing expiry is invalid');
  }
}

function copySession(value: TrustPairingSession): TrustPairingSession {
  return {
    role: value.role,
    offerBytes: value.offerBytes.slice(),
    approvalBytes: value.approvalBytes?.slice(),
    expiresAtUnixMs: value.expiresAtUnixMs,
  };
}

function optionalBytesEqual(left?: Uint8Array, right?: Uint8Array): boolean {
  return left === undefined ? right === undefined : right !== undefined && bytesEqual(left, right);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
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

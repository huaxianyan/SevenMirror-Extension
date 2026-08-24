import { generateNonExtractableIdentity, type HpkeIdentity } from './auth-hpke';

const STORE_NAME = 'identities';
const RECORD_ID = 'primary-hpke-auth-v1';
const RECORD_FORMAT_VERSION = 1;

interface LegacyIdentityRotationRecord {
  formatVersion: number;
  current: HpkeIdentity;
  pending?: HpkeIdentity;
}

type StoredIdentityRecord = HpkeIdentity | LegacyIdentityRotationRecord;

/** Persists one non-extractable WebCrypto identity. */
export class IndexedDbIdentityStore {
  constructor(private readonly databaseName = 'syncnotifications-crypto-v1') {}

  async loadExisting(): Promise<HpkeIdentity | undefined> {
    const stored = await this.readStored();
    if (stored === undefined) return undefined;
    const identity = normalizeStoredIdentity(stored);
    validateIdentity(identity);
    return identity;
  }

  async loadOrCreate(): Promise<HpkeIdentity> {
    const existing = await this.loadExisting();
    if (existing !== undefined) return existing;

    const generated = await generateNonExtractableIdentity();
    const database = await this.openDatabase();
    try {
      // Serialize competing creators and recheck inside the write transaction.
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const concurrentlyCreated = await requestResult<StoredIdentityRecord | undefined>(
        store.get(RECORD_ID),
      );
      if (concurrentlyCreated !== undefined) {
        await completed;
        const identity = normalizeStoredIdentity(concurrentlyCreated);
        validateIdentity(identity);
        return identity;
      }

      await requestResult(store.add(generated, RECORD_ID));
      await completed;
      validateIdentity(generated);
      return generated;
    } finally {
      database.close();
    }
  }

  async clear(): Promise<void> {
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

  private async readStored(): Promise<StoredIdentityRecord | undefined> {
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readonly');
      const completed = transactionCompleted(transaction);
      const stored = await requestResult<StoredIdentityRecord | undefined>(
        transaction.objectStore(STORE_NAME).get(RECORD_ID),
      );
      await completed;
      return stored;
    } finally {
      database.close();
    }
  }

  private openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) {
          request.result.createObjectStore(STORE_NAME);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Failed to open identity database'));
      request.onblocked = () => reject(new Error('Identity database upgrade was blocked'));
    });
  }
}

function normalizeStoredIdentity(stored: StoredIdentityRecord): HpkeIdentity {
  if (!('current' in stored)) return stored;
  if (stored.formatVersion !== RECORD_FORMAT_VERSION) {
    throw new Error('Stored HPKE identity record version is unsupported');
  }
  if (stored.pending !== undefined) {
    throw new Error(
      'Retired pending HPKE identity state requires administrator revocation and re-enrollment',
    );
  }
  return stored.current;
}

function validateIdentity(identity: HpkeIdentity): void {
  const algorithm = identity.privateKey.algorithm as EcKeyAlgorithm;
  if (
    identity.privateKey.type !== 'private' ||
    identity.privateKey.extractable ||
    algorithm.name !== 'ECDH' ||
    algorithm.namedCurve !== 'P-256' ||
    !identity.privateKey.usages.includes('deriveBits')
  ) {
    throw new Error('Stored HPKE identity does not meet non-extractable P-256 policy');
  }
  if (identity.publicKey.type !== 'public') {
    throw new Error('Stored HPKE identity public key is invalid');
  }
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

import type { DeviceTransportCredential } from './device-auth-frame';

const STORE_NAME = 'credentials';
const RECORD_ID = 'primary-transport-v1';
const DATABASE_VERSION = 1;

export interface StoredTransportCredential extends DeviceTransportCredential {
  serverOrigin: string;
  identityKeyId: Uint8Array;
}

export type CredentialCandidateSource = 'current' | 'pending';
export type CredentialRotationPhase = 'prepared' | 'attempted';

export interface StoredCredentialRotation {
  current: StoredTransportCredential;
  pendingAuthToken: Uint8Array;
  phase: CredentialRotationPhase;
}

export interface TransportCredentialCandidate {
  credential: StoredTransportCredential;
  source: CredentialCandidateSource;
}

interface CredentialRecord extends StoredTransportCredential {
  id: string;
  pendingAuthToken?: Uint8Array;
  rotationPhase?: CredentialRotationPhase;
}

/**
 * Extension-origin-only persistence for transport bearer credentials. Current
 * and at most one pending credential share one IndexedDB record so rotation
 * preparation and promotion are atomic across MV3 Worker suspension.
 */
export class IndexedDbTransportCredentialStore {
  constructor(private readonly databaseName = 'syncnotifications-transport-v1') {}

  /** Loads only the current credential. Business routing remains bound to this device tuple. */
  async load(): Promise<StoredTransportCredential | undefined> {
    const record = await this.readRecord();
    return record === undefined ? undefined : copyCredential(record);
  }

  async loadRotation(): Promise<StoredCredentialRotation | undefined> {
    const record = await this.readRecord();
    if (record?.pendingAuthToken === undefined || record.rotationPhase === undefined) return undefined;
    return {
      current: copyCredential(record),
      pendingAuthToken: record.pendingAuthToken.slice(),
      phase: record.rotationPhase,
    };
  }

  async loadConnectionCandidate(preferCurrentFallback = false): Promise<TransportCredentialCandidate | undefined> {
    const record = await this.readRecord();
    if (record === undefined) return undefined;
    if (!preferCurrentFallback && record.rotationPhase === 'attempted' &&
        record.pendingAuthToken !== undefined) {
      const credential = copyCredential(record);
      credential.authToken.fill(0);
      credential.authToken = record.pendingAuthToken.slice();
      return { credential, source: 'pending' };
    }
    return { credential: copyCredential(record), source: 'current' };
  }

  /** Writes once; an existing credential can only be replaced after explicit clear(). */
  async saveNew(credential: StoredTransportCredential): Promise<void> {
    validateCredential(credential);
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const existing = await requestResult<CredentialRecord | undefined>(store.get(RECORD_ID));
      if (existing !== undefined) {
        await completed;
        validateRecord(existing);
        if (!credentialsEqual(existing, credential)) {
          throw new Error('Transport credential already exists; explicit clear is required');
        }
        return;
      }
      await requestResult(store.add({ id: RECORD_ID, ...copyCredential(credential) } satisfies CredentialRecord));
      await completed;
    } finally {
      database.close();
    }
  }

  /** Adds one pending secret without replacing current; exact duplicate preparation is idempotent. */
  async prepareRotation(pendingAuthToken: Uint8Array): Promise<StoredCredentialRotation> {
    validateBytes(pendingAuthToken, 32, 'pendingAuthToken', false);
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const record = await requestResult<CredentialRecord | undefined>(store.get(RECORD_ID));
      if (record === undefined) {
        transaction.abort();
        await completed.catch(() => undefined);
        throw new Error('Transport credential is not configured');
      }
      validateRecord(record);
      if (bytesEqual(record.authToken, pendingAuthToken)) {
        transaction.abort();
        await completed.catch(() => undefined);
        throw new Error('Pending credential must differ from current');
      }
      if (record.pendingAuthToken !== undefined) {
        await completed;
        if (!bytesEqual(record.pendingAuthToken, pendingAuthToken)) {
          throw new Error('A different pending credential already exists');
        }
        return rotationFromRecord(record);
      }
      const updated: CredentialRecord = {
        ...copyCredential(record),
        id: RECORD_ID,
        pendingAuthToken: pendingAuthToken.slice(),
        rotationPhase: 'prepared',
      };
      await requestResult(store.put(updated));
      await completed;
      return rotationFromRecord(updated);
    } finally {
      database.close();
    }
  }

  /** Must commit before the request can leave the extension process. */
  async markRotationAttempted(pendingAuthToken: Uint8Array): Promise<void> {
    validateBytes(pendingAuthToken, 32, 'pendingAuthToken', false);
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const record = await requestResult<CredentialRecord | undefined>(store.get(RECORD_ID));
      if (record === undefined || record.pendingAuthToken === undefined ||
          record.rotationPhase === undefined || !bytesEqual(record.pendingAuthToken, pendingAuthToken)) {
        transaction.abort();
        await completed.catch(() => undefined);
        throw new Error('Exact pending credential is not prepared');
      }
      validateRecord(record);
      if (record.rotationPhase !== 'attempted') {
        record.rotationPhase = 'attempted';
        await requestResult(store.put(record));
      }
      await completed;
    } finally {
      database.close();
    }
  }

  /** Called only after this pending credential receives exact SNO1. */
  async promotePending(): Promise<StoredTransportCredential> {
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const record = await requestResult<CredentialRecord | undefined>(store.get(RECORD_ID));
      if (record === undefined || record.pendingAuthToken === undefined || record.rotationPhase !== 'attempted') {
        transaction.abort();
        await completed.catch(() => undefined);
        throw new Error('No attempted pending credential can be promoted');
      }
      validateRecord(record);
      const promoted: CredentialRecord = {
        id: RECORD_ID,
        serverOrigin: record.serverOrigin,
        workspaceId: record.workspaceId.slice(),
        deviceId: record.deviceId.slice(),
        authToken: record.pendingAuthToken.slice(),
        identityKeyId: record.identityKeyId.slice(),
      };
      await requestResult(store.put(promoted));
      await completed;
      return copyCredential(promoted);
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

  private async readRecord(): Promise<CredentialRecord | undefined> {
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readonly');
      const completed = transactionCompleted(transaction);
      const record = await requestResult<CredentialRecord | undefined>(
        transaction.objectStore(STORE_NAME).get(RECORD_ID),
      );
      await completed;
      if (record !== undefined) validateRecord(record);
      return record;
    } finally {
      database.close();
    }
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
      request.onerror = () => reject(request.error ?? new Error('Failed to open transport credential database'));
      request.onblocked = () => reject(new Error('Transport credential database upgrade was blocked'));
    });
  }
}

function validateRecord(value: CredentialRecord): void {
  validateCredential(value);
  const hasPending = value.pendingAuthToken !== undefined;
  const hasPhase = value.rotationPhase !== undefined;
  if (hasPending !== hasPhase) throw new Error('Transport credential rotation state is incomplete');
  if (value.pendingAuthToken !== undefined) {
    validateBytes(value.pendingAuthToken, 32, 'pendingAuthToken', false);
    if (bytesEqual(value.authToken, value.pendingAuthToken)) {
      throw new Error('Pending credential must differ from current');
    }
  }
  if (value.rotationPhase !== undefined && value.rotationPhase !== 'prepared' &&
      value.rotationPhase !== 'attempted') {
    throw new Error('Transport credential rotation phase is invalid');
  }
}

function validateCredential(value: StoredTransportCredential): void {
  validateOrigin(value.serverOrigin);
  validateBytes(value.workspaceId, 16, 'workspaceId', true);
  validateBytes(value.deviceId, 16, 'deviceId', true);
  validateBytes(value.authToken, 32, 'authToken', false);
  validateBytes(value.identityKeyId, 32, 'identityKeyId', true);
}

export function normalizeServerOrigin(value: string): string {
  const parsed = new URL(value);
  if (parsed.username || parsed.password || parsed.search || parsed.hash ||
      (parsed.pathname !== '/' && parsed.pathname !== '')) {
    throw new Error('Server URL must contain only an origin');
  }
  const loopback = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' ||
    parsed.hostname === '[::1]';
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) {
    throw new Error('Server URL must use HTTPS outside loopback');
  }
  return parsed.origin;
}

function validateOrigin(value: string): void {
  if (normalizeServerOrigin(value) !== value) {
    throw new Error('serverOrigin must be canonical');
  }
}

function validateBytes(value: Uint8Array, size: number, name: string, nonZero: boolean): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== size ||
      (nonZero && value.every((byte) => byte === 0))) {
    throw new Error(`${name} must be ${nonZero ? 'a non-zero ' : ''}${size}-byte value`);
  }
}

function copyCredential(value: StoredTransportCredential): StoredTransportCredential {
  return {
    serverOrigin: value.serverOrigin,
    workspaceId: value.workspaceId.slice(),
    deviceId: value.deviceId.slice(),
    authToken: value.authToken.slice(),
    identityKeyId: value.identityKeyId.slice(),
  };
}

function rotationFromRecord(record: CredentialRecord): StoredCredentialRotation {
  if (record.pendingAuthToken === undefined || record.rotationPhase === undefined) {
    throw new Error('Transport credential rotation state is incomplete');
  }
  return {
    current: copyCredential(record),
    pendingAuthToken: record.pendingAuthToken.slice(),
    phase: record.rotationPhase,
  };
}

function credentialsEqual(left: StoredTransportCredential, right: StoredTransportCredential): boolean {
  return left.serverOrigin === right.serverOrigin &&
    bytesEqual(left.workspaceId, right.workspaceId) &&
    bytesEqual(left.deviceId, right.deviceId) &&
    bytesEqual(left.authToken, right.authToken) &&
    bytesEqual(left.identityKeyId, right.identityKeyId);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
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

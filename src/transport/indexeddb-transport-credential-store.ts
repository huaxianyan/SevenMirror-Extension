import type { DeviceTransportCredential } from './device-auth-frame';

const STORE_NAME = 'credentials';
const RECORD_ID = 'primary-transport-v1';
const DATABASE_VERSION = 1;

export interface StoredTransportCredential extends DeviceTransportCredential {
  serverOrigin: string;
  identityKeyId: Uint8Array;
}

interface CredentialRecord extends StoredTransportCredential {
  id: string;
}

/**
 * Extension-origin-only persistence for the bearer credential. It is never put
 * in chrome.storage.sync, a URL, or a log. Unlike an ECDH CryptoKey, WebSocket
 * authentication requires the raw 32 bytes, so fail-closed extension storage
 * and minimal lifetime are the available browser boundary.
 */
export class IndexedDbTransportCredentialStore {
  constructor(private readonly databaseName = 'syncnotifications-transport-v1') {}

  async load(): Promise<StoredTransportCredential | undefined> {
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readonly');
      const completed = transactionCompleted(transaction);
      const record = await requestResult<CredentialRecord | undefined>(
        transaction.objectStore(STORE_NAME).get(RECORD_ID),
      );
      await completed;
      if (record === undefined) return undefined;
      validateCredential(record);
      return copyCredential(record);
    } finally {
      database.close();
    }
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
        validateCredential(existing);
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

function credentialsEqual(left: StoredTransportCredential, right: StoredTransportCredential): boolean {
  return left.serverOrigin === right.serverOrigin &&
    bytesEqual(left.workspaceId, right.workspaceId) &&
    bytesEqual(left.deviceId, right.deviceId) &&
    bytesEqual(left.authToken, right.authToken) &&
    bytesEqual(left.identityKeyId, right.identityKeyId);
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

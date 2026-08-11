const STORE_NAME = 'approved-peer';
const DATABASE_VERSION = 1;
const IDENTIFIER_BYTES = 16;
const KEY_ID_BYTES = 32;
const P256_PUBLIC_KEY_BYTES = 65;

interface ApprovedPeerRecord {
  tuple: string;
  workspaceId: Uint8Array;
  deviceId: Uint8Array;
  keyId: Uint8Array;
  publicKey: Uint8Array;
}

/** Local immutable pins only; server directory data must never be written here directly. */
export class IndexedDbTrustedPeerStore {
  constructor(private readonly databaseName = 'syncnotifications-trusted-peers-v1') {}

  /** Called only after a separate trust/approval workflow has authenticated this exact key. */
  async pinApproved(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    publicKey: Uint8Array,
  ): Promise<'pinned' | 'already-pinned'> {
    validateIdentifier(workspaceId, 'workspaceId');
    validateIdentifier(deviceId, 'deviceId');
    validatePublicKey(publicKey);
    await validatePublicKeyPoint(publicKey);
    const keyId = await sha256(publicKey);
    const tuple = peerTuple(workspaceId, deviceId);
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const existing = await requestResult<ApprovedPeerRecord | undefined>(store.get(tuple));
      if (existing !== undefined) {
        await completed;
        validateRecord(existing);
        if (!bytesEqual(existing.keyId, keyId) || !bytesEqual(existing.publicKey, publicKey)) {
          throw new Error('Approved peer key replacement requires explicit removal and approval');
        }
        return 'already-pinned';
      }
      await requestResult(store.add({
        tuple,
        workspaceId: workspaceId.slice(),
        deviceId: deviceId.slice(),
        keyId,
        publicKey: publicKey.slice(),
      } satisfies ApprovedPeerRecord));
      await completed;
      return 'pinned';
    } finally {
      database.close();
    }
  }

  async findApproved(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    keyId: Uint8Array,
  ): Promise<Uint8Array | undefined> {
    validateIdentifier(workspaceId, 'workspaceId');
    validateIdentifier(deviceId, 'deviceId');
    validateKeyId(keyId);
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readonly');
      const completed = transactionCompleted(transaction);
      const record = await requestResult<ApprovedPeerRecord | undefined>(
        transaction.objectStore(STORE_NAME).get(peerTuple(workspaceId, deviceId)),
      );
      await completed;
      if (record === undefined) return undefined;
      validateRecord(record);
      await validatePublicKeyPoint(record.publicKey);
      if (!bytesEqual(record.keyId, await sha256(record.publicKey))) {
        throw new Error('Approved peer record key binding is corrupt');
      }
      if (!bytesEqual(record.keyId, keyId)) return undefined;
      return record.publicKey.slice();
    } finally {
      database.close();
    }
  }

  async remove(workspaceId: Uint8Array, deviceId: Uint8Array): Promise<void> {
    validateIdentifier(workspaceId, 'workspaceId');
    validateIdentifier(deviceId, 'deviceId');
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      await requestResult(
        transaction.objectStore(STORE_NAME).delete(peerTuple(workspaceId, deviceId)),
      );
      await completed;
    } finally {
      database.close();
    }
  }

  async clear(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.databaseName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error ?? new Error('Unable to delete trusted peer store'));
      request.onblocked = () => reject(new Error('Trusted peer store deletion was blocked'));
    });
  }

  private openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) {
          request.result.createObjectStore(STORE_NAME, { keyPath: 'tuple' });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Unable to open trusted peer store'));
      request.onblocked = () => reject(new Error('Trusted peer store open was blocked'));
    });
  }
}

function validateRecord(record: ApprovedPeerRecord): void {
  validateIdentifier(record.workspaceId, 'workspaceId');
  validateIdentifier(record.deviceId, 'deviceId');
  validateKeyId(record.keyId);
  validatePublicKey(record.publicKey);
  if (record.tuple !== peerTuple(record.workspaceId, record.deviceId)) {
    throw new Error('Approved peer record tuple is invalid');
  }
}

function validateIdentifier(value: Uint8Array, name: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== IDENTIFIER_BYTES ||
      value.every((byte) => byte === 0)) {
    throw new Error(`${name} must be a non-zero ${IDENTIFIER_BYTES}-byte value`);
  }
}

function validateKeyId(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== KEY_ID_BYTES ||
      value.every((byte) => byte === 0)) {
    throw new Error(`keyId must be a non-zero ${KEY_ID_BYTES}-byte value`);
  }
}

function validatePublicKey(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== P256_PUBLIC_KEY_BYTES || value[0] !== 4) {
    throw new Error('publicKey must be an uncompressed P-256 point');
  }
}

function peerTuple(workspaceId: Uint8Array, deviceId: Uint8Array): string {
  return `${toHex(workspaceId)}:${toHex(deviceId)}`;
}

async function validatePublicKeyPoint(value: Uint8Array): Promise<void> {
  try {
    await crypto.subtle.importKey(
      'raw',
      value.slice().buffer,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    );
  } catch {
    throw new Error('publicKey is not a valid P-256 point');
  }
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
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

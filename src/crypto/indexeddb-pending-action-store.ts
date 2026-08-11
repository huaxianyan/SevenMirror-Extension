import { ActionResultStatus } from '../protocol/generated/notification/v1/payload_pb';

export type PendingActionRegistration =
  | 'registered'
  | 'already-registered'
  | 'capacity-exceeded';

export type ActionResultReconciliation =
  | 'completed'
  | 'already-completed'
  | 'not-found'
  | 'sender-mismatch'
  | 'conflict';

export interface PendingActionRecord {
  idempotencyKey: string;
  senderDeviceId: string;
  operationDigest: string;
  createdAtUnixMs: number;
  expiresAtUnixMs: number;
  state: 'pending' | 'completed';
  resultStatus?: ActionResultStatus;
  resultDetail?: string;
  completedAtUnixMs?: number;
  canonicalInvokePayload?: Uint8Array;
  recipientKeyId?: Uint8Array;
  nextAttemptAtUnixMs?: number;
  invokeAttemptCount?: number;
}

export interface PendingInvokeDelivery {
  idempotencyKey: Uint8Array;
  recipientDeviceId: Uint8Array;
  recipientKeyId: Uint8Array;
  canonicalInvokePayload: Uint8Array;
  attemptCount: number;
  expiresAtUnixMs: number;
}

const STORE_NAME = 'pending-action';
const EXPIRY_INDEX = 'by-expiry';
const DATABASE_VERSION = 1;
const IDENTIFIER_BYTES = 16;
const DIGEST_BYTES = 32;

/** Persistent correlation state for action.invoke/action.result across MV3 restarts. */
export class IndexedDbPendingActionStore {
  private readonly databaseName: string;

  constructor(
    storeName = 'default',
    private readonly maxEntries = 4096,
  ) {
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(storeName)) {
      throw new Error('storeName must be 1-64 URL-safe characters');
    }
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new Error('maxEntries must be a positive safe integer');
    }
    this.databaseName = `syncnotifications-pending-actions-${storeName}`;
  }

  /** Must complete before the corresponding action.invoke can be transmitted. */
  async register(
    idempotencyKey: Uint8Array,
    senderDeviceId: Uint8Array,
    operationDigest: Uint8Array,
    createdAtUnixMs: number,
    expiresAtUnixMs: number,
    canonicalInvokePayload?: Uint8Array,
    recipientKeyId?: Uint8Array,
  ): Promise<PendingActionRegistration> {
    validateIdentifier(idempotencyKey, 'idempotencyKey', true);
    validateIdentifier(senderDeviceId, 'senderDeviceId', true);
    validateDigest(operationDigest);
    validateTimestamp(createdAtUnixMs, 'createdAtUnixMs');
    validateTimestamp(expiresAtUnixMs, 'expiresAtUnixMs');
    if (expiresAtUnixMs <= createdAtUnixMs) {
      throw new Error('expiresAtUnixMs must be greater than createdAtUnixMs');
    }
    if ((canonicalInvokePayload === undefined) !== (recipientKeyId === undefined)) {
      throw new Error('Invoke delivery payload and recipient key must be provided together');
    }
    if (canonicalInvokePayload !== undefined && recipientKeyId !== undefined) {
      validateKeyId(recipientKeyId);
      if (!bytesEqual(await sha256(canonicalInvokePayload), operationDigest)) {
        throw new Error('Canonical invoke payload does not match operation digest');
      }
    }

    return this.withWriteTransaction(async (store) => {
      await purgeExpired(store, createdAtUnixMs);
      const key = toHex(idempotencyKey);
      const sender = toHex(senderDeviceId);
      const digest = toHex(operationDigest);
      const existing = await requestResult<PendingActionRecord | undefined>(store.get(key));
      if (existing !== undefined) {
        if (existing.senderDeviceId !== sender || existing.operationDigest !== digest) {
          throw new Error('Idempotency key is already bound to another operation');
        }
        if (canonicalInvokePayload !== undefined && recipientKeyId !== undefined) {
          if (existing.state === 'completed') {
            throw new Error('Idempotency key already has a terminal result');
          }
          if (existing.canonicalInvokePayload !== undefined &&
              !bytesEqual(existing.canonicalInvokePayload, canonicalInvokePayload)) {
            throw new Error('Idempotency key is already bound to different invoke bytes');
          }
          if (existing.recipientKeyId !== undefined &&
              !bytesEqual(existing.recipientKeyId, recipientKeyId)) {
            throw new Error('Idempotency key is already bound to a different recipient key');
          }
          if (existing.state === 'pending') {
            await requestResult(store.put({
              ...existing,
              canonicalInvokePayload: canonicalInvokePayload.slice(),
              recipientKeyId: recipientKeyId.slice(),
              nextAttemptAtUnixMs: createdAtUnixMs,
              invokeAttemptCount: 0,
            } satisfies PendingActionRecord));
          }
        }
        return 'already-registered';
      }
      if (await requestResult<number>(store.count()) >= this.maxEntries) {
        return 'capacity-exceeded';
      }
      await requestResult(store.add({
        idempotencyKey: key,
        senderDeviceId: sender,
        operationDigest: digest,
        createdAtUnixMs,
        expiresAtUnixMs,
        state: 'pending',
        ...(canonicalInvokePayload === undefined || recipientKeyId === undefined ? {} : {
          canonicalInvokePayload: canonicalInvokePayload.slice(),
          recipientKeyId: recipientKeyId.slice(),
          nextAttemptAtUnixMs: createdAtUnixMs,
          invokeAttemptCount: 0,
        }),
      } satisfies PendingActionRecord));
      return 'registered';
    });
  }

  /** Atomically applies only an authenticated result from the expected Android device. */
  async reconcile(
    idempotencyKey: Uint8Array,
    senderDeviceId: Uint8Array,
    status: ActionResultStatus,
    detail: string | undefined,
    nowUnixMs: number,
  ): Promise<ActionResultReconciliation> {
    validateIdentifier(idempotencyKey, 'idempotencyKey', true);
    validateIdentifier(senderDeviceId, 'senderDeviceId', true);
    validateResult(status, detail);
    validateTimestamp(nowUnixMs, 'nowUnixMs');

    return this.withWriteTransaction(async (store) => {
      await purgeExpired(store, nowUnixMs);
      const key = toHex(idempotencyKey);
      const existing = await requestResult<PendingActionRecord | undefined>(store.get(key));
      if (existing === undefined) return 'not-found';
      if (existing.senderDeviceId !== toHex(senderDeviceId)) return 'sender-mismatch';
      if (existing.state === 'completed') {
        return existing.resultStatus === status && existing.resultDetail === detail
          ? 'already-completed'
          : 'conflict';
      }
      await requestResult(store.put({
        ...existing,
        state: 'completed',
        resultStatus: status,
        resultDetail: detail,
        completedAtUnixMs: nowUnixMs,
      } satisfies PendingActionRecord));
      return 'completed';
    });
  }

  async dueInvokes(nowUnixMs: number, limit = 16): Promise<PendingInvokeDelivery[]> {
    validateTimestamp(nowUnixMs, 'nowUnixMs');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 128) {
      throw new Error('limit must be 1..128');
    }
    return this.withWriteTransaction(async (store) => {
      await purgeExpired(store, nowUnixMs);
      const records = await requestResult<PendingActionRecord[]>(store.getAll());
      records.forEach(validateDeliveryRecord);
      return records
        .filter((record) => record.state === 'pending' &&
          record.canonicalInvokePayload !== undefined && record.recipientKeyId !== undefined &&
          record.nextAttemptAtUnixMs !== undefined && record.nextAttemptAtUnixMs <= nowUnixMs)
        .sort((left, right) =>
          (left.nextAttemptAtUnixMs! - right.nextAttemptAtUnixMs!) ||
          left.idempotencyKey.localeCompare(right.idempotencyKey))
        .slice(0, limit)
        .map((record) => ({
          idempotencyKey: fromHex(record.idempotencyKey, IDENTIFIER_BYTES),
          recipientDeviceId: fromHex(record.senderDeviceId, IDENTIFIER_BYTES),
          recipientKeyId: record.recipientKeyId!.slice(),
          canonicalInvokePayload: record.canonicalInvokePayload!.slice(),
          attemptCount: record.invokeAttemptCount ?? 0,
          expiresAtUnixMs: record.expiresAtUnixMs,
        }));
    });
  }

  /** Records only a frame synchronously accepted by WebSocket.send. */
  async recordInvokeSendAttempt(
    idempotencyKey: Uint8Array,
    nextAttemptAtUnixMs: number,
    maximumAttempts = 5,
  ): Promise<void> {
    validateIdentifier(idempotencyKey, 'idempotencyKey', true);
    validateTimestamp(nextAttemptAtUnixMs, 'nextAttemptAtUnixMs');
    if (!Number.isSafeInteger(maximumAttempts) || maximumAttempts < 1) {
      throw new Error('maximumAttempts must be positive');
    }
    await this.withWriteTransaction(async (store) => {
      const key = toHex(idempotencyKey);
      const existing = await requestResult<PendingActionRecord | undefined>(store.get(key));
      if (existing === undefined || existing.state !== 'pending' ||
          existing.canonicalInvokePayload === undefined) return;
      const attemptCount = (existing.invokeAttemptCount ?? 0) + 1;
      await requestResult(store.put({
        ...existing,
        invokeAttemptCount: attemptCount,
        nextAttemptAtUnixMs: attemptCount >= maximumAttempts
          ? existing.expiresAtUnixMs
          : nextAttemptAtUnixMs,
      } satisfies PendingActionRecord));
    });
  }

  async get(idempotencyKey: Uint8Array): Promise<PendingActionRecord | undefined> {
    validateIdentifier(idempotencyKey, 'idempotencyKey', true);
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readonly');
      const completed = transactionCompleted(transaction);
      const result = await requestResult<PendingActionRecord | undefined>(
        transaction.objectStore(STORE_NAME).get(toHex(idempotencyKey)),
      );
      await completed;
      return result;
    } finally {
      database.close();
    }
  }

  async clear(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.databaseName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error ?? new Error('Unable to delete pending action store'));
      request.onblocked = () => reject(new Error('Pending action store deletion was blocked'));
    });
  }

  private async withWriteTransaction<T>(work: (store: IDBObjectStore) => Promise<T>): Promise<T> {
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      try {
        const result = await work(transaction.objectStore(STORE_NAME));
        await completed;
        return result;
      } catch (error: unknown) {
        await completed.catch(() => undefined);
        throw error;
      }
    } finally {
      database.close();
    }
  }

  private async openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        const store = request.result.createObjectStore(STORE_NAME, { keyPath: 'idempotencyKey' });
        store.createIndex(EXPIRY_INDEX, 'expiresAtUnixMs', { unique: false });
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Unable to open pending action store'));
      request.onblocked = () => reject(new Error('Pending action store open was blocked'));
    });
  }
}

async function purgeExpired(store: IDBObjectStore, nowUnixMs: number): Promise<void> {
  const keys = await requestResult<IDBValidKey[]>(
    store.index(EXPIRY_INDEX).getAllKeys(IDBKeyRange.upperBound(nowUnixMs)),
  );
  await Promise.all(keys.map((key) => requestResult(store.delete(key))));
}

function validateDeliveryRecord(record: PendingActionRecord): void {
  const values = [
    record.canonicalInvokePayload,
    record.recipientKeyId,
    record.nextAttemptAtUnixMs,
    record.invokeAttemptCount,
  ];
  if (values.every((value) => value === undefined)) return;
  if (values.some((value) => value === undefined)) {
    throw new Error('Stored invoke delivery state is partial');
  }
  if (!(record.canonicalInvokePayload instanceof Uint8Array) ||
      record.canonicalInvokePayload.byteLength === 0) {
    throw new Error('Stored invoke payload is corrupt');
  }
  validateKeyId(record.recipientKeyId!);
  validateTimestamp(record.nextAttemptAtUnixMs!, 'nextAttemptAtUnixMs');
  if (!Number.isSafeInteger(record.invokeAttemptCount) || record.invokeAttemptCount! < 0) {
    throw new Error('Stored invoke attempt count is corrupt');
  }
}

function validateResult(status: ActionResultStatus, detail: string | undefined): void {
  if (status < ActionResultStatus.SUCCEEDED || status > ActionResultStatus.OUTCOME_UNKNOWN) {
    throw new Error('Action result status is unsupported');
  }
  if (detail !== undefined) {
    const size = new TextEncoder().encode(detail).byteLength;
    if (size < 1 || size > 256) {
      throw new Error('Action result detail is out of range');
    }
  }
}

function validateIdentifier(value: Uint8Array, name: string, nonZero: boolean): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== IDENTIFIER_BYTES) {
    throw new Error(`${name} must be ${IDENTIFIER_BYTES} bytes`);
  }
  if (nonZero && value.every((byte) => byte === 0)) {
    throw new Error(`${name} must not be zero`);
  }
}

function validateKeyId(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== DIGEST_BYTES ||
      value.every((byte) => byte === 0)) {
    throw new Error(`recipientKeyId must be a non-zero ${DIGEST_BYTES}-byte value`);
  }
}

function validateDigest(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== DIGEST_BYTES) {
    throw new Error(`operationDigest must be ${DIGEST_BYTES} bytes`);
  }
}

function validateTimestamp(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

function fromHex(value: string, expectedBytes: number): Uint8Array {
  if (value.length !== expectedBytes * 2 || !/^[0-9a-f]+$/.test(value)) {
    throw new Error('Stored pending action identifier is corrupt');
  }
  return Uint8Array.from({ length: expectedBytes }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16));
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

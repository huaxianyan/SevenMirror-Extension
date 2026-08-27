const STORE_NAME = 'relay-delivery-cursor';
const DATABASE_VERSION = 1;
const MAX_CURSOR = 0x7fff_ffff_ffff_ffffn;

interface StoredRelayDeliveryCursor {
  tuple: string;
  committedDeliveryId: string;
  snapshotRequiredHighWater?: string;
}

export interface RelayDeliveryCursorState {
  committedDeliveryId: bigint;
  snapshotRequiredHighWater?: bigint;
}

export class IndexedDbRelayDeliveryCursorStore {
  constructor(private readonly databaseName = 'syncnotifications-relay-delivery-cursor-v1') {}

  async load(workspaceId: Uint8Array, deviceId: Uint8Array): Promise<RelayDeliveryCursorState> {
    const tuple = cursorTuple(workspaceId, deviceId);
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readonly');
      const completed = transactionCompleted(transaction);
      const stored = await requestResult<StoredRelayDeliveryCursor | undefined>(
        transaction.objectStore(STORE_NAME).get(tuple),
      );
      await completed;
      return stored === undefined
        ? { committedDeliveryId: 0n }
        : decodeStored(stored, tuple);
    } finally {
      database.close();
    }
  }

  async commitDelivery(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    deliveryId: bigint,
  ): Promise<RelayDeliveryCursorState> {
    validateCursor(deliveryId, false);
    return this.mutate(workspaceId, deviceId, (current) => {
      if (current.snapshotRequiredHighWater !== undefined) {
        throw new Error('Relay delivery cursor requires snapshot reconciliation');
      }
      if (deliveryId === current.committedDeliveryId) return current;
      if (deliveryId !== current.committedDeliveryId + 1n) {
        throw new Error('Relay deliveries are not contiguous');
      }
      return { committedDeliveryId: deliveryId };
    });
  }

  async requireSnapshot(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    highWater: bigint,
  ): Promise<RelayDeliveryCursorState> {
    validateCursor(highWater, true);
    return this.mutate(workspaceId, deviceId, (current) => {
      if (highWater < current.committedDeliveryId) {
        throw new Error('Relay snapshot high-water is behind the committed cursor');
      }
      const existing = current.snapshotRequiredHighWater;
      return {
        committedDeliveryId: current.committedDeliveryId,
        snapshotRequiredHighWater: existing === undefined || highWater > existing
          ? highWater
          : existing,
      };
    });
  }

  async clear(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.databaseName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error ?? new Error('Unable to delete relay cursor state'));
      request.onblocked = () => reject(new Error('Relay cursor deletion was blocked'));
    });
  }

  private async mutate(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    update: (current: RelayDeliveryCursorState) => RelayDeliveryCursorState,
  ): Promise<RelayDeliveryCursorState> {
    const tuple = cursorTuple(workspaceId, deviceId);
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      try {
        const store = transaction.objectStore(STORE_NAME);
        const stored = await requestResult<StoredRelayDeliveryCursor | undefined>(store.get(tuple));
        const current = stored === undefined
          ? { committedDeliveryId: 0n }
          : decodeStored(stored, tuple);
        const next = update(current);
        validateState(next);
        await requestResult(store.put({
          tuple,
          committedDeliveryId: next.committedDeliveryId.toString(),
          ...(next.snapshotRequiredHighWater === undefined
            ? {}
            : { snapshotRequiredHighWater: next.snapshotRequiredHighWater.toString() }),
        } satisfies StoredRelayDeliveryCursor));
        await completed;
        return { ...next };
      } catch (error) {
        try {
          transaction.abort();
        } catch {
          // A failed request may already have aborted the transaction.
        }
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
        request.result.createObjectStore(STORE_NAME, { keyPath: 'tuple' });
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Unable to open relay cursor state'));
      request.onblocked = () => reject(new Error('Relay cursor state open was blocked'));
    });
  }
}

function cursorTuple(workspaceId: Uint8Array, deviceId: Uint8Array): string {
  validateId(workspaceId, 'workspaceId');
  validateId(deviceId, 'deviceId');
  return `${toHex(workspaceId)}:${toHex(deviceId)}`;
}

function decodeStored(stored: StoredRelayDeliveryCursor, expectedTuple: string): RelayDeliveryCursorState {
  if (stored.tuple !== expectedTuple) throw new Error('Stored relay cursor tuple is corrupt');
  const state: RelayDeliveryCursorState = {
    committedDeliveryId: parseCursor(stored.committedDeliveryId, true),
    ...(stored.snapshotRequiredHighWater === undefined
      ? {}
      : { snapshotRequiredHighWater: parseCursor(stored.snapshotRequiredHighWater, true) }),
  };
  validateState(state);
  return state;
}

function validateState(state: RelayDeliveryCursorState): void {
  validateCursor(state.committedDeliveryId, true);
  if (state.snapshotRequiredHighWater !== undefined) {
    validateCursor(state.snapshotRequiredHighWater, true);
    if (state.snapshotRequiredHighWater < state.committedDeliveryId) {
      throw new Error('Stored relay snapshot high-water is corrupt');
    }
  }
}

function parseCursor(value: string, allowZero: boolean): bigint {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error('Stored relay delivery cursor is corrupt');
  }
  const cursor = BigInt(value);
  validateCursor(cursor, allowZero);
  return cursor;
}

function validateCursor(cursor: bigint, allowZero: boolean): void {
  if (cursor < 0n || cursor > MAX_CURSOR || (!allowZero && cursor === 0n)) {
    throw new Error('Relay delivery cursor is out of range');
  }
}

function validateId(value: Uint8Array, name: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== 16 ||
      value.every((byte) => byte === 0)) {
    throw new Error(`${name} must be a non-zero 16-byte identifier`);
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

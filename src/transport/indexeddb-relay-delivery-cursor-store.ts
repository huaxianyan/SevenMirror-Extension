const STORE_NAME = 'relay-delivery-cursor';
const DATABASE_VERSION = 1;
const MAX_CURSOR = 0x7fff_ffff_ffff_ffffn;

interface StoredRelayDeliveryCursor {
  tuple: string;
  committedDeliveryId: string;
  snapshotRequiredHighWater?: string;
  recoveryRequestId?: string;
  expectedSources?: Array<{ deviceId: string; keyId: string }>;
  completedSourceIds?: string[];
}

export interface RelayDeliveryRecoverySource {
  deviceId: Uint8Array;
  keyId: Uint8Array;
}

export interface RelayDeliveryRecoverySession {
  requestId: Uint8Array;
  expectedSources: RelayDeliveryRecoverySource[];
  completedSourceIds: Uint8Array[];
}

export interface RelayDeliveryCursorState {
  committedDeliveryId: bigint;
  snapshotRequiredHighWater?: bigint;
  recovery?: RelayDeliveryRecoverySession;
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
      if (existing !== undefined && highWater === existing) return current;
      return {
        committedDeliveryId: current.committedDeliveryId,
        snapshotRequiredHighWater: existing === undefined || highWater > existing
          ? highWater
          : existing,
      };
    });
  }

  async beginSnapshotRecovery(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    highWater: bigint,
    requestId: Uint8Array,
    expectedSources: RelayDeliveryRecoverySource[],
  ): Promise<RelayDeliveryCursorState> {
    validateCursor(highWater, true);
    validateId(requestId, 'recoveryRequestId');
    const expected = canonicalSources(expectedSources);
    return this.mutate(workspaceId, deviceId, (current) => {
      if (current.snapshotRequiredHighWater !== highWater) {
        throw new Error('Snapshot recovery high-water does not match relay reset');
      }
      if (current.recovery !== undefined) {
        if (!equal(current.recovery.requestId, requestId) ||
            !sameSources(current.recovery.expectedSources, expected)) {
          throw new Error('Snapshot recovery session is already bound');
        }
        return current;
      }
      return {
        ...current,
        recovery: {
          requestId: requestId.slice(),
          expectedSources: expected,
          completedSourceIds: [],
        },
      };
    });
  }

  async recordSnapshotRecoverySource(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    requestId: Uint8Array,
    sourceDeviceId: Uint8Array,
    sourceKeyId: Uint8Array,
  ): Promise<RelayDeliveryCursorState> {
    validateId(requestId, 'recoveryRequestId');
    validateId(sourceDeviceId, 'sourceDeviceId');
    validateKeyId(sourceKeyId);
    return this.mutate(workspaceId, deviceId, (current) => {
      const recovery = current.recovery;
      if (recovery === undefined || !equal(recovery.requestId, requestId)) {
        throw new Error('Snapshot recovery request id is not active');
      }
      const source = toHex(sourceDeviceId);
      if (!recovery.expectedSources.some((candidate) =>
        toHex(candidate.deviceId) === source && equal(candidate.keyId, sourceKeyId))) {
        throw new Error('Snapshot source identity is not part of the recovery session');
      }
      const completed = canonicalSourceIds([...recovery.completedSourceIds, sourceDeviceId]);
      return { ...current, recovery: { ...recovery, completedSourceIds: completed } };
    });
  }

  async acceptSnapshotRecovery(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    requestId: Uint8Array,
  ): Promise<RelayDeliveryCursorState> {
    validateId(requestId, 'recoveryRequestId');
    return this.mutate(workspaceId, deviceId, (current) => {
      const recovery = current.recovery;
      const highWater = current.snapshotRequiredHighWater;
      if (recovery === undefined || highWater === undefined || !equal(recovery.requestId, requestId) ||
          !sameIds(recovery.expectedSources.map((source) => source.deviceId), recovery.completedSourceIds)) {
        throw new Error('Snapshot recovery is incomplete');
      }
      return { committedDeliveryId: highWater };
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
        await requestResult(store.put(encodeStored(next, tuple)));
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
  const recoveryFields = [stored.recoveryRequestId, stored.expectedSources, stored.completedSourceIds];
  if (recoveryFields.some((value) => value !== undefined) &&
      recoveryFields.some((value) => value === undefined)) {
    throw new Error('Stored relay snapshot recovery is corrupt');
  }
  const state: RelayDeliveryCursorState = {
    committedDeliveryId: parseCursor(stored.committedDeliveryId, true),
    ...(stored.snapshotRequiredHighWater === undefined
      ? {}
      : { snapshotRequiredHighWater: parseCursor(stored.snapshotRequiredHighWater, true) }),
    ...(stored.recoveryRequestId === undefined ? {} : {
      recovery: {
        requestId: fromHex(stored.recoveryRequestId, 'recovery request id', 16),
        expectedSources: stored.expectedSources!.map((value) => ({
          deviceId: fromHex(value.deviceId, 'source device id', 16),
          keyId: fromHex(value.keyId, 'source key id', 32),
        })),
        completedSourceIds: stored.completedSourceIds!.map((value) =>
          fromHex(value, 'source device id', 16)),
      },
    }),
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
  if (state.recovery !== undefined) {
    if (state.snapshotRequiredHighWater === undefined) {
      throw new Error('Stored relay snapshot recovery is corrupt');
    }
    validateId(state.recovery.requestId, 'recoveryRequestId');
    const expected = canonicalSources(state.recovery.expectedSources);
    const completed = canonicalSourceIds(state.recovery.completedSourceIds);
    if (!sameSources(expected, state.recovery.expectedSources) ||
        !sameIds(completed, state.recovery.completedSourceIds) ||
        completed.some((value) => !expected.some((candidate) => equal(value, candidate.deviceId)))) {
      throw new Error('Stored relay snapshot recovery is corrupt');
    }
  }
}

function encodeStored(state: RelayDeliveryCursorState, tuple: string): StoredRelayDeliveryCursor {
  return {
    tuple,
    committedDeliveryId: state.committedDeliveryId.toString(),
    ...(state.snapshotRequiredHighWater === undefined
      ? {}
      : { snapshotRequiredHighWater: state.snapshotRequiredHighWater.toString() }),
    ...(state.recovery === undefined ? {} : {
      recoveryRequestId: toHex(state.recovery.requestId),
      expectedSources: state.recovery.expectedSources.map((source) => ({
        deviceId: toHex(source.deviceId),
        keyId: toHex(source.keyId),
      })),
      completedSourceIds: state.recovery.completedSourceIds.map(toHex),
    }),
  };
}

function canonicalSources(values: RelayDeliveryRecoverySource[]): RelayDeliveryRecoverySource[] {
  const unique = new Map<string, RelayDeliveryRecoverySource>();
  for (const value of values) {
    validateId(value.deviceId, 'sourceDeviceId');
    validateKeyId(value.keyId);
    const deviceId = toHex(value.deviceId);
    const existing = unique.get(deviceId);
    if (existing !== undefined && !equal(existing.keyId, value.keyId)) {
      throw new Error('Snapshot recovery source has conflicting identities');
    }
    unique.set(deviceId, { deviceId: value.deviceId.slice(), keyId: value.keyId.slice() });
  }
  return [...unique.entries()].sort(([left], [right]) => left.localeCompare(right))
    .map(([, value]) => value);
}

function canonicalSourceIds(values: Uint8Array[]): Uint8Array[] {
  const unique = new Map<string, Uint8Array>();
  for (const value of values) {
    validateId(value, 'sourceDeviceId');
    unique.set(toHex(value), value.slice());
  }
  return [...unique.entries()].sort(([left], [right]) => left.localeCompare(right))
    .map(([, value]) => value);
}

function sameSources(
  left: RelayDeliveryRecoverySource[],
  right: RelayDeliveryRecoverySource[],
): boolean {
  return left.length === right.length && left.every((value, index) =>
    equal(value.deviceId, right[index]!.deviceId) && equal(value.keyId, right[index]!.keyId));
}

function sameIds(left: Uint8Array[], right: Uint8Array[]): boolean {
  return left.length === right.length && left.every((value, index) => equal(value, right[index]!));
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}

function fromHex(value: string, name: string, byteLength: number): Uint8Array {
  if (!(new RegExp(`^[0-9a-f]{${byteLength * 2}}$`)).test(value)) {
    throw new Error(`Stored ${name} is corrupt`);
  }
  return Uint8Array.from({ length: byteLength }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16));
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

function validateKeyId(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== 32 ||
      value.every((byte) => byte === 0)) {
    throw new Error('sourceKeyId must be a non-zero 32-byte identifier');
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

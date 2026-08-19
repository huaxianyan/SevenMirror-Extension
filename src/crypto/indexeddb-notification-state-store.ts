import {
  createNotificationRemovedPayload,
  encodeEncryptedPayloadV1,
} from '../protocol/encrypted-payload';
import type {
  NotificationRemoved,
  NotificationSnapshotManifest,
  NotificationUpsert,
} from '../protocol/generated/notification/v1/payload_pb';

const STORE_NAME = 'notification-state';
const SNAPSHOT_STORE_NAME = 'notification-snapshot';
const DATABASE_VERSION = 2;

export interface MirroredNotificationState {
  tuple: string;
  sourceDeviceId: Uint8Array;
  notificationId: string;
  chromeNotificationId: string;
  revision: string;
  phase: 'visible' | 'removed';
  payloadSha256: Uint8Array;
  title?: string;
  body?: string;
}

export interface NotificationStateReconciliation {
  disposition: 'applied' | 'already-applied' | 'stale';
  state: MirroredNotificationState;
}

export interface NotificationSnapshotReconciliation {
  disposition: 'applied' | 'already-applied' | 'stale';
  closedStates: MirroredNotificationState[];
}

interface StoredNotificationSnapshot {
  sourceKey: string;
  sourceDeviceId: Uint8Array;
  highWaterRevision: string;
  manifestSha256: Uint8Array;
}

export class IndexedDbNotificationStateStore {
  constructor(private readonly databaseName = 'syncnotifications-notification-state-v1') {}

  async reconcileUpsert(
    sourceDeviceId: Uint8Array,
    notification: NotificationUpsert,
    canonicalPayload: Uint8Array,
  ): Promise<NotificationStateReconciliation> {
    return this.reconcile(sourceDeviceId, {
      notificationId: notification.notificationId,
      revision: notification.notificationRevision,
      phase: 'visible',
      payloadSha256: await sha256(canonicalPayload),
      ...(notification.title === undefined ? {} : { title: notification.title }),
      ...(notification.body === undefined ? {} : { body: notification.body }),
    });
  }

  async reconcileRemoved(
    sourceDeviceId: Uint8Array,
    notification: NotificationRemoved,
    canonicalPayload: Uint8Array,
  ): Promise<NotificationStateReconciliation> {
    return this.reconcile(sourceDeviceId, {
      notificationId: notification.notificationId,
      revision: notification.notificationRevision,
      phase: 'removed',
      payloadSha256: await sha256(canonicalPayload),
    });
  }

  async reconcileSnapshot(
    sourceDeviceId: Uint8Array,
    manifest: NotificationSnapshotManifest,
    canonicalPayload: Uint8Array,
  ): Promise<NotificationSnapshotReconciliation> {
    validateDeviceId(sourceDeviceId);
    const sourceKey = toHex(sourceDeviceId);
    const highWaterRevision = manifest.highWaterRevision;
    const manifestSha256 = await sha256(canonicalPayload);

    // WebCrypto hashing cannot safely keep an IndexedDB transaction active. Compute exact
    // snapshot-derived removal bindings first, then re-read and compare every source record
    // inside the atomic write transaction before applying them.
    const observedStates = await this.listSourceStates(sourceKey);
    const activeIds = new Set(manifest.activeNotifications.map((entry) => entry.notificationId));
    const derivedRemovalDigests = new Map<string, Uint8Array>();
    for (const state of observedStates) {
      if (state.phase === 'visible' && !activeIds.has(state.notificationId) &&
          BigInt(state.revision) < highWaterRevision) {
        const removed = encodeEncryptedPayloadV1(createNotificationRemovedPayload({
          notificationId: state.notificationId,
          notificationRevision: highWaterRevision,
        }));
        derivedRemovalDigests.set(state.notificationId, await sha256(removed));
        removed.fill(0);
      }
    }

    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(
        [STORE_NAME, SNAPSHOT_STORE_NAME],
        'readwrite',
      );
      const completed = transactionCompleted(transaction);
      try {
        const stateStore = transaction.objectStore(STORE_NAME);
        const snapshotStore = transaction.objectStore(SNAPSHOT_STORE_NAME);
        const existingSnapshot = await requestResult<StoredNotificationSnapshot | undefined>(
          snapshotStore.get(sourceKey),
        );
        if (existingSnapshot !== undefined) {
          validateStoredSnapshot(existingSnapshot);
          const storedHighWater = BigInt(existingSnapshot.highWaterRevision);
          if (highWaterRevision < storedHighWater) {
            await completed;
            return { disposition: 'stale', closedStates: [] };
          }
          if (highWaterRevision === storedHighWater) {
            if (!bytesEqual(existingSnapshot.manifestSha256, manifestSha256)) {
              throw new Error('Snapshot high-water revision is bound to different canonical bytes');
            }
            const repeatedStates = await readSourceStates(stateStore, sourceKey);
            if (!sameStateSet(observedStates, repeatedStates)) {
              throw new Error('Notification state changed during snapshot reconciliation');
            }
            await completed;
            return {
              disposition: 'already-applied',
              closedStates: repeatedStates.filter((state) =>
                state.phase === 'removed' &&
                BigInt(state.revision) === highWaterRevision &&
                !activeIds.has(state.notificationId),
              ).map(copyState),
            };
          }
        }

        const currentStates = await readSourceStates(stateStore, sourceKey);
        if (!sameStateSet(observedStates, currentStates)) {
          throw new Error('Notification state changed during snapshot reconciliation');
        }
        const byId = new Map(currentStates.map((state) => [state.notificationId, state]));
        for (const entry of manifest.activeNotifications) {
          const state = byId.get(entry.notificationId);
          if (state === undefined || BigInt(state.revision) < entry.notificationRevision) {
            throw new Error('Snapshot entry is missing its durable notification upsert');
          }
          if (BigInt(state.revision) === entry.notificationRevision && state.phase !== 'visible') {
            throw new Error('Snapshot entry conflicts with a removed notification revision');
          }
        }

        const closedStates: MirroredNotificationState[] = [];
        for (const state of currentStates) {
          if (state.phase !== 'visible' || activeIds.has(state.notificationId)) continue;
          const revision = BigInt(state.revision);
          if (revision > highWaterRevision) continue;
          if (revision === highWaterRevision) {
            throw new Error('Snapshot omits an active notification at its high-water revision');
          }
          const removedState: MirroredNotificationState = {
            tuple: state.tuple,
            sourceDeviceId: state.sourceDeviceId.slice(),
            notificationId: state.notificationId,
            chromeNotificationId: state.chromeNotificationId,
            revision: highWaterRevision.toString(),
            phase: 'removed',
            payloadSha256: requireDigest(derivedRemovalDigests.get(state.notificationId)),
          };
          await requestResult(stateStore.put(removedState));
          closedStates.push(copyState(removedState));
        }
        const storedSnapshot: StoredNotificationSnapshot = {
          sourceKey,
          sourceDeviceId: sourceDeviceId.slice(),
          highWaterRevision: highWaterRevision.toString(),
          manifestSha256: manifestSha256.slice(),
        };
        await requestResult(snapshotStore.put(storedSnapshot));
        await completed;
        return { disposition: 'applied', closedStates };
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

  async clear(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.databaseName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error ?? new Error('Unable to delete notification state'));
      request.onblocked = () => reject(new Error('Notification state deletion was blocked'));
    });
  }

  private async reconcile(
    sourceDeviceId: Uint8Array,
    incoming: Omit<MirroredNotificationState, 'tuple' | 'sourceDeviceId' | 'chromeNotificationId' | 'revision'> & {
      revision: bigint;
    },
  ): Promise<NotificationStateReconciliation> {
    validateDeviceId(sourceDeviceId);
    const tuple = `${toHex(sourceDeviceId)}:${incoming.notificationId}`;
    const proposed: MirroredNotificationState = {
      ...incoming,
      tuple,
      sourceDeviceId: sourceDeviceId.slice(),
      chromeNotificationId: await chromeNotificationId(sourceDeviceId, incoming.notificationId),
      revision: incoming.revision.toString(),
      payloadSha256: incoming.payloadSha256.slice(),
    };
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      try {
        const existing = await requestResult<MirroredNotificationState | undefined>(store.get(tuple));
        if (existing !== undefined) {
          validateStored(existing);
          const comparison = incoming.revision === BigInt(existing.revision)
            ? 0
            : incoming.revision < BigInt(existing.revision) ? -1 : 1;
          if (comparison < 0) {
            await completed;
            return { disposition: 'stale', state: copyState(existing) };
          }
          if (comparison === 0) {
            if (existing.phase !== proposed.phase ||
                !bytesEqual(existing.payloadSha256, proposed.payloadSha256)) {
              throw new Error('Notification revision is already bound to different canonical bytes');
            }
            await completed;
            return { disposition: 'already-applied', state: copyState(existing) };
          }
        }
        await requestResult(store.put(proposed));
        await completed;
        return { disposition: 'applied', state: copyState(proposed) };
      } catch (error) {
        await completed.catch(() => undefined);
        throw error;
      }
    } finally {
      database.close();
    }
  }

  private async listSourceStates(sourceKey: string): Promise<MirroredNotificationState[]> {
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readonly');
      const completed = transactionCompleted(transaction);
      const states = await readSourceStates(transaction.objectStore(STORE_NAME), sourceKey);
      await completed;
      return states;
    } finally {
      database.close();
    }
  }

  private async openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) {
          request.result.createObjectStore(STORE_NAME, { keyPath: 'tuple' });
        }
        if (!request.result.objectStoreNames.contains(SNAPSHOT_STORE_NAME)) {
          request.result.createObjectStore(SNAPSHOT_STORE_NAME, { keyPath: 'sourceKey' });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Unable to open notification state'));
      request.onblocked = () => reject(new Error('Notification state open was blocked'));
    });
  }
}

function validateStored(state: MirroredNotificationState): void {
  validateDeviceId(state.sourceDeviceId);
  if (!/^[1-9][0-9]*$/.test(state.revision) || BigInt(state.revision) > 0x7fff_ffff_ffff_ffffn) {
    throw new Error('Stored notification revision is corrupt');
  }
  if (state.phase !== 'visible' && state.phase !== 'removed') {
    throw new Error('Stored notification phase is corrupt');
  }
  if (!(state.payloadSha256 instanceof Uint8Array) || state.payloadSha256.byteLength !== 32) {
    throw new Error('Stored notification digest is corrupt');
  }
}

function validateStoredSnapshot(snapshot: StoredNotificationSnapshot): void {
  validateDeviceId(snapshot.sourceDeviceId);
  if (snapshot.sourceKey !== toHex(snapshot.sourceDeviceId)) {
    throw new Error('Stored notification snapshot source is corrupt');
  }
  if (!/^(0|[1-9][0-9]*)$/.test(snapshot.highWaterRevision) ||
      BigInt(snapshot.highWaterRevision) > 0x7fff_ffff_ffff_ffffn) {
    throw new Error('Stored notification snapshot revision is corrupt');
  }
  if (!(snapshot.manifestSha256 instanceof Uint8Array) || snapshot.manifestSha256.byteLength !== 32) {
    throw new Error('Stored notification snapshot digest is corrupt');
  }
}

function copyState(state: MirroredNotificationState): MirroredNotificationState {
  return {
    ...state,
    sourceDeviceId: state.sourceDeviceId.slice(),
    payloadSha256: state.payloadSha256.slice(),
  };
}

function sameStateSet(
  left: MirroredNotificationState[],
  right: MirroredNotificationState[],
): boolean {
  if (left.length !== right.length) return false;
  const rightByTuple = new Map(right.map((state) => [state.tuple, state]));
  return left.every((state) => {
    const other = rightByTuple.get(state.tuple);
    return other !== undefined &&
      state.revision === other.revision &&
      state.phase === other.phase &&
      bytesEqual(state.payloadSha256, other.payloadSha256);
  });
}

function requireDigest(value: Uint8Array | undefined): Uint8Array {
  if (value === undefined) {
    throw new Error('Snapshot-derived removal binding is unavailable');
  }
  return value.slice();
}

function readSourceStates(
  store: IDBObjectStore,
  sourceKey: string,
): Promise<MirroredNotificationState[]> {
  const prefix = `${sourceKey}:`;
  return new Promise((resolve, reject) => {
    const states: MirroredNotificationState[] = [];
    const request = store.openCursor(IDBKeyRange.lowerBound(prefix));
    request.onsuccess = () => {
      const cursor = request.result;
      if (cursor === null || typeof cursor.key !== 'string' || !cursor.key.startsWith(prefix)) {
        resolve(states);
        return;
      }
      const state = cursor.value as MirroredNotificationState;
      validateStored(state);
      states.push(copyState(state));
      cursor.continue();
    };
    request.onerror = () => reject(request.error ?? new Error('Notification cursor failed'));
  });
}

async function chromeNotificationId(sourceDeviceId: Uint8Array, notificationId: string): Promise<string> {
  const notificationBytes = new TextEncoder().encode(notificationId);
  const input = new Uint8Array(sourceDeviceId.byteLength + notificationBytes.byteLength);
  input.set(sourceDeviceId);
  input.set(notificationBytes, sourceDeviceId.byteLength);
  return `sn1:${toHex(await sha256(input))}`;
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

function validateDeviceId(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== 16 || value.every((byte) => byte === 0)) {
    throw new Error('sourceDeviceId must be a non-zero 16-byte value');
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength &&
    left.every((value, index) => value === right[index]);
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

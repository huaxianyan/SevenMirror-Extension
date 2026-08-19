import type {
  NotificationRemoved,
  NotificationUpsert,
} from '../protocol/generated/notification/v1/payload_pb';

const STORE_NAME = 'notification-state';
const DATABASE_VERSION = 1;

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

  private async openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        request.result.createObjectStore(STORE_NAME, { keyPath: 'tuple' });
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

function copyState(state: MirroredNotificationState): MirroredNotificationState {
  return {
    ...state,
    sourceDeviceId: state.sourceDeviceId.slice(),
    payloadSha256: state.payloadSha256.slice(),
  };
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

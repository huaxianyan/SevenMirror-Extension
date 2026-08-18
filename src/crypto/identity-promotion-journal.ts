import { serializeIdentityPublicKey } from './auth-hpke';
import { IndexedDbIdentityStore } from './indexeddb-identity-store';
import { IndexedDbLocalIdentityTransitionStore } from './indexeddb-local-identity-transition-store';
import { IndexedDbTransportCredentialStore } from '../transport/indexeddb-transport-credential-store';

const STORE_NAME = 'identity-promotion-journal';
const RECORD_ID = 'active-identity-promotion-v1';

interface PromotionJournalRecord {
  id: string;
  workspaceId: Uint8Array;
  deviceId: Uint8Array;
  transitionId: Uint8Array;
  previousKeyId: Uint8Array;
  newKeyId: Uint8Array;
  phase: 'prepared' | 'transport-rebound' | 'identity-promoted';
}

export type IdentityPromotionResult =
  'not-ready' | 'deferred-transport-rotation' | 'promoted' | 'recovered';

/** Recoverably coordinates identity, transport metadata, and local transition databases. */
export class IdentityPromotionCoordinator {
  private exclusive = Promise.resolve();

  constructor(
    private readonly identities: IndexedDbIdentityStore,
    private readonly transport: IndexedDbTransportCredentialStore,
    private readonly localTransitions: IndexedDbLocalIdentityTransitionStore,
    private readonly journal = new IndexedDbIdentityPromotionJournal(),
    private readonly now: () => number = Date.now,
  ) {}

  promoteReady(): Promise<IdentityPromotionResult> {
    return this.runExclusive(async () => {
      let record = await this.journal.load();
      const recovering = record !== undefined;
      if (record === undefined) {
        const session = await this.localTransitions.promotionReadiness(this.now());
        if (session === undefined) return 'not-ready';
        record = {
          id: RECORD_ID,
          workspaceId: session.workspaceId,
          deviceId: session.localDeviceId,
          transitionId: session.transitionId,
          previousKeyId: session.previousKeyId,
          newKeyId: session.newKeyId,
          phase: 'prepared',
        };
        await this.validatePreparedState(record);
        await this.journal.create(record);
      }

      if (await this.mustDeferForTransportRotation(record)) {
        return 'deferred-transport-rotation';
      }
      await this.transport.rebindIdentityKey(record.previousKeyId, record.newKeyId);
      if (record.phase === 'prepared') {
        record = { ...record, phase: 'transport-rebound' };
        await this.journal.update(record);
      }

      await this.identities.promotePending(record.previousKeyId, record.newKeyId);
      if (record.phase !== 'identity-promoted') {
        record = { ...record, phase: 'identity-promoted' };
        await this.journal.update(record);
      }

      await this.verifyPromotedState(record);
      await this.localTransitions.markPromotionCompleted(
        record.transitionId,
        record.previousKeyId,
        record.newKeyId,
      );
      await this.journal.remove(record);
      return recovering ? 'recovered' : 'promoted';
    });
  }

  private async mustDeferForTransportRotation(
    record: PromotionJournalRecord,
  ): Promise<boolean> {
    const rotation = await this.transport.loadRotation();
    if (rotation === undefined) return false;
    try {
      if (bytesEqual(rotation.current.identityKeyId, record.newKeyId)) return false;
      if (record.phase === 'prepared' &&
          bytesEqual(rotation.current.identityKeyId, record.previousKeyId)) return true;
      throw new Error('Transport credential rotation conflicts with identity promotion journal');
    } finally {
      rotation.current.authToken.fill(0);
      rotation.pendingAuthToken.fill(0);
    }
  }

  private async validatePreparedState(record: PromotionJournalRecord): Promise<void> {
    if (await this.transport.loadRotation() !== undefined) {
      throw new Error('Transport credential rotation must finish before identity promotion');
    }
    const credential = await this.transport.load();
    if (credential === undefined ||
        !bytesEqual(credential.workspaceId, record.workspaceId) ||
        !bytesEqual(credential.deviceId, record.deviceId) ||
        !bytesEqual(credential.identityKeyId, record.previousKeyId)) {
      credential?.authToken.fill(0);
      throw new Error('Transport credential does not match identity promotion journal');
    }
    credential.authToken.fill(0);
    const rotation = await this.identities.loadRotation();
    if (rotation === undefined ||
        !bytesEqual(await identityKeyId(rotation.current), record.previousKeyId) ||
        !bytesEqual(await identityKeyId(rotation.pending), record.newKeyId)) {
      throw new Error('Identity slots do not match identity promotion journal');
    }
  }

  private async verifyPromotedState(record: PromotionJournalRecord): Promise<void> {
    if (await this.identities.loadRotation() !== undefined) {
      throw new Error('Pending identity remains after promotion');
    }
    const identity = await this.identities.loadExisting();
    const credential = await this.transport.load();
    if (identity === undefined || credential === undefined ||
        !bytesEqual(await identityKeyId(identity), record.newKeyId) ||
        !bytesEqual(credential.identityKeyId, record.newKeyId) ||
        !bytesEqual(credential.workspaceId, record.workspaceId) ||
        !bytesEqual(credential.deviceId, record.deviceId)) {
      credential?.authToken.fill(0);
      throw new Error('Promoted identity and transport binding do not converge');
    }
    credential.authToken.fill(0);
  }

  private runExclusive<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.exclusive.then(operation, operation);
    this.exclusive = result.then(() => undefined, () => undefined);
    return result;
  }
}

export class IndexedDbIdentityPromotionJournal {
  constructor(private readonly databaseName = 'syncnotifications-identity-promotion-v1') {}

  async load(): Promise<PromotionJournalRecord | undefined> {
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readonly');
      const completed = transactionCompleted(transaction);
      const record = await requestResult<PromotionJournalRecord | undefined>(
        transaction.objectStore(STORE_NAME).get(RECORD_ID),
      );
      await completed;
      if (record !== undefined) validateRecord(record);
      return record === undefined ? undefined : copyRecord(record);
    } finally {
      database.close();
    }
  }

  async create(record: PromotionJournalRecord): Promise<void> {
    validateRecord(record);
    if (record.phase !== 'prepared') throw new Error('New promotion journal must be prepared');
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const existing = await requestResult<PromotionJournalRecord | undefined>(store.get(RECORD_ID));
      if (existing !== undefined) {
        transaction.abort();
        await completed.catch(() => undefined);
        throw new Error('A different identity promotion journal already exists');
      }
      await requestResult(store.add(copyRecord(record)));
      await completed;
    } finally {
      database.close();
    }
  }

  async update(record: PromotionJournalRecord): Promise<void> {
    validateRecord(record);
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const existing = await requestResult<PromotionJournalRecord | undefined>(store.get(RECORD_ID));
      if (existing === undefined || !sameBinding(existing, record) ||
          phaseOrder(record.phase) < phaseOrder(existing.phase)) {
        transaction.abort();
        await completed.catch(() => undefined);
        throw new Error('Identity promotion journal update does not match');
      }
      await requestResult(store.put(copyRecord(record)));
      await completed;
    } finally {
      database.close();
    }
  }

  async remove(record: PromotionJournalRecord): Promise<void> {
    validateRecord(record);
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const existing = await requestResult<PromotionJournalRecord | undefined>(store.get(RECORD_ID));
      if (existing !== undefined) {
        if (!sameBinding(existing, record) || existing.phase !== 'identity-promoted') {
          transaction.abort();
          await completed.catch(() => undefined);
          throw new Error('Identity promotion journal cannot be removed before completion');
        }
        await requestResult(store.delete(RECORD_ID));
      }
      await completed;
    } finally {
      database.close();
    }
  }

  async clear(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.databaseName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error ?? new Error('Unable to delete promotion journal'));
      request.onblocked = () => reject(new Error('Promotion journal deletion was blocked'));
    });
  }

  private openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) {
          request.result.createObjectStore(STORE_NAME, { keyPath: 'id' });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Unable to open promotion journal'));
      request.onblocked = () => reject(new Error('Promotion journal open was blocked'));
    });
  }
}

function validateRecord(record: PromotionJournalRecord): void {
  if (record.id !== RECORD_ID) throw new Error('Identity promotion journal id is invalid');
  validateIdentifier(record.workspaceId, 'workspaceId');
  validateIdentifier(record.deviceId, 'deviceId');
  validateIdentifier(record.transitionId, 'transitionId');
  validateKeyId(record.previousKeyId, 'previousKeyId');
  validateKeyId(record.newKeyId, 'newKeyId');
  if (bytesEqual(record.previousKeyId, record.newKeyId)) {
    throw new Error('Identity promotion journal keys must differ');
  }
  phaseOrder(record.phase);
}

function sameBinding(left: PromotionJournalRecord, right: PromotionJournalRecord): boolean {
  return bytesEqual(left.workspaceId, right.workspaceId) &&
    bytesEqual(left.deviceId, right.deviceId) &&
    bytesEqual(left.transitionId, right.transitionId) &&
    bytesEqual(left.previousKeyId, right.previousKeyId) &&
    bytesEqual(left.newKeyId, right.newKeyId);
}

function phaseOrder(value: PromotionJournalRecord['phase']): number {
  switch (value) {
    case 'prepared': return 0;
    case 'transport-rebound': return 1;
    case 'identity-promoted': return 2;
  }
}

function copyRecord(record: PromotionJournalRecord): PromotionJournalRecord {
  return {
    ...record,
    workspaceId: record.workspaceId.slice(),
    deviceId: record.deviceId.slice(),
    transitionId: record.transitionId.slice(),
    previousKeyId: record.previousKeyId.slice(),
    newKeyId: record.newKeyId.slice(),
  };
}

async function identityKeyId(identity: Parameters<typeof serializeIdentityPublicKey>[0]): Promise<Uint8Array> {
  const publicKey = await serializeIdentityPublicKey(identity);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', publicKey.slice().buffer));
}

function validateIdentifier(value: Uint8Array, name: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== 16 || value.every((byte) => byte === 0)) {
    throw new Error(`${name} must be a non-zero 16-byte value`);
  }
}

function validateKeyId(value: Uint8Array, name: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== 32 || value.every((byte) => byte === 0)) {
    throw new Error(`${name} must be a non-zero 32-byte value`);
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) difference |= left[index]! ^ right[index]!;
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

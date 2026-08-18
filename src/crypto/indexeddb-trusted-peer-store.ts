import {
  createIdentityKeyTransitionAckPayload,
  decodeIdentityKeyLifecyclePayload,
  encodeIdentityKeyLifecyclePayload,
} from '../protocol/identity-key-transition-payload';

const STORE_NAME = 'approved-peer';
const TRANSITION_STORE_NAME = 'peer-identity-transition';
const DATABASE_VERSION = 3;
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

export interface PeerIdentityTransitionState {
  workspaceId: Uint8Array;
  peerDeviceId: Uint8Array;
  transitionId: Uint8Array;
  previousKeyId: Uint8Array;
  newKeyId: Uint8Array;
  newPublicKey: Uint8Array;
  canonicalTransition: Uint8Array;
  transitionSha256: Uint8Array;
  canonicalAck: Uint8Array;
  ackSha256: Uint8Array;
  acceptedAtUnixMs: number;
  expiresAtUnixMs: number;
  nextAckAttemptAtUnixMs: number;
  ackAttemptCount: number;
  phase: 'pending-commit' | 'blocked';
}

interface StoredPeerIdentityTransition extends PeerIdentityTransitionState {
  tuple: string;
}

export interface AcceptPeerIdentityTransitionResult {
  disposition: 'accepted' | 'already-accepted';
  state: PeerIdentityTransitionState;
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

  async listApproved(workspaceId: Uint8Array): Promise<Array<{
    deviceId: Uint8Array;
    keyId: Uint8Array;
  }>> {
    validateIdentifier(workspaceId, 'workspaceId');
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readonly');
      const completed = transactionCompleted(transaction);
      const records = await requestResult<ApprovedPeerRecord[]>(
        transaction.objectStore(STORE_NAME).getAll(),
      );
      await completed;
      const approved: Array<{ deviceId: Uint8Array; keyId: Uint8Array }> = [];
      for (const record of records) {
        validateRecord(record);
        await validatePublicKeyPoint(record.publicKey);
        if (!bytesEqual(record.keyId, await sha256(record.publicKey))) {
          throw new Error('Approved peer record key binding is corrupt');
        }
        if (bytesEqual(record.workspaceId, workspaceId)) {
          approved.push({ deviceId: record.deviceId.slice(), keyId: record.keyId.slice() });
        }
      }
      return approved.sort((left, right) => toHex(left.deviceId).localeCompare(toHex(right.deviceId)));
    } finally {
      database.close();
    }
  }

  /** Atomically binds one exact successor and its deterministic ACK intent to the active pin. */
  async acceptIdentityTransition(
    workspaceId: Uint8Array,
    peerDeviceId: Uint8Array,
    canonicalTransition: Uint8Array,
    nowUnixMs: number,
  ): Promise<AcceptPeerIdentityTransitionResult> {
    validateIdentifier(workspaceId, 'workspaceId');
    validateIdentifier(peerDeviceId, 'peerDeviceId');
    validateTimestamp(nowUnixMs, 'nowUnixMs');
    const payload = await decodeIdentityKeyLifecyclePayload(canonicalTransition);
    if (payload.body.case !== 'identityKeyTransition') {
      throw new Error('Expected canonical identity key transition payload');
    }
    const transition = payload.body.value;
    const approvedPublicKey = await this.findApproved(
      workspaceId,
      peerDeviceId,
      transition.previousKeyId,
    );
    if (approvedPublicKey === undefined) {
      throw new Error('Identity transition is not authenticated by the active approved peer key');
    }
    const transitionSha256 = await sha256(canonicalTransition);
    const canonicalAck = await encodeIdentityKeyLifecyclePayload(
      createIdentityKeyTransitionAckPayload({
        transitionId: transition.transitionId,
        previousKeyId: transition.previousKeyId,
        newKeyId: transition.newKeyId,
        transitionSha256,
      }),
    );
    const ackSha256 = await sha256(canonicalAck);
    const expiresAtUnixMs = safeAdd(nowUnixMs, IDENTITY_TRANSITION_RETENTION_MS);
    const tuple = peerTuple(workspaceId, peerDeviceId);
    const proposed: StoredPeerIdentityTransition = {
      tuple,
      workspaceId: workspaceId.slice(),
      peerDeviceId: peerDeviceId.slice(),
      transitionId: transition.transitionId.slice(),
      previousKeyId: transition.previousKeyId.slice(),
      newKeyId: transition.newKeyId.slice(),
      newPublicKey: transition.newPublicKey.slice(),
      canonicalTransition: canonicalTransition.slice(),
      transitionSha256,
      canonicalAck,
      ackSha256,
      acceptedAtUnixMs: nowUnixMs,
      expiresAtUnixMs,
      nextAckAttemptAtUnixMs: nowUnixMs,
      ackAttemptCount: 0,
      phase: 'pending-commit',
    };

    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(
        [STORE_NAME, TRANSITION_STORE_NAME],
        'readwrite',
      );
      const completed = transactionCompleted(transaction);
      const approved = await requestResult<ApprovedPeerRecord | undefined>(
        transaction.objectStore(STORE_NAME).get(tuple),
      );
      if (approved === undefined ||
          !bytesEqual(approved.keyId, transition.previousKeyId) ||
          !bytesEqual(approved.publicKey, approvedPublicKey)) {
        transaction.abort();
        await completed.catch(() => undefined);
        throw new Error('Approved peer changed before identity transition persistence');
      }
      const transitionStore = transaction.objectStore(TRANSITION_STORE_NAME);
      const existing = await requestResult<StoredPeerIdentityTransition | undefined>(
        transitionStore.get(tuple),
      );
      if (existing !== undefined) {
        validateStoredTransition(existing);
        if (existing.phase === 'blocked' || nowUnixMs >= existing.expiresAtUnixMs) {
          if (existing.phase !== 'blocked') {
            await requestResult(transitionStore.put({ ...existing, phase: 'blocked' }));
          }
          await completed;
          throw new Error('Identity transition is blocked after expiry');
        }
        if (!sameAcceptedTransition(existing, proposed)) {
          await completed;
          throw new Error('A different identity successor is already pending for this peer');
        }
        const reactivated = existing.ackAttemptCount === 0 &&
          existing.nextAckAttemptAtUnixMs <= nowUnixMs
          ? existing
          : {
              ...existing,
              nextAckAttemptAtUnixMs: nowUnixMs,
              ackAttemptCount: 0,
            };
        if (reactivated !== existing) await requestResult(transitionStore.put(reactivated));
        await completed;
        return { disposition: 'already-accepted', state: copyTransition(reactivated) };
      }
      await requestResult(transitionStore.add(proposed));
      await completed;
      return { disposition: 'accepted', state: copyTransition(proposed) };
    } finally {
      approvedPublicKey.fill(0);
      database.close();
    }
  }

  async loadIdentityTransition(
    workspaceId: Uint8Array,
    peerDeviceId: Uint8Array,
    nowUnixMs: number,
  ): Promise<PeerIdentityTransitionState | undefined> {
    validateIdentifier(workspaceId, 'workspaceId');
    validateIdentifier(peerDeviceId, 'peerDeviceId');
    validateTimestamp(nowUnixMs, 'nowUnixMs');
    const database = await this.openDatabase();
    let record: StoredPeerIdentityTransition | undefined;
    try {
      const transaction = database.transaction(TRANSITION_STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(TRANSITION_STORE_NAME);
      record = await requestResult<StoredPeerIdentityTransition | undefined>(
        store.get(peerTuple(workspaceId, peerDeviceId)),
      );
      if (record !== undefined) {
        validateStoredTransition(record);
        if (record.phase === 'pending-commit' && nowUnixMs >= record.expiresAtUnixMs) {
          record = { ...record, phase: 'blocked' };
          await requestResult(store.put(record));
        }
      }
      await completed;
    } finally {
      database.close();
    }
    if (record === undefined) return undefined;
    await validateStoredTransitionCryptography(record);
    return copyTransition(record);
  }

  async dueIdentityTransitionAcks(
    workspaceId: Uint8Array,
    nowUnixMs: number,
    limit = 16,
  ): Promise<PeerIdentityTransitionState[]> {
    validateIdentifier(workspaceId, 'workspaceId');
    validateTimestamp(nowUnixMs, 'nowUnixMs');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 128) {
      throw new Error('limit must be 1..128');
    }
    const database = await this.openDatabase();
    const due: StoredPeerIdentityTransition[] = [];
    try {
      const transaction = database.transaction(TRANSITION_STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(TRANSITION_STORE_NAME);
      const records = await requestResult<StoredPeerIdentityTransition[]>(store.getAll());
      for (const value of records) {
        validateStoredTransition(value);
        let record = value;
        if (record.phase === 'pending-commit' && nowUnixMs >= record.expiresAtUnixMs) {
          record = { ...record, phase: 'blocked' };
          await requestResult(store.put(record));
        }
        if (record.phase === 'pending-commit' &&
            bytesEqual(record.workspaceId, workspaceId) &&
            record.nextAckAttemptAtUnixMs <= nowUnixMs) {
          due.push(record);
        }
      }
      await completed;
    } finally {
      database.close();
    }
    due.sort((left, right) =>
      left.nextAckAttemptAtUnixMs - right.nextAckAttemptAtUnixMs ||
      left.tuple.localeCompare(right.tuple));
    const selected = due.slice(0, limit);
    for (const record of selected) await validateStoredTransitionCryptography(record);
    return selected.map(copyTransition);
  }

  async recordIdentityTransitionAckSendAttempt(
    workspaceId: Uint8Array,
    peerDeviceId: Uint8Array,
    transitionId: Uint8Array,
    ackSha256: Uint8Array,
    nextAttemptAtUnixMs: number,
    maximumAttempts = 5,
  ): Promise<void> {
    validateIdentifier(workspaceId, 'workspaceId');
    validateIdentifier(peerDeviceId, 'peerDeviceId');
    validateIdentifier(transitionId, 'transitionId');
    validateKeyId(ackSha256);
    validateTimestamp(nextAttemptAtUnixMs, 'nextAttemptAtUnixMs');
    if (!Number.isSafeInteger(maximumAttempts) || maximumAttempts < 1) {
      throw new Error('maximumAttempts must be positive');
    }
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(TRANSITION_STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(TRANSITION_STORE_NAME);
      const record = await requestResult<StoredPeerIdentityTransition | undefined>(
        store.get(peerTuple(workspaceId, peerDeviceId)),
      );
      if (record !== undefined) {
        validateStoredTransition(record);
        if (!bytesEqual(record.transitionId, transitionId) ||
            !bytesEqual(record.ackSha256, ackSha256)) {
          transaction.abort();
          await completed.catch(() => undefined);
          throw new Error('Identity transition ACK attempt binding changed');
        }
        if (record.phase === 'pending-commit') {
          const attemptCount = record.ackAttemptCount + 1;
          await requestResult(store.put({
            ...record,
            ackAttemptCount: attemptCount,
            nextAckAttemptAtUnixMs: attemptCount >= maximumAttempts
              ? record.expiresAtUnixMs
              : Math.min(nextAttemptAtUnixMs, record.expiresAtUnixMs),
          }));
        }
      }
      await completed;
    } finally {
      database.close();
    }
  }

  async remove(workspaceId: Uint8Array, deviceId: Uint8Array): Promise<void> {
    validateIdentifier(workspaceId, 'workspaceId');
    validateIdentifier(deviceId, 'deviceId');
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(
        [STORE_NAME, TRANSITION_STORE_NAME],
        'readwrite',
      );
      const completed = transactionCompleted(transaction);
      const tuple = peerTuple(workspaceId, deviceId);
      await requestResult(transaction.objectStore(TRANSITION_STORE_NAME).delete(tuple));
      await requestResult(transaction.objectStore(STORE_NAME).delete(tuple));
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
      request.onupgradeneeded = (event) => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) {
          request.result.createObjectStore(STORE_NAME, { keyPath: 'tuple' });
        }
        if (!request.result.objectStoreNames.contains(TRANSITION_STORE_NAME)) {
          request.result.createObjectStore(TRANSITION_STORE_NAME, { keyPath: 'tuple' });
        } else if ((event as IDBVersionChangeEvent).oldVersion < 3) {
          const store = request.transaction!.objectStore(TRANSITION_STORE_NAME);
          store.openCursor().onsuccess = (event) => {
            const cursor = (event.target as IDBRequest<IDBCursorWithValue | null>).result;
            if (cursor === null) return;
            const record = cursor.value as StoredPeerIdentityTransition;
            cursor.update({
              ...record,
              nextAckAttemptAtUnixMs: record.acceptedAtUnixMs,
              ackAttemptCount: 0,
            });
            cursor.continue();
          };
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Unable to open trusted peer store'));
      request.onblocked = () => reject(new Error('Trusted peer store open was blocked'));
    });
  }
}

function validateStoredTransition(record: StoredPeerIdentityTransition): void {
  validateIdentifier(record.workspaceId, 'workspaceId');
  validateIdentifier(record.peerDeviceId, 'peerDeviceId');
  validateIdentifier(record.transitionId, 'transitionId');
  validateKeyId(record.previousKeyId);
  validateKeyId(record.newKeyId);
  validatePublicKey(record.newPublicKey);
  validateKeyId(record.transitionSha256);
  validateKeyId(record.ackSha256);
  validateTimestamp(record.acceptedAtUnixMs, 'acceptedAtUnixMs');
  validateTimestamp(record.expiresAtUnixMs, 'expiresAtUnixMs');
  validateTimestamp(record.nextAckAttemptAtUnixMs, 'nextAckAttemptAtUnixMs');
  if (!Number.isSafeInteger(record.ackAttemptCount) || record.ackAttemptCount < 0) {
    throw new Error('Stored identity transition ACK attempt count is invalid');
  }
  if (record.expiresAtUnixMs !== safeAdd(record.acceptedAtUnixMs, IDENTITY_TRANSITION_RETENTION_MS)) {
    throw new Error('Stored identity transition expiry is invalid');
  }
  if (record.phase !== 'pending-commit' && record.phase !== 'blocked') {
    throw new Error('Stored identity transition phase is invalid');
  }
  if (record.tuple !== peerTuple(record.workspaceId, record.peerDeviceId)) {
    throw new Error('Stored identity transition tuple is invalid');
  }
  if (!(record.canonicalTransition instanceof Uint8Array) ||
      !(record.canonicalAck instanceof Uint8Array)) {
    throw new Error('Stored identity transition canonical payload is invalid');
  }
}

async function validateStoredTransitionCryptography(
  record: StoredPeerIdentityTransition,
): Promise<void> {
  const transitionPayload = await decodeIdentityKeyLifecyclePayload(record.canonicalTransition);
  if (transitionPayload.body.case !== 'identityKeyTransition') {
    throw new Error('Stored identity transition payload has wrong body');
  }
  const transition = transitionPayload.body.value;
  if (!bytesEqual(transition.transitionId, record.transitionId) ||
      !bytesEqual(transition.previousKeyId, record.previousKeyId) ||
      !bytesEqual(transition.newKeyId, record.newKeyId) ||
      !bytesEqual(transition.newPublicKey, record.newPublicKey) ||
      !bytesEqual(await sha256(record.canonicalTransition), record.transitionSha256)) {
    throw new Error('Stored identity transition binding is corrupt');
  }
  const ackPayload = await decodeIdentityKeyLifecyclePayload(record.canonicalAck);
  if (ackPayload.body.case !== 'identityKeyTransitionAck') {
    throw new Error('Stored identity transition acknowledgement has wrong body');
  }
  const ack = ackPayload.body.value;
  if (!bytesEqual(ack.transitionId, record.transitionId) ||
      !bytesEqual(ack.previousKeyId, record.previousKeyId) ||
      !bytesEqual(ack.newKeyId, record.newKeyId) ||
      !bytesEqual(ack.transitionSha256, record.transitionSha256) ||
      !bytesEqual(await sha256(record.canonicalAck), record.ackSha256)) {
    throw new Error('Stored identity transition acknowledgement binding is corrupt');
  }
}

function sameAcceptedTransition(
  left: StoredPeerIdentityTransition,
  right: StoredPeerIdentityTransition,
): boolean {
  return bytesEqual(left.transitionId, right.transitionId) &&
    bytesEqual(left.previousKeyId, right.previousKeyId) &&
    bytesEqual(left.newKeyId, right.newKeyId) &&
    bytesEqual(left.newPublicKey, right.newPublicKey) &&
    bytesEqual(left.canonicalTransition, right.canonicalTransition) &&
    bytesEqual(left.transitionSha256, right.transitionSha256) &&
    bytesEqual(left.canonicalAck, right.canonicalAck) &&
    bytesEqual(left.ackSha256, right.ackSha256);
}

function copyTransition(value: PeerIdentityTransitionState): PeerIdentityTransitionState {
  return {
    workspaceId: value.workspaceId.slice(),
    peerDeviceId: value.peerDeviceId.slice(),
    transitionId: value.transitionId.slice(),
    previousKeyId: value.previousKeyId.slice(),
    newKeyId: value.newKeyId.slice(),
    newPublicKey: value.newPublicKey.slice(),
    canonicalTransition: value.canonicalTransition.slice(),
    transitionSha256: value.transitionSha256.slice(),
    canonicalAck: value.canonicalAck.slice(),
    ackSha256: value.ackSha256.slice(),
    acceptedAtUnixMs: value.acceptedAtUnixMs,
    expiresAtUnixMs: value.expiresAtUnixMs,
    nextAckAttemptAtUnixMs: value.nextAckAttemptAtUnixMs,
    ackAttemptCount: value.ackAttemptCount,
    phase: value.phase,
  };
}

function validateTimestamp(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} is invalid`);
}

function safeAdd(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) throw new Error('Identity transition expiry is out of range');
  return result;
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

const IDENTITY_TRANSITION_RETENTION_MS = 7 * 24 * 60 * 60 * 1_000;

function transactionCompleted(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB transaction aborted'));
    transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB transaction failed'));
  });
}

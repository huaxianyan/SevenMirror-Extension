import {
  createIdentityKeyTransitionCommitPayload,
  decodeIdentityKeyLifecyclePayload,
  encodeIdentityKeyLifecyclePayload,
} from '../protocol/identity-key-transition-payload';

const SESSION_STORE = 'local-transition-session';
const PEER_STORE = 'local-transition-peer';
const SESSION_ID = 'active-local-identity-transition-v1';
const DATABASE_VERSION = 1;
const RETENTION_MS = 7 * 24 * 60 * 60 * 1_000;

export interface LocalIdentityTransitionPeerSnapshot {
  deviceId: Uint8Array;
  keyId: Uint8Array;
}

export interface LocalIdentityTransitionSession {
  workspaceId: Uint8Array;
  localDeviceId: Uint8Array;
  transitionId: Uint8Array;
  previousKeyId: Uint8Array;
  newKeyId: Uint8Array;
  newPublicKey: Uint8Array;
  canonicalTransition: Uint8Array;
  transitionSha256: Uint8Array;
  createdAtUnixMs: number;
  expiresAtUnixMs: number;
  phase: 'awaiting-acks' | 'blocked';
}

export interface LocalIdentityTransitionPeerState extends LocalIdentityTransitionPeerSnapshot {
  transitionId: Uint8Array;
  canonicalAck?: Uint8Array;
  ackSha256?: Uint8Array;
  canonicalCommit?: Uint8Array;
  phase: 'awaiting-ack' | 'commit-queued';
}

interface StoredSession extends LocalIdentityTransitionSession {
  id: string;
}

interface StoredPeer extends LocalIdentityTransitionPeerState {
  tuple: string;
}

export interface LocalIdentityAckBinding {
  workspaceId: Uint8Array;
  localDeviceId: Uint8Array;
  senderDeviceId: Uint8Array;
  senderKeyId: Uint8Array;
  transitionId: Uint8Array;
  previousKeyId: Uint8Array;
  newKeyId: Uint8Array;
  transitionSha256: Uint8Array;
}

export interface AcceptedLocalIdentityAck {
  disposition: 'accepted' | 'already-accepted';
  peer: LocalIdentityTransitionPeerState;
}

/** One rotating-device transition and its immutable peer snapshot. */
export class IndexedDbLocalIdentityTransitionStore {
  constructor(private readonly databaseName = 'syncnotifications-local-identity-transition-v1') {}

  async create(
    workspaceId: Uint8Array,
    localDeviceId: Uint8Array,
    canonicalTransition: Uint8Array,
    peers: LocalIdentityTransitionPeerSnapshot[],
    nowUnixMs: number,
  ): Promise<LocalIdentityTransitionSession> {
    validateIdentifier(workspaceId, 'workspaceId');
    validateIdentifier(localDeviceId, 'localDeviceId');
    validateTimestamp(nowUnixMs, 'nowUnixMs');
    if (peers.length < 1 || peers.length > 128) throw new Error('Peer snapshot size is out of range');
    const payload = await decodeIdentityKeyLifecyclePayload(canonicalTransition);
    if (payload.body.case !== 'identityKeyTransition') {
      throw new Error('Expected canonical identity key transition payload');
    }
    const transition = payload.body.value;
    const transitionSha256 = await sha256(canonicalTransition);
    const expiresAtUnixMs = safeAdd(nowUnixMs, RETENTION_MS);
    const session: StoredSession = {
      id: SESSION_ID,
      workspaceId: workspaceId.slice(),
      localDeviceId: localDeviceId.slice(),
      transitionId: transition.transitionId.slice(),
      previousKeyId: transition.previousKeyId.slice(),
      newKeyId: transition.newKeyId.slice(),
      newPublicKey: transition.newPublicKey.slice(),
      canonicalTransition: canonicalTransition.slice(),
      transitionSha256,
      createdAtUnixMs: nowUnixMs,
      expiresAtUnixMs,
      phase: 'awaiting-acks',
    };
    const peerRecords = peers.map((peer) => {
      validateIdentifier(peer.deviceId, 'peerDeviceId');
      validateDigest(peer.keyId, 'peerKeyId');
      return {
        tuple: peerTuple(transition.transitionId, peer.deviceId),
        transitionId: transition.transitionId.slice(),
        deviceId: peer.deviceId.slice(),
        keyId: peer.keyId.slice(),
        phase: 'awaiting-ack' as const,
      } satisfies StoredPeer;
    });
    if (new Set(peerRecords.map((peer) => peer.tuple)).size !== peerRecords.length) {
      throw new Error('Peer snapshot contains a duplicate device');
    }

    const database = await this.openDatabase();
    try {
      const transaction = database.transaction([SESSION_STORE, PEER_STORE], 'readwrite');
      const completed = transactionCompleted(transaction);
      const sessions = transaction.objectStore(SESSION_STORE);
      if (await requestResult<StoredSession | undefined>(sessions.get(SESSION_ID)) !== undefined) {
        transaction.abort();
        await completed.catch(() => undefined);
        throw new Error('An active local identity transition already exists');
      }
      await requestResult(sessions.add(session));
      const peerStore = transaction.objectStore(PEER_STORE);
      for (const peer of peerRecords) await requestResult(peerStore.add(peer));
      await completed;
      return copySession(session);
    } finally {
      database.close();
    }
  }

  async expectedAckBinding(
    senderDeviceId: Uint8Array,
    nowUnixMs: number,
  ): Promise<LocalIdentityAckBinding | undefined> {
    validateIdentifier(senderDeviceId, 'senderDeviceId');
    validateTimestamp(nowUnixMs, 'nowUnixMs');
    const state = await this.loadSessionAndPeer(senderDeviceId, nowUnixMs);
    if (state === undefined) return undefined;
    return {
      workspaceId: state.session.workspaceId.slice(),
      localDeviceId: state.session.localDeviceId.slice(),
      senderDeviceId: state.peer.deviceId.slice(),
      senderKeyId: state.peer.keyId.slice(),
      transitionId: state.session.transitionId.slice(),
      previousKeyId: state.session.previousKeyId.slice(),
      newKeyId: state.session.newKeyId.slice(),
      transitionSha256: state.session.transitionSha256.slice(),
    };
  }

  /** Atomically stores the exact ACK and the exact commit derived from its digest. */
  async acceptAck(
    senderDeviceId: Uint8Array,
    senderKeyId: Uint8Array,
    canonicalAck: Uint8Array,
    nowUnixMs: number,
  ): Promise<AcceptedLocalIdentityAck> {
    validateIdentifier(senderDeviceId, 'senderDeviceId');
    validateDigest(senderKeyId, 'senderKeyId');
    validateTimestamp(nowUnixMs, 'nowUnixMs');
    const preflight = await this.loadSessionAndPeer(senderDeviceId, nowUnixMs);
    if (preflight === undefined) {
      throw new Error('Identity transition acknowledgement sender is not in the peer snapshot');
    }
    if (!bytesEqual(preflight.peer.keyId, senderKeyId)) {
      throw new Error('Identity transition acknowledgement sender is not in the peer snapshot');
    }
    const payload = await decodeIdentityKeyLifecyclePayload(canonicalAck);
    if (payload.body.case !== 'identityKeyTransitionAck') {
      throw new Error('Expected canonical identity key transition acknowledgement');
    }
    const ack = payload.body.value;
    const ackSha256 = await sha256(canonicalAck);
    const canonicalCommit = await encodeIdentityKeyLifecyclePayload(
      createIdentityKeyTransitionCommitPayload({
        transitionId: ack.transitionId,
        previousKeyId: ack.previousKeyId,
        newKeyId: ack.newKeyId,
        transitionSha256: ack.transitionSha256,
        ackSha256,
      }),
    );

    const database = await this.openDatabase();
    try {
      const transaction = database.transaction([SESSION_STORE, PEER_STORE], 'readwrite');
      const completed = transactionCompleted(transaction);
      const sessionStore = transaction.objectStore(SESSION_STORE);
      const session = await requestResult<StoredSession | undefined>(sessionStore.get(SESSION_ID));
      if (session === undefined) {
        transaction.abort();
        await completed.catch(() => undefined);
        throw new Error('No active local identity transition exists');
      }
      validateSession(session);
      if (session.phase === 'blocked' || nowUnixMs >= session.expiresAtUnixMs) {
        if (session.phase !== 'blocked') await requestResult(sessionStore.put({ ...session, phase: 'blocked' }));
        await completed;
        throw new Error('Local identity transition is blocked after expiry');
      }
      if (!bytesEqual(ack.transitionId, session.transitionId) ||
          !bytesEqual(ack.previousKeyId, session.previousKeyId) ||
          !bytesEqual(ack.newKeyId, session.newKeyId) ||
          !bytesEqual(ack.transitionSha256, session.transitionSha256)) {
        await completed;
        throw new Error('Identity transition acknowledgement binding does not match');
      }
      const peers = transaction.objectStore(PEER_STORE);
      const peer = await requestResult<StoredPeer | undefined>(
        peers.get(peerTuple(session.transitionId, senderDeviceId)),
      );
      if (peer === undefined || !bytesEqual(peer.keyId, senderKeyId)) {
        transaction.abort();
        await completed.catch(() => undefined);
        throw new Error('Identity transition acknowledgement sender is not in the peer snapshot');
      }
      validatePeer(peer);
      if (peer.phase === 'commit-queued') {
        if (!optionalBytesEqual(peer.canonicalAck, canonicalAck) ||
            !optionalBytesEqual(peer.ackSha256, ackSha256) ||
            !optionalBytesEqual(peer.canonicalCommit, canonicalCommit)) {
          await completed;
          throw new Error('Peer acknowledgement is already bound to different bytes');
        }
        await completed;
        return { disposition: 'already-accepted', peer: copyPeer(peer) };
      }
      const committed: StoredPeer = {
        ...peer,
        canonicalAck: canonicalAck.slice(),
        ackSha256,
        canonicalCommit,
        phase: 'commit-queued',
      };
      await requestResult(peers.put(committed));
      await completed;
      return { disposition: 'accepted', peer: copyPeer(committed) };
    } finally {
      database.close();
    }
  }

  async loadPeer(
    senderDeviceId: Uint8Array,
    nowUnixMs: number,
  ): Promise<LocalIdentityTransitionPeerState | undefined> {
    const state = await this.loadSessionAndPeer(senderDeviceId, nowUnixMs);
    return state === undefined ? undefined : copyPeer(state.peer);
  }

  async clear(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.databaseName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error ?? new Error('Unable to delete local transition store'));
      request.onblocked = () => reject(new Error('Local transition store deletion was blocked'));
    });
  }

  private async loadSessionAndPeer(
    senderDeviceId: Uint8Array,
    nowUnixMs: number,
  ): Promise<{ session: StoredSession; peer: StoredPeer } | undefined> {
    const database = await this.openDatabase();
    let result: { session: StoredSession; peer: StoredPeer } | undefined;
    try {
      const transaction = database.transaction([SESSION_STORE, PEER_STORE], 'readwrite');
      const completed = transactionCompleted(transaction);
      const sessions = transaction.objectStore(SESSION_STORE);
      let session = await requestResult<StoredSession | undefined>(sessions.get(SESSION_ID));
      if (session !== undefined) {
        validateSession(session);
        if (session.phase === 'awaiting-acks' && nowUnixMs >= session.expiresAtUnixMs) {
          session = { ...session, phase: 'blocked' };
          await requestResult(sessions.put(session));
        }
        const peer = await requestResult<StoredPeer | undefined>(
          transaction.objectStore(PEER_STORE).get(peerTuple(session.transitionId, senderDeviceId)),
        );
        if (peer !== undefined) {
          validatePeer(peer);
          result = { session, peer };
        }
      }
      await completed;
    } finally {
      database.close();
    }
    if (result !== undefined) await validateStoredCryptography(result.session, result.peer);
    return result;
  }

  private openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(SESSION_STORE)) {
          request.result.createObjectStore(SESSION_STORE, { keyPath: 'id' });
        }
        if (!request.result.objectStoreNames.contains(PEER_STORE)) {
          request.result.createObjectStore(PEER_STORE, { keyPath: 'tuple' });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Unable to open local transition store'));
      request.onblocked = () => reject(new Error('Local transition store open was blocked'));
    });
  }
}

function validateSession(value: StoredSession): void {
  validateIdentifier(value.workspaceId, 'workspaceId');
  validateIdentifier(value.localDeviceId, 'localDeviceId');
  validateIdentifier(value.transitionId, 'transitionId');
  validateDigest(value.previousKeyId, 'previousKeyId');
  validateDigest(value.newKeyId, 'newKeyId');
  validateDigest(value.transitionSha256, 'transitionSha256');
  validateTimestamp(value.createdAtUnixMs, 'createdAtUnixMs');
  validateTimestamp(value.expiresAtUnixMs, 'expiresAtUnixMs');
  if (value.expiresAtUnixMs !== safeAdd(value.createdAtUnixMs, RETENTION_MS)) {
    throw new Error('Stored local identity transition expiry is invalid');
  }
  if (value.phase !== 'awaiting-acks' && value.phase !== 'blocked') {
    throw new Error('Stored local identity transition phase is invalid');
  }
}

async function validateStoredCryptography(session: StoredSession, peer: StoredPeer): Promise<void> {
  const transition = await decodeIdentityKeyLifecyclePayload(session.canonicalTransition);
  if (transition.body.case !== 'identityKeyTransition' ||
      !bytesEqual(await sha256(session.canonicalTransition), session.transitionSha256) ||
      !bytesEqual(transition.body.value.transitionId, session.transitionId) ||
      !bytesEqual(transition.body.value.previousKeyId, session.previousKeyId) ||
      !bytesEqual(transition.body.value.newKeyId, session.newKeyId) ||
      !bytesEqual(transition.body.value.newPublicKey, session.newPublicKey)) {
    throw new Error('Stored local identity transition binding is corrupt');
  }
  if (peer.phase !== 'commit-queued') return;
  const canonicalAck = requireBytes(peer.canonicalAck, 'acknowledgement');
  const ackSha256 = requireBytes(peer.ackSha256, 'acknowledgement digest');
  const canonicalCommit = requireBytes(peer.canonicalCommit, 'commit');
  const acknowledgement = await decodeIdentityKeyLifecyclePayload(canonicalAck);
  const commit = await decodeIdentityKeyLifecyclePayload(canonicalCommit);
  if (acknowledgement.body.case !== 'identityKeyTransitionAck' ||
      commit.body.case !== 'identityKeyTransitionCommit' ||
      !bytesEqual(await sha256(canonicalAck), ackSha256) ||
      !bytesEqual(acknowledgement.body.value.transitionId, session.transitionId) ||
      !bytesEqual(acknowledgement.body.value.previousKeyId, session.previousKeyId) ||
      !bytesEqual(acknowledgement.body.value.newKeyId, session.newKeyId) ||
      !bytesEqual(acknowledgement.body.value.transitionSha256, session.transitionSha256) ||
      !bytesEqual(commit.body.value.transitionId, session.transitionId) ||
      !bytesEqual(commit.body.value.previousKeyId, session.previousKeyId) ||
      !bytesEqual(commit.body.value.newKeyId, session.newKeyId) ||
      !bytesEqual(commit.body.value.transitionSha256, session.transitionSha256) ||
      !bytesEqual(commit.body.value.ackSha256, ackSha256)) {
    throw new Error('Stored local identity transition acknowledgement or commit is corrupt');
  }
}

function requireBytes(value: Uint8Array | undefined, name: string): Uint8Array {
  if (value === undefined) throw new Error(`Stored local identity transition ${name} is missing`);
  return value;
}

function validatePeer(value: StoredPeer): void {
  validateIdentifier(value.transitionId, 'transitionId');
  validateIdentifier(value.deviceId, 'peerDeviceId');
  validateDigest(value.keyId, 'peerKeyId');
  if (value.tuple !== peerTuple(value.transitionId, value.deviceId)) {
    throw new Error('Stored local identity transition peer tuple is invalid');
  }
  const hasAck = value.canonicalAck !== undefined;
  if (hasAck !== (value.ackSha256 !== undefined) || hasAck !== (value.canonicalCommit !== undefined)) {
    throw new Error('Stored local identity transition peer state is partial');
  }
  if ((value.phase === 'commit-queued') !== hasAck) {
    throw new Error('Stored local identity transition peer phase is inconsistent');
  }
}

function copySession(value: LocalIdentityTransitionSession): LocalIdentityTransitionSession {
  return {
    ...value,
    workspaceId: value.workspaceId.slice(),
    localDeviceId: value.localDeviceId.slice(),
    transitionId: value.transitionId.slice(),
    previousKeyId: value.previousKeyId.slice(),
    newKeyId: value.newKeyId.slice(),
    newPublicKey: value.newPublicKey.slice(),
    canonicalTransition: value.canonicalTransition.slice(),
    transitionSha256: value.transitionSha256.slice(),
  };
}

function copyPeer(value: LocalIdentityTransitionPeerState): LocalIdentityTransitionPeerState {
  return {
    transitionId: value.transitionId.slice(),
    deviceId: value.deviceId.slice(),
    keyId: value.keyId.slice(),
    canonicalAck: value.canonicalAck?.slice(),
    ackSha256: value.ackSha256?.slice(),
    canonicalCommit: value.canonicalCommit?.slice(),
    phase: value.phase,
  };
}

function peerTuple(transitionId: Uint8Array, deviceId: Uint8Array): string {
  return `${toHex(transitionId)}:${toHex(deviceId)}`;
}

function validateIdentifier(value: Uint8Array, name: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== 16 || value.every((byte) => byte === 0)) {
    throw new Error(`${name} must be a non-zero 16-byte value`);
  }
}

function validateDigest(value: Uint8Array, name: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== 32 || value.every((byte) => byte === 0)) {
    throw new Error(`${name} must be a non-zero 32-byte value`);
  }
}

function validateTimestamp(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} is invalid`);
}

function safeAdd(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) throw new Error('Local identity transition expiry is out of range');
  return result;
}

function optionalBytesEqual(left: Uint8Array | undefined, right: Uint8Array): boolean {
  return left !== undefined && bytesEqual(left, right);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
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

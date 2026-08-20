import { decodePendingIdentityProof } from '../protocol/workspace-membership';
import { normalizeServerOrigin } from './indexeddb-transport-credential-store';
import type { PendingChromeMembership } from './workspace-membership-client';

const STORE_NAME = 'pending-membership';
const RECORD_ID = 'primary-membership-enrollment-v1';
export type PendingMembershipPhase = 'registered' | 'proof-attempted' | 'pending-approval';

export interface StoredPendingChromeMembership extends PendingChromeMembership {
  authorityPublicKey: Uint8Array;
  challengeEnc: Uint8Array;
  challengeCiphertext: Uint8Array;
  canonicalProof?: Uint8Array;
  phase: PendingMembershipPhase;
}
export interface PendingChromeMembershipStore {
  prepareRegistration(value: PendingChromeMembership, authorityPublicKey: Uint8Array, challengeEnc: Uint8Array, challengeCiphertext: Uint8Array): Promise<StoredPendingChromeMembership>;
  bindProof(value: PendingChromeMembership, canonicalProof: Uint8Array): Promise<void>;
  markProofAttempted(value: PendingChromeMembership, canonicalProof: Uint8Array): Promise<void>;
  markPendingApproval(value: PendingChromeMembership): Promise<void>;
  load(): Promise<StoredPendingChromeMembership | undefined>;
  clear(): Promise<void>;
}
interface Record extends StoredPendingChromeMembership { id: string }

/** One exact enrollment intent, retained across MV3 Worker suspension until transport promotion. */
export class IndexedDbPendingMembershipStore implements PendingChromeMembershipStore {
  constructor(private readonly databaseName = 'syncnotifications-pending-membership-v1') {}

  async prepareRegistration(value: PendingChromeMembership, authorityPublicKey: Uint8Array, challengeEnc: Uint8Array, challengeCiphertext: Uint8Array): Promise<StoredPendingChromeMembership> {
    const proposed = recordFrom(value, authorityPublicKey, challengeEnc, challengeCiphertext);
    return this.write(async (store, completed) => {
      const existing = await requestResult<Record | undefined>(store.get(RECORD_ID));
      if (existing) {
        validateRecord(existing); await completed;
        if (!sameRegistration(existing, proposed)) throw new Error('A different membership enrollment is already pending');
        return copy(existing);
      }
      await requestResult(store.add(proposed)); await completed; return copy(proposed);
    });
  }

  async bindProof(value: PendingChromeMembership, canonicalProof: Uint8Array): Promise<void> {
    validateProofBinding(value, canonicalProof);
    await this.mutate(value, (record) => {
      if (record.canonicalProof && !equal(record.canonicalProof, canonicalProof)) throw new Error('A different membership proof is already durable');
      return record.canonicalProof ? record : { ...record, canonicalProof: canonicalProof.slice() };
    });
  }
  async markProofAttempted(value: PendingChromeMembership, canonicalProof: Uint8Array): Promise<void> {
    await this.mutate(value, (record) => {
      if (!record.canonicalProof || !equal(record.canonicalProof, canonicalProof)) throw new Error('Exact pending membership proof is not prepared');
      return phaseRank(record.phase) < 1 ? { ...record, phase: 'proof-attempted' } : record;
    });
  }
  async markPendingApproval(value: PendingChromeMembership): Promise<void> {
    await this.mutate(value, (record) => {
      if (!record.canonicalProof) throw new Error('Pending membership proof is missing');
      return phaseRank(record.phase) < 2 ? { ...record, phase: 'pending-approval' } : record;
    });
  }
  async load(): Promise<StoredPendingChromeMembership | undefined> {
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readonly'); const completed = transactionCompleted(transaction);
      const value = await requestResult<Record | undefined>(transaction.objectStore(STORE_NAME).get(RECORD_ID)); await completed;
      if (!value) return undefined; validateRecord(value); return copy(value);
    } finally { database.close(); }
  }
  async clear(): Promise<void> {
    await this.write(async (store, completed) => { await requestResult(store.delete(RECORD_ID)); await completed; });
  }

  private async mutate(value: PendingChromeMembership, update: (record: Record) => Record): Promise<void> {
    await this.write(async (store, completed, transaction) => {
      const current = await requestResult<Record | undefined>(store.get(RECORD_ID));
      if (!current || !samePending(current, value)) { transaction.abort(); await completed.catch(() => undefined); throw new Error('Exact pending membership enrollment is not prepared'); }
      validateRecord(current); const next = update(current); validateRecord(next);
      if (next !== current) await requestResult(store.put(next)); await completed;
    });
  }
  private async write<T>(action: (store: IDBObjectStore, completed: Promise<void>, transaction: IDBTransaction) => Promise<T>): Promise<T> {
    const database = await this.openDatabase();
    try { const transaction = database.transaction(STORE_NAME, 'readwrite'); return await action(transaction.objectStore(STORE_NAME), transactionCompleted(transaction), transaction); }
    finally { database.close(); }
  }
  private openDatabase(): Promise<IDBDatabase> { return new Promise((resolve, reject) => { const request = indexedDB.open(this.databaseName, 1); request.onupgradeneeded = () => { if (!request.result.objectStoreNames.contains(STORE_NAME)) request.result.createObjectStore(STORE_NAME, { keyPath: 'id' }); }; request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error ?? new Error('Unable to open pending membership database')); request.onblocked = () => reject(new Error('Pending membership database upgrade is blocked')); }); }
}

function recordFrom(value: PendingChromeMembership, authority: Uint8Array, enc: Uint8Array, ciphertext: Uint8Array): Record {
  const record: Record = { id: RECORD_ID, serverOrigin: normalizeServerOrigin(value.serverOrigin), workspaceId: value.workspaceId.slice(), deviceId: value.deviceId.slice(), authToken: value.authToken.slice(), identityKeyId: value.identityKeyId.slice(), authorityPublicKey: authority.slice(), challengeEnc: enc.slice(), challengeCiphertext: ciphertext.slice(), phase: 'registered' };
  validateRecord(record); return record;
}
function validateRecord(value: Record): void {
  if (value.id !== RECORD_ID || normalizeServerOrigin(value.serverOrigin) !== value.serverOrigin) throw new Error('Pending membership metadata is corrupt');
  validateBytes(value.workspaceId, 16, true); validateBytes(value.deviceId, 16, true); validateBytes(value.authToken, 32, false); validateBytes(value.identityKeyId, 32, true); validateBytes(value.authorityPublicKey, 32, true); validateBytes(value.challengeEnc, 65, false);
  if (!(value.challengeCiphertext instanceof Uint8Array) || value.challengeCiphertext.byteLength < 17 || value.challengeCiphertext.byteLength > 2048) throw new Error('Pending membership challenge is corrupt');
  if (value.canonicalProof) validateProofBinding(value, value.canonicalProof);
  if (value.phase !== 'registered' && !value.canonicalProof) throw new Error('Pending membership phase requires a proof');
  if (!['registered', 'proof-attempted', 'pending-approval'].includes(value.phase)) throw new Error('Pending membership phase is corrupt');
}
function validateProofBinding(value: PendingChromeMembership, proofBytes: Uint8Array): void { if (!(proofBytes instanceof Uint8Array) || proofBytes.byteLength < 1 || proofBytes.byteLength > 1024) throw new Error('Pending membership proof is corrupt'); const proof = decodePendingIdentityProof(proofBytes); if (!equal(proof.workspaceId, value.workspaceId) || !equal(proof.deviceId, value.deviceId) || !equal(proof.identityKeyId, value.identityKeyId)) throw new Error('Pending membership proof binding is corrupt'); }
function samePending(left: PendingChromeMembership, right: PendingChromeMembership): boolean { return left.serverOrigin === right.serverOrigin && equal(left.workspaceId, right.workspaceId) && equal(left.deviceId, right.deviceId) && equal(left.authToken, right.authToken) && equal(left.identityKeyId, right.identityKeyId); }
function sameRegistration(left: Record, right: Record): boolean { return samePending(left, right) && equal(left.authorityPublicKey, right.authorityPublicKey) && equal(left.challengeEnc, right.challengeEnc) && equal(left.challengeCiphertext, right.challengeCiphertext); }
function copy(value: Record): StoredPendingChromeMembership { return { serverOrigin: value.serverOrigin, workspaceId: value.workspaceId.slice(), deviceId: value.deviceId.slice(), authToken: value.authToken.slice(), identityKeyId: value.identityKeyId.slice(), authorityPublicKey: value.authorityPublicKey.slice(), challengeEnc: value.challengeEnc.slice(), challengeCiphertext: value.challengeCiphertext.slice(), ...(value.canonicalProof ? { canonicalProof: value.canonicalProof.slice() } : {}), phase: value.phase }; }
function phaseRank(value: PendingMembershipPhase): number { return value === 'registered' ? 0 : value === 'proof-attempted' ? 1 : 2; }
function validateBytes(value: Uint8Array, size: number, nonZero: boolean): void { if (!(value instanceof Uint8Array) || value.byteLength !== size || (nonZero && value.every((item) => item === 0))) throw new Error('Pending membership byte field is corrupt'); }
function equal(left: Uint8Array, right: Uint8Array): boolean { return left.byteLength === right.byteLength && left.every((item, index) => item === right[index]); }
function requestResult<T>(request: IDBRequest<T>): Promise<T> { return new Promise((resolve, reject) => { request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed')); }); }
function transactionCompleted(transaction: IDBTransaction): Promise<void> { return new Promise((resolve, reject) => { transaction.oncomplete = () => resolve(); transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB transaction aborted')); transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB transaction failed')); }); }

import {
  decodeSignedAuthorityKeyTransition,
  decodeSignedDeviceCertificate,
  decodeSignedWorkspaceRoster,
  encodeSignedDeviceCertificate,
  verifySignedAuthorityKeyTransition,
  verifySignedDeviceCertificate,
  verifySignedWorkspaceRoster,
} from '../protocol/workspace-membership';

const STORE_NAME = 'workspace-membership';
const DATABASE_VERSION = 1;

interface StoredMembershipState {
  tuple: string;
  workspaceId: Uint8Array;
  deviceId: Uint8Array;
  authorityPublicKey: Uint8Array;
  authorityEpoch?: string;
  authorityTransitionDigest?: Uint8Array;
  signedCertificate?: Uint8Array;
  rosterEpoch: string;
  rosterDigest?: Uint8Array;
  signedRoster?: Uint8Array;
  localDeviceActive: boolean;
}

export interface WorkspaceMembershipState {
  workspaceId: Uint8Array;
  deviceId: Uint8Array;
  authorityPublicKey: Uint8Array;
  authorityEpoch: bigint;
  authorityTransitionDigest: Uint8Array;
  signedCertificate?: Uint8Array;
  rosterEpoch: bigint;
  rosterDigest?: Uint8Array;
  signedRoster?: Uint8Array;
  localDeviceActive: boolean;
}

export class IndexedDbWorkspaceMembershipStore {
  constructor(private readonly databaseName = 'syncnotifications-workspace-membership-v1') {}

  async pinAuthority(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    authorityPublicKey: Uint8Array,
  ): Promise<'pinned' | 'already-pinned'> {
    validateId(workspaceId, 'workspaceId');
    validateId(deviceId, 'deviceId');
    if (authorityPublicKey.byteLength !== 32) throw new Error('Authority public key must be 32 bytes');
    const tuple = key(workspaceId, deviceId);
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const existing = await requestResult<StoredMembershipState | undefined>(store.get(tuple));
      if (existing !== undefined) {
        const normalized = normalizeStored(existing)!;
        validateStored(normalized);
        if (!equal(normalized.authorityPublicKey, authorityPublicKey)) {
          transaction.abort();
          await completed.catch(() => undefined);
          throw new Error('Workspace authority replacement requires an authenticated transition');
        }
        if (existing.authorityEpoch === undefined || existing.authorityTransitionDigest === undefined) {
          await requestResult(store.put(normalized));
        }
        await completed;
        return 'already-pinned';
      }
      await requestResult(store.add({
        tuple,
        workspaceId: workspaceId.slice(),
        deviceId: deviceId.slice(),
        authorityPublicKey: authorityPublicKey.slice(),
        authorityEpoch: '1',
        authorityTransitionDigest: new Uint8Array(32),
        rosterEpoch: '0',
        localDeviceActive: false,
      } satisfies StoredMembershipState));
      await completed;
      return 'pinned';
    } finally {
      database.close();
    }
  }

  async reconcileApproved(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    signedCertificate: Uint8Array,
    signedRoster: Uint8Array,
  ): Promise<'applied' | 'already-applied'> {
    const observed = await this.readRaw(workspaceId, deviceId);
    if (observed === undefined) {
      throw new Error('Workspace authority must be pinned before membership reconciliation');
    }
    const certificate = decodeSignedDeviceCertificate(signedCertificate);
    await verifySignedDeviceCertificate(certificate, observed.authorityPublicKey);
    if (!certificate.certificate ||
        !equal(certificate.certificate.workspaceId, workspaceId) ||
        !equal(certificate.certificate.deviceId, deviceId)) {
      throw new Error('Device certificate is not bound to this local device');
    }
    if (observed.signedCertificate !== undefined &&
        !equal(observed.signedCertificate, signedCertificate)) {
      throw new Error('Device certificate replacement requires a higher-level membership transition');
    }
    const roster = decodeSignedWorkspaceRoster(signedRoster);
    await verifySignedWorkspaceRoster(roster, observed.authorityPublicKey);
    if (!roster.roster || !equal(roster.roster.workspaceId, workspaceId)) {
      throw new Error('Workspace roster is not bound to the pinned workspace');
    }
    const epoch = roster.roster.rosterEpoch;
    const localActive = roster.roster.activeCertificates.some((item) =>
      equal(item.certificateId, certificate.certificateId) &&
      equal(encodeSignedDeviceCertificate(item), signedCertificate));
    let disposition: 'applied' | 'already-applied';
    if (observed.rosterEpoch === '0') {
      if (epoch < certificate.certificate.membershipEpoch || !localActive) {
        throw new Error('Bootstrap roster must contain the exact local device certificate');
      }
      disposition = 'applied';
    } else if (epoch === BigInt(observed.rosterEpoch)) {
      if (!observed.rosterDigest || !observed.signedRoster ||
          !equal(observed.rosterDigest, roster.rosterDigest) ||
          !equal(observed.signedRoster, signedRoster)) {
        throw new Error('Roster epoch is bound to different canonical bytes');
      }
      disposition = 'already-applied';
    } else if (epoch === BigInt(observed.rosterEpoch) + 1n) {
      if (!observed.rosterDigest || !equal(observed.rosterDigest, roster.roster.previousRosterDigest)) {
        throw new Error('Roster previous digest does not match the durable rollback floor');
      }
      disposition = 'applied';
    } else {
      throw new Error('Roster epoch is stale or non-contiguous');
    }
    if (disposition === 'already-applied') return disposition;

    const proposed: StoredMembershipState = {
      tuple: observed.tuple,
      workspaceId: workspaceId.slice(),
      deviceId: deviceId.slice(),
      authorityPublicKey: observed.authorityPublicKey.slice(),
      authorityEpoch: observed.authorityEpoch,
      authorityTransitionDigest: observed.authorityTransitionDigest!.slice(),
      signedCertificate: signedCertificate.slice(),
      rosterEpoch: epoch.toString(),
      rosterDigest: roster.rosterDigest.slice(),
      signedRoster: signedRoster.slice(),
      localDeviceActive: localActive,
    };
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const current = await requestResult<StoredMembershipState | undefined>(store.get(observed.tuple));
      if (current === undefined || !sameStored(current, observed)) {
        transaction.abort();
        await completed.catch(() => undefined);
        throw new Error('Membership state changed during reconciliation');
      }
      await requestResult(store.put(proposed));
      await completed;
      return disposition;
    } finally {
      database.close();
    }
  }

  async reconcileAuthorityTransition(
    workspaceId: Uint8Array,
    deviceId: Uint8Array,
    signedTransition: Uint8Array,
    signedActivationRoster: Uint8Array,
  ): Promise<'applied' | 'already-applied'> {
    const observed = await this.readRaw(workspaceId, deviceId);
    if (observed === undefined || observed.rosterEpoch === '0' || !observed.rosterDigest) {
      throw new Error('Authority transition requires an accepted predecessor roster');
    }
    const transition = decodeSignedAuthorityKeyTransition(signedTransition);
    await verifySignedAuthorityKeyTransition(transition);
    const body = transition.transition!;
    const authorityEpoch = BigInt(observed.authorityEpoch!);
    if (!equal(body.workspaceId, workspaceId)) throw new Error('Authority transition is not bound to the workspace');
    if (body.transitionEpoch === authorityEpoch) {
      if (!equal(transition.transitionDigest, observed.authorityTransitionDigest!) ||
          !equal(body.newAuthorityPublicKey, observed.authorityPublicKey) ||
          !observed.signedRoster || !equal(signedActivationRoster, observed.signedRoster)) {
        throw new Error('Authority transition epoch is bound to a different transition');
      }
      return 'already-applied';
    }
    if (!equal(body.previousAuthorityPublicKey, observed.authorityPublicKey) ||
        body.transitionEpoch !== authorityEpoch + 1n ||
        !equal(body.previousTransitionDigest, observed.authorityTransitionDigest!)) {
      throw new Error('Authority transition is stale, forked, or non-contiguous');
    }
    if (body.activationRosterEpoch !== BigInt(observed.rosterEpoch) + 1n ||
        !equal(body.previousRosterDigest, observed.rosterDigest)) {
      throw new Error('Authority transition does not extend the durable roster floor');
    }
    const roster = decodeSignedWorkspaceRoster(signedActivationRoster);
    await verifySignedWorkspaceRoster(roster, body.newAuthorityPublicKey);
    if (!roster.roster || !equal(roster.roster.workspaceId, workspaceId) ||
        roster.roster.rosterEpoch !== body.activationRosterEpoch ||
        !equal(roster.roster.previousRosterDigest, body.previousRosterDigest)) {
      throw new Error('Authority activation roster does not match the transition');
    }
    const local = roster.roster.activeCertificates.find((item) =>
      item.certificate !== undefined && equal(item.certificate.deviceId, deviceId));
    if (!local) throw new Error('Authority activation roster does not contain the local device');
    const proposed: StoredMembershipState = {
      tuple: observed.tuple, workspaceId: workspaceId.slice(), deviceId: deviceId.slice(),
      authorityPublicKey: body.newAuthorityPublicKey.slice(), authorityEpoch: body.transitionEpoch.toString(),
      authorityTransitionDigest: transition.transitionDigest.slice(), signedCertificate: encodeSignedDeviceCertificate(local),
      rosterEpoch: roster.roster.rosterEpoch.toString(), rosterDigest: roster.rosterDigest.slice(),
      signedRoster: signedActivationRoster.slice(), localDeviceActive: true,
    };
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      const store = transaction.objectStore(STORE_NAME);
      const current = normalizeStored(await requestResult<StoredMembershipState | undefined>(store.get(observed.tuple)));
      if (current === undefined || !sameStored(current, observed)) {
        transaction.abort(); await completed.catch(() => undefined);
        throw new Error('Membership state changed during authority transition');
      }
      await requestResult(store.put(proposed)); await completed; return 'applied';
    } finally { database.close(); }
  }

  async load(workspaceId: Uint8Array, deviceId: Uint8Array): Promise<WorkspaceMembershipState | undefined> {
    const stored = await this.readRaw(workspaceId, deviceId);
    if (stored === undefined) return undefined;
    if (stored.signedCertificate && stored.signedRoster) {
      const certificate = decodeSignedDeviceCertificate(stored.signedCertificate);
      const roster = decodeSignedWorkspaceRoster(stored.signedRoster);
      await verifySignedDeviceCertificate(certificate, stored.authorityPublicKey);
      await verifySignedWorkspaceRoster(roster, stored.authorityPublicKey);
      const localActive = roster.roster?.activeCertificates.some((item) =>
        equal(item.certificateId, certificate.certificateId) &&
        equal(encodeSignedDeviceCertificate(item), stored.signedCertificate!));
      if (!certificate.certificate || !roster.roster ||
          !equal(certificate.certificate.workspaceId, stored.workspaceId) ||
          !equal(certificate.certificate.deviceId, stored.deviceId) ||
          !equal(roster.roster.workspaceId, stored.workspaceId) ||
          roster.roster.rosterEpoch.toString() !== stored.rosterEpoch ||
          !equal(roster.rosterDigest, stored.rosterDigest!) ||
          localActive !== stored.localDeviceActive) {
        throw new Error('Persisted membership cryptographic binding is corrupt');
      }
    }
    return copyState(stored);
  }

  async clear(): Promise<void> {
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readwrite');
      const completed = transactionCompleted(transaction);
      await requestResult(transaction.objectStore(STORE_NAME).clear());
      await completed;
    } finally {
      database.close();
    }
  }

  private async readRaw(workspaceId: Uint8Array, deviceId: Uint8Array): Promise<StoredMembershipState | undefined> {
    validateId(workspaceId, 'workspaceId');
    validateId(deviceId, 'deviceId');
    const database = await this.openDatabase();
    try {
      const transaction = database.transaction(STORE_NAME, 'readonly');
      const completed = transactionCompleted(transaction);
      const value = await requestResult<StoredMembershipState | undefined>(
        transaction.objectStore(STORE_NAME).get(key(workspaceId, deviceId)),
      );
      await completed;
      const normalized = normalizeStored(value);
      if (normalized !== undefined) validateStored(normalized);
      return normalized;
    } finally {
      database.close();
    }
  }

  private openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains(STORE_NAME)) {
          database.createObjectStore(STORE_NAME, { keyPath: 'tuple' });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Unable to open membership database'));
      request.onblocked = () => reject(new Error('Membership database upgrade is blocked'));
    });
  }
}

function validateStored(value: StoredMembershipState): void {
  validateId(value.workspaceId, 'stored workspaceId');
  validateId(value.deviceId, 'stored deviceId');
  if (value.tuple !== key(value.workspaceId, value.deviceId) || value.authorityPublicKey.byteLength !== 32 ||
      !/^[1-9][0-9]*$/.test(value.authorityEpoch!) || value.authorityTransitionDigest?.byteLength !== 32 ||
      !/^(0|[1-9][0-9]*)$/.test(value.rosterEpoch)) {
    throw new Error('Persisted membership state is corrupt');
  }
  const empty = value.rosterEpoch === '0';
  if (typeof value.localDeviceActive !== 'boolean' ||
      (empty && (value.signedCertificate !== undefined || value.rosterDigest !== undefined ||
        value.signedRoster !== undefined || value.localDeviceActive)) ||
      (!empty && (value.signedCertificate === undefined || value.rosterDigest?.byteLength !== 32 ||
        value.signedRoster === undefined))) {
    throw new Error('Persisted membership state is incomplete');
  }
}
function sameStored(left: StoredMembershipState, right: StoredMembershipState): boolean {
  return left.tuple === right.tuple && left.rosterEpoch === right.rosterEpoch &&
    left.localDeviceActive === right.localDeviceActive &&
    equal(left.workspaceId, right.workspaceId) && equal(left.deviceId, right.deviceId) &&
    equal(left.authorityPublicKey, right.authorityPublicKey) && left.authorityEpoch === right.authorityEpoch &&
    optionalEqual(left.authorityTransitionDigest, right.authorityTransitionDigest) &&
    optionalEqual(left.signedCertificate, right.signedCertificate) &&
    optionalEqual(left.rosterDigest, right.rosterDigest) && optionalEqual(left.signedRoster, right.signedRoster);
}
function copyState(value: StoredMembershipState): WorkspaceMembershipState {
  return {
    workspaceId: value.workspaceId.slice(), deviceId: value.deviceId.slice(),
    authorityPublicKey: value.authorityPublicKey.slice(),
    authorityEpoch: BigInt(value.authorityEpoch!), authorityTransitionDigest: value.authorityTransitionDigest!.slice(),
    ...(value.signedCertificate ? { signedCertificate: value.signedCertificate.slice() } : {}),
    rosterEpoch: BigInt(value.rosterEpoch),
    ...(value.rosterDigest ? { rosterDigest: value.rosterDigest.slice() } : {}),
    ...(value.signedRoster ? { signedRoster: value.signedRoster.slice() } : {}),
    localDeviceActive: value.localDeviceActive,
  };
}
function normalizeStored(value: StoredMembershipState | undefined): StoredMembershipState | undefined {
  if (value === undefined) return undefined;
  return { ...value, authorityEpoch: value.authorityEpoch ?? '1', authorityTransitionDigest: value.authorityTransitionDigest?.slice() ?? new Uint8Array(32) };
}
function validateId(value: Uint8Array, name: string): void {
  if (value.byteLength !== 16 || value.every((item) => item === 0)) throw new Error(`${name} must be a non-zero 16-byte value`);
}
function key(workspaceId: Uint8Array, deviceId: Uint8Array): string { return `${hex(workspaceId)}:${hex(deviceId)}`; }
function hex(value: Uint8Array): string { return Array.from(value, (item) => item.toString(16).padStart(2, '0')).join(''); }
function equal(left: Uint8Array, right: Uint8Array): boolean { return left.byteLength === right.byteLength && left.every((item, index) => item === right[index]); }
function optionalEqual(left?: Uint8Array, right?: Uint8Array): boolean { return left === undefined ? right === undefined : right !== undefined && equal(left, right); }
function requestResult<T>(request: IDBRequest<T>): Promise<T> { return new Promise((resolve, reject) => { request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed')); }); }
function transactionCompleted(transaction: IDBTransaction): Promise<void> { return new Promise((resolve, reject) => { transaction.oncomplete = () => resolve(); transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB transaction aborted')); transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB transaction failed')); }); }

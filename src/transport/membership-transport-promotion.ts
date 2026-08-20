import { requireTransportCertificateBinding } from '../protocol/workspace-membership';
import type { IndexedDbWorkspaceMembershipStore } from '../crypto/indexeddb-workspace-membership-store';
import type { PendingChromeMembershipStore } from './indexeddb-pending-membership-store';
import {
  type StoredTransportCredential,
  IndexedDbTransportCredentialStore,
} from './indexeddb-transport-credential-store';

/** Recoverably promotes one authority-approved enrollment into transport current. */
export async function promoteApprovedMembership(
  pendingStore: PendingChromeMembershipStore,
  membershipStore: IndexedDbWorkspaceMembershipStore,
  transportStore: IndexedDbTransportCredentialStore,
  nowUnixMs = BigInt(Date.now()),
): Promise<StoredTransportCredential> {
  const enrollment = await pendingStore.load();
  if (!enrollment) throw new Error('No pending membership enrollment can be promoted');
  if (enrollment.phase !== 'pending-approval') throw new Error('Membership proof is not pending approval');

  const membership = await membershipStore.load(enrollment.workspaceId, enrollment.deviceId);
  if (!membership) throw new Error('Durable membership state is unavailable');
  if (!equal(membership.workspaceId, enrollment.workspaceId) ||
      !equal(membership.deviceId, enrollment.deviceId) ||
      !equal(membership.authorityPublicKey, enrollment.authorityPublicKey)) {
    throw new Error('Durable membership state does not match the pending enrollment');
  }
  if (!membership.localDeviceActive || membership.rosterEpoch < 1n) {
    throw new Error('Local device is not active in the durable workspace roster');
  }
  if (!membership.signedCertificate) throw new Error('Durable local device certificate is unavailable');
  await requireTransportCertificateBinding(
    membership.signedCertificate,
    enrollment.authorityPublicKey,
    enrollment,
    nowUnixMs,
  );

  const proposed: StoredTransportCredential = {
    serverOrigin: enrollment.serverOrigin,
    workspaceId: enrollment.workspaceId.slice(),
    deviceId: enrollment.deviceId.slice(),
    authToken: enrollment.authToken.slice(),
    identityKeyId: enrollment.identityKeyId.slice(),
  };
  await transportStore.saveNew(proposed);
  const durable = await transportStore.load();
  if (!durable) throw new Error('Transport credential disappeared during promotion');
  if (!credentialEqual(durable, proposed)) {
    throw new Error('Durable transport credential does not match the approved enrollment');
  }
  await pendingStore.clear();
  return durable;
}

function credentialEqual(left: StoredTransportCredential, right: StoredTransportCredential): boolean {
  return left.serverOrigin === right.serverOrigin && equal(left.workspaceId, right.workspaceId) &&
    equal(left.deviceId, right.deviceId) && equal(left.authToken, right.authToken) &&
    equal(left.identityKeyId, right.identityKeyId);
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((value, index) => value === right[index]);
}

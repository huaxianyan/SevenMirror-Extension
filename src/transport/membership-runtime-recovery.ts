import type { IndexedDbIdentityStore } from '../crypto/indexeddb-identity-store';
import type { IndexedDbWorkspaceMembershipStore } from '../crypto/indexeddb-workspace-membership-store';
import type { IndexedDbPendingMembershipStore } from './indexeddb-pending-membership-store';
import type {
  IndexedDbTransportCredentialStore,
  StoredTransportCredential,
} from './indexeddb-transport-credential-store';
import { promoteApprovedMembership } from './membership-transport-promotion';
import {
  refreshChromeMembership,
  resumeChromeMembership,
} from './workspace-membership-client';

export type MembershipRecoveryResult = 'absent' | 'pending' | 'promoted';
export type ActiveMembershipRefreshResult = 'legacy' | 'active' | 'inactive';

/** Reconciles a promoted credential without creating or mutating enrollment intent. */
export async function refreshActiveMembership(
  credential: StoredTransportCredential,
  membershipStore: IndexedDbWorkspaceMembershipStore,
  fetcher: typeof fetch = fetch,
): Promise<ActiveMembershipRefreshResult> {
  const durable = await membershipStore.load(credential.workspaceId, credential.deviceId);
  if (durable === undefined) return 'legacy';
  const refreshed = await refreshChromeMembership(credential, membershipStore, fetcher);
  if (refreshed.serverState !== 'approved' || !refreshed.transportEligible) return 'inactive';
  return 'active';
}

/** Runs before transport reads current credentials. Callers must serialize invocations. */
export async function recoverPendingMembership(
  pendingStore: IndexedDbPendingMembershipStore,
  membershipStore: IndexedDbWorkspaceMembershipStore,
  transportStore: IndexedDbTransportCredentialStore,
  identityStore: IndexedDbIdentityStore,
  fetcher: typeof fetch = fetch,
  nowUnixMs = BigInt(Date.now()),
): Promise<MembershipRecoveryResult> {
  if (await pendingStore.load() === undefined) return 'absent';
  const identity = await identityStore.loadExisting();
  if (identity === undefined) throw new Error('Pending membership enrollment has no local identity');
  const refreshed = await resumeChromeMembership(pendingStore, membershipStore, identity, fetcher);
  if (refreshed.serverState !== 'approved') return 'pending';
  if (!refreshed.transportEligible) {
    throw new Error('Approved local device is not active in the durable workspace roster');
  }
  await promoteApprovedMembership(
    pendingStore,
    membershipStore,
    transportStore,
    nowUnixMs,
  );
  return 'promoted';
}

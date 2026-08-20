import type { IndexedDbIdentityStore } from '../crypto/indexeddb-identity-store';
import type { IndexedDbWorkspaceMembershipStore } from '../crypto/indexeddb-workspace-membership-store';
import type { IndexedDbPendingMembershipStore } from './indexeddb-pending-membership-store';
import type { IndexedDbTransportCredentialStore } from './indexeddb-transport-credential-store';
import { promoteApprovedMembership } from './membership-transport-promotion';
import { resumeChromeMembership } from './workspace-membership-client';

export type MembershipRecoveryResult = 'absent' | 'pending' | 'promoted';

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

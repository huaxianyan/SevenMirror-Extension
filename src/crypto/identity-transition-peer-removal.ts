import type { IndexedDbTransportCredentialStore } from '../transport/indexeddb-transport-credential-store';
import type { IndexedDbLocalIdentityTransitionStore } from './indexeddb-local-identity-transition-store';
import type { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';

/** Removes trust first, then excludes that exact peer from the immutable transition snapshot. */
export class IdentityTransitionPeerRemovalCoordinator {
  private exclusive = Promise.resolve();

  constructor(
    private readonly credentials: IndexedDbTransportCredentialStore,
    private readonly trustedPeers: IndexedDbTrustedPeerStore,
    private readonly localTransitions: IndexedDbLocalIdentityTransitionStore,
    private readonly now: () => number = Date.now,
  ) {}

  remove(peerDeviceId: Uint8Array): Promise<'removed' | 'recovered'> {
    return this.runExclusive(async () => {
      const credential = await this.credentials.load();
      if (credential === undefined) throw new Error('Transport is not configured');
      try {
        const session = await this.localTransitions.loadSession(this.now());
        if (session === undefined) throw new Error('No local identity transition is active');
        if (!bytesEqual(session.workspaceId, credential.workspaceId) ||
            !bytesEqual(session.localDeviceId, credential.deviceId)) {
          throw new Error('Local identity transition does not match transport registration');
        }
        const peer = await this.localTransitions.loadPeer(peerDeviceId, this.now());
        if (peer === undefined || !bytesEqual(peer.transitionId, session.transitionId)) {
          throw new Error('Peer is not in the active identity transition snapshot');
        }
        const approved = await this.trustedPeers.listApproved(credential.workspaceId);
        try {
          const active = approved.find((candidate) => bytesEqual(candidate.deviceId, peer.deviceId));
          if (active !== undefined) {
            if (!bytesEqual(active.keyId, peer.keyId)) {
              throw new Error('Approved peer key changed after identity transition snapshot');
            }
            await this.trustedPeers.remove(credential.workspaceId, peer.deviceId);
          }
          const result = await this.localTransitions.removePeerFromSnapshot(
            peer.deviceId,
            peer.keyId,
            session.transitionId,
          );
          return result === 'removed' && active !== undefined ? 'removed' : 'recovered';
        } finally {
          for (const candidate of approved) {
            candidate.deviceId.fill(0);
            candidate.keyId.fill(0);
          }
        }
      } finally {
        credential.authToken.fill(0);
      }
    });
  }

  private runExclusive<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.exclusive.then(operation, operation);
    this.exclusive = result.then(() => undefined, () => undefined);
    return result;
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

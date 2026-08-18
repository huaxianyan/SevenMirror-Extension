import {
  createIdentityKeyTransitionPayload,
  encodeIdentityKeyLifecyclePayload,
} from '../protocol/identity-key-transition-payload';
import type { IndexedDbTransportCredentialStore } from '../transport/indexeddb-transport-credential-store';
import { deriveIdentityKeyId, serializeIdentityPublicKey } from './auth-hpke';
import type { IndexedDbIdentityStore } from './indexeddb-identity-store';
import type {
  IndexedDbLocalIdentityTransitionStore,
  LocalIdentityTransitionSession,
} from './indexeddb-local-identity-transition-store';
import type { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';

export class IdentityTransitionPreconditionError extends Error {}

export class IdentityTransitionInitiator {
  private exclusive = Promise.resolve();

  constructor(
    private readonly credentials: IndexedDbTransportCredentialStore,
    private readonly identities: IndexedDbIdentityStore,
    private readonly trustedPeers: IndexedDbTrustedPeerStore,
    private readonly localTransitions: IndexedDbLocalIdentityTransitionStore,
    private readonly now: () => number = Date.now,
    private readonly random: (target: Uint8Array) => void = (target) => crypto.getRandomValues(target),
  ) {}

  prepare(): Promise<LocalIdentityTransitionSession> {
    return this.runExclusive(async () => {
      const nowUnixMs = this.now();
      const credential = await this.credentials.load();
      if (credential === undefined) {
        throw new IdentityTransitionPreconditionError('Transport is not configured');
      }
      try {
        const credentialRotation = await this.credentials.loadRotation();
        if (credentialRotation !== undefined) {
          credentialRotation.current.authToken.fill(0);
          credentialRotation.pendingAuthToken.fill(0);
          throw new IdentityTransitionPreconditionError(
            'Transport credential rotation must finish before identity transition',
          );
        }
        const existing = await this.localTransitions.loadSession(nowUnixMs);
        const rotation = await this.identities.loadRotation() ??
          await this.identities.prepareRotation();
        const currentKeyId = await deriveIdentityKeyId(
          await serializeIdentityPublicKey(rotation.current),
        );
        const pendingPublicKey = await serializeIdentityPublicKey(rotation.pending);
        const pendingKeyId = await deriveIdentityKeyId(pendingPublicKey);
        if (!bytesEqual(currentKeyId, credential.identityKeyId)) {
          throw new Error('Transport credential E2EE identity binding does not match current identity');
        }
        if (existing !== undefined) {
          if (!bytesEqual(existing.workspaceId, credential.workspaceId) ||
              !bytesEqual(existing.localDeviceId, credential.deviceId) ||
              !bytesEqual(existing.previousKeyId, currentKeyId) ||
              !bytesEqual(existing.newKeyId, pendingKeyId) ||
              !bytesEqual(existing.newPublicKey, pendingPublicKey)) {
            throw new Error('Existing identity transition does not match current/pending identity slots');
          }
          return existing;
        }
        const peers = await this.trustedPeers.listApproved(credential.workspaceId);
        if (peers.length < 1) {
          throw new IdentityTransitionPreconditionError('At least one approved peer is required');
        }
        const transitionId = this.nextIdentifier();
        const canonicalTransition = await encodeIdentityKeyLifecyclePayload(
          createIdentityKeyTransitionPayload({
            transitionId,
            previousKeyId: currentKeyId,
            newPublicKey: pendingPublicKey,
            newKeyId: pendingKeyId,
          }),
        );
        return this.localTransitions.create(
          credential.workspaceId,
          credential.deviceId,
          canonicalTransition,
          peers.map((peer) => ({ deviceId: peer.deviceId, keyId: peer.keyId })),
          nowUnixMs,
        );
      } finally {
        credential.authToken.fill(0);
      }
    });
  }

  private nextIdentifier(): Uint8Array {
    const value = new Uint8Array(16);
    do this.random(value); while (value.every((byte) => byte === 0));
    return value;
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

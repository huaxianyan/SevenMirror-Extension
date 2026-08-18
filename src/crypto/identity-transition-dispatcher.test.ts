import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { encodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import { createActionResultPayload, encodeEncryptedPayloadV1 } from '../protocol/encrypted-payload';
import {
  createIdentityKeyTransitionPayload,
  encodeIdentityKeyLifecyclePayload,
} from '../protocol/identity-key-transition-payload';
import { ActionResultStatus } from '../protocol/generated/notification/v1/payload_pb';
import { encodeRoutingHeaderV1 } from '../protocol/routing-header';
import { IndexedDbTransportCredentialStore } from '../transport/indexeddb-transport-credential-store';
import {
  generateNonExtractableIdentity,
  sealWithIdentity,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import type { ReplayLedgerWriter } from './envelope-receiver';
import { IndexedDbIdentityStore } from './indexeddb-identity-store';
import { IndexedDbLocalIdentityTransitionStore } from './indexeddb-local-identity-transition-store';
import { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';
import { IdentityTransitionDispatcher } from './identity-transition-dispatcher';

const now = 1_800_000_000_000;
const workspaceId = new Uint8Array(16).fill(1);
const senderDeviceId = new Uint8Array(16).fill(2);
const recipientDeviceId = new Uint8Array(16).fill(3);

class MemoryReplayLedger implements ReplayLedgerWriter {
  async checkAndRecord(): Promise<'accepted'> { return 'accepted'; }
}

describe('IdentityTransitionDispatcher', () => {
  it('routes an old-key transition and falls back only for authenticated business plaintext', async () => {
    const suffix = `${Date.now()}-${Math.random()}`;
    const identities = new IndexedDbIdentityStore(`dispatch-identity-${suffix}`);
    const credentials = new IndexedDbTransportCredentialStore(`dispatch-credential-${suffix}`);
    const peers = new IndexedDbTrustedPeerStore(`dispatch-peers-${suffix}`);
    const local = new IndexedDbLocalIdentityTransitionStore(`dispatch-local-${suffix}`);
    let businessFrames = 0;
    try {
      const recipient = await identities.loadOrCreate();
      const recipientPublicKey = await serializeIdentityPublicKey(recipient);
      await credentials.saveNew({
        serverOrigin: 'https://relay.example',
        workspaceId,
        deviceId: recipientDeviceId,
        authToken: new Uint8Array(32).fill(9),
        identityKeyId: await sha256(recipientPublicKey),
      });
      const sender = await generateNonExtractableIdentity();
      const senderPublicKey = await serializeIdentityPublicKey(sender);
      const senderKeyId = await sha256(senderPublicKey);
      await peers.pinApproved(workspaceId, senderDeviceId, senderPublicKey);
      const successor = await generateNonExtractableIdentity();
      const successorPublicKey = await serializeIdentityPublicKey(successor);
      const transition = await encodeIdentityKeyLifecyclePayload(
        createIdentityKeyTransitionPayload({
          transitionId: new Uint8Array(16).fill(4),
          previousKeyId: senderKeyId,
          newPublicKey: successorPublicKey,
          newKeyId: await sha256(successorPublicKey),
        }),
      );
      const dispatcher = new IdentityTransitionDispatcher(
        credentials,
        identities,
        peers,
        local,
        new MemoryReplayLedger(),
        async () => { businessFrames += 1; },
        () => now,
      );

      await expect(dispatcher.receive(await frame(
        sender,
        senderPublicKey,
        recipientPublicKey,
        transition,
        new Uint8Array(16).fill(6),
      ))).resolves.toBe('peer-transition');
      expect(businessFrames).toBe(0);
      expect(await peers.loadIdentityTransition(workspaceId, senderDeviceId, now))
        .toBeDefined();

      const business = encodeEncryptedPayloadV1(createActionResultPayload({
        idempotencyKey: new Uint8Array(16).fill(7),
        status: ActionResultStatus.SUCCEEDED,
      }));
      await expect(dispatcher.receive(await frame(
        sender,
        senderPublicKey,
        recipientPublicKey,
        business,
        new Uint8Array(16).fill(8),
      ))).resolves.toBe('business-fallback');
      expect(businessFrames).toBe(1);
    } finally {
      await local.clear();
      await peers.clear();
      await credentials.clear();
      await identities.clear();
    }
  });
});

async function frame(
  sender: HpkeIdentity,
  senderPublicKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  plaintext: Uint8Array,
  messageId: Uint8Array,
): Promise<Uint8Array> {
  const routingHeader = encodeRoutingHeaderV1({
    workspaceId,
    senderDeviceId,
    recipientDeviceId,
    senderKeyId: await sha256(senderPublicKey),
    recipientKeyId: await sha256(recipientPublicKey),
    messageId,
    sequence: BigInt(messageId[0]!),
    createdAtUnixMs: now,
    expiresAtUnixMs: now + 60_000,
  });
  const encrypted = await sealWithIdentity(recipientPublicKey, sender, plaintext, routingHeader);
  return encodeEncryptedEnvelopeV1({
    routingHeader,
    encapsulatedKey: encrypted.encapsulatedKey,
    ciphertext: encrypted.ciphertext,
  });
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

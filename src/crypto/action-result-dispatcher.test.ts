import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { ActionResultStatus } from '../protocol/generated/notification/v1/payload_pb';
import { encodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import { createActionResultPayload, encodeEncryptedPayloadV1 } from '../protocol/encrypted-payload';
import { encodeRoutingHeaderV1 } from '../protocol/routing-header';
import type { StoredTransportCredential } from '../transport/indexeddb-transport-credential-store';
import { ActionResultDispatchError, ActionResultDispatcher } from './action-result-dispatcher';
import {
  generateNonExtractableIdentity,
  sealWithIdentity,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import type { ReplayLedgerWriter } from './envelope-receiver';
import { IndexedDbPendingActionStore } from './indexeddb-pending-action-store';
import { IndexedDbTrustedPeerStore } from './indexeddb-trusted-peer-store';

const now = 1_800_000_000_000;
const workspaceId = new Uint8Array(16).fill(1);
const androidDeviceId = new Uint8Array(16).fill(2);
const chromeDeviceId = new Uint8Array(16).fill(3);
const idempotencyKey = new Uint8Array(16).fill(4);

class MemoryReplayLedger implements ReplayLedgerWriter {
  calls = 0;
  async checkAndRecord(): Promise<'accepted'> {
    this.calls += 1;
    return 'accepted';
  }
}

describe('ActionResultDispatcher', () => {
  it('resolves an approved sender pin and reconciles through the production boundary', async () => {
    const fixture = await createFixture();
    try {
      await fixture.trustedPeers.pinApproved(workspaceId, androidDeviceId, fixture.androidPublicKey);
      const receipt = await fixture.dispatcher.receive(toArrayBuffer(fixture.frame));
      expect(receipt.reconciliation).toBe('completed');
      expect(receipt.result.status).toBe(ActionResultStatus.SUCCEEDED);
      expect(fixture.loadedCredential.authToken.every((byte) => byte === 0)).toBe(true);
      expect(fixture.replay.calls).toBe(1);
      expect((await fixture.pending.get(idempotencyKey))?.state).toBe('completed');
    } finally {
      await fixture.clear();
    }
  });

  it('rejects an unapproved sender before HPKE, replay, or reconciliation', async () => {
    const fixture = await createFixture();
    try {
      await expect(fixture.dispatcher.receive(toArrayBuffer(fixture.frame))).rejects.toMatchObject({
        code: 'UNAPPROVED_SENDER',
      } satisfies Partial<ActionResultDispatchError>);
      expect(fixture.loadedCredential.authToken.every((byte) => byte === 0)).toBe(true);
      expect(fixture.replay.calls).toBe(0);
      expect((await fixture.pending.get(idempotencyKey))?.state).toBe('pending');
    } finally {
      await fixture.clear();
    }
  });
});

async function createFixture() {
  const androidIdentity = await generateNonExtractableIdentity();
  const chromeIdentity = await generateNonExtractableIdentity();
  const androidPublicKey = await serializeIdentityPublicKey(androidIdentity);
  const chromePublicKey = await serializeIdentityPublicKey(chromeIdentity);
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const pending = new IndexedDbPendingActionStore(`dispatcher-${suffix}`);
  const trustedPeers = new IndexedDbTrustedPeerStore(`trusted-${suffix}`);
  const replay = new MemoryReplayLedger();
  await pending.register(
    idempotencyKey,
    androidDeviceId,
    new Uint8Array(32).fill(9),
    now,
    now + 60_000,
  );
  const loadedCredential: StoredTransportCredential = {
    serverOrigin: 'https://notify.example',
    workspaceId: workspaceId.slice(),
    deviceId: chromeDeviceId.slice(),
    authToken: new Uint8Array(32).fill(7),
    identityKeyId: await sha256(chromePublicKey),
  };
  const dispatcher = new ActionResultDispatcher(
    { load: async () => loadedCredential },
    { loadExisting: async () => chromeIdentity },
    trustedPeers,
    replay,
    pending,
    () => now,
  );
  return {
    androidPublicKey,
    dispatcher,
    frame: await resultFrame(androidIdentity, androidPublicKey, chromePublicKey),
    loadedCredential,
    pending,
    replay,
    trustedPeers,
    clear: async () => {
      await pending.clear();
      await trustedPeers.clear();
    },
  };
}

async function resultFrame(
  senderIdentity: HpkeIdentity,
  senderPublicKey: Uint8Array,
  recipientPublicKey: Uint8Array,
): Promise<Uint8Array> {
  const routingHeader = encodeRoutingHeaderV1({
    workspaceId,
    senderDeviceId: androidDeviceId,
    recipientDeviceId: chromeDeviceId,
    senderKeyId: await sha256(senderPublicKey),
    recipientKeyId: await sha256(recipientPublicKey),
    messageId: new Uint8Array(16).fill(5),
    sequence: 1n,
    createdAtUnixMs: now,
    expiresAtUnixMs: now + 60_000,
  });
  const plaintext = encodeEncryptedPayloadV1(createActionResultPayload({
    idempotencyKey,
    status: ActionResultStatus.SUCCEEDED,
  }));
  const encrypted = await sealWithIdentity(
    recipientPublicKey,
    senderIdentity,
    plaintext,
    routingHeader,
  );
  return encodeEncryptedEnvelopeV1({
    routingHeader,
    encapsulatedKey: encrypted.encapsulatedKey,
    ciphertext: encrypted.ciphertext,
  });
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

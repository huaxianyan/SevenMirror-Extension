import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import {
  generateNonExtractableIdentity,
  serializeIdentityPublicKey,
} from '../crypto/auth-hpke';
import type { WorkspaceBusinessPeerResolver } from '../crypto/workspace-business-peer-resolver';
import { decodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import { IndexedDbRelayDeliveryCursorStore } from './indexeddb-relay-delivery-cursor-store';
import { SnapshotRecoveryCoordinator } from './snapshot-recovery';

const workspaceId = new Uint8Array(16).fill(1);
const localDeviceId = new Uint8Array(16).fill(2);
const sourceDeviceId = new Uint8Array(16).fill(3);
const sourceKeyId = new Uint8Array(32).fill(6);

describe('SnapshotRecoveryCoordinator', () => {
  it('persists expected sources, sends an online-only encrypted request, and accepts after the matching manifest', async () => {
    const chromeIdentity = await generateNonExtractableIdentity();
    const androidIdentity = await generateNonExtractableIdentity();
    const androidPublicKey = await serializeIdentityPublicKey(androidIdentity);
    const cursor = new IndexedDbRelayDeliveryCursorStore(
      `snapshot-recovery-${Date.now()}-${Math.random()}`,
    );
    await cursor.commitDelivery(workspaceId, localDeviceId, 1n);
    await cursor.requireSnapshot(workspaceId, localDeviceId, 9n);
    const sent: Uint8Array[] = [];
    let sequence = 0n;
    const credential = {
      serverOrigin: 'http://127.0.0.1:8080',
      workspaceId,
      deviceId: localDeviceId,
      authToken: new Uint8Array(32).fill(4),
      identityKeyId: new Uint8Array(32).fill(5),
    };
    const peers = {
      listNotificationSources: async () => [{
        deviceId: sourceDeviceId,
        keyId: sourceKeyId,
        publicKey: androidPublicKey.slice(),
      }],
    } as unknown as WorkspaceBusinessPeerResolver;
    const coordinator = new SnapshotRecoveryCoordinator(
      { load: async () => ({ ...credential, authToken: credential.authToken.slice() }) },
      { loadExisting: async () => chromeIdentity },
      peers,
      { allocate: async () => ++sequence } as never,
      cursor,
      (frame) => { sent.push(frame.slice()); return true; },
      async (requestId) => {
        await cursor.acceptSnapshotRecovery(workspaceId, localDeviceId, requestId);
        return true;
      },
      () => 1_800_000_000_000,
      (target) => target.fill(7),
    );

    await coordinator.begin(9n);
    const state = await cursor.load(workspaceId, localDeviceId);
    expect(state.recovery?.expectedSources).toEqual([{
      deviceId: sourceDeviceId,
      keyId: sourceKeyId,
    }]);
    expect(sent).toHaveLength(1);
    expect(decodeEncryptedEnvelopeV1(sent[0]).routingHeader.recipientDeviceId)
      .toEqual(sourceDeviceId);

    await coordinator.observeManifest(
      sourceDeviceId, sourceKeyId, state.recovery!.requestId,
    );
    expect(await cursor.load(workspaceId, localDeviceId)).toEqual({ committedDeliveryId: 9n });
    expect(await coordinator.isActive()).toBe(false);
  });

  it('accepts a fully completed persisted session after Worker reconstruction', async () => {
    const cursor = new IndexedDbRelayDeliveryCursorStore(
      `snapshot-recovery-restart-${Date.now()}-${Math.random()}`,
    );
    const requestId = new Uint8Array(16).fill(8);
    await cursor.requireSnapshot(workspaceId, localDeviceId, 9n);
    await cursor.beginSnapshotRecovery(
      workspaceId, localDeviceId, 9n, requestId,
      [{ deviceId: sourceDeviceId, keyId: sourceKeyId }],
    );
    await cursor.recordSnapshotRecoverySource(
      workspaceId, localDeviceId, requestId, sourceDeviceId, sourceKeyId,
    );
    const credential = {
      serverOrigin: 'http://127.0.0.1:8080', workspaceId, deviceId: localDeviceId,
      authToken: new Uint8Array(32).fill(4), identityKeyId: new Uint8Array(32).fill(5),
    };
    const reconstructed = new SnapshotRecoveryCoordinator(
      { load: async () => ({ ...credential, authToken: credential.authToken.slice() }) },
      { loadExisting: async () => undefined },
      {} as WorkspaceBusinessPeerResolver,
      {} as never,
      cursor,
      () => false,
      async (activeRequestId) => {
        await cursor.acceptSnapshotRecovery(workspaceId, localDeviceId, activeRequestId);
        return true;
      },
    );

    await reconstructed.retry();
    expect(await cursor.load(workspaceId, localDeviceId)).toEqual({ committedDeliveryId: 9n });
  });

  it('fails closed when the authority roster no longer contains the pinned source identity', async () => {
    const cursor = new IndexedDbRelayDeliveryCursorStore(
      `snapshot-recovery-revoked-${Date.now()}-${Math.random()}`,
    );
    const requestId = new Uint8Array(16).fill(8);
    await cursor.requireSnapshot(workspaceId, localDeviceId, 9n);
    await cursor.beginSnapshotRecovery(
      workspaceId, localDeviceId, 9n, requestId,
      [{ deviceId: sourceDeviceId, keyId: sourceKeyId }],
    );
    const credential = {
      serverOrigin: 'http://127.0.0.1:8080', workspaceId, deviceId: localDeviceId,
      authToken: new Uint8Array(32).fill(4), identityKeyId: new Uint8Array(32).fill(5),
    };
    const coordinator = new SnapshotRecoveryCoordinator(
      { load: async () => ({ ...credential, authToken: credential.authToken.slice() }) },
      { loadExisting: async () => generateNonExtractableIdentity() },
      { listNotificationSources: async () => [] } as unknown as WorkspaceBusinessPeerResolver,
      { allocate: async () => 1n } as never,
      cursor,
      () => false,
      async () => false,
    );

    await expect(coordinator.retry()).rejects.toThrow('no longer authorized');
    expect((await cursor.load(workspaceId, localDeviceId)).recovery).toBeDefined();
  });
});

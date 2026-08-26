import 'fake-indexeddb/auto';
import { create } from '@bufbuild/protobuf';
import { describe, expect, it } from 'vitest';
import {
  ActionResultStatus,
  NotificationActionDescriptorSchema,
  NotificationMediaMimeType,
  NotificationMediaSchema,
} from '../protocol/generated/notification/v1/payload_pb';
import payloadVector from '../../protocol/test-vectors/encrypted-payload-v1.json';
import { encodeEncryptedEnvelopeV1 } from '../protocol/encrypted-envelope';
import {
  createActionResultPayload,
  createNotificationRemovedPayload,
  createNotificationSnapshotManifestPayload,
  createNotificationUpsertPayload,
  encodeEncryptedPayloadV1,
} from '../protocol/encrypted-payload';
import { encodeRoutingHeaderV1 } from '../protocol/routing-header';
import type { StoredTransportCredential } from '../transport/indexeddb-transport-credential-store';
import { ActionResultDispatchError, ActionResultDispatcher } from './action-result-dispatcher';
import {
  NotificationPresenter,
  type NotificationsApi,
} from '../background/notification-presenter';
import {
  generateNonExtractableIdentity,
  sealWithIdentity,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from './auth-hpke';
import type { ReplayLedgerWriter } from './envelope-receiver';
import { IndexedDbNotificationStateStore } from './indexeddb-notification-state-store';
import { IndexedDbPendingActionStore } from './indexeddb-pending-action-store';

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
  it('resolves an authorized sender and reconciles through the production boundary', async () => {
    const fixture = await createFixture();
    try {
      fixture.authorize();
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

  it('reconciles authenticated updates, removals and reconnect snapshots without stale resurrection', async () => {
    const fixture = await createFixture();
    const visible = new Map<string, chrome.notifications.NotificationOptions<true>>();
    const programmaticMarkers: string[] = [];
    const mediaAttempts: number[] = [];
    const notifications: NotificationsApi = {
      getAll: (callback) => callback(Object.fromEntries([...visible.keys()].map((key) => [key, true]))),
      create: (id, options, callback) => { visible.set(id, options); callback?.(id); },
      update: (id, options, callback) => { visible.set(id, options); callback?.(true); },
      clear: (id, callback) => callback?.(visible.delete(id)),
    };
    const presenter = new NotificationPresenter(
      notifications,
      async (id) => { programmaticMarkers.push(id); },
      async () => undefined,
      () => 'extension://notification-icon',
      async (media) => {
        mediaAttempts.push(media.width);
        return media.width === payloadVector.notificationAvatar.width
          ? undefined
          : 'data:image/png;base64,app-icon';
      },
      () => 'Clear',
    );
    try {
      fixture.authorize();
      const upsert = await fixture.dispatcher.receiveBusiness(toArrayBuffer(await notificationFrame(
        fixture.androidIdentity,
        fixture.androidPublicKey,
        fixture.chromePublicKey,
        7n,
        'first body',
        false,
        6,
        true,
      )));
      expect(upsert.kind).toBe('notification');
      if (upsert.kind === 'notification') await presenter.present(upsert.receipt);
      expect([...visible.values()][0]?.message).toBe('first body');
      expect([...visible.values()][0]?.iconUrl).toBe('data:image/png;base64,app-icon');
      expect([...visible.values()][0]?.requireInteraction).toBe(true);
      expect([...visible.values()][0]?.buttons).toEqual([
        { title: 'Mark handled' },
        { title: 'Clear' },
      ]);
      expect(mediaAttempts).toEqual([1, 2]);

      mediaAttempts.length = 0;
      const exactRetry = await fixture.dispatcher.receiveBusiness(toArrayBuffer(await notificationFrame(
        fixture.androidIdentity,
        fixture.androidPublicKey,
        fixture.chromePublicKey,
        7n,
        'first body',
        false,
        16,
        true,
      )));
      if (exactRetry.kind === 'notification') await presenter.present(exactRetry.receipt);
      expect(exactRetry.kind === 'notification' && exactRetry.receipt.kind === 'item'
        ? exactRetry.receipt.reconciliation.disposition
        : undefined).toBe('already-applied');
      expect(mediaAttempts).toEqual([1, 2]);

      const update = await fixture.dispatcher.receiveBusiness(toArrayBuffer(await notificationFrame(
        fixture.androidIdentity,
        fixture.androidPublicKey,
        fixture.chromePublicKey,
        8n,
        'updated body',
        false,
        7,
      )));
      if (update.kind === 'notification') await presenter.present(update.receipt);
      expect([...visible.values()][0]?.message).toBe('updated body');
      expect([...visible.values()][0]?.iconUrl).toBe('extension://notification-icon');

      const activeSnapshot = await fixture.dispatcher.receiveBusiness(toArrayBuffer(await snapshotFrame(
        fixture.androidIdentity,
        fixture.androidPublicKey,
        fixture.chromePublicKey,
        8n,
        [{ notificationId: 'synthetic.notification/42', notificationRevision: 8n }],
        8,
      )));
      if (activeSnapshot.kind === 'notification') await presenter.present(activeSnapshot.receipt);
      expect(visible.size).toBe(1);
      expect(programmaticMarkers).toHaveLength(0);

      const removed = await fixture.dispatcher.receiveBusiness(toArrayBuffer(await notificationFrame(
        fixture.androidIdentity,
        fixture.androidPublicKey,
        fixture.chromePublicKey,
        9n,
        undefined,
        true,
        9,
      )));
      if (removed.kind === 'notification') await presenter.present(removed.receipt);
      expect(visible.size).toBe(0);
      expect(programmaticMarkers).toHaveLength(1);

      const stale = await fixture.dispatcher.receiveBusiness(toArrayBuffer(await notificationFrame(
        fixture.androidIdentity,
        fixture.androidPublicKey,
        fixture.chromePublicKey,
        8n,
        'delayed body',
        false,
        10,
      )));
      if (stale.kind === 'notification') await presenter.present(stale.receipt);
      expect(visible.size).toBe(0);

      const restored = await fixture.dispatcher.receiveBusiness(toArrayBuffer(await notificationFrame(
        fixture.androidIdentity,
        fixture.androidPublicKey,
        fixture.chromePublicKey,
        10n,
        'restored body',
        false,
        11,
      )));
      if (restored.kind === 'notification') await presenter.present(restored.receipt);
      expect([...visible.values()][0]?.message).toBe('restored body');

      const emptySnapshot = await fixture.dispatcher.receiveBusiness(toArrayBuffer(await snapshotFrame(
        fixture.androidIdentity,
        fixture.androidPublicKey,
        fixture.chromePublicKey,
        11n,
        [],
        12,
      )));
      if (emptySnapshot.kind === 'notification') await presenter.present(emptySnapshot.receipt);
      expect(visible.size).toBe(0);
      expect(programmaticMarkers).toHaveLength(2);

      const delayedAfterSnapshot = await fixture.dispatcher.receiveBusiness(toArrayBuffer(
        await notificationFrame(
          fixture.androidIdentity,
          fixture.androidPublicKey,
          fixture.chromePublicKey,
          10n,
          'delayed after snapshot',
          false,
          13,
        ),
      ));
      if (delayedAfterSnapshot.kind === 'notification') {
        await presenter.present(delayedAfterSnapshot.receipt);
      }
      expect(visible.size).toBe(0);
    } finally {
      await fixture.clear();
    }
  });

  it('rejects a notification when the local certified role permits actions only', async () => {
    const fixture = await createFixture({
      mayReceiveNotifications: false,
      mayReceiveActionResults: true,
    });
    try {
      fixture.authorize();
      const frame = await notificationFrame(
        fixture.androidIdentity,
        fixture.androidPublicKey,
        fixture.chromePublicKey,
        7n,
        'role-restricted body',
        false,
        6,
      );
      await expect(fixture.dispatcher.receiveBusiness(toArrayBuffer(frame))).rejects.toMatchObject({
        code: 'UNAUTHORIZED_ROLE',
      } satisfies Partial<ActionResultDispatchError>);
      expect(fixture.replay.calls).toBe(0);
    } finally {
      await fixture.clear();
    }
  });

  it('rejects an unauthorized sender before HPKE, replay, or reconciliation', async () => {
    const fixture = await createFixture();
    try {
      await expect(fixture.dispatcher.receive(toArrayBuffer(fixture.frame))).rejects.toMatchObject({
        code: 'UNAUTHORIZED_SENDER',
      } satisfies Partial<ActionResultDispatchError>);
      expect(fixture.loadedCredential.authToken.every((byte) => byte === 0)).toBe(true);
      expect(fixture.replay.calls).toBe(0);
      expect((await fixture.pending.get(idempotencyKey))?.state).toBe('pending');
    } finally {
      await fixture.clear();
    }
  });
});

async function createFixture(authorization = {
  mayReceiveNotifications: true,
  mayReceiveActionResults: true,
}) {
  const androidIdentity = await generateNonExtractableIdentity();
  const chromeIdentity = await generateNonExtractableIdentity();
  const androidPublicKey = await serializeIdentityPublicKey(androidIdentity);
  const chromePublicKey = await serializeIdentityPublicKey(chromeIdentity);
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const pending = new IndexedDbPendingActionStore(`dispatcher-${suffix}`);
  const notificationState = new IndexedDbNotificationStateStore(`notifications-${suffix}`);
  let senderAuthorized = false;
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
    {
      resolve: async (resolvedWorkspace, _localDevice, senderDevice, senderKey) => {
        if (!senderAuthorized ||
            !bytesEqual(resolvedWorkspace, workspaceId) ||
            !bytesEqual(senderDevice, androidDeviceId) ||
            !bytesEqual(senderKey, await sha256(androidPublicKey))) {
          return undefined;
        }
        return {
          senderPublicKey: androidPublicKey,
          mayReceiveNotifications: authorization.mayReceiveNotifications,
          mayReceiveActionResults: authorization.mayReceiveActionResults,
        };
      },
    },
    replay,
    pending,
    () => now,
    notificationState,
  );
  return {
    androidIdentity,
    androidPublicKey,
    chromePublicKey,
    dispatcher,
    frame: await resultFrame(androidIdentity, androidPublicKey, chromePublicKey),
    loadedCredential,
    pending,
    replay,
    authorize: () => { senderAuthorized = true; },
    clear: async () => {
      await notificationState.clear();
      await pending.clear();
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

async function notificationFrame(
  senderIdentity: HpkeIdentity,
  senderPublicKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  revision: bigint,
  body: string | undefined,
  removed: boolean,
  messageByte: number,
  includeMedia = false,
): Promise<Uint8Array> {
  const routingHeader = encodeRoutingHeaderV1({
    workspaceId,
    senderDeviceId: androidDeviceId,
    recipientDeviceId: chromeDeviceId,
    senderKeyId: await sha256(senderPublicKey),
    recipientKeyId: await sha256(recipientPublicKey),
    messageId: new Uint8Array(16).fill(messageByte),
    sequence: BigInt(messageByte),
    createdAtUnixMs: now,
    expiresAtUnixMs: now + 60_000,
  });
  const payload = removed
    ? createNotificationRemovedPayload({
      notificationId: 'synthetic.notification/42',
      notificationRevision: revision,
    })
    : createNotificationUpsertPayload({
      notificationId: 'synthetic.notification/42',
      notificationRevision: revision,
      title: 'Synthetic notification',
      body,
      ...(includeMedia ? {
        appIcon: vectorMedia(payloadVector.notificationAppIcon),
        avatar: vectorMedia(payloadVector.notificationAvatar),
        actions: payloadVector.notificationActions.map((action) =>
          create(NotificationActionDescriptorSchema, {
            actionId: fromHex(action.actionIdHex),
            title: action.title,
            requiresTextInput: action.requiresTextInput,
            allowsFreeFormInput: action.allowsFreeFormInput,
          })),
      } : {}),
    });
  const plaintext = encodeEncryptedPayloadV1(payload);
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

async function snapshotFrame(
  senderIdentity: HpkeIdentity,
  senderPublicKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  highWaterRevision: bigint,
  activeNotifications: Array<{ notificationId: string; notificationRevision: bigint }>,
  messageByte: number,
): Promise<Uint8Array> {
  const routingHeader = encodeRoutingHeaderV1({
    workspaceId,
    senderDeviceId: androidDeviceId,
    recipientDeviceId: chromeDeviceId,
    senderKeyId: await sha256(senderPublicKey),
    recipientKeyId: await sha256(recipientPublicKey),
    messageId: new Uint8Array(16).fill(messageByte),
    sequence: BigInt(messageByte),
    createdAtUnixMs: now,
    expiresAtUnixMs: now + 60_000,
  });
  const plaintext = encodeEncryptedPayloadV1(createNotificationSnapshotManifestPayload({
    highWaterRevision,
    activeNotifications,
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

function vectorMedia(media: typeof payloadVector.notificationAppIcon) {
  return create(NotificationMediaSchema, {
    contentSha256: fromHex(media.contentSha256Hex),
    mimeType: NotificationMediaMimeType.PNG,
    width: media.width,
    height: media.height,
    encodedBytes: fromHex(media.encodedHex),
  });
}

function fromHex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength &&
    left.every((value, index) => value === right[index]);
}

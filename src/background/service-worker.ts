import {
  clearLifecycleTestNotification,
  createLifecycleTestNotification,
  getLifecycleSpikeStatus,
  handleNotificationClosed,
  recordWorkerStart,
} from './lifecycle-spike';
import { DEFAULT_CONNECTION_STATE } from '../shared/status';
import { runE2eePersistenceSpike } from './e2ee-spike';
import { IndexedDbIdentityStore } from '../crypto/indexeddb-identity-store';
import { ActionInvokeOutbox } from '../crypto/action-invoke-outbox';
import { IndexedDbOutboundSequenceStore } from '../crypto/indexeddb-outbound-sequence-store';
import { IndexedDbPendingActionStore } from '../crypto/indexeddb-pending-action-store';
import { IndexedDbReplayLedger } from '../crypto/indexeddb-replay-ledger';
import { IndexedDbTrustedPeerStore } from '../crypto/indexeddb-trusted-peer-store';
import { ActionResultDispatcher } from '../crypto/action-result-dispatcher';
import { IndexedDbTransportCredentialStore } from '../transport/indexeddb-transport-credential-store';
import { TransportRuntime } from '../transport/transport-runtime';

const CONNECTION_STATE_KEY = 'connectionState';
const TRANSPORT_RECONNECT_ALARM = 'transport-reconnect-v1';
const ACTION_INVOKE_RETRY_ALARM = 'action-invoke-retry-v1';
const credentialStore = new IndexedDbTransportCredentialStore();
const identityStore = new IndexedDbIdentityStore();
const trustedPeerStore = new IndexedDbTrustedPeerStore();
const pendingActionStore = new IndexedDbPendingActionStore();
const actionResultDispatcher = new ActionResultDispatcher(
  credentialStore,
  identityStore,
  trustedPeerStore,
  new IndexedDbReplayLedger('action-results'),
  pendingActionStore,
);
let transportRuntime: TransportRuntime;
const actionInvokeOutbox = new ActionInvokeOutbox(
  credentialStore,
  identityStore,
  trustedPeerStore,
  pendingActionStore,
  new IndexedDbOutboundSequenceStore(),
  (frame) => transportRuntime.sendEnvelope(frame),
);
transportRuntime = new TransportRuntime(
  credentialStore,
  identityStore,
  async (state) => chrome.storage.local.set({ [CONNECTION_STATE_KEY]: state }),
  async (frame) => { await actionResultDispatcher.receive(frame); },
  undefined,
  {
    // Alarms survive MV3 worker suspension; worker startup remains an immediate recovery path.
    setTimer: (_callback, delayMs) => {
      void chrome.alarms.create(TRANSPORT_RECONNECT_ALARM, {
        when: Date.now() + Math.max(1_000, delayMs),
      });
      return 0 as unknown as ReturnType<typeof setTimeout>;
    },
    clearTimer: () => {
      void chrome.alarms.clear(TRANSPORT_RECONNECT_ALARM);
    },
    onAuthenticated: () => { void drainActionInvokes(); },
  },
);

void recordWorkerStart();
void transportRuntime.connect().catch(() => undefined);

chrome.runtime.onInstalled.addListener(async () => {
  const stored = await chrome.storage.local.get(CONNECTION_STATE_KEY);
  if (stored[CONNECTION_STATE_KEY] === undefined) {
    await chrome.storage.local.set({ [CONNECTION_STATE_KEY]: DEFAULT_CONNECTION_STATE });
  }
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === TRANSPORT_RECONNECT_ALARM) {
    void transportRuntime.retryScheduledConnection().catch(() => undefined);
  } else if (alarm.name === ACTION_INVOKE_RETRY_ALARM) {
    void drainActionInvokes();
  }
});

chrome.notifications.onClosed.addListener((notificationId, byUser) => {
  void handleNotificationClosed(notificationId, byUser);
});

chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
  if (!isMessage(message)) {
    return false;
  }

  switch (message.type) {
    case 'get-status':
      void Promise.all([
        chrome.storage.local.get(CONNECTION_STATE_KEY),
        getLifecycleSpikeStatus(),
      ]).then(([stored, lifecycle]) => {
        sendResponse({
          state: stored[CONNECTION_STATE_KEY] ?? DEFAULT_CONNECTION_STATE,
          lifecycle,
        });
      });
      return true;

    case 'create-lifecycle-test':
      void createLifecycleTestNotification().then((notificationId) => {
        sendResponse({ notificationId });
      });
      return true;

    case 'clear-lifecycle-test':
      void clearLifecycleTestNotification().then((cleared) => {
        sendResponse({ cleared });
      });
      return true;

    case 'transport-connect':
      void transportRuntime.connect().then(
        () => sendResponse({ started: true }),
        () => sendResponse({ started: false }),
      );
      return true;

    case 'get-synthetic-action-target':
      void getSyntheticActionTarget().then(
        (target) => sendResponse({ target }),
        () => sendResponse({ target: undefined }),
      );
      return true;

    case 'get-synthetic-action-status':
      void getSyntheticActionStatus(message).then(
        (result) => sendResponse(result),
        () => sendResponse({ found: false }),
      );
      return true;

    case 'resend-synthetic-action':
      void resendSyntheticAction(message).then(
        (accepted) => sendResponse({ accepted }),
        () => sendResponse({ accepted: false }),
      );
      return true;

    case 'queue-action-invoke':
      void queueActionInvoke(message).then(
        (result) => sendResponse(result),
        () => sendResponse({ queued: false, accepted: false }),
      );
      return true;

    case 'run-e2ee-persistence-test':
      void runE2eePersistenceSpike().then(
        (result) => sendResponse({ result }),
        (error: unknown) => sendResponse({
          error: error instanceof Error ? error.message : 'Unknown E2EE test failure',
        }),
      );
      return true;

    default:
      return false;
  }
});

async function getSyntheticActionTarget(): Promise<{
  targetDeviceId: string;
  targetKeyId: string;
} | undefined> {
  const credential = await credentialStore.load();
  if (credential === undefined) return undefined;
  try {
    const approved = await trustedPeerStore.listApproved(credential.workspaceId);
    if (approved.length !== 1) return undefined;
    return {
      targetDeviceId: toHex(approved[0]!.deviceId),
      targetKeyId: toHex(approved[0]!.keyId),
    };
  } finally {
    credential.authToken.fill(0);
  }
}

async function getSyntheticActionStatus(message: Record<string, unknown>): Promise<{
  found: boolean;
  state?: 'pending' | 'completed';
  resultStatus?: string;
  invokeAttemptCount?: number;
  authenticatedResultCount?: number;
}> {
  const key = parseHex(message.idempotencyKey, 16, 'idempotencyKey');
  const record = await pendingActionStore.get(key);
  if (record === undefined) return { found: false };
  return {
    found: true,
    state: record.state,
    resultStatus: record.resultStatus === undefined ? undefined : String(record.resultStatus),
    invokeAttemptCount: record.invokeAttemptCount,
    authenticatedResultCount: record.authenticatedResultCount,
  };
}

async function resendSyntheticAction(message: Record<string, unknown>): Promise<boolean> {
  const key = parseHex(message.idempotencyKey, 16, 'idempotencyKey');
  return actionInvokeOutbox.resendExact(key);
}

async function drainActionInvokes(): Promise<void> {
  try {
    const result = await actionInvokeOutbox.drainDue();
    const delayMs = result.nextWakeDelayMs ??
      (result.attemptedEntries > result.acceptedSends ? 1_000 : undefined);
    if (delayMs !== undefined) {
      await chrome.alarms.create(ACTION_INVOKE_RETRY_ALARM, {
        when: Date.now() + Math.max(1_000, delayMs),
      });
    }
  } catch {
    // Corrupt local delivery state or encryption failure is not a network outage.
    await transportRuntime.failClosed();
  }
}

async function queueActionInvoke(message: Record<string, unknown>): Promise<{
  queued: boolean;
  accepted: boolean;
  idempotencyKey: string;
}> {
  const targetDeviceId = parseHex(message.targetDeviceId, 16, 'targetDeviceId');
  const targetKeyId = parseHex(message.targetKeyId, 32, 'targetKeyId');
  const actionId = parseHex(message.actionId, 16, 'actionId');
  const idempotencyKey = message.idempotencyKey === undefined
    ? randomIdentifier()
    : parseHex(message.idempotencyKey, 16, 'idempotencyKey');
  if (typeof message.notificationId !== 'string' || message.notificationId.length < 1 ||
      new TextEncoder().encode(message.notificationId).byteLength > 512) {
    throw new Error('notificationId is invalid');
  }
  if (typeof message.notificationRevision !== 'string' ||
      !/^[1-9][0-9]*$/.test(message.notificationRevision)) {
    throw new Error('notificationRevision is invalid');
  }
  const notificationRevision = BigInt(message.notificationRevision);
  const replyText = message.replyText;
  if (replyText !== undefined && (typeof replyText !== 'string' || replyText.length < 1 ||
      new TextEncoder().encode(replyText).byteLength > 4_096)) {
    throw new Error('replyText is invalid');
  }
  try {
    const result = await actionInvokeOutbox.queueAndSend(
      { deviceId: targetDeviceId, keyId: targetKeyId },
      {
        notificationId: message.notificationId,
        notificationRevision,
        actionId,
        idempotencyKey,
        ...(typeof replyText === 'string' ? { replyText } : {}),
      },
    );
    if (result.nextWakeDelayMs !== undefined) {
      await chrome.alarms.create(ACTION_INVOKE_RETRY_ALARM, {
        when: Date.now() + Math.max(1_000, result.nextWakeDelayMs),
      });
    }
    return { queued: true, accepted: result.accepted, idempotencyKey: toHex(idempotencyKey) };
  } catch {
    // Preserve the generated business key for callers even when persistence/send fails.
    return { queued: false, accepted: false, idempotencyKey: toHex(idempotencyKey) };
  }
}

function randomIdentifier(): Uint8Array {
  const value = new Uint8Array(16);
  do {
    crypto.getRandomValues(value);
  } while (value.every((byte) => byte === 0));
  return value;
}

function parseHex(value: unknown, bytes: number, name: string): Uint8Array {
  if (typeof value !== 'string' || value.length !== bytes * 2 || !/^[0-9a-f]+$/.test(value)) {
    throw new Error(`${name} must be canonical lowercase hex`);
  }
  const result = Uint8Array.from({ length: bytes }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16));
  if (result.every((byte) => byte === 0)) throw new Error(`${name} must not be zero`);
  return result;
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function isMessage(value: unknown): value is Record<string, unknown> & { type: string } {
  return typeof value === 'object' && value !== null && 'type' in value &&
    typeof value.type === 'string';
}

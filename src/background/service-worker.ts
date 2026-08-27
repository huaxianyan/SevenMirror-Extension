import {
  clearLifecycleTestNotification,
  createLifecycleTestNotification,
  getLifecycleSpikeStatus,
  handleNotificationClosed,
  markProgrammaticClose,
  recordWorkerStart,
} from './lifecycle-spike';
import { DEFAULT_CONNECTION_STATE } from '../shared/status';
import { runE2eePersistenceSpike } from './e2ee-spike';
import { IndexedDbIdentityStore } from '../crypto/indexeddb-identity-store';
import { ActionInvokeOutbox } from '../crypto/action-invoke-outbox';
import { ActionResultAckOutbox } from '../crypto/action-result-ack-outbox';
import { IndexedDbOutboundSequenceStore } from '../crypto/indexeddb-outbound-sequence-store';
import { IndexedDbPendingActionStore } from '../crypto/indexeddb-pending-action-store';
import { IndexedDbReplayLedger } from '../crypto/indexeddb-replay-ledger';
import { ActionResultDispatcher } from '../crypto/action-result-dispatcher';
import {
  IndexedDbNotificationStateStore,
  type MirroredNotificationState,
} from '../crypto/indexeddb-notification-state-store';
import { NotificationPresenter } from './notification-presenter';
import { NotificationButtonBindingStore } from './notification-button-binding-store';
import { NotificationShortcutPreferencesStore } from './notification-shortcuts';
import {
  IndexedDbTransportCredentialStore,
  type StoredTransportCredential,
} from '../transport/indexeddb-transport-credential-store';
import { IndexedDbPendingMembershipStore } from '../transport/indexeddb-pending-membership-store';
import { IndexedDbWorkspaceMembershipStore } from '../crypto/indexeddb-workspace-membership-store';
import {
  recoverPendingMembership,
  refreshActiveMembership,
} from '../transport/membership-runtime-recovery';
import { TransportRuntime } from '../transport/transport-runtime';
import { WorkspaceBusinessPeerResolver } from '../crypto/workspace-business-peer-resolver';
import { isAppOwnedSyntheticInvoke } from './synthetic-ack-hold';
import { ActionResultStatus } from '../protocol/generated/notification/v1/payload_pb';
import {
  interactionPageUrl,
  interactionSummary,
  resolveCurrentAction,
  validateReplyText,
} from './notification-interaction';

const CONNECTION_STATE_KEY = 'connectionState';
const TRANSPORT_RECONNECT_ALARM = 'transport-reconnect-v1';
const MEMBERSHIP_REFRESH_ALARM = 'membership-refresh-v1';
const ACTION_INVOKE_RETRY_ALARM = 'action-invoke-retry-v1';
const ACTION_RESULT_ACK_RETRY_ALARM = 'action-result-ack-retry-v1';
const SYNTHETIC_ACK_HOLD_MAX_MS = 10 * 60_000;
const TRANSPORT_AUTH_WATCHDOG_MS = 60_000;
let syntheticAckHold: { idempotencyKeyHex: string; expiresAtUnixMs: number } | undefined;
const credentialStore = new IndexedDbTransportCredentialStore();
const identityStore = new IndexedDbIdentityStore();
const pendingMembershipStore = new IndexedDbPendingMembershipStore();
const workspaceMembershipStore = new IndexedDbWorkspaceMembershipStore();
const businessPeerResolver = new WorkspaceBusinessPeerResolver(workspaceMembershipStore);
let membershipRecovery: Promise<void> | undefined;
const pendingActionStore = new IndexedDbPendingActionStore();
const outboundSequenceStore = new IndexedDbOutboundSequenceStore();
const inboundReplayLedger = new IndexedDbReplayLedger('action-results');
const notificationStateStore = new IndexedDbNotificationStateStore();
const notificationButtonBindingStore = new NotificationButtonBindingStore();
const notificationShortcutPreferencesStore = new NotificationShortcutPreferencesStore();
const notificationPresenter = new NotificationPresenter({
  loadShortcutPreferences: () => notificationShortcutPreferencesStore.load(),
  saveButtonBindings: (notificationId, revision, buttons) =>
    notificationButtonBindingStore.save(notificationId, revision, buttons),
  removeButtonBindings: (notificationId) => notificationButtonBindingStore.remove(notificationId),
});
const actionResultDispatcher = new ActionResultDispatcher(
  credentialStore,
  identityStore,
  businessPeerResolver,
  inboundReplayLedger,
  pendingActionStore,
  Date.now,
  notificationStateStore,
);
let transportRuntime: TransportRuntime;
const actionInvokeOutbox = new ActionInvokeOutbox(
  credentialStore,
  identityStore,
  businessPeerResolver,
  pendingActionStore,
  outboundSequenceStore,
  (frame) => transportRuntime.sendEnvelope(frame),
);
const actionResultAckOutbox = new ActionResultAckOutbox(
  credentialStore,
  identityStore,
  businessPeerResolver,
  pendingActionStore,
  outboundSequenceStore,
  (frame) => transportRuntime.sendEnvelope(frame),
);
transportRuntime = new TransportRuntime(
  credentialStore,
  identityStore,
  async (state) => chrome.storage.local.set({ [CONNECTION_STATE_KEY]: state }),
  async (frame) => {
    const result = await actionResultDispatcher.receiveBusiness(frame);
    if (result.kind === 'notification') {
      await notificationPresenter.present(result.receipt);
    }
    await drainActionResultAcks();
  },
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
    onAuthenticated: () => {
      void chrome.alarms.clear(TRANSPORT_RECONNECT_ALARM);
      void chrome.alarms.create(MEMBERSHIP_REFRESH_ALARM, {
        delayInMinutes: 1,
        periodInMinutes: 1,
      });
      void drainActionInvokes();
      void drainActionResultAcks();
    },
    beforeConnect: recoverMembershipBeforeConnect,
    beforeAuthenticate: refreshMembershipBeforeAuthenticate,
  },
);

void recordWorkerStart();
void connectTransportWithWatchdog().catch(() => undefined);

chrome.runtime.onInstalled.addListener(async () => {
  const stored = await chrome.storage.local.get(CONNECTION_STATE_KEY);
  if (stored[CONNECTION_STATE_KEY] === undefined) {
    await chrome.storage.local.set({ [CONNECTION_STATE_KEY]: DEFAULT_CONNECTION_STATE });
  }
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === TRANSPORT_RECONNECT_ALARM) {
    void retryTransportWithWatchdog().catch(() => undefined);
  } else if (alarm.name === MEMBERSHIP_REFRESH_ALARM) {
    void refreshMembershipWhileOnline();
  } else if (alarm.name === ACTION_INVOKE_RETRY_ALARM) {
    void drainActionInvokes();
  } else if (alarm.name === ACTION_RESULT_ACK_RETRY_ALARM) {
    void drainActionResultAcks();
  }
});

chrome.notifications.onClosed.addListener((notificationId, byUser) => {
  void handleNotificationClosed(notificationId, byUser).then((audit) => {
    if (audit?.decision === 'request-remote-dismiss') {
      return requestNotificationDismiss(notificationId);
    }
    return undefined;
  }).catch(() => transportRuntime.failClosed());
});

chrome.notifications.onClicked.addListener((notificationId) => {
  // Persist the close reason before opening the interaction page so a browser-generated close
  // accompanying this click can never dismiss the Android source.
  void markProgrammaticClose(notificationId, 'body-click')
    .then(() => openNotificationInteraction(notificationId).catch(() => undefined))
    .catch(() => transportRuntime.failClosed());
});

chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
  // Persist the close reason before resolving state, authorization, or transport.
  void markProgrammaticClose(notificationId, 'action-click')
    .then(() => invokeNotificationButton(notificationId, buttonIndex))
    .catch(() => transportRuntime.failClosed());
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
      void connectTransportWithWatchdog().then(
        () => sendResponse({ started: true }),
        () => sendResponse({ started: false }),
      );
      return true;

    case 'get-notification-shortcut-settings':
      void getNotificationShortcutSettings().then(sendResponse, () => sendResponse(undefined));
      return true;

    case 'save-notification-shortcut-settings':
      void saveNotificationShortcutSettings(message.preferences).then(
        () => sendResponse({ saved: true }),
        () => sendResponse({ saved: false }),
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
        (result) => sendResponse(result),
        () => sendResponse({ accepted: false, reason: 'failed-closed' }),
      );
      return true;

    case 'hold-synthetic-result-ack':
      void holdSyntheticResultAck(message).then(
        (held) => sendResponse({ held }),
        () => sendResponse({ held: false }),
      );
      return true;

    case 'release-synthetic-result-ack':
      void releaseSyntheticResultAck(message).then(
        (released) => sendResponse({ released }),
        () => sendResponse({ released: false }),
      );
      return true;

    case 'queue-action-invoke':
      void queueActionInvoke(message).then(
        (result) => sendResponse(result),
        () => sendResponse({ queued: false, accepted: false }),
      );
      return true;

    case 'get-notification-interaction':
      void getNotificationInteraction(message).then(
        (notification) => sendResponse({ notification }),
        () => sendResponse({ notification: undefined }),
      );
      return true;

    case 'invoke-notification-interaction':
      void invokeNotificationInteraction(message).then(
        (result) => sendResponse(result),
        () => sendResponse({ outcome: 'unavailable' }),
      );
      return true;

    case 'get-notification-interaction-operation':
      void getNotificationInteractionOperation(message).then(
        (result) => sendResponse(result),
        () => sendResponse({ state: 'unavailable' }),
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

async function recoverMembershipBeforeConnect(): Promise<void> {
  if (membershipRecovery !== undefined) return membershipRecovery;
  membershipRecovery = (async () => {
    let result: Awaited<ReturnType<typeof recoverPendingMembership>>;
    try {
      result = await recoverPendingMembership(
        pendingMembershipStore,
        workspaceMembershipStore,
        credentialStore,
        identityStore,
      );
    } catch (error) {
      if (error instanceof TypeError) {
        await chrome.alarms.create(TRANSPORT_RECONNECT_ALARM, {
          when: Date.now() + TRANSPORT_AUTH_WATCHDOG_MS,
        });
      }
      throw error;
    }
    if (result === 'pending') {
      await chrome.alarms.create(TRANSPORT_RECONNECT_ALARM, {
        when: Date.now() + TRANSPORT_AUTH_WATCHDOG_MS,
      });
      throw new Error('Membership approval is pending');
    }
  })();
  try {
    await membershipRecovery;
  } finally {
    membershipRecovery = undefined;
  }
}

async function refreshMembershipBeforeAuthenticate(
  credential: StoredTransportCredential,
): Promise<void> {
  try {
    const result = await refreshActiveMembership(credential, workspaceMembershipStore);
    if (result === 'inactive') throw new Error('Local device is not active in the durable workspace roster');
  } catch (error) {
    if (error instanceof TypeError) {
      await chrome.alarms.create(TRANSPORT_RECONNECT_ALARM, {
        when: Date.now() + TRANSPORT_AUTH_WATCHDOG_MS,
      });
    }
    throw error;
  }
}

async function refreshMembershipWhileOnline(): Promise<void> {
  const stored = await chrome.storage.local.get(CONNECTION_STATE_KEY);
  if (stored[CONNECTION_STATE_KEY] !== 'online') return;
  const credential = await credentialStore.load();
  if (credential === undefined) {
    await chrome.alarms.clear(MEMBERSHIP_REFRESH_ALARM);
    await transportRuntime.failClosed();
    return;
  }
  try {
    const result = await refreshActiveMembership(credential, workspaceMembershipStore);
    if (result === 'legacy') {
      await chrome.alarms.clear(MEMBERSHIP_REFRESH_ALARM);
    } else if (result === 'inactive') {
      await chrome.alarms.clear(MEMBERSHIP_REFRESH_ALARM);
      await transportRuntime.failClosed();
    }
  } catch (error) {
    if (!(error instanceof TypeError)) {
      await chrome.alarms.clear(MEMBERSHIP_REFRESH_ALARM);
      await transportRuntime.failClosed();
    }
  } finally {
    credential.authToken.fill(0);
  }
}

async function connectTransportWithWatchdog(): Promise<void> {
  await transportRuntime.connect();
  await scheduleTransportAuthWatchdog();
}

async function retryTransportWithWatchdog(): Promise<void> {
  await transportRuntime.retryScheduledConnection();
  await scheduleTransportAuthWatchdog();
}

async function scheduleTransportAuthWatchdog(): Promise<void> {
  if (transportRuntime.hasAuthenticatedConnection()) {
    await chrome.alarms.clear(TRANSPORT_RECONNECT_ALARM);
    return;
  }
  await chrome.alarms.create(TRANSPORT_RECONNECT_ALARM, {
    when: Date.now() + TRANSPORT_AUTH_WATCHDOG_MS,
  });
}

async function getSyntheticActionTarget(): Promise<{
  targetDeviceId: string;
  targetKeyId: string;
} | undefined> {
  const credential = await credentialStore.load();
  if (credential === undefined) return undefined;
  try {
    const recipients = await businessPeerResolver.listActionRecipients(
      credential.workspaceId,
      credential.deviceId,
      Date.now(),
    );
    if (recipients.length !== 1) return undefined;
    return {
      targetDeviceId: toHex(recipients[0]!.deviceId),
      targetKeyId: toHex(recipients[0]!.keyId),
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
  ackAttemptCount?: number;
  ackPending?: boolean;
  ackHoldActive?: boolean;
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
    ackAttemptCount: record.ackAttemptCount,
    ackPending: record.canonicalResultAckPayload !== undefined,
    ackHoldActive: currentSyntheticAckHold()?.idempotencyKeyHex === toHex(key),
  };
}

async function resendSyntheticAction(message: Record<string, unknown>): Promise<{
  accepted: boolean;
  reason?: 'recipient-not-approved';
}> {
  const key = parseHex(message.idempotencyKey, 16, 'idempotencyKey');
  try {
    let accepted = await actionInvokeOutbox.resendExact(key);
    if (!accepted && await transportRuntime.ensureAuthenticated()) {
      accepted = await actionInvokeOutbox.resendExact(key);
    }
    return { accepted };
  } catch (error) {
    if (error instanceof Error && error.message === 'Action recipient is not authorized') {
      return { accepted: false, reason: 'recipient-not-approved' };
    }
    throw error;
  }
}

async function drainActionResultAcks(): Promise<void> {
  let excludedKey: Uint8Array | undefined;
  try {
    const hold = currentSyntheticAckHold();
    excludedKey = hold === undefined
      ? undefined
      : parseHex(hold.idempotencyKeyHex, 16, 'held idempotencyKey');
    const result = await actionResultAckOutbox.drainDue(excludedKey);
    const deliveryDelayMs = result.nextWakeDelayMs ??
      (result.attemptedEntries > result.acceptedSends ? 1_000 : undefined);
    const holdDelayMs = hold === undefined ? undefined : Math.max(1_000, hold.expiresAtUnixMs - Date.now());
    const delayMs = deliveryDelayMs === undefined
      ? holdDelayMs
      : holdDelayMs === undefined ? deliveryDelayMs : Math.min(deliveryDelayMs, holdDelayMs);
    if (delayMs !== undefined) {
      await chrome.alarms.create(ACTION_RESULT_ACK_RETRY_ALARM, {
        when: Date.now() + Math.max(1_000, delayMs),
      });
    } else {
      await chrome.alarms.clear(ACTION_RESULT_ACK_RETRY_ALARM);
    }
  } catch {
    // Corrupt ACK state, trust changes during encryption, or identity mismatch fail closed.
    await transportRuntime.failClosed();
  } finally {
    excludedKey?.fill(0);
  }
}

async function holdSyntheticResultAck(message: Record<string, unknown>): Promise<boolean> {
  const key = parseHex(message.idempotencyKey, 16, 'idempotencyKey');
  const record = await pendingActionStore.get(key);
  if (record?.canonicalInvokePayload === undefined) return false;
  if (!isAppOwnedSyntheticInvoke(record.canonicalInvokePayload, key)) return false;
  syntheticAckHold = {
    idempotencyKeyHex: toHex(key),
    expiresAtUnixMs: Date.now() + SYNTHETIC_ACK_HOLD_MAX_MS,
  };
  await drainActionResultAcks();
  return true;
}

async function releaseSyntheticResultAck(message: Record<string, unknown>): Promise<boolean> {
  const key = parseHex(message.idempotencyKey, 16, 'idempotencyKey');
  const hold = currentSyntheticAckHold();
  if (hold?.idempotencyKeyHex !== toHex(key)) return false;
  syntheticAckHold = undefined;
  await drainActionResultAcks();
  return true;
}

function currentSyntheticAckHold(): { idempotencyKeyHex: string; expiresAtUnixMs: number } | undefined {
  if (syntheticAckHold !== undefined && syntheticAckHold.expiresAtUnixMs <= Date.now()) {
    syntheticAckHold = undefined;
  }
  return syntheticAckHold;
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

async function openNotificationInteraction(notificationId: string): Promise<void> {
  const state = await notificationStateStore.findVisibleByChromeNotificationId(notificationId);
  if (state === undefined) return;
  await chrome.tabs.create({
    url: interactionPageUrl(chrome.runtime.getURL('/'), notificationId),
  });
}

async function getNotificationInteraction(
  message: Record<string, unknown>,
): Promise<ReturnType<typeof interactionSummary> | undefined> {
  if (typeof message.chromeNotificationId !== 'string') return undefined;
  const state = await notificationStateStore.findVisibleByChromeNotificationId(
    message.chromeNotificationId,
  );
  if (state === undefined) return undefined;
  const credential = await credentialStore.load();
  if (credential === undefined) return undefined;
  try {
    const sourceName = await businessPeerResolver.resolveNotificationSourceName(
      credential.workspaceId,
      credential.deviceId,
      state.sourceDeviceId,
      Date.now(),
    );
    return sourceName === undefined ? undefined : interactionSummary(state, sourceName);
  } finally {
    credential.authToken.fill(0);
  }
}

async function invokeNotificationInteraction(message: Record<string, unknown>): Promise<{
  outcome: 'sent' | 'queued' | 'awaiting-result' | 'unavailable' | 'changed';
  idempotencyKey?: string;
}> {
  if (typeof message.chromeNotificationId !== 'string' ||
      typeof message.revision !== 'string') return { outcome: 'unavailable' };
  const state = await notificationStateStore.findVisibleByChromeNotificationId(
    message.chromeNotificationId,
  );
  if (state === undefined || state.revision !== message.revision) return { outcome: 'changed' };

  let result: Awaited<ReturnType<typeof queueStateOperation>>;
  if (message.operation === 'dismiss') {
    result = await queueStateOperation(state, { dismissNotification: true });
  } else if (message.operation === 'action' && typeof message.actionId === 'string') {
    const action = resolveCurrentAction(state, message.revision, message.actionId);
    if (action === undefined || action.requiresTextInput) return { outcome: 'unavailable' };
    result = await queueStateOperation(state, { actionId: action.actionId });
  } else if (message.operation === 'reply' && typeof message.actionId === 'string' &&
      typeof message.replyText === 'string') {
    const action = resolveCurrentAction(state, message.revision, message.actionId);
    if (action === undefined || !action.requiresTextInput || !action.allowsFreeFormInput ||
        validateReplyText(message.replyText) !== 'valid') {
      return { outcome: 'unavailable' };
    }
    result = await queueStateOperation(state, {
      actionId: action.actionId,
      replyText: message.replyText,
      sendOnce: true,
    });
  } else {
    return { outcome: 'unavailable' };
  }
  if (result === undefined || !result.queued) return { outcome: 'unavailable' };
  if (message.operation === 'reply') {
    return result.accepted
      ? { outcome: 'awaiting-result', idempotencyKey: result.idempotencyKey }
      : { outcome: 'unavailable' };
  }
  return { outcome: result.accepted ? 'sent' : 'queued' };
}

async function getNotificationInteractionOperation(message: Record<string, unknown>): Promise<{
  state: 'pending' | 'succeeded' | 'changed' | 'failed' | 'unknown' | 'unavailable';
}> {
  const key = parseHex(message.idempotencyKey, 16, 'idempotencyKey');
  const record = await pendingActionStore.get(key);
  if (record === undefined || record.invokeDeliveryMode !== 'once') return { state: 'unavailable' };
  if (record.state === 'pending') return { state: 'pending' };
  switch (record.resultStatus) {
    case ActionResultStatus.SUCCEEDED:
      return { state: 'succeeded' };
    case ActionResultStatus.STALE_NOTIFICATION_VERSION:
      return { state: 'changed' };
    case ActionResultStatus.OUTCOME_UNKNOWN:
      return { state: 'unknown' };
    default:
      return { state: 'failed' };
  }
}

async function getNotificationShortcutSettings(): Promise<{
  preferences: Awaited<ReturnType<NotificationShortcutPreferencesStore['load']>>;
  applications: Array<{ id: string; name: string }>;
}> {
  const [preferences, states] = await Promise.all([
    notificationShortcutPreferencesStore.load(),
    notificationStateStore.listVisible(),
  ]);
  const applications = new Map<string, string>();
  for (const state of states) {
    if (state.sourceApplicationId !== undefined && state.sourceApplicationName !== undefined) {
      applications.set(state.sourceApplicationId, state.sourceApplicationName);
    }
  }
  return {
    preferences,
    applications: [...applications].map(([id, name]) => ({ id, name }))
      .sort((left, right) => left.name.localeCompare(right.name)),
  };
}

async function saveNotificationShortcutSettings(value: unknown): Promise<void> {
  await notificationShortcutPreferencesStore.save(value);
  const states = await notificationStateStore.listVisible();
  await Promise.allSettled(states.map((state) => notificationPresenter.presentState(state)));
}

async function invokeNotificationButton(notificationId: string, buttonIndex: number): Promise<void> {
  if (!Number.isInteger(buttonIndex) || buttonIndex < 0 || buttonIndex > 1) return;
  const state = await notificationStateStore.findVisibleByChromeNotificationId(notificationId);
  if (state === undefined) return;
  const bindings = await notificationButtonBindingStore.load(notificationId, state.revision);
  const button = bindings?.[buttonIndex];
  if (button === undefined) return;
  if (button.kind === 'dismiss') {
    await markProgrammaticClose(notificationId, 'explicit-clear');
    await queueStateOperation(state, { dismissNotification: true });
    return;
  }
  if (button.kind === 'more' || button.requiresTextInput) {
    await openNotificationInteraction(notificationId);
    return;
  }
  const action = state.actions?.find((candidate) =>
    toHex(candidate.actionId) === toHex(button.actionId));
  if (action === undefined || action.requiresTextInput) return;
  await queueStateOperation(state, { actionId: action.actionId });
}

async function requestNotificationDismiss(notificationId: string): Promise<void> {
  const state = await notificationStateStore.findVisibleByChromeNotificationId(notificationId);
  if (state === undefined) return;
  await queueStateOperation(state, { dismissNotification: true });
}

async function queueStateOperation(
  state: MirroredNotificationState,
  operation:
    | { actionId: Uint8Array; replyText?: string; sendOnce?: boolean }
    | { dismissNotification: true },
): Promise<{ queued: boolean; accepted: boolean; idempotencyKey: string } | undefined> {
  const credential = await credentialStore.load();
  if (credential === undefined) return undefined;
  try {
    const recipients = await businessPeerResolver.listActionRecipients(
      credential.workspaceId,
      credential.deviceId,
      Date.now(),
    );
    const recipient = recipients.find((candidate) =>
      toHex(candidate.deviceId) === toHex(state.sourceDeviceId));
    if (recipient === undefined) return undefined;
    return await queueActionInvoke({
      targetDeviceId: toHex(recipient.deviceId),
      targetKeyId: toHex(recipient.keyId),
      notificationId: state.notificationId,
      notificationRevision: state.revision,
      ...('actionId' in operation
        ? {
          actionId: toHex(operation.actionId),
          ...(operation.replyText === undefined ? {} : { replyText: operation.replyText }),
          ...(operation.sendOnce === true ? { sendOnce: true } : {}),
        }
        : { dismissNotification: true }),
    });
  } finally {
    credential.authToken.fill(0);
  }
}

async function queueActionInvoke(message: Record<string, unknown>): Promise<{
  queued: boolean;
  accepted: boolean;
  idempotencyKey: string;
}> {
  const targetDeviceId = parseHex(message.targetDeviceId, 16, 'targetDeviceId');
  const targetKeyId = parseHex(message.targetKeyId, 32, 'targetKeyId');
  const dismissNotification = message.dismissNotification === true;
  if (message.dismissNotification !== undefined && !dismissNotification) {
    throw new Error('dismissNotification is invalid');
  }
  const actionId = dismissNotification ? undefined : parseHex(message.actionId, 16, 'actionId');
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
  const sendOnce = message.sendOnce === true;
  if (message.sendOnce !== undefined && !sendOnce) {
    throw new Error('sendOnce is invalid');
  }
  if (sendOnce && (dismissNotification || typeof replyText !== 'string')) {
    throw new Error('sendOnce is only valid for replies');
  }
  if (replyText !== undefined && (dismissNotification || typeof replyText !== 'string' ||
      replyText.length < 1 || new TextEncoder().encode(replyText).byteLength > 4_000)) {
    throw new Error('replyText is invalid');
  }
  if (dismissNotification && message.actionId !== undefined) {
    throw new Error('dismiss operation cannot include actionId');
  }
  try {
    const target = { deviceId: targetDeviceId, keyId: targetKeyId };
    const request = dismissNotification
      ? {
        notificationId: message.notificationId,
        notificationRevision,
        idempotencyKey,
        dismissNotification: true as const,
      }
      : {
        notificationId: message.notificationId,
        notificationRevision,
        actionId: requireDefined(actionId),
        idempotencyKey,
        ...(typeof replyText === 'string' ? { replyText } : {}),
      };
    if (sendOnce) {
      const result = await actionInvokeOutbox.sendOnce(target, request);
      return { queued: true, accepted: result.accepted, idempotencyKey: toHex(idempotencyKey) };
    }
    const result = await actionInvokeOutbox.queueAndSend(target, request);
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

function requireDefined<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('Required action value is unavailable');
  return value;
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

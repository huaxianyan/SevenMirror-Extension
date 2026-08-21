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
import { IdentityTransitionAckOutbox } from '../crypto/identity-transition-ack-outbox';
import { IdentityTransitionCommitOutbox } from '../crypto/identity-transition-commit-outbox';
import { IdentityTransitionDispatcher } from '../crypto/identity-transition-dispatcher';
import { IdentityTransitionOutbox } from '../crypto/identity-transition-outbox';
import { IdentityTransitionPeerRemovalCoordinator } from '../crypto/identity-transition-peer-removal';
import {
  IdentityTransitionInitiator,
  IdentityTransitionPreconditionError,
} from '../crypto/identity-transition-initiator';
import {
  IdentityPromotionCoordinator,
  IndexedDbIdentityPromotionJournal,
} from '../crypto/identity-promotion-journal';
import { IndexedDbLocalIdentityTransitionStore } from '../crypto/indexeddb-local-identity-transition-store';
import { ActionInvokeOutbox } from '../crypto/action-invoke-outbox';
import { ActionResultAckOutbox } from '../crypto/action-result-ack-outbox';
import { IndexedDbOutboundSequenceStore } from '../crypto/indexeddb-outbound-sequence-store';
import { IndexedDbPendingActionStore } from '../crypto/indexeddb-pending-action-store';
import { IndexedDbReplayLedger } from '../crypto/indexeddb-replay-ledger';
import { IndexedDbTrustedPeerStore } from '../crypto/indexeddb-trusted-peer-store';
import { ActionResultDispatcher } from '../crypto/action-result-dispatcher';
import { IndexedDbNotificationStateStore } from '../crypto/indexeddb-notification-state-store';
import { NotificationPresenter } from './notification-presenter';
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

const CONNECTION_STATE_KEY = 'connectionState';
const TRANSPORT_RECONNECT_ALARM = 'transport-reconnect-v1';
const MEMBERSHIP_REFRESH_ALARM = 'membership-refresh-v1';
const ACTION_INVOKE_RETRY_ALARM = 'action-invoke-retry-v1';
const ACTION_RESULT_ACK_RETRY_ALARM = 'action-result-ack-retry-v1';
const IDENTITY_TRANSITION_RETRY_ALARM = 'identity-transition-retry-v1';
const IDENTITY_TRANSITION_ACK_RETRY_ALARM = 'identity-transition-ack-retry-v1';
const IDENTITY_TRANSITION_COMMIT_RETRY_ALARM = 'identity-transition-commit-retry-v1';
const SYNTHETIC_ACK_HOLD_MAX_MS = 10 * 60_000;
const TRANSPORT_AUTH_WATCHDOG_MS = 60_000;
let syntheticAckHold: { idempotencyKeyHex: string; expiresAtUnixMs: number } | undefined;
const credentialStore = new IndexedDbTransportCredentialStore();
const identityStore = new IndexedDbIdentityStore();
const pendingMembershipStore = new IndexedDbPendingMembershipStore();
const workspaceMembershipStore = new IndexedDbWorkspaceMembershipStore();
const businessPeerResolver = new WorkspaceBusinessPeerResolver(workspaceMembershipStore);
let membershipRecovery: Promise<void> | undefined;
const trustedPeerStore = new IndexedDbTrustedPeerStore();
const pendingActionStore = new IndexedDbPendingActionStore();
const outboundSequenceStore = new IndexedDbOutboundSequenceStore();
const localIdentityTransitionStore = new IndexedDbLocalIdentityTransitionStore();
const identityPromotionCoordinator = new IdentityPromotionCoordinator(
  identityStore,
  credentialStore,
  localIdentityTransitionStore,
  new IndexedDbIdentityPromotionJournal(),
);
const inboundReplayLedger = new IndexedDbReplayLedger('action-results');
const notificationStateStore = new IndexedDbNotificationStateStore();
const notificationPresenter = new NotificationPresenter();
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
const identityTransitionInitiator = new IdentityTransitionInitiator(
  credentialStore,
  identityStore,
  trustedPeerStore,
  localIdentityTransitionStore,
);
const identityTransitionPeerRemoval = new IdentityTransitionPeerRemovalCoordinator(
  credentialStore,
  trustedPeerStore,
  localIdentityTransitionStore,
);
const identityTransitionOutbox = new IdentityTransitionOutbox(
  credentialStore,
  identityStore,
  localIdentityTransitionStore,
  trustedPeerStore,
  outboundSequenceStore,
  (frame) => transportRuntime.sendEnvelope(frame),
);
const identityTransitionAckOutbox = new IdentityTransitionAckOutbox(
  credentialStore,
  identityStore,
  trustedPeerStore,
  outboundSequenceStore,
  (frame) => transportRuntime.sendEnvelope(frame),
);
const identityTransitionCommitOutbox = new IdentityTransitionCommitOutbox(
  credentialStore,
  identityStore,
  localIdentityTransitionStore,
  trustedPeerStore,
  outboundSequenceStore,
  (frame) => transportRuntime.sendEnvelope(frame),
);
const identityTransitionDispatcher = new IdentityTransitionDispatcher(
  credentialStore,
  identityStore,
  trustedPeerStore,
  localIdentityTransitionStore,
  inboundReplayLedger,
  async (frame) => {
    const result = await actionResultDispatcher.receiveBusiness(
      frame.slice().buffer as ArrayBuffer,
    );
    if (result.kind === 'notification') {
      await notificationPresenter.present(result.receipt);
    }
  },
);
transportRuntime = new TransportRuntime(
  credentialStore,
  identityStore,
  async (state) => chrome.storage.local.set({ [CONNECTION_STATE_KEY]: state }),
  async (frame) => {
    const result = await identityTransitionDispatcher.receive(new Uint8Array(frame));
    if (result === 'peer-transition') {
      await drainIdentityTransitionAcks();
    } else if (result === 'local-ack') {
      await identityPromotionCoordinator.promoteReady();
      await drainIdentityTransitionCommits();
    } else if (result === 'business-fallback') {
      await drainActionResultAcks();
    }
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
      void drainIdentityTransitions();
      void drainIdentityTransitionAcks();
      void drainIdentityTransitionCommits();
    },
    // No socket may observe a half-completed cross-database identity promotion.
    beforeConnect: async () => {
      await identityPromotionCoordinator.promoteReady();
      await recoverMembershipBeforeConnect();
    },
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
  } else if (alarm.name === IDENTITY_TRANSITION_RETRY_ALARM) {
    void drainIdentityTransitions();
  } else if (alarm.name === IDENTITY_TRANSITION_ACK_RETRY_ALARM) {
    void drainIdentityTransitionAcks();
  } else if (alarm.name === IDENTITY_TRANSITION_COMMIT_RETRY_ALARM) {
    void drainIdentityTransitionCommits();
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
      void connectTransportWithWatchdog().then(
        () => sendResponse({ started: true }),
        () => sendResponse({ started: false }),
      );
      return true;

    case 'get-identity-transition-status':
      void getIdentityTransitionStatus().then(
        (status) => sendResponse(status),
        () => sendResponse({ active: false, error: 'Identity transition status failed closed' }),
      );
      return true;

    case 'remove-identity-transition-peer':
      void removeIdentityTransitionPeer(message).then(
        (result) => sendResponse(result),
        (error: unknown) => sendResponse({
          removed: false,
          error: error instanceof Error ? error.message : 'Peer removal failed closed',
        }),
      );
      return true;

    case 'start-identity-transition':
      void identityTransitionInitiator.prepare().then(
        async (session) => {
          await drainIdentityTransitions();
          sendResponse({ started: true });
        },
        async (error: unknown) => {
          if (!(error instanceof IdentityTransitionPreconditionError)) {
            await transportRuntime.failClosed();
          }
          sendResponse({
            started: false,
            error: error instanceof Error ? error.message : 'Identity transition failed closed',
          });
        },
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

async function getIdentityTransitionStatus(): Promise<Record<string, unknown>> {
  const session = await localIdentityTransitionStore.loadSession(Date.now());
  if (session === undefined) return { active: false };
  const peers = await localIdentityTransitionStore.listPeers(Date.now());
  return {
    active: true,
    phase: session.phase,
    expiresAtUnixMs: session.expiresAtUnixMs,
    peers: peers.map((peer) => ({
      deviceId: encodeBase64Url(peer.deviceId),
      deviceRef: encodeHex(peer.deviceId).slice(0, 12),
      keyRef: encodeHex(peer.keyId).slice(0, 12),
      phase: peer.phase,
    })),
  };
}

async function removeIdentityTransitionPeer(
  message: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (typeof message.peerDeviceId !== 'string') throw new Error('Peer device ID is required');
  const peerDeviceId = decodeBase64Url(message.peerDeviceId, 16);
  try {
    const disposition = await identityTransitionPeerRemoval.remove(peerDeviceId);
    const promotion = await identityPromotionCoordinator.promoteReady();
    await drainIdentityTransitionCommits();
    return { removed: true, disposition, promotion };
  } finally {
    peerDeviceId.fill(0);
  }
}

async function drainIdentityTransitions(): Promise<void> {
  try {
    const result = await identityTransitionOutbox.drainDue();
    await scheduleIdentityTransitionRetry(
      IDENTITY_TRANSITION_RETRY_ALARM,
      result.nextWakeDelayMs,
      result.attemptedEntries > result.acceptedSends,
    );
  } catch {
    await transportRuntime.failClosed();
  }
}

async function drainIdentityTransitionAcks(): Promise<void> {
  try {
    const result = await identityTransitionAckOutbox.drainDue();
    await scheduleIdentityTransitionRetry(
      IDENTITY_TRANSITION_ACK_RETRY_ALARM,
      result.nextWakeDelayMs,
      result.attemptedEntries > result.acceptedSends,
    );
  } catch {
    await transportRuntime.failClosed();
  }
}

async function drainIdentityTransitionCommits(): Promise<void> {
  try {
    const result = await identityTransitionCommitOutbox.drainDue();
    await scheduleIdentityTransitionRetry(
      IDENTITY_TRANSITION_COMMIT_RETRY_ALARM,
      result.nextWakeDelayMs,
      result.attemptedEntries > result.acceptedSends,
    );
  } catch {
    await transportRuntime.failClosed();
  }
}

async function scheduleIdentityTransitionRetry(
  alarmName: string,
  nextWakeDelayMs: number | undefined,
  sendRejected: boolean,
): Promise<void> {
  const delayMs = nextWakeDelayMs ?? (sendRejected ? 1_000 : undefined);
  if (delayMs === undefined) {
    await chrome.alarms.clear(alarmName);
  } else {
    await chrome.alarms.create(alarmName, {
      when: Date.now() + Math.max(1_000, delayMs),
    });
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

function encodeBase64Url(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64Url(value: string, expectedLength: number): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Peer device ID is not canonical base64url');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') +
    '='.repeat((4 - value.length % 4) % 4);
  const decoded = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  if (decoded.byteLength !== expectedLength || encodeBase64Url(decoded) !== value) {
    throw new Error('Peer device ID has wrong length or encoding');
  }
  return decoded;
}

function encodeHex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function isMessage(value: unknown): value is Record<string, unknown> & { type: string } {
  return typeof value === 'object' && value !== null && 'type' in value &&
    typeof value.type === 'string';
}

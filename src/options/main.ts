import { IndexedDbIdentityStore } from '../crypto/indexeddb-identity-store';
import { IndexedDbPendingMembershipStore } from '../transport/indexeddb-pending-membership-store';
import { IndexedDbWorkspaceMembershipStore } from '../crypto/indexeddb-workspace-membership-store';
import { beginChromeMembership } from '../transport/workspace-membership-client';
import { rotateChromeTransportCredential } from '../transport/transport-credential-rotation-client';
import {
  IndexedDbTransportCredentialStore,
  normalizeServerOrigin,
} from '../transport/indexeddb-transport-credential-store';
import { presentActionResultStatus } from './action-result-status';
import { localizeDocument, message } from '../shared/i18n';

const identityStore = new IndexedDbIdentityStore();
const credentialStore = new IndexedDbTransportCredentialStore();
const pendingMembershipStore = new IndexedDbPendingMembershipStore();
const workspaceMembershipStore = new IndexedDbWorkspaceMembershipStore();
const versionOutput = document.querySelector<HTMLElement>('#extension-version');
const form = document.querySelector<HTMLFormElement>('#registration-form');
const serverInput = document.querySelector<HTMLInputElement>('#server-origin');
const codeInput = document.querySelector<HTMLInputElement>('#pairing-code');
const nameInput = document.querySelector<HTMLInputElement>('#device-name');
const submit = document.querySelector<HTMLButtonElement>('#register');
const status = document.querySelector<HTMLElement>('#registration-status');
const reconnectTransportButton = document.querySelector<HTMLButtonElement>('#reconnect-transport');
const rotationSection = document.querySelector<HTMLElement>('#credential-rotation');
const rotationForm = document.querySelector<HTMLFormElement>('#credential-rotation-form');
const rotationCodeInput = document.querySelector<HTMLInputElement>('#credential-rotation-code');
const rotateCredentialButton = document.querySelector<HTMLButtonElement>('#rotate-credential');
const rotationStatus = document.querySelector<HTMLElement>('#credential-rotation-status');
const relayTestSection = document.querySelector<HTMLElement>('#synthetic-relay-test');
const syntheticTargetInput = document.querySelector<HTMLTextAreaElement>('#synthetic-action-target');
const queueSyntheticActionButton = document.querySelector<HTMLButtonElement>('#queue-synthetic-action');
const refreshSyntheticActionButton = document.querySelector<HTMLButtonElement>('#refresh-synthetic-action');
const resendSyntheticActionButton = document.querySelector<HTMLButtonElement>('#resend-synthetic-action');
const holdSyntheticResultAckButton = document.querySelector<HTMLButtonElement>('#hold-synthetic-result-ack');
const releaseSyntheticResultAckButton = document.querySelector<HTMLButtonElement>('#release-synthetic-result-ack');
const syntheticActionStatus = document.querySelector<HTMLElement>('#synthetic-action-status');
let currentSyntheticIdempotencyKey: string | undefined;
let currentSyntheticResultUncertain = false;
const SYNTHETIC_OPERATION_SELECTION_KEY = 'syntheticOperationSelectionV1';

localizeDocument();

async function render(): Promise<void> {
  if (versionOutput) {
    versionOutput.textContent = message(
      'extensionVersionValue',
      chrome.runtime.getManifest().version,
    );
  }
  const existing = await credentialStore.load();
  if (existing !== undefined) {
    existing.authToken.fill(0);
    form?.setAttribute('hidden', '');
    setStatus(message('profileRegistered'));
    reconnectTransportButton?.removeAttribute('hidden');
    rotationSection?.removeAttribute('hidden');
    await renderCredentialRotation();
    await renderSyntheticRelayAvailability();
    await restoreSyntheticOperationSelection();
    return;
  }
  const pending = await pendingMembershipStore.load();
  if (pending !== undefined) {
    pending.authToken.fill(0);
    pending.canonicalProof?.fill(0);
    form?.setAttribute('hidden', '');
    reconnectTransportButton?.removeAttribute('hidden');
    setStatus(message('waitingForAdminApproval'));
  }
}

rotationForm?.addEventListener('submit', (event) => {
  event.preventDefault();
  if (!rotationCodeInput || !rotateCredentialButton) return;
  const rotationCode = rotationCodeInput.value;
  rotationCodeInput.value = '';
  rotateCredentialButton.disabled = true;
  setRotationStatus('Persisting one pending credential before any network request…');
  void rotateChromeTransportCredential(rotationCode, credentialStore).then(async () => {
    setRotationStatus('Rotation request accepted. Probing pending authentication; completion requires SNO1.');
    await chrome.runtime.sendMessage({ type: 'transport-connect' });
  }).catch(async () => {
    const rotation = await credentialStore.loadRotation().catch(() => undefined);
    if (rotation?.phase === 'attempted') {
      rotation.current.authToken.fill(0);
      rotation.pendingAuthToken.fill(0);
      setRotationStatus('Rotation was not confirmed. Exact pending state was retained; transport will probe pending, then fall back to current. Retry with the same or a newly issued code.');
      await chrome.runtime.sendMessage({ type: 'transport-connect' }).catch(() => undefined);
    } else {
      setRotationStatus('Rotation was not attempted. Verify the exact 32-character code.');
    }
  }).finally(() => {
    rotateCredentialButton.disabled = false;
  });
});

reconnectTransportButton?.addEventListener('click', () => {
  reconnectTransportButton.disabled = true;
  void (async () => {
    const pending = await pendingMembershipStore.load();
    if (pending !== undefined) {
      pending.authToken.fill(0);
      pending.canonicalProof?.fill(0);
      setStatus(message('waitingForAdminApproval'));
      await chrome.runtime.sendMessage({ type: 'transport-connect' }).catch(() => undefined);
      await render();
      return;
    }
    setStatus(message('reconnectingTransport'));
    const response = await chrome.runtime.sendMessage({ type: 'transport-connect' }) as {
      started?: boolean;
    };
    setStatus(response.started ? message('reconnectRequested') : message('reconnectRejected'));
  })().catch(() => setStatus(message('reconnectFailed')))
    .finally(() => { reconnectTransportButton.disabled = false; });
});

form?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!serverInput || !codeInput || !nameInput || !submit) return;
  submit.disabled = true;
  setStatus(message('validatingRegistration'));
  let originPermission: string | undefined;
  let permissionAlreadyGranted = false;
  try {
    const serverOrigin = normalizeServerOrigin(serverInput.value);
    originPermission = `${serverOrigin}/*`;
    permissionAlreadyGranted = await chrome.permissions.contains({ origins: [originPermission] });
    const permissionGranted = permissionAlreadyGranted || await chrome.permissions.request({
      origins: [originPermission],
    });
    if (!permissionGranted) {
      setStatus(message('hostPermissionDenied'));
      return;
    }

    if (await credentialStore.load() !== undefined) {
      throw new Error('This Chrome profile is already registered');
    }
    const identity = await identityStore.loadOrCreate();
    setStatus(message('registering'));
    await beginChromeMembership({
      serverOrigin,
      pairingCode: codeInput.value,
      deviceName: nameInput.value,
      identity,
    }, workspaceMembershipStore, pendingMembershipStore);
    codeInput.value = '';
    setStatus(message('waitingForAdminApproval'));
    form.setAttribute('hidden', '');
    reconnectTransportButton?.removeAttribute('hidden');
    await chrome.runtime.sendMessage({ type: 'transport-connect' }).catch(() => undefined);
  } catch {
    const pending = await pendingMembershipStore.load().catch(() => undefined);
    if (pending !== undefined) {
      pending.authToken.fill(0);
      pending.canonicalProof?.fill(0);
      setStatus(message('waitingForAdminApproval'));
      form.setAttribute('hidden', '');
      reconnectTransportButton?.removeAttribute('hidden');
    } else {
      if (originPermission !== undefined && !permissionAlreadyGranted) {
        await chrome.permissions.remove({ origins: [originPermission] });
      }
      setStatus(message('registrationFailed'));
    }
  } finally {
    codeInput.value = '';
    submit.disabled = false;
  }
});

queueSyntheticActionButton?.addEventListener('click', () => {
  const raw = syntheticTargetInput?.value ?? '';
  if (!raw) return;
  if (queueSyntheticActionButton) queueSyntheticActionButton.disabled = true;
  setSyntheticActionStatus('Validating and durably queueing the synthetic action…');
  void queueSyntheticAction(raw).finally(() => {
    if (queueSyntheticActionButton) queueSyntheticActionButton.disabled = false;
  });
});

refreshSyntheticActionButton?.addEventListener('click', () => {
  void refreshSyntheticActionStatus();
});

resendSyntheticActionButton?.addEventListener('click', () => {
  void resendSyntheticAction();
});

holdSyntheticResultAckButton?.addEventListener('click', () => {
  void holdSyntheticResultAck();
});

releaseSyntheticResultAckButton?.addEventListener('click', () => {
  void releaseSyntheticResultAck();
});

async function renderSyntheticRelayAvailability(): Promise<void> {
  const response = await chrome.runtime.sendMessage({ type: 'get-synthetic-action-target' }) as {
    target?: { targetDeviceId: string; targetKeyId: string };
  };
  if (relayTestSection) relayTestSection.hidden = response.target === undefined;
  if (response.target === undefined) return;
  setSyntheticActionStatus('Ready. Post the Android app-owned test notification and copy its synthetic relay target.');
}

async function queueSyntheticAction(raw: string): Promise<void> {
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (parsed.version !== 1 || typeof parsed.targetDeviceId !== 'string' ||
        typeof parsed.targetKeyId !== 'string' || typeof parsed.notificationId !== 'string' ||
        typeof parsed.notificationRevision !== 'string' || typeof parsed.actionId !== 'string') {
      throw new Error('Synthetic target shape is invalid');
    }
    const expected = await chrome.runtime.sendMessage({ type: 'get-synthetic-action-target' }) as {
      target?: { targetDeviceId: string; targetKeyId: string };
    };
    if (expected.target === undefined || parsed.targetDeviceId !== expected.target.targetDeviceId ||
        parsed.targetKeyId !== expected.target.targetKeyId) {
      throw new Error('Synthetic target does not match the sole approved Android peer');
    }
    const result = await chrome.runtime.sendMessage({
      type: 'queue-action-invoke',
      targetDeviceId: parsed.targetDeviceId,
      targetKeyId: parsed.targetKeyId,
      notificationId: parsed.notificationId,
      notificationRevision: parsed.notificationRevision,
      actionId: parsed.actionId,
    }) as { queued?: boolean; accepted?: boolean; idempotencyKey?: string };
    if (!result.queued || typeof result.idempotencyKey !== 'string') {
      throw new Error('Synthetic action was not durably queued');
    }
    currentSyntheticIdempotencyKey = result.idempotencyKey;
    currentSyntheticResultUncertain = false;
    await chrome.storage.local.set({
      [SYNTHETIC_OPERATION_SELECTION_KEY]: result.idempotencyKey,
    });
    if (refreshSyntheticActionButton) refreshSyntheticActionButton.hidden = false;
    if (resendSyntheticActionButton) resendSyntheticActionButton.hidden = true;
    if (holdSyntheticResultAckButton) holdSyntheticResultAckButton.hidden = true;
    if (releaseSyntheticResultAckButton) releaseSyntheticResultAckButton.hidden = true;
    setSyntheticActionStatus(result.accepted
      ? 'Queued durably; current authenticated socket accepted the encrypted frame locally. Awaiting Android result.'
      : 'Queued durably; no current socket acceptance. Durable retry remains pending.');
    window.setTimeout(() => { void refreshSyntheticActionStatus(); }, 1_000);
  } catch {
    setSyntheticActionStatus('Synthetic action rejected before queueing. Verify the current app-owned target and approved peer.');
  }
}

async function restoreSyntheticOperationSelection(): Promise<void> {
  const stored = await chrome.storage.local.get(SYNTHETIC_OPERATION_SELECTION_KEY);
  const key = stored[SYNTHETIC_OPERATION_SELECTION_KEY];
  if (typeof key !== 'string' || !/^[0-9a-f]{32}$/.test(key) || /^0+$/.test(key)) return;
  currentSyntheticIdempotencyKey = key;
  if (refreshSyntheticActionButton) refreshSyntheticActionButton.hidden = false;
  await refreshSyntheticActionStatus();
}

async function refreshSyntheticActionStatus(): Promise<void> {
  if (currentSyntheticIdempotencyKey === undefined) return;
  const result = await chrome.runtime.sendMessage({
    type: 'get-synthetic-action-status',
    idempotencyKey: currentSyntheticIdempotencyKey,
  }) as {
    found?: boolean;
    state?: string;
    resultStatus?: string;
    invokeAttemptCount?: number;
    authenticatedResultCount?: number;
    ackAttemptCount?: number;
    ackPending?: boolean;
    ackHoldActive?: boolean;
  };
  if (!result.found) {
    currentSyntheticResultUncertain = false;
    setSyntheticActionStatus('Durable action record was not found.');
    return;
  }
  if (result.state === 'completed') {
    const numericStatus = result.resultStatus !== undefined && /^[0-9]+$/.test(result.resultStatus)
      ? Number(result.resultStatus)
      : undefined;
    const presentation = presentActionResultStatus(numericStatus);
    currentSyntheticResultUncertain = presentation.uncertain;
    if (resendSyntheticActionButton) {
      resendSyntheticActionButton.hidden = false;
      resendSyntheticActionButton.textContent = presentation.resendLabel;
    }
    if (holdSyntheticResultAckButton) holdSyntheticResultAckButton.hidden = result.ackHoldActive === true;
    if (releaseSyntheticResultAckButton) releaseSyntheticResultAckButton.hidden = result.ackHoldActive !== true;
    setSyntheticActionStatus(`Operation: terminal. Result: ${presentation.headline}. ${presentation.explanation} Authenticated Android status code: ${result.resultStatus ?? 'unknown'}. Locally accepted invoke deliveries: ${result.invokeAttemptCount ?? 0}; authenticated result deliveries observed: ${result.authenticatedResultCount ?? 1}; locally accepted result ACK deliveries: ${result.ackAttemptCount ?? 0}; durable ACK intent: ${result.ackPending === true ? 'present' : 'not present'}; synthetic ACK hold: ${result.ackHoldActive === true ? 'active' : 'inactive'}.`, presentation.uncertain);
  } else {
    currentSyntheticResultUncertain = false;
    if (resendSyntheticActionButton) resendSyntheticActionButton.textContent = 'Resend exact completed action';
    if (holdSyntheticResultAckButton) holdSyntheticResultAckButton.hidden = true;
    if (releaseSyntheticResultAckButton) releaseSyntheticResultAckButton.hidden = true;
    setSyntheticActionStatus(`Still pending. Locally accepted send attempts: ${result.invokeAttemptCount ?? 0}.`);
  }
}

async function holdSyntheticResultAck(): Promise<void> {
  if (currentSyntheticIdempotencyKey === undefined || !holdSyntheticResultAckButton) return;
  holdSyntheticResultAckButton.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({
      type: 'hold-synthetic-result-ack',
      idempotencyKey: currentSyntheticIdempotencyKey,
    }) as { held?: boolean };
    setSyntheticActionStatus(result.held
      ? 'Synthetic ACK hold armed in this Worker. Resend the exact operation to create a held ACK intent.'
      : 'ACK hold rejected: the selected operation is not the app-owned synthetic action.');
    await refreshSyntheticActionStatus();
  } finally {
    holdSyntheticResultAckButton.disabled = false;
  }
}

async function releaseSyntheticResultAck(): Promise<void> {
  if (currentSyntheticIdempotencyKey === undefined || !releaseSyntheticResultAckButton) return;
  releaseSyntheticResultAckButton.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({
      type: 'release-synthetic-result-ack',
      idempotencyKey: currentSyntheticIdempotencyKey,
    }) as { released?: boolean };
    setSyntheticActionStatus(result.released
      ? 'Synthetic ACK hold released; authenticated delivery has been requested.'
      : 'No matching synthetic ACK hold was active.');
    window.setTimeout(() => { void refreshSyntheticActionStatus(); }, 1_000);
  } finally {
    releaseSyntheticResultAckButton.disabled = false;
  }
}

async function resendSyntheticAction(): Promise<void> {
  if (currentSyntheticIdempotencyKey === undefined || !resendSyntheticActionButton) return;
  resendSyntheticActionButton.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({
      type: 'resend-synthetic-action',
      idempotencyKey: currentSyntheticIdempotencyKey,
    }) as { accepted?: boolean; reason?: string };
    setSyntheticActionStatus(result.accepted
      ? currentSyntheticResultUncertain
        ? 'Exact operation envelope accepted locally. Android execute-once prevents re-execution; awaiting the duplicate terminal uncertainty.'
        : 'Fresh encrypted envelope accepted locally for the exact completed operation. Awaiting duplicate result reconciliation.'
      : result.reason === 'recipient-not-approved'
        ? 'Exact resend rejected before encryption: the Android recipient is not approved.'
        : 'Exact resend was not accepted by the current authenticated socket.', currentSyntheticResultUncertain);
    window.setTimeout(() => { void refreshSyntheticActionStatus(); }, 5_000);
  } finally {
    resendSyntheticActionButton.disabled = false;
  }
}

function setSyntheticActionStatus(message: string, uncertain = false): void {
  if (!syntheticActionStatus) return;
  syntheticActionStatus.textContent = message;
  syntheticActionStatus.classList.toggle('uncertain-result', uncertain);
}

async function renderCredentialRotation(): Promise<void> {
  const rotation = await credentialStore.loadRotation();
  if (rotation === undefined) {
    setRotationStatus('No pending transport credential.');
    return;
  }
  try {
    setRotationStatus(rotation.phase === 'prepared'
      ? 'A pending credential is durable, but no request was marked attempted. Submit the exact rotation code to continue.'
      : 'An exact pending credential is durable. Transport will probe it first, fall back to current if denied, and promote only after pending SNO1.');
  } finally {
    rotation.current.authToken.fill(0);
    rotation.pendingAuthToken.fill(0);
  }
}

function setRotationStatus(message: string): void {
  if (rotationStatus) rotationStatus.textContent = message;
}

function setStatus(message: string): void {
  if (status) status.textContent = message;
}

void render().catch(() => setStatus(message('registrationUnreadable')));

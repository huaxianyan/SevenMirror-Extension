import {
  deriveIdentityKeyId,
  serializeIdentityPublicKey,
} from '../crypto/auth-hpke';
import { IndexedDbIdentityStore } from '../crypto/indexeddb-identity-store';
import { IndexedDbTrustedPeerStore } from '../crypto/indexeddb-trusted-peer-store';
import { IndexedDbTrustPairingSessionStore } from '../crypto/indexeddb-trust-pairing-session-store';
import {
  TrustPairingCoordinator,
  type LocalTrustIdentity,
  type TrustPairingView,
} from '../crypto/trust-pairing-coordinator';
import { registerChromeDevice } from '../transport/device-registration-client';
import {
  IndexedDbTransportCredentialStore,
  normalizeServerOrigin,
} from '../transport/indexeddb-transport-credential-store';

const identityStore = new IndexedDbIdentityStore();
const credentialStore = new IndexedDbTransportCredentialStore();
const pairingSessions = new IndexedDbTrustPairingSessionStore();
const trustedPeers = new IndexedDbTrustedPeerStore();
const pairingCoordinator = new TrustPairingCoordinator(pairingSessions, trustedPeers);
const versionOutput = document.querySelector<HTMLElement>('#extension-version');
const form = document.querySelector<HTMLFormElement>('#registration-form');
const serverInput = document.querySelector<HTMLInputElement>('#server-origin');
const codeInput = document.querySelector<HTMLInputElement>('#pairing-code');
const nameInput = document.querySelector<HTMLInputElement>('#device-name');
const submit = document.querySelector<HTMLButtonElement>('#register');
const status = document.querySelector<HTMLElement>('#registration-status');
const reconnectTransportButton = document.querySelector<HTMLButtonElement>('#reconnect-transport');
const pairingSection = document.querySelector<HTMLElement>('#trust-pairing');
const pairingStage = document.querySelector<HTMLElement>('#trust-pairing-stage');
const createOfferButton = document.querySelector<HTMLButtonElement>('#create-trust-offer');
const payloadInput = document.querySelector<HTMLTextAreaElement>('#trust-payload-input');
const importPayloadButton = document.querySelector<HTMLButtonElement>('#import-trust-payload');
const pairingOutput = document.querySelector<HTMLElement>('#pairing-output');
const payloadOutputLabel = document.querySelector<HTMLElement>('#trust-payload-output-label');
const payloadOutput = document.querySelector<HTMLTextAreaElement>('#trust-payload-output');
const copyPayloadButton = document.querySelector<HTMLButtonElement>('#copy-trust-payload');
const safetySection = document.querySelector<HTMLElement>('#safety-confirmation');
const safetyCodeOutput = document.querySelector<HTMLOutputElement>('#trust-safety-code');
const safetyConfirmed = document.querySelector<HTMLInputElement>('#trust-code-confirmed');
const approvePeerButton = document.querySelector<HTMLButtonElement>('#approve-trust-peer');
const cancelPairingButton = document.querySelector<HTMLButtonElement>('#cancel-trust-pairing');
const removeApprovedPeerButton = document.querySelector<HTMLButtonElement>('#remove-approved-peer');
const pairingStatus = document.querySelector<HTMLElement>('#trust-pairing-status');
const relayTestSection = document.querySelector<HTMLElement>('#synthetic-relay-test');
const syntheticTargetInput = document.querySelector<HTMLTextAreaElement>('#synthetic-action-target');
const queueSyntheticActionButton = document.querySelector<HTMLButtonElement>('#queue-synthetic-action');
const refreshSyntheticActionButton = document.querySelector<HTMLButtonElement>('#refresh-synthetic-action');
const resendSyntheticActionButton = document.querySelector<HTMLButtonElement>('#resend-synthetic-action');
const syntheticActionStatus = document.querySelector<HTMLElement>('#synthetic-action-status');
let currentSyntheticIdempotencyKey: string | undefined;
let currentSafetyCode: string | undefined;
let currentPairingView: TrustPairingView | undefined;
let pairingFailed = false;
let pairingBusy = false;
const SYNTHETIC_OPERATION_SELECTION_KEY = 'syntheticOperationSelectionV1';

async function render(): Promise<void> {
  if (versionOutput) {
    versionOutput.textContent = `Extension version: ${chrome.runtime.getManifest().version}`;
  }
  const existing = await credentialStore.load();
  if (existing !== undefined) {
    form?.setAttribute('hidden', '');
    setStatus('This Chrome profile is registered. Connection status is available in the extension popup.');
    reconnectTransportButton?.removeAttribute('hidden');
    pairingSection?.removeAttribute('hidden');
    await renderPairing();
    await renderApprovedPeerControl();
    await renderSyntheticRelayAvailability();
    await restoreSyntheticOperationSelection();
  }
}

reconnectTransportButton?.addEventListener('click', () => {
  reconnectTransportButton.disabled = true;
  setStatus('Restarting authenticated transport…');
  void chrome.runtime.sendMessage({ type: 'transport-connect' }).then(
    (response: { started?: boolean }) => setStatus(response.started
      ? 'Authenticated transport restart requested; check the popup for Online status.'
      : 'Authenticated transport restart was not accepted.'),
    () => setStatus('Authenticated transport restart failed.'),
  ).finally(() => { reconnectTransportButton.disabled = false; });
});

form?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!serverInput || !codeInput || !nameInput || !submit) return;
  submit.disabled = true;
  setStatus('Validating registration…');
  let originPermission: string | undefined;
  let permissionAlreadyGranted = false;
  let registered = false;
  try {
    const serverOrigin = normalizeServerOrigin(serverInput.value);
    originPermission = `${serverOrigin}/*`;
    permissionAlreadyGranted = await chrome.permissions.contains({ origins: [originPermission] });
    const permissionGranted = permissionAlreadyGranted || await chrome.permissions.request({
      origins: [originPermission],
    });
    if (!permissionGranted) {
      setStatus('Host access was not granted. Registration was not attempted.');
      return;
    }

    const identity = await identityStore.loadOrCreate();
    const publicKey = await serializeIdentityPublicKey(identity);
    const identityKeyId = await deriveIdentityKeyId(publicKey);
    setStatus('Registering…');
    await registerChromeDevice({
      serverOrigin,
      pairingCode: codeInput.value,
      deviceName: nameInput.value,
      e2eePublicKey: publicKey,
      identityKeyId,
    }, credentialStore);
    registered = true;
    codeInput.value = '';
    setStatus('Registered. Starting authenticated connection…');
    const response = await chrome.runtime.sendMessage({ type: 'transport-connect' }) as {
      started?: boolean;
    };
    setStatus(response.started
      ? 'Registered. Connection authentication has started; check the popup for status.'
      : 'Registered, but the connection could not start. The credential remains safely stored.');
    form.setAttribute('hidden', '');
    reconnectTransportButton?.removeAttribute('hidden');
    pairingSection?.removeAttribute('hidden');
    await renderPairing();
    await renderApprovedPeerControl();
    await renderSyntheticRelayAvailability();
  } catch {
    if (originPermission !== undefined && !permissionAlreadyGranted && !registered) {
      await chrome.permissions.remove({ origins: [originPermission] });
    }
    setStatus(registered
      ? 'Registered, but the connection could not start. Reopen this page to retry.'
      : 'Registration failed. Verify the HTTPS server, one-time code, and device name.');
  } finally {
    codeInput.value = '';
    submit.disabled = false;
  }
});

createOfferButton?.addEventListener('click', () => {
  void runPairingOperation(async (local) => {
    const view = await pairingCoordinator.createOffer(local);
    renderPairingView(view);
    setPairingStatus('Offer persisted. Transfer this payload to the other registered device.');
  });
});

importPayloadButton?.addEventListener('click', () => {
  const payload = payloadInput?.value ?? '';
  if (!payload) return;
  if (payloadInput) payloadInput.value = '';
  void runPairingOperation(async (local) => {
    const active = await pairingSessions.load();
    const view = active?.role === 'offerer' && active.approvalBytes === undefined
      ? await pairingCoordinator.acceptApproval(payload, local)
      : await pairingCoordinator.acceptOffer(payload, local);
    renderPairingView(view);
    setPairingStatus(view.role === 'approver'
      ? 'Offer accepted. Android/this device created an approval response. Send that response back to the device that created the offer.'
      : 'Approval response accepted. Both devices must now show the same safety code.');
  });
});

copyPayloadButton?.addEventListener('click', () => {
  const payload = payloadOutput?.value;
  if (!payload) return;
  void navigator.clipboard.writeText(payload)
    .then(() => setPairingStatus('Pairing payload copied. It contains public identity metadata, not credentials.'))
    .catch(() => setPairingStatus('Clipboard write failed. Select and copy the payload manually.'));
});

safetyConfirmed?.addEventListener('change', () => {
  if (approvePeerButton) approvePeerButton.disabled = !safetyConfirmed.checked || pairingBusy;
});

approvePeerButton?.addEventListener('click', () => {
  const safetyCode = currentSafetyCode;
  if (!safetyCode || !safetyConfirmed?.checked) return;
  void runPairingOperation(async (local) => {
    await pairingCoordinator.confirmSafetyCode(safetyCode, local);
    renderPairingView(undefined);
    await renderApprovedPeerControl();
    setPairingStatus('Peer approved locally. The other device must confirm independently.');
  });
});

removeApprovedPeerButton?.addEventListener('click', () => {
  if (!window.confirm(
    'Remove the sole approved Android peer? Encrypted action delivery will fail closed until the devices complete safety-code approval again.',
  )) return;
  removeApprovedPeerButton.disabled = true;
  void removeSoleApprovedPeer()
    .then(() => {
      removeApprovedPeerButton.hidden = true;
      setPairingStatus('Approved Android peer removed locally. Re-approval with a complete matching safety code is required.');
      setSyntheticActionStatus('Exact resend is now expected to fail closed before encryption because the Android peer is not approved.');
    })
    .catch(() => setPairingStatus('Approved-peer removal failed closed; the existing trust state was not reported as removed.'))
    .finally(() => { removeApprovedPeerButton.disabled = false; });
});

cancelPairingButton?.addEventListener('click', () => {
  if (pairingBusy) return;
  pairingBusy = true;
  setPairingButtonsBusy(true);
  void pairingCoordinator.cancel()
    .then(() => {
      renderPairingView(undefined);
      setPairingStatus('Pairing session cancelled. No peer was approved by this action.');
    })
    .catch(() => setPairingStatus('Pairing cancellation failed closed. Reopen this page and retry.'))
    .finally(() => {
      pairingBusy = false;
      setPairingButtonsBusy(false);
    });
});

async function renderApprovedPeerControl(): Promise<void> {
  const credential = await credentialStore.load();
  if (credential === undefined) return;
  try {
    const approved = await trustedPeers.listApproved(credential.workspaceId);
    if (removeApprovedPeerButton) removeApprovedPeerButton.hidden = approved.length !== 1;
    for (const peer of approved) {
      peer.deviceId.fill(0);
      peer.keyId.fill(0);
    }
  } finally {
    credential.authToken.fill(0);
  }
}

async function removeSoleApprovedPeer(): Promise<void> {
  const credential = await credentialStore.load();
  if (credential === undefined) throw new Error('Transport registration is required');
  try {
    const approved = await trustedPeers.listApproved(credential.workspaceId);
    if (approved.length !== 1) throw new Error('Exactly one approved peer is required');
    try {
      await trustedPeers.remove(credential.workspaceId, approved[0]!.deviceId);
    } finally {
      for (const peer of approved) {
        peer.deviceId.fill(0);
        peer.keyId.fill(0);
      }
    }
  } finally {
    credential.authToken.fill(0);
  }
}

async function renderPairing(): Promise<void> {
  try {
    const local = await loadLocalTrustIdentity();
    const view = await pairingCoordinator.resume(local);
    renderPairingView(view);
    setPairingStatus(view === undefined
      ? 'No active trust pairing session.'
      : 'Durable pairing session restored.');
  } catch {
    renderPairingView(undefined, true);
    setPairingStatus('Pairing state failed security validation. Cancel it before starting again.');
  }
}

function renderPairingView(view: TrustPairingView | undefined, failed = false): void {
  currentPairingView = view;
  pairingFailed = failed;
  currentSafetyCode = view?.stage === 'compare-safety-code' ? view.safetyCode : undefined;
  if (createOfferButton) createOfferButton.hidden = view !== undefined || failed;
  if (payloadInput) payloadInput.disabled = view?.stage === 'compare-safety-code' || failed;
  if (importPayloadButton) importPayloadButton.disabled =
    view?.stage === 'compare-safety-code' || failed || pairingBusy;
  if (cancelPairingButton) cancelPairingButton.hidden = view === undefined && !failed;
  if (pairingStage) {
    pairingStage.textContent = view === undefined
      ? 'Step 1 — Create or import an offer'
      : view.stage === 'offer-created'
        ? 'Step 2 — Send this offer, then import the approval response'
        : 'Step 3 — Compare the complete safety code and approve independently';
  }

  const transferablePayload = view?.stage === 'offer-created'
    ? view.offerQr
    : view?.approvalQr;
  if (pairingOutput && payloadOutput) {
    pairingOutput.hidden = transferablePayload === undefined;
    payloadOutput.value = transferablePayload ?? '';
    if (payloadOutputLabel) {
      payloadOutputLabel.textContent = view?.stage === 'offer-created'
        ? 'Offer — send this once to the other device'
        : 'Approval response — send this back to the offer creator';
    }
  }

  if (safetySection && safetyCodeOutput && safetyConfirmed && approvePeerButton) {
    const comparing = view?.stage === 'compare-safety-code';
    safetySection.hidden = !comparing;
    safetyCodeOutput.value = comparing ? view.safetyCode : '';
    safetyCodeOutput.textContent = comparing ? view.safetyCode : '';
    safetyConfirmed.checked = false;
    approvePeerButton.disabled = true;
  }
}

async function runPairingOperation(
  operation: (local: LocalTrustIdentity) => Promise<void>,
): Promise<void> {
  if (pairingBusy) return;
  pairingBusy = true;
  setPairingButtonsBusy(true);
  try {
    const local = await loadLocalTrustIdentity();
    await operation(local);
  } catch (error) {
    const failure = pairingFailureMessage(error);
    try {
      const local = await loadLocalTrustIdentity();
      const restored = await pairingCoordinator.resume(local);
      renderPairingView(restored);
      setPairingStatus(`${failure} The previous durable session is still active.`);
    } catch {
      renderPairingView(undefined, true);
      setPairingStatus(`${failure} Pairing state could not be restored; cancel before retrying.`);
    }
  } finally {
    pairingBusy = false;
    setPairingButtonsBusy(false);
    if (approvePeerButton && safetyConfirmed) {
      approvePeerButton.disabled = !safetyConfirmed.checked || currentSafetyCode === undefined;
    }
  }
}

async function loadLocalTrustIdentity(): Promise<LocalTrustIdentity> {
  const credential = await credentialStore.load();
  if (credential === undefined) throw new Error('Transport registration is required');
  try {
    const identity = await identityStore.loadExisting();
    if (identity === undefined) throw new Error('HPKE identity is missing');
    const publicKey = await serializeIdentityPublicKey(identity);
    const keyId = await deriveIdentityKeyId(publicKey);
    if (!bytesEqual(keyId, credential.identityKeyId)) {
      throw new Error('Transport credential and HPKE identity do not match');
    }
    return {
      workspaceId: credential.workspaceId.slice(),
      deviceId: credential.deviceId.slice(),
      publicKey,
    };
  } finally {
    credential.authToken.fill(0);
  }
}

function setPairingButtonsBusy(busy: boolean): void {
  if (createOfferButton) createOfferButton.disabled = busy;
  if (importPayloadButton) importPayloadButton.disabled = busy || pairingFailed ||
    currentPairingView?.stage === 'compare-safety-code';
  if (payloadInput) payloadInput.disabled = pairingFailed ||
    currentPairingView?.stage === 'compare-safety-code';
  if (cancelPairingButton) cancelPairingButton.disabled = busy;
  if (copyPayloadButton) copyPayloadButton.disabled = busy;
  if (approvePeerButton) approvePeerButton.disabled = busy || !safetyConfirmed?.checked;
}

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
    await chrome.storage.local.set({
      [SYNTHETIC_OPERATION_SELECTION_KEY]: result.idempotencyKey,
    });
    if (refreshSyntheticActionButton) refreshSyntheticActionButton.hidden = false;
    if (resendSyntheticActionButton) resendSyntheticActionButton.hidden = true;
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
  };
  if (!result.found) {
    setSyntheticActionStatus('Durable action record was not found.');
    return;
  }
  if (result.state === 'completed') {
    if (resendSyntheticActionButton) resendSyntheticActionButton.hidden = false;
    setSyntheticActionStatus(`Operation: completed. Authenticated Android result status: ${result.resultStatus ?? 'unknown'}. Locally accepted invoke deliveries: ${result.invokeAttemptCount ?? 0}; authenticated result deliveries observed: ${result.authenticatedResultCount ?? 1}; locally accepted result ACK deliveries: ${result.ackAttemptCount ?? 0}; durable ACK intent: ${result.ackPending === true ? 'present' : 'not present'}.`);
  } else {
    setSyntheticActionStatus(`Still pending. Locally accepted send attempts: ${result.invokeAttemptCount ?? 0}.`);
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
      ? 'Fresh encrypted envelope accepted locally for the exact completed operation. Awaiting duplicate result reconciliation.'
      : result.reason === 'recipient-not-approved'
        ? 'Exact resend rejected before encryption: the Android recipient is not approved.'
        : 'Exact resend was not accepted by the current authenticated socket.');
    window.setTimeout(() => { void refreshSyntheticActionStatus(); }, 1_000);
  } finally {
    resendSyntheticActionButton.disabled = false;
  }
}

function setSyntheticActionStatus(message: string): void {
  if (syntheticActionStatus) syntheticActionStatus.textContent = message;
}

function pairingFailureMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (message.includes('expired')) return 'Import rejected: this pairing payload expired. Cancel both sides and create a new offer.';
  if (message.includes('different workspace')) return 'Import rejected: the devices are registered in different workspaces.';
  if (message.includes('exact trust offer') || message.includes('does not match this approval')) {
    return 'Import rejected: this approval response does not belong to the active Chrome offer.';
  }
  if (message.includes('base64url') || message.includes('prefix') || message.includes('magic') ||
      message.includes('bytes') || message.includes('length')) {
    return 'Import rejected: the copied pairing payload is incomplete or malformed.';
  }
  if (message.includes('No offer is awaiting') || message.includes('No active trust pairing')) {
    return 'Import rejected: Chrome no longer has the offer session required by this approval response.';
  }
  if (message.includes('already exists') || message.includes('Cancel the active')) {
    return 'Import rejected: another pairing session is active. Cancel it explicitly before importing a new offer.';
  }
  if (message.includes('Safety code')) return 'Approval rejected: the safety code does not match the active transcript.';
  return 'Pairing failed closed. Verify the payload, expiry, workspace, and active step.';
}

function setPairingStatus(message: string): void {
  if (pairingStatus) pairingStatus.textContent = message;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}

function setStatus(message: string): void {
  if (status) status.textContent = message;
}

void render().catch(() => setStatus('Stored registration state could not be read.'));

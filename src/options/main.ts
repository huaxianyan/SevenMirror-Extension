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
const form = document.querySelector<HTMLFormElement>('#registration-form');
const serverInput = document.querySelector<HTMLInputElement>('#server-origin');
const codeInput = document.querySelector<HTMLInputElement>('#pairing-code');
const nameInput = document.querySelector<HTMLInputElement>('#device-name');
const submit = document.querySelector<HTMLButtonElement>('#register');
const status = document.querySelector<HTMLElement>('#registration-status');
const pairingSection = document.querySelector<HTMLElement>('#trust-pairing');
const createOfferButton = document.querySelector<HTMLButtonElement>('#create-trust-offer');
const payloadInput = document.querySelector<HTMLTextAreaElement>('#trust-payload-input');
const importPayloadButton = document.querySelector<HTMLButtonElement>('#import-trust-payload');
const pairingOutput = document.querySelector<HTMLElement>('#pairing-output');
const payloadOutput = document.querySelector<HTMLTextAreaElement>('#trust-payload-output');
const copyPayloadButton = document.querySelector<HTMLButtonElement>('#copy-trust-payload');
const safetySection = document.querySelector<HTMLElement>('#safety-confirmation');
const safetyCodeOutput = document.querySelector<HTMLOutputElement>('#trust-safety-code');
const safetyConfirmed = document.querySelector<HTMLInputElement>('#trust-code-confirmed');
const approvePeerButton = document.querySelector<HTMLButtonElement>('#approve-trust-peer');
const cancelPairingButton = document.querySelector<HTMLButtonElement>('#cancel-trust-pairing');
const pairingStatus = document.querySelector<HTMLElement>('#trust-pairing-status');
let currentSafetyCode: string | undefined;
let currentPairingView: TrustPairingView | undefined;
let pairingFailed = false;
let pairingBusy = false;

async function render(): Promise<void> {
  const existing = await credentialStore.load();
  if (existing !== undefined) {
    form?.setAttribute('hidden', '');
    setStatus('This Chrome profile is registered. Connection status is available in the extension popup.');
    pairingSection?.removeAttribute('hidden');
    await renderPairing();
  }
}

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
    pairingSection?.removeAttribute('hidden');
    await renderPairing();
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
      ? 'Approval persisted. Transfer the approval payload, then compare both complete codes.'
      : 'Approval persisted. Compare the complete safety code on both devices.');
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
    setPairingStatus('Peer approved locally. The other device must confirm independently.');
  });
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

  const transferablePayload = view?.stage === 'offer-created'
    ? view.offerQr
    : view?.approvalQr;
  if (pairingOutput && payloadOutput) {
    pairingOutput.hidden = transferablePayload === undefined;
    payloadOutput.value = transferablePayload ?? '';
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
  } catch {
    setPairingStatus('Pairing failed closed. Verify the payload, expiry, workspace, and safety code.');
    await renderPairing().catch(() => {
      renderPairingView(undefined, true);
    });
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

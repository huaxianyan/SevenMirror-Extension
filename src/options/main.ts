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
const rotationSection = document.querySelector<HTMLElement>('#credential-rotation');
const rotationForm = document.querySelector<HTMLFormElement>('#credential-rotation-form');
const rotationCodeInput = document.querySelector<HTMLInputElement>('#credential-rotation-code');
const rotateCredentialButton = document.querySelector<HTMLButtonElement>('#rotate-credential');
const rotationStatus = document.querySelector<HTMLElement>('#credential-rotation-status');
const identityRotationSection = document.querySelector<HTMLElement>('#identity-rotation');
const rotateIdentityButton = document.querySelector<HTMLButtonElement>('#rotate-identity');
const identityRotationStatus = document.querySelector<HTMLElement>('#identity-rotation-status');
const refreshIdentityTransitionButton = document.querySelector<HTMLButtonElement>(
  '#refresh-identity-transition',
);
const identityTransitionPeers = document.querySelector<HTMLElement>('#identity-transition-peers');
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
const holdSyntheticResultAckButton = document.querySelector<HTMLButtonElement>('#hold-synthetic-result-ack');
const releaseSyntheticResultAckButton = document.querySelector<HTMLButtonElement>('#release-synthetic-result-ack');
const syntheticActionStatus = document.querySelector<HTMLElement>('#synthetic-action-status');
let currentSyntheticIdempotencyKey: string | undefined;
let currentSyntheticResultUncertain = false;
let currentSafetyCode: string | undefined;
let currentPairingView: TrustPairingView | undefined;
let pairingFailed = false;
let pairingBusy = false;
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
    identityRotationSection?.removeAttribute('hidden');
    await renderIdentityTransitionStatus();
    pairingSection?.removeAttribute('hidden');
    await renderPairing();
    await renderApprovedPeerControl();
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

refreshIdentityTransitionButton?.addEventListener('click', () => {
  void renderIdentityTransitionStatus();
});

rotateIdentityButton?.addEventListener('click', () => {
  const confirmed = window.confirm(
    'Start E2EE identity transition? Every approved peer must acknowledge it. ' +
      'After the first acknowledgement, the old identity cannot be silently restored.',
  );
  if (!confirmed || !rotateIdentityButton) return;
  rotateIdentityButton.disabled = true;
  if (identityRotationStatus) {
    identityRotationStatus.textContent = 'Preparing a durable peer snapshot and pending identity…';
  }
  void chrome.runtime.sendMessage({ type: 'start-identity-transition' }).then(
    (response: { started?: boolean; error?: string }) => {
      if (identityRotationStatus) {
        identityRotationStatus.textContent = response.started
          ? 'Transition started. Exact lifecycle messages retry until every approved peer converges.'
          : (response.error ?? 'Identity transition failed closed.');
      }
    },
    () => {
      if (identityRotationStatus) identityRotationStatus.textContent = 'Identity transition request failed.';
    },
  ).finally(() => { void renderIdentityTransitionStatus(); });
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

createOfferButton?.addEventListener('click', () => {
  void runPairingOperation(async (local) => {
    const view = await pairingCoordinator.createOffer(local);
    renderPairingView(view);
    setPairingStatus(message('offerPersisted'));
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
      ? message('offerAccepted')
      : message('approvalAccepted'));
  });
});

copyPayloadButton?.addEventListener('click', () => {
  const payload = payloadOutput?.value;
  if (!payload) return;
  void navigator.clipboard.writeText(payload)
    .then(() => setPairingStatus(message('pairingPayloadCopied')))
    .catch(() => setPairingStatus(message('clipboardWriteFailed')));
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
    setPairingStatus(message('peerApprovedLocal'));
  });
});

removeApprovedPeerButton?.addEventListener('click', () => {
  if (!window.confirm(
    message('removeApprovedPeerConfirm'),
  )) return;
  removeApprovedPeerButton.disabled = true;
  void removeSoleApprovedPeer()
    .then(() => {
      removeApprovedPeerButton.hidden = true;
      setPairingStatus(message('approvedPeerRemoved'));
      setSyntheticActionStatus('Exact resend is now expected to fail closed before encryption because the Android peer is not approved.');
    })
    .catch(() => setPairingStatus(message('approvedPeerRemovalFailed')))
    .finally(() => { removeApprovedPeerButton.disabled = false; });
});

cancelPairingButton?.addEventListener('click', () => {
  if (pairingBusy) return;
  pairingBusy = true;
  setPairingButtonsBusy(true);
  void pairingCoordinator.cancel()
    .then(() => {
      renderPairingView(undefined);
      setPairingStatus(message('pairingCancelled'));
    })
    .catch(() => setPairingStatus(message('pairingCancelFailed')))
    .finally(() => {
      pairingBusy = false;
      setPairingButtonsBusy(false);
    });
});

interface IdentityTransitionStatusResponse {
  active?: boolean;
  phase?: string;
  expiresAtUnixMs?: number;
  error?: string;
  peers?: Array<{
    deviceId: string;
    deviceRef: string;
    keyRef: string;
    phase: string;
  }>;
}

async function renderIdentityTransitionStatus(): Promise<void> {
  if (!identityRotationStatus || !identityTransitionPeers) return;
  const response = await chrome.runtime.sendMessage({
    type: 'get-identity-transition-status',
  }) as IdentityTransitionStatusResponse;
  identityTransitionPeers.replaceChildren();
  if (!response.active) {
    rotateIdentityButton?.removeAttribute('disabled');
    identityRotationStatus.textContent = response.error ?? 'No active E2EE identity transition.';
    return;
  }
  if (rotateIdentityButton) rotateIdentityButton.disabled = true;
  const expires = response.expiresAtUnixMs === undefined
    ? 'unknown'
    : new Date(response.expiresAtUnixMs).toLocaleString();
  identityRotationStatus.textContent =
    `Transition phase: ${response.phase ?? 'unknown'}. Original deadline: ${expires}.`;
  if ((response.peers ?? []).length === 0) {
    const warning = document.createElement('p');
    warning.textContent =
      'No snapshot peers remain. Automatic promotion is forbidden; use explicit lost-device recovery.';
    identityTransitionPeers.append(warning);
  }
  for (const peer of response.peers ?? []) {
    const row = document.createElement('p');
    row.textContent = `Peer ${peer.deviceRef}, key ${peer.keyRef}: ${peer.phase}. `;
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.textContent = 'Remove trust and exclude peer';
    remove.addEventListener('click', () => {
      if (!window.confirm(
        `Explicitly remove peer ${peer.deviceRef} from local trust and this transition? ` +
          'This device must complete a fresh safety-code approval to regain trust.',
      )) return;
      remove.disabled = true;
      void chrome.runtime.sendMessage({
        type: 'remove-identity-transition-peer',
        peerDeviceId: peer.deviceId,
      }).then((result: { removed?: boolean; error?: string }) => {
        identityRotationStatus.textContent = result.removed
          ? 'Peer explicitly removed. Rechecking transition promotion readiness…'
          : (result.error ?? 'Peer removal failed closed.');
        return renderIdentityTransitionStatus();
      }).catch(() => {
        identityRotationStatus.textContent = 'Peer removal request failed closed.';
      }).finally(() => { remove.disabled = false; });
    });
    row.append(remove);
    identityTransitionPeers.append(row);
  }
}

async function renderApprovedPeerControl(): Promise<void> {
  const credential = await credentialStore.load();
  if (credential === undefined) return;
  try {
    const approved = await trustedPeers.listApproved(credential.workspaceId);
    const transition = await chrome.runtime.sendMessage({
      type: 'get-identity-transition-status',
    }) as IdentityTransitionStatusResponse;
    if (removeApprovedPeerButton) {
      removeApprovedPeerButton.hidden = approved.length !== 1 || transition.active === true;
    }
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
      ? message('noPairingSession')
      : message('pairingSessionRestored'));
  } catch {
    renderPairingView(undefined, true);
    setPairingStatus(message('pairingStateInvalid'));
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
      ? message('pairingStepCreate')
      : view.stage === 'offer-created'
        ? message('pairingStepApproval')
        : message('pairingStepSafetyCode');
  }

  const transferablePayload = view?.stage === 'offer-created'
    ? view.offerQr
    : view?.approvalQr;
  if (pairingOutput && payloadOutput) {
    pairingOutput.hidden = transferablePayload === undefined;
    payloadOutput.value = transferablePayload ?? '';
    if (payloadOutputLabel) {
      payloadOutputLabel.textContent = view?.stage === 'offer-created'
        ? message('offerOutputLabel')
        : message('approvalOutputLabel');
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
      setPairingStatus(message('pairingSessionStillActive', failure));
    } catch {
      renderPairingView(undefined, true);
      setPairingStatus(message('pairingStateRestoreFailed', failure));
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

function pairingFailureMessage(error: unknown): string {
  const errorMessage = error instanceof Error ? error.message : '';
  if (errorMessage.includes('expired')) return message('pairingExpired');
  if (errorMessage.includes('different workspace')) return message('pairingWorkspaceMismatch');
  if (errorMessage.includes('exact trust offer') ||
      errorMessage.includes('does not match this approval')) {
    return message('pairingApprovalMismatch');
  }
  if (errorMessage.includes('base64url') || errorMessage.includes('prefix') ||
      errorMessage.includes('magic') || errorMessage.includes('bytes') ||
      errorMessage.includes('length')) {
    return message('pairingMalformed');
  }
  if (errorMessage.includes('No offer is awaiting') ||
      errorMessage.includes('No active trust pairing')) {
    return message('pairingOfferMissing');
  }
  if (errorMessage.includes('already exists') || errorMessage.includes('Cancel the active')) {
    return message('pairingSessionConflict');
  }
  if (errorMessage.includes('Safety code')) return message('pairingSafetyMismatch');
  return message('pairingFailed');
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

function setPairingStatus(message: string): void {
  if (pairingStatus) pairingStatus.textContent = message;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}

function setStatus(message: string): void {
  if (status) status.textContent = message;
}

void render().catch(() => setStatus(message('registrationUnreadable')));

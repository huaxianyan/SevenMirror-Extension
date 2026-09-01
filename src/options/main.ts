import { IndexedDbIdentityStore } from '../crypto/indexeddb-identity-store';
import { IndexedDbPendingMembershipStore } from '../transport/indexeddb-pending-membership-store';
import { IndexedDbWorkspaceMembershipStore } from '../crypto/indexeddb-workspace-membership-store';
import { beginChromeMembership } from '../transport/workspace-membership-client';
import {
  IndexedDbTransportCredentialStore,
  normalizeServerOrigin,
} from '../transport/indexeddb-transport-credential-store';
import { localizeDocument, message } from '../shared/i18n';

interface OptionsOverview {
  state: 'not-configured' | 'waiting-approval' | 'connecting' | 'online' | 'offline' |
    'access-removed' | 'resetting' | 'needs-repair';
  serverOrigin?: string;
  localDeviceName?: string;
  devices: Array<{
    deviceKey: string;
    displayName: string;
    deviceType: 'android' | 'chrome';
    isCurrentDevice: boolean;
    accessCurrent: boolean;
  }>;
  badgeEnabled: boolean;
  nativeNotificationsEnabled: boolean;
  showBody: boolean;
  showImages: boolean;
  silentNotifications: boolean;
  mutedSourceDeviceIds: string[];
}

type PresentationPreferences = Pick<OptionsOverview,
  'badgeEnabled' | 'nativeNotificationsEnabled' | 'showBody' | 'showImages' |
  'silentNotifications' | 'mutedSourceDeviceIds'>;

const identityStore = new IndexedDbIdentityStore();
const credentialStore = new IndexedDbTransportCredentialStore();
const pendingMembershipStore = new IndexedDbPendingMembershipStore();
const workspaceMembershipStore = new IndexedDbWorkspaceMembershipStore();
const versionOutput = requireElement<HTMLElement>('extension-version');
const registrationForm = requireElement<HTMLFormElement>('registration-form');
const serverInput = requireElement<HTMLInputElement>('server-origin');
const codeInput = requireElement<HTMLInputElement>('pairing-code');
const nameInput = requireElement<HTMLInputElement>('device-name');
const submit = requireElement<HTMLButtonElement>('register');
const registrationStatus = requireElement<HTMLElement>('registration-status');
const reconnect = requireElement<HTMLButtonElement>('reconnect-transport');
const reEnrollDevice = requireElement<HTMLButtonElement>('re-enroll-device');
const reEnrollConfirmation = requireElement<HTMLDialogElement>('re-enroll-confirmation');
const confirmReEnroll = requireElement<HTMLButtonElement>('confirm-re-enroll');
const connectionState = requireElement<HTMLHeadingElement>('connection-state');
const connectionGuidance = requireElement<HTMLParagraphElement>('connection-guidance');
const connectionDetails = requireElement<HTMLElement>('connection-details');
const savedServerOrigin = requireElement<HTMLElement>('saved-server-origin');
const currentDeviceName = requireElement<HTMLElement>('current-device-name');
const deviceCounts = requireElement<HTMLElement>('device-counts');
const deviceList = requireElement<HTMLElement>('device-list');
const devicesEmpty = requireElement<HTMLElement>('devices-empty');
const sourceList = requireElement<HTMLElement>('source-list');
const sourcesEmpty = requireElement<HTMLElement>('sources-empty');
const badgeEnabled = requireElement<HTMLInputElement>('badge-enabled');
const nativeNotificationsEnabled = requireElement<HTMLInputElement>('native-notifications-enabled');
const showBody = requireElement<HTMLInputElement>('show-body');
const showImages = requireElement<HTMLInputElement>('show-images');
const silentNotifications = requireElement<HTMLInputElement>('silent-notifications');
const notificationSettingsStatus = requireElement<HTMLElement>('notification-settings-status');
const clearLocalNotifications = requireElement<HTMLButtonElement>('clear-local-notifications');
const clearConfirmation = requireElement<HTMLDialogElement>('clear-confirmation');
const confirmClear = requireElement<HTMLButtonElement>('confirm-clear');
let savedPreferences: PresentationPreferences = {
  badgeEnabled: true,
  nativeNotificationsEnabled: true,
  showBody: true,
  showImages: true,
  silentNotifications: false,
  mutedSourceDeviceIds: [],
};

localizeDocument();
versionOutput.textContent = message('extensionVersionValue', chrome.runtime.getManifest().version);

registrationForm.addEventListener('submit', (event) => {
  event.preventDefault();
  void submitRegistration();
});

reconnect.addEventListener('click', () => {
  reconnect.disabled = true;
  registrationStatus.textContent = message('reconnectingTransport');
  void chrome.runtime.sendMessage({ type: 'transport-connect' })
    .then(() => {
      registrationStatus.textContent = message('reconnectRequested');
      window.setTimeout(() => { void render(); }, 800);
    })
    .catch(() => { registrationStatus.textContent = message('reconnectFailed'); })
    .finally(() => { reconnect.disabled = false; });
});

reEnrollDevice.addEventListener('click', () => reEnrollConfirmation.showModal());
confirmReEnroll.addEventListener('click', (event) => {
  event.preventDefault();
  confirmReEnroll.disabled = true;
  connectionGuidance.textContent = message('optionsReEnrollResetting');
  void chrome.runtime.sendMessage({ type: 're-enroll-after-certified-removal' })
    .then(async (response: { reset?: boolean }) => {
      if (!response.reset) {
        connectionGuidance.textContent = message('optionsReEnrollFailed');
        return;
      }
      reEnrollConfirmation.close();
      registrationStatus.textContent = message('optionsReEnrollReady');
      await render();
    })
    .catch(() => { connectionGuidance.textContent = message('optionsReEnrollFailed'); })
    .finally(() => { confirmReEnroll.disabled = false; });
});

badgeEnabled.addEventListener('change', () => {
  void savePresentationPreferences({ ...savedPreferences, badgeEnabled: badgeEnabled.checked });
});
nativeNotificationsEnabled.addEventListener('change', () => {
  void savePresentationPreferences({
    ...savedPreferences,
    nativeNotificationsEnabled: nativeNotificationsEnabled.checked,
  });
});
showBody.addEventListener('change', () => {
  void savePresentationPreferences({ ...savedPreferences, showBody: showBody.checked });
});
showImages.addEventListener('change', () => {
  void savePresentationPreferences({ ...savedPreferences, showImages: showImages.checked });
});
silentNotifications.addEventListener('change', () => {
  void savePresentationPreferences({
    ...savedPreferences,
    silentNotifications: silentNotifications.checked,
  });
});

clearLocalNotifications.addEventListener('click', () => clearConfirmation.showModal());
confirmClear.addEventListener('click', (event) => {
  event.preventDefault();
  confirmClear.disabled = true;
  void chrome.runtime.sendMessage({ type: 'clear-local-notification-state' })
    .then((response: { cleared?: boolean }) => {
      notificationSettingsStatus.textContent = message(
        response.cleared ? 'optionsLocalNotificationsCleared' : 'optionsClearFailed',
      );
      clearConfirmation.close();
    })
    .catch(() => { notificationSettingsStatus.textContent = message('optionsClearFailed'); })
    .finally(() => { confirmClear.disabled = false; });
});

async function render(): Promise<void> {
  const response = await chrome.runtime.sendMessage({ type: 'get-options-overview' }) as {
    overview: OptionsOverview;
  };
  renderConnection(response.overview);
  savedPreferences = preferencesFromOverview(response.overview);
  applyPreferenceInputs(savedPreferences);
  renderDevices(response.overview);
}

function renderConnection(overview: OptionsOverview): void {
  connectionState.textContent = message(`optionsState_${overview.state.replaceAll('-', '_')}`);
  connectionGuidance.textContent = message(`optionsGuidance_${overview.state.replaceAll('-', '_')}`);
  const configured = overview.state !== 'not-configured';
  registrationForm.hidden = configured;
  reconnect.hidden = overview.state === 'not-configured' || overview.state === 'access-removed' ||
    overview.state === 'resetting' || overview.state === 'needs-repair';
  reEnrollDevice.hidden = overview.state !== 'access-removed' && overview.state !== 'resetting';
  if (overview.serverOrigin !== undefined) {
    connectionDetails.hidden = false;
    savedServerOrigin.textContent = overview.serverOrigin;
    currentDeviceName.textContent = overview.localDeviceName ?? message('notAvailable');
  } else {
    connectionDetails.hidden = true;
  }
}

function renderDevices(overview: OptionsOverview): void {
  const { devices } = overview;
  const androidCount = devices.filter((device) => device.deviceType === 'android').length;
  const chromeCount = devices.filter((device) => device.deviceType === 'chrome').length;
  deviceCounts.textContent = devices.length === 0
    ? ''
    : message('optionsDeviceCounts', [androidCount.toString(), chromeCount.toString()]);
  deviceList.replaceChildren(...devices.map((device) => {
    const card = document.createElement('article');
    card.className = 'device';
    const name = document.createElement('strong');
    name.textContent = device.displayName;
    const meta = document.createElement('span');
    meta.className = 'device-meta';
    meta.textContent = [
      message(device.deviceType === 'android' ? 'androidDevice' : 'chromeDevice'),
      device.isCurrentDevice ? message('thisDevice') : '',
      message(device.accessCurrent ? 'deviceAuthorized' : 'deviceAccessExpired'),
    ].filter(Boolean).join(' · ');
    card.append(name, meta);
    return card;
  }));
  devicesEmpty.hidden = devices.length !== 0;

  const sources = devices.filter((device) => device.deviceType === 'android');
  sourceList.replaceChildren(...sources.map((source) => {
    const label = document.createElement('label');
    label.className = 'switch-row source-toggle';
    const copy = document.createElement('span');
    const name = document.createElement('strong');
    name.textContent = source.displayName;
    const state = document.createElement('small');
    const enabled = !overview.mutedSourceDeviceIds.includes(source.deviceKey);
    state.textContent = message(enabled ? 'optionsSourceShown' : 'optionsSourceHidden');
    copy.append(name, state);
    const toggle = document.createElement('input');
    toggle.type = 'checkbox';
    toggle.setAttribute('role', 'switch');
    toggle.checked = enabled;
    toggle.addEventListener('change', () => {
      const muted = new Set(savedPreferences.mutedSourceDeviceIds);
      if (toggle.checked) muted.delete(source.deviceKey);
      else muted.add(source.deviceKey);
      void savePresentationPreferences({
        ...savedPreferences,
        mutedSourceDeviceIds: [...muted].sort(),
      });
    });
    label.append(copy, toggle);
    return label;
  }));
  sourcesEmpty.hidden = sources.length !== 0;
}

function preferencesFromOverview(overview: OptionsOverview): PresentationPreferences {
  return {
    badgeEnabled: overview.badgeEnabled,
    nativeNotificationsEnabled: overview.nativeNotificationsEnabled,
    showBody: overview.showBody,
    showImages: overview.showImages,
    silentNotifications: overview.silentNotifications,
    mutedSourceDeviceIds: [...overview.mutedSourceDeviceIds],
  };
}

function applyPreferenceInputs(preferences: PresentationPreferences): void {
  badgeEnabled.checked = preferences.badgeEnabled;
  nativeNotificationsEnabled.checked = preferences.nativeNotificationsEnabled;
  showBody.checked = preferences.showBody;
  showImages.checked = preferences.showImages;
  silentNotifications.checked = preferences.silentNotifications;
}

async function savePresentationPreferences(next: PresentationPreferences): Promise<void> {
  setPreferenceInputsDisabled(true);
  notificationSettingsStatus.textContent = message('optionsSaving');
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'save-notification-presentation-preferences',
      preferences: next,
    }) as { saved?: boolean };
    if (!response.saved) throw new Error('Preference save failed');
    savedPreferences = { ...next, mutedSourceDeviceIds: [...next.mutedSourceDeviceIds] };
    notificationSettingsStatus.textContent = message('optionsSaved');
    await render();
  } catch {
    applyPreferenceInputs(savedPreferences);
    notificationSettingsStatus.textContent = message('optionsSaveFailed');
  } finally {
    setPreferenceInputsDisabled(false);
  }
}

function setPreferenceInputsDisabled(disabled: boolean): void {
  for (const input of [
    badgeEnabled,
    nativeNotificationsEnabled,
    showBody,
    showImages,
    silentNotifications,
    ...Array.from(sourceList.querySelectorAll<HTMLInputElement>('input')),
  ]) input.disabled = disabled;
}

async function submitRegistration(): Promise<void> {
  submit.disabled = true;
  registrationStatus.textContent = message('validatingRegistration');
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
      registrationStatus.textContent = message('hostPermissionDenied');
      return;
    }
    const existingCredential = await credentialStore.load();
    if (existingCredential !== undefined) {
      existingCredential.authToken.fill(0);
      throw new Error('Already registered');
    }
    const identity = await identityStore.loadOrCreate();
    registrationStatus.textContent = message('registering');
    await beginChromeMembership({
      serverOrigin,
      pairingCode: codeInput.value,
      deviceName: nameInput.value,
      identity,
    }, workspaceMembershipStore, pendingMembershipStore);
    codeInput.value = '';
    registrationStatus.textContent = message('waitingForAdminApproval');
    await chrome.runtime.sendMessage({ type: 'transport-connect' }).catch(() => undefined);
    await render();
  } catch {
    const pending = await pendingMembershipStore.load().catch(() => undefined);
    if (pending !== undefined) {
      pending.authToken.fill(0);
      pending.canonicalProof?.fill(0);
      registrationStatus.textContent = message('waitingForAdminApproval');
      await render();
    } else {
      if (originPermission !== undefined && !permissionAlreadyGranted) {
        await chrome.permissions.remove({ origins: [originPermission] });
      }
      registrationStatus.textContent = message('registrationFailed');
    }
  } finally {
    codeInput.value = '';
    submit.disabled = false;
  }
}

function requireElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`Missing options element: ${id}`);
  return element as T;
}

void render().catch(() => {
  connectionState.textContent = message('optionsState_needs_repair');
  connectionGuidance.textContent = message('optionsGuidance_needs_repair');
});

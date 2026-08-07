import {
  deriveIdentityKeyId,
  serializeIdentityPublicKey,
} from '../crypto/auth-hpke';
import { IndexedDbIdentityStore } from '../crypto/indexeddb-identity-store';
import { registerChromeDevice } from '../transport/device-registration-client';
import {
  IndexedDbTransportCredentialStore,
  normalizeServerOrigin,
} from '../transport/indexeddb-transport-credential-store';

const identityStore = new IndexedDbIdentityStore();
const credentialStore = new IndexedDbTransportCredentialStore();
const form = document.querySelector<HTMLFormElement>('#registration-form');
const serverInput = document.querySelector<HTMLInputElement>('#server-origin');
const codeInput = document.querySelector<HTMLInputElement>('#pairing-code');
const nameInput = document.querySelector<HTMLInputElement>('#device-name');
const submit = document.querySelector<HTMLButtonElement>('#register');
const status = document.querySelector<HTMLElement>('#registration-status');

async function render(): Promise<void> {
  const existing = await credentialStore.load();
  if (existing !== undefined) {
    form?.setAttribute('hidden', '');
    setStatus('This Chrome profile is registered. Connection status is available in the extension popup.');
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

function setStatus(message: string): void {
  if (status) status.textContent = message;
}

void render().catch(() => setStatus('Stored registration state could not be read.'));

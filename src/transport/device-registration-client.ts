import {
  normalizeServerOrigin,
  type IndexedDbTransportCredentialStore,
  type StoredTransportCredential,
} from './indexeddb-transport-credential-store';

const MAX_RESPONSE_BYTES = 4096;
const encoder = new TextEncoder();

export interface ChromeDeviceRegistration {
  serverOrigin: string;
  pairingCode: string;
  deviceName: string;
  e2eePublicKey: Uint8Array;
  identityKeyId: Uint8Array;
}

interface RegistrationResponse {
  workspace_id: string;
  device_id: string;
  auth_token: string;
}

/** Registers once and persists the returned credential before exposing success. */
export async function registerChromeDevice(
  request: ChromeDeviceRegistration,
  store: IndexedDbTransportCredentialStore,
  fetcher: typeof fetch = fetch,
): Promise<StoredTransportCredential> {
  const serverOrigin = normalizeServerOrigin(request.serverOrigin);
  if (await store.load() !== undefined) {
    throw new Error('A transport credential already exists; unpair explicitly first');
  }
  validatePairingCode(request.pairingCode);
  validateDeviceName(request.deviceName);
  validateBytes(request.e2eePublicKey, 65, 'e2eePublicKey', false);
  if (request.e2eePublicKey[0] !== 0x04) {
    throw new Error('e2eePublicKey must be an uncompressed P-256 point');
  }
  validateBytes(request.identityKeyId, 32, 'identityKeyId', true);

  const response = await fetcher(`${serverOrigin}/v1/devices/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      pairing_code: request.pairingCode,
      device_type: 'chrome',
      device_name: request.deviceName,
      e2ee_public_key: toBase64Url(request.e2eePublicKey),
    }),
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  if (response.status !== 201) {
    throw new Error(`Device registration failed with status ${response.status}`);
  }
  const contentType = response.headers.get('Content-Type')?.split(';', 1)[0]?.trim();
  if (contentType !== 'application/json') {
    throw new Error('Device registration returned an unexpected content type');
  }
  const payload = parseRegistrationResponse(await readBoundedText(response));
  const credential: StoredTransportCredential = {
    serverOrigin,
    workspaceId: fromBase64Url(payload.workspace_id, 16, 'workspace_id'),
    deviceId: fromBase64Url(payload.device_id, 16, 'device_id'),
    authToken: fromBase64Url(payload.auth_token, 32, 'auth_token'),
    identityKeyId: request.identityKeyId.slice(),
  };
  await store.saveNew(credential);
  return credential;
}

function parseRegistrationResponse(text: string): RegistrationResponse {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error('Device registration returned invalid JSON');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Device registration returned an invalid object');
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.join(',') !== 'auth_token,device_id,workspace_id' ||
      typeof record.workspace_id !== 'string' || typeof record.device_id !== 'string' ||
      typeof record.auth_token !== 'string') {
    throw new Error('Device registration returned unexpected fields');
  }
  return record as unknown as RegistrationResponse;
}

async function readBoundedText(response: Response): Promise<string> {
  if (response.body === null) {
    throw new Error('Device registration returned an empty body');
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error('Device registration response exceeds 4096 bytes');
    }
    chunks.push(value);
  }
  const combined = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(combined);
}

function validatePairingCode(value: string): void {
  if (!/^[A-Za-z0-9_-]{32}$/.test(value)) {
    throw new Error('pairingCode must be a 192-bit base64url value');
  }
}

function validateDeviceName(value: string): void {
  const size = encoder.encode(value).byteLength;
  if (value.trim() === '' || size < 1 || size > 100) {
    throw new Error('deviceName must be non-blank UTF-8 up to 100 bytes');
  }
}

function validateBytes(value: Uint8Array, size: number, name: string, nonZero: boolean): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== size ||
      (nonZero && value.every((byte) => byte === 0))) {
    throw new Error(`${name} must be ${nonZero ? 'a non-zero ' : ''}${size}-byte value`);
  }
}

function toBase64Url(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function fromBase64Url(value: string, size: number, name: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(`${name} is not base64url`);
  const padding = '='.repeat((4 - value.length % 4) % 4);
  let binary: string;
  try {
    binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
  } catch {
    throw new Error(`${name} is not base64url`);
  }
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (decoded.byteLength !== size || toBase64Url(decoded) !== value) {
    throw new Error(`${name} must canonically encode ${size} bytes`);
  }
  return decoded;
}

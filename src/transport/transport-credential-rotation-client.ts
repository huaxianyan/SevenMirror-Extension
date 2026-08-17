import {
  type IndexedDbTransportCredentialStore,
  type StoredCredentialRotation,
} from './indexeddb-transport-credential-store';

const MAX_RESPONSE_BYTES = 1024;

export interface RotationSubmission {
  status: 'awaiting-pending-authentication';
  phase: 'attempted';
}

type RandomFiller = (target: Uint8Array) => Uint8Array;

/**
 * Persists pending and attempted before the request can leave this process.
 * HTTP success never promotes; only TransportRuntime may do that after SNO1.
 */
export async function rotateChromeTransportCredential(
  rotationCode: string,
  store: IndexedDbTransportCredentialStore,
  fetcher: typeof fetch = fetch,
  fillRandom: RandomFiller = (target) => crypto.getRandomValues(target),
): Promise<RotationSubmission> {
  validateRotationCode(rotationCode);
  let rotation = await store.loadRotation();
  if (rotation === undefined) {
    const current = await store.load();
    if (current === undefined) throw new Error('Transport credential is not configured');
    let pending: Uint8Array = new Uint8Array(32);
    try {
      pending = fillRandom(pending);
      if (!(pending instanceof Uint8Array) || pending.byteLength !== 32) {
        throw new Error('Credential random source returned an invalid value');
      }
      try {
        rotation = await store.prepareRotation(pending);
      } catch (error) {
        // Another extension context may have won the one-pending transaction.
        const existing = await store.loadRotation();
        if (existing === undefined) throw error;
        rotation = existing;
      }
    } finally {
      pending.fill(0);
      current.authToken.fill(0);
    }
  }
  try {
    await store.markRotationAttempted(rotation.pendingAuthToken);
    const endpoint = `${rotation.current.serverOrigin}/v1/devices/rotate`;
    const body = JSON.stringify({
      workspace_id: toBase64Url(rotation.current.workspaceId),
      device_id: toBase64Url(rotation.current.deviceId),
      current_auth_token: toBase64Url(rotation.current.authToken),
      rotation_code: rotationCode,
      pending_auth_token: toBase64Url(rotation.pendingAuthToken),
    });
    rotation.current.authToken.fill(0);
    rotation.pendingAuthToken.fill(0);

    const response = await fetcher(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body,
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
    if (response.redirected || response.url !== endpoint) {
      throw new Error('Credential rotation response endpoint changed');
    }
    if (response.status !== 200) {
      throw new Error(`Credential rotation failed with status ${response.status}`);
    }
    if (response.headers.get('Content-Type') !== 'application/json') {
      throw new Error('Credential rotation returned an unexpected content type');
    }
    const payload = await readBoundedJSON(response);
    if (typeof payload !== 'object' || payload === null || Array.isArray(payload) ||
        Object.keys(payload).join(',') !== 'status' ||
        (payload as Record<string, unknown>).status !== 'rotated') {
      throw new Error('Credential rotation returned unexpected fields');
    }
    return { status: 'awaiting-pending-authentication', phase: 'attempted' };
  } finally {
    rotation.current.authToken.fill(0);
    rotation.pendingAuthToken.fill(0);
  }
}

function validateRotationCode(value: string): void {
  if (!/^[A-Za-z0-9_-]{32}$/.test(value)) {
    throw new Error('rotationCode must be a 192-bit base64url value');
  }
}

async function readBoundedJSON(response: Response): Promise<unknown> {
  if (response.body === null) throw new Error('Credential rotation returned an empty body');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error('Credential rotation response exceeds 1024 bytes');
    }
    chunks.push(value);
  }
  const combined = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(combined));
  } catch {
    throw new Error('Credential rotation returned invalid JSON');
  }
}

function toBase64Url(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

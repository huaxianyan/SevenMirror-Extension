import type { StoredTransportCredential } from './indexeddb-transport-credential-store';

const MAX_PREFERENCE_RESPONSE_BYTES = 512 * 1024;
const MAX_INT64 = 0x7fff_ffff_ffff_ffffn;

/** The server rejected the write because another device stored a different revision. */
export class WorkspacePreferenceConflictError extends Error {
  constructor() {
    super('Workspace preference revision conflict');
    this.name = 'WorkspacePreferenceConflictError';
  }
}

/** The device tuple is not an approved member, so the preference stays unreachable. */
export class WorkspacePreferenceDeniedError extends Error {
  constructor() {
    super('Workspace preference access denied');
    this.name = 'WorkspacePreferenceDeniedError';
  }
}

export interface WorkspacePreferenceValue {
  /** Zero means the key has never been written. */
  revision: number;
  payload?: Uint8Array;
  updatedAtMs: number;
}

export async function readWorkspacePreference(
  credential: StoredTransportCredential,
  key: string,
  fetcher: typeof fetch = fetch,
): Promise<WorkspacePreferenceValue> {
  const response = await postPreference(fetcher, credential, '/v1/workspace/preferences/read', {
    key,
  });
  const body = await readPreferenceJson(response);
  const revision = parseDecimal(body, 'revision');
  // An unwritten key carries no value, so the server sends its other fields empty
  // rather than as canonical decimals. Reading the revision first keeps that case
  // from failing on a field that has no meaning without a stored value.
  if (revision === 0) return { revision, updatedAtMs: 0 };
  const updatedAtMs = parseDecimal(body, 'updated_at_ms');
  const encoded = body.payload;
  if (typeof encoded !== 'string' || encoded.length === 0) {
    throw new Error('Workspace preference response is missing its payload');
  }
  return { revision, payload: fromBase64Url(encoded), updatedAtMs };
}

/** Returns the revision the server stored. Throws on a conflict rather than overwriting. */
export async function writeWorkspacePreference(
  credential: StoredTransportCredential,
  key: string,
  expectedRevision: number,
  payload: Uint8Array,
  fetcher: typeof fetch = fetch,
): Promise<number> {
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
    throw new Error('expectedRevision must be a non-negative safe integer');
  }
  if (!(payload instanceof Uint8Array) || payload.byteLength === 0) {
    throw new Error('payload must be a non-empty byte array');
  }
  const response = await postPreference(fetcher, credential, '/v1/workspace/preferences/write', {
    key,
    expected_revision: expectedRevision.toString(),
    payload: toBase64Url(payload),
  });
  return parseDecimal(await readPreferenceJson(response), 'revision');
}

async function postPreference(
  fetcher: typeof fetch,
  credential: StoredTransportCredential,
  path: string,
  extra: Record<string, string>,
): Promise<Response> {
  const response = await fetcher(`${credential.serverOrigin}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      workspace_id: toBase64Url(credential.workspaceId),
      device_id: toBase64Url(credential.deviceId),
      auth_token: toBase64Url(credential.authToken),
      ...extra,
    }),
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  if (response.status === 403) throw new WorkspacePreferenceDeniedError();
  if (response.status === 409) throw new WorkspacePreferenceConflictError();
  if (response.status !== 200) {
    throw new Error(`Workspace preference request failed with status ${response.status}`);
  }
  return response;
}

async function readPreferenceJson(response: Response): Promise<Record<string, unknown>> {
  const mediaType = response.headers.get('Content-Type')?.split(';', 1)[0]?.trim();
  if (mediaType !== 'application/json') {
    throw new Error('Workspace preference request returned an unexpected content type');
  }
  const text = await readBoundedText(response);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error('Workspace preference request returned invalid JSON');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Workspace preference request returned an unexpected body');
  }
  return parsed as Record<string, unknown>;
}

async function readBoundedText(response: Response): Promise<string> {
  if (!response.body) throw new Error('Workspace preference request returned an empty body');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_PREFERENCE_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error('Workspace preference response exceeds 512 KiB');
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

function parseDecimal(body: Record<string, unknown>, name: string): number {
  const value = body[name];
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`Workspace preference ${name} is not canonical`);
  }
  if (BigInt(value) > MAX_INT64) throw new Error(`Workspace preference ${name} exceeds int64`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`Workspace preference ${name} exceeds the safe integer range`);
  }
  return parsed;
}

export function toBase64Url(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('value is not base64url');
  let binary: string;
  try {
    binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4));
  } catch {
    throw new Error('value is not base64url');
  }
  const decoded = Uint8Array.from(binary, (item) => item.charCodeAt(0));
  if (toBase64Url(decoded) !== value) throw new Error('value is not canonical base64url');
  return decoded;
}

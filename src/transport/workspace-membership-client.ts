import { deriveIdentityKeyId, serializeIdentityPublicKey, type HpkeIdentity } from '../crypto/auth-hpke';
import {
  type IndexedDbWorkspaceMembershipStore,
  type WorkspaceMembershipState,
} from '../crypto/indexeddb-workspace-membership-store';
import {
  createPendingIdentityProof,
  encodeIdentityPossessionChallenge,
  openIdentityPossessionChallenge,
} from '../protocol/workspace-membership';
import { normalizeServerOrigin } from './indexeddb-transport-credential-store';

const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_ROSTERS_PER_PAGE = 256;
const MAX_INT64 = 0x7fff_ffff_ffff_ffffn;

export interface ChromeMembershipRegistration {
  serverOrigin: string;
  pairingCode: string;
  deviceName: string;
  identity: HpkeIdentity;
}

export interface PendingChromeMembership {
  serverOrigin: string;
  workspaceId: Uint8Array;
  deviceId: Uint8Array;
  authToken: Uint8Array;
  identityKeyId: Uint8Array;
}

export interface ChromeMembershipRefresh {
  serverState: 'pending_proof' | 'pending_approval' | 'approved';
  transportEligible: boolean;
  state: WorkspaceMembershipState;
}

/** Registers, pins the returned authority, opens the HPKE challenge, and submits its exact proof. */
export async function beginChromeMembership(
  request: ChromeMembershipRegistration,
  store: IndexedDbWorkspaceMembershipStore,
  fetcher: typeof fetch = fetch,
): Promise<PendingChromeMembership> {
  const serverOrigin = normalizeServerOrigin(request.serverOrigin);
  validatePairingCode(request.pairingCode);
  validateDeviceName(request.deviceName);
  const publicKey = await serializeIdentityPublicKey(request.identity);
  const identityKeyId = await deriveIdentityKeyId(publicKey);
  const registration = parseRegistration(await postJson(fetcher, serverOrigin, '/v1/membership/register', 201, {
    pairing_code: request.pairingCode,
    device_type: 'chrome',
    device_name: request.deviceName,
    e2ee_public_key: toBase64Url(publicKey),
  }));
  const pending: PendingChromeMembership = {
    serverOrigin,
    workspaceId: fromBase64Url(registration.workspace_id, 16, 'workspace_id'),
    deviceId: fromBase64Url(registration.device_id, 16, 'device_id'),
    authToken: fromBase64Url(registration.auth_token, 32, 'auth_token'),
    identityKeyId,
  };
  const authority = fromBase64Url(registration.authority_public_key, 32, 'authority_public_key');
  try {
    await store.pinAuthority(pending.workspaceId, pending.deviceId, authority);
    const challenge = await openIdentityPossessionChallenge(
      request.identity.privateKey,
      { workspaceId: pending.workspaceId, deviceId: pending.deviceId, identityKeyId },
      fromBase64Url(registration.challenge_enc, 65, 'challenge_enc'),
      fromBase64UrlVariable(registration.challenge_ciphertext, 'challenge_ciphertext'),
    );
    const canonicalChallenge = encodeIdentityPossessionChallenge(challenge);
    const proof = await createPendingIdentityProof(canonicalChallenge);
    try {
      const proved = parseProofResponse(await postJson(fetcher, serverOrigin, '/v1/membership/prove', 200, {
        workspace_id: registration.workspace_id,
        device_id: registration.device_id,
        auth_token: registration.auth_token,
        proof: toBase64Url(proof),
      }));
      if (proved.state !== 'pending_approval') throw new Error('Membership proof returned an invalid state');
    } finally {
      canonicalChallenge.fill(0);
      proof.fill(0);
    }
    return copyPending(pending);
  } catch (error) {
    pending.authToken.fill(0);
    throw error;
  }
}

/** Reconciles all currently missing roster pages, persisting each accepted epoch before the next request. */
export async function refreshChromeMembership(
  pending: PendingChromeMembership,
  store: IndexedDbWorkspaceMembershipStore,
  fetcher: typeof fetch = fetch,
): Promise<ChromeMembershipRefresh> {
  const serverOrigin = normalizeServerOrigin(pending.serverOrigin);
  validateId(pending.workspaceId, 'workspaceId');
  validateId(pending.deviceId, 'deviceId');
  validateBytes(pending.authToken, 32, 'authToken', true);
  validateBytes(pending.identityKeyId, 32, 'identityKeyId', true);
  let pages = 0;
  while (true) {
    if (++pages > 4096) throw new Error('Membership roster pagination did not converge');
    const durable = await store.load(pending.workspaceId, pending.deviceId);
    if (durable === undefined) throw new Error('Workspace authority pin is missing');
    const response = parseStateResponse(await postJson(fetcher, serverOrigin, '/v1/membership/state', 200, {
      workspace_id: toBase64Url(pending.workspaceId),
      device_id: toBase64Url(pending.deviceId),
      auth_token: toBase64Url(pending.authToken),
      after_roster_epoch: durable.rosterEpoch.toString(),
    }));
    await store.pinAuthority(
      pending.workspaceId,
      pending.deviceId,
      fromBase64Url(response.authority_public_key, 32, 'authority_public_key'),
    );
    if (response.state !== 'approved') {
      if (response.signed_certificate !== undefined || response.rosters.length !== 0 ||
          response.latest_roster_epoch !== '0') {
        throw new Error('Pending membership state exposed approved membership data');
      }
      return { serverState: response.state, transportEligible: false, state: durable };
    }
    if (response.signed_certificate === undefined) {
      throw new Error('Approved membership state is missing the device certificate');
    }
    const latest = parseEpoch(response.latest_roster_epoch, 'latest_roster_epoch');
    if (latest < durable.rosterEpoch) throw new Error('Membership server attempted a roster rollback');
    const certificate = fromBase64UrlVariable(response.signed_certificate, 'signed_certificate');
    for (const encoded of response.rosters) {
      const roster = fromBase64UrlVariable(encoded, 'roster');
      await store.reconcileApproved(pending.workspaceId, pending.deviceId, certificate, roster);
    }
    const accepted = await store.load(pending.workspaceId, pending.deviceId);
    if (accepted === undefined) throw new Error('Membership state disappeared during reconciliation');
    if (accepted.rosterEpoch === latest) {
      if (response.rosters.length === 0 && durable.rosterEpoch !== latest) {
        throw new Error('Membership roster response made no progress');
      }
      return {
        serverState: 'approved',
        transportEligible: accepted.localDeviceActive,
        state: accepted,
      };
    }
    if (accepted.rosterEpoch <= durable.rosterEpoch || accepted.rosterEpoch > latest) {
      throw new Error('Membership roster pagination made invalid progress');
    }
  }
}

type RegistrationResponse = {
  workspace_id: string; device_id: string; auth_token: string; authority_public_key: string;
  challenge_enc: string; challenge_ciphertext: string;
};
type StateResponse = {
  state: 'pending_proof' | 'pending_approval' | 'approved'; authority_public_key: string;
  signed_certificate?: string; rosters: string[]; latest_roster_epoch: string;
};

function parseRegistration(value: unknown): RegistrationResponse {
  const record = exactRecord(value, ['auth_token', 'authority_public_key', 'challenge_ciphertext', 'challenge_enc', 'device_id', 'workspace_id'], 'registration');
  for (const key of Object.keys(record)) if (typeof record[key] !== 'string') throw new Error('Membership registration returned invalid fields');
  return record as RegistrationResponse;
}
function parseProofResponse(value: unknown): { state: string } {
  const record = exactRecord(value, ['state'], 'proof');
  if (typeof record.state !== 'string') throw new Error('Membership proof returned invalid fields');
  return { state: record.state };
}
function parseStateResponse(value: unknown): StateResponse {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('Membership state returned an invalid object');
  const record = value as Record<string, unknown>;
  const expected = record.signed_certificate === undefined
    ? ['authority_public_key', 'latest_roster_epoch', 'rosters', 'state']
    : ['authority_public_key', 'latest_roster_epoch', 'rosters', 'signed_certificate', 'state'];
  if (Object.keys(record).sort().join(',') !== expected.join(',')) throw new Error('Membership state returned unexpected fields');
  if ((record.state !== 'pending_proof' && record.state !== 'pending_approval' && record.state !== 'approved') ||
      typeof record.authority_public_key !== 'string' || typeof record.latest_roster_epoch !== 'string' ||
      (record.signed_certificate !== undefined && typeof record.signed_certificate !== 'string') ||
      !Array.isArray(record.rosters) || record.rosters.length > MAX_ROSTERS_PER_PAGE ||
      record.rosters.some((item) => typeof item !== 'string')) throw new Error('Membership state returned invalid fields');
  return record as StateResponse;
}
function exactRecord(value: unknown, keys: string[], context: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || Object.keys(value).sort().join(',') !== keys.join(',')) {
    throw new Error(`Membership ${context} returned unexpected fields`);
  }
  return value as Record<string, unknown>;
}
async function postJson(fetcher: typeof fetch, origin: string, path: string, status: number, body: unknown): Promise<unknown> {
  const response = await fetcher(`${origin}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body), cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer' });
  if (response.status !== status) throw new Error(`Membership request failed with status ${response.status}`);
  if (response.headers.get('Content-Type')?.split(';', 1)[0]?.trim() !== 'application/json') throw new Error('Membership request returned an unexpected content type');
  const text = await readBoundedText(response);
  try { return JSON.parse(text) as unknown; } catch { throw new Error('Membership request returned invalid JSON'); }
}
async function readBoundedText(response: Response): Promise<string> {
  if (!response.body) throw new Error('Membership request returned an empty body');
  const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
  while (true) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength; if (size > MAX_RESPONSE_BYTES) { await reader.cancel(); throw new Error('Membership response exceeds 2 MiB'); } chunks.push(value); }
  const combined = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { combined.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder('utf-8', { fatal: true }).decode(combined);
}
function parseEpoch(value: string, name: string): bigint { if (!/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`${name} is not canonical`); const parsed = BigInt(value); if (parsed > MAX_INT64) throw new Error(`${name} exceeds int64`); return parsed; }
function validatePairingCode(value: string): void { if (!/^[A-Za-z0-9_-]{32}$/.test(value)) throw new Error('pairingCode must be a 192-bit base64url value'); }
function validateDeviceName(value: string): void { const size = new TextEncoder().encode(value).byteLength; if (!value.trim() || size > 100) throw new Error('deviceName must be non-blank UTF-8 up to 100 bytes'); }
function validateId(value: Uint8Array, name: string): void { validateBytes(value, 16, name, true); }
function validateBytes(value: Uint8Array, size: number, name: string, nonZero: boolean): void { if (!(value instanceof Uint8Array) || value.byteLength !== size || (nonZero && value.every((item) => item === 0))) throw new Error(`${name} has invalid length or value`); }
function toBase64Url(value: Uint8Array): string { let binary = ''; for (const byte of value) binary += String.fromCharCode(byte); return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, ''); }
function fromBase64Url(value: string, size: number, name: string): Uint8Array { const decoded = fromBase64UrlVariable(value, name); if (decoded.byteLength !== size) throw new Error(`${name} must encode ${size} bytes`); return decoded; }
function fromBase64UrlVariable(value: string, name: string): Uint8Array { if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(`${name} is not base64url`); let binary: string; try { binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4)); } catch { throw new Error(`${name} is not base64url`); } const decoded = Uint8Array.from(binary, (item) => item.charCodeAt(0)); if (toBase64Url(decoded) !== value) throw new Error(`${name} is not canonical base64url`); return decoded; }
function copyPending(value: PendingChromeMembership): PendingChromeMembership { return { serverOrigin: value.serverOrigin, workspaceId: value.workspaceId.slice(), deviceId: value.deviceId.slice(), authToken: value.authToken.slice(), identityKeyId: value.identityKeyId.slice() }; }

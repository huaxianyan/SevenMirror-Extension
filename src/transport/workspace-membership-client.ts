import { deriveIdentityKeyId, serializeIdentityPublicKey, type HpkeIdentity } from '../crypto/auth-hpke';
import {
  type IndexedDbWorkspaceMembershipStore,
  type WorkspaceMembershipState,
} from '../crypto/indexeddb-workspace-membership-store';
import {
  createPendingIdentityProof,
  decodeSignedAuthorityKeyTransition,
  decodeSignedWorkspaceRoster,
  encodeIdentityPossessionChallenge,
  openIdentityPossessionChallenge,
} from '../protocol/workspace-membership';
import { normalizeServerOrigin } from './indexeddb-transport-credential-store';
import type { PendingChromeMembershipStore, StoredPendingChromeMembership } from './indexeddb-pending-membership-store';

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
  journal: PendingChromeMembershipStore,
  fetcher: typeof fetch = fetch,
): Promise<PendingChromeMembership> {
  const existing = await journal.load();
  if (existing !== undefined) {
    existing.authToken.fill(0);
    existing.canonicalProof?.fill(0);
    throw new Error('A membership enrollment is already pending');
  }
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
  const challengeEnc = fromBase64Url(registration.challenge_enc, 65, 'challenge_enc');
  const challengeCiphertext = fromBase64UrlVariable(registration.challenge_ciphertext, 'challenge_ciphertext');
  try {
    await journal.prepareRegistration(pending, authority, challengeEnc, challengeCiphertext);
    await store.pinAuthority(pending.workspaceId, pending.deviceId, authority);
    const challenge = await openIdentityPossessionChallenge(
      request.identity.privateKey,
      { workspaceId: pending.workspaceId, deviceId: pending.deviceId, identityKeyId },
      challengeEnc,
      challengeCiphertext,
    );
    const canonicalChallenge = encodeIdentityPossessionChallenge(challenge);
    const proof = await createPendingIdentityProof(canonicalChallenge);
    try {
      await journal.bindProof(pending, proof);
      await journal.markProofAttempted(pending, proof);
      await submitChromeProof(pending, proof, fetcher);
      await journal.markPendingApproval(pending);
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

/** Recovers an exact durable proof intent after Worker suspension or an ambiguous response. */
export async function resumeChromeMembership(
  journal: PendingChromeMembershipStore,
  store: IndexedDbWorkspaceMembershipStore,
  identity: HpkeIdentity,
  fetcher: typeof fetch = fetch,
): Promise<ChromeMembershipRefresh> {
  const pending = await journal.load();
  if (pending === undefined) throw new Error('Pending membership enrollment is missing');
  try {
    await store.pinAuthority(pending.workspaceId, pending.deviceId, pending.authorityPublicKey);
    const proof = await recoverChromeProof(pending, identity, journal);
    let refreshed = await refreshChromeMembership(pending, store, fetcher);
    if (refreshed.serverState === 'pending_proof') {
      if (pending.phase === 'pending-approval') throw new Error('Membership server rolled back completed identity proof');
      await journal.markProofAttempted(pending, proof);
      await submitChromeProof(pending, proof, fetcher);
      await journal.markPendingApproval(pending);
      refreshed = await refreshChromeMembership(pending, store, fetcher);
    } else {
      await journal.markPendingApproval(pending);
    }
    proof.fill(0);
    return refreshed;
  } finally {
    pending.authToken.fill(0);
    pending.canonicalProof?.fill(0);
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
    if (response.state !== 'approved') {
      await store.pinAuthority(pending.workspaceId, pending.deviceId,
        fromBase64Url(response.authority_public_key, 32, 'authority_public_key'));
      if (response.signed_certificate !== undefined || response.rosters.length !== 0 ||
          response.authority_transitions.length !== 0 || response.latest_roster_epoch !== '0') {
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
    const transitions = response.authority_transitions.map((encoded) => {
      const bytes = fromBase64UrlVariable(encoded, 'authority_transition');
      return { bytes, value: decodeSignedAuthorityKeyTransition(bytes) };
    });
    for (const encoded of response.rosters) {
      const roster = fromBase64UrlVariable(encoded, 'roster');
      const rosterEpoch = decodeSignedWorkspaceRoster(roster).roster!.rosterEpoch;
      const current = await store.load(pending.workspaceId, pending.deviceId);
      if (current === undefined) throw new Error('Membership state disappeared during reconciliation');
      const transition = transitions.find((item) =>
        item.value.transition!.activationRosterEpoch === rosterEpoch &&
        item.value.transition!.transitionEpoch === current.authorityEpoch + 1n);
      if (transition) {
        await store.reconcileAuthorityTransition(pending.workspaceId, pending.deviceId, transition.bytes, roster);
      } else {
        const currentCertificate = current.signedCertificate ?? certificate;
        await store.reconcileApproved(pending.workspaceId, pending.deviceId, currentCertificate, roster);
      }
    }
    const accepted = await store.load(pending.workspaceId, pending.deviceId);
    if (accepted === undefined) throw new Error('Membership state disappeared during reconciliation');
    if (accepted.rosterEpoch === latest) {
      if (!accepted.signedCertificate || !equalBytes(accepted.signedCertificate, certificate)) {
        throw new Error('Membership certificate does not match the accepted roster');
      }
      await store.pinAuthority(pending.workspaceId, pending.deviceId,
        fromBase64Url(response.authority_public_key, 32, 'authority_public_key'));
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

async function recoverChromeProof(
  pending: StoredPendingChromeMembership,
  identity: HpkeIdentity,
  journal: PendingChromeMembershipStore,
): Promise<Uint8Array> {
  const publicKey = await serializeIdentityPublicKey(identity);
  if (!equalBytes(await deriveIdentityKeyId(publicKey), pending.identityKeyId)) throw new Error('Pending enrollment identity no longer matches');
  if (pending.canonicalProof) return pending.canonicalProof.slice();
  const challenge = await openIdentityPossessionChallenge(identity.privateKey, {
    workspaceId: pending.workspaceId, deviceId: pending.deviceId, identityKeyId: pending.identityKeyId,
  }, pending.challengeEnc, pending.challengeCiphertext);
  const canonicalChallenge = encodeIdentityPossessionChallenge(challenge);
  try {
    const proof = await createPendingIdentityProof(canonicalChallenge);
    await journal.bindProof(pending, proof);
    return proof;
  } finally { canonicalChallenge.fill(0); }
}

async function submitChromeProof(
  pending: PendingChromeMembership,
  canonicalProof: Uint8Array,
  fetcher: typeof fetch,
): Promise<void> {
  const proved = parseProofResponse(await postJson(fetcher, normalizeServerOrigin(pending.serverOrigin), '/v1/membership/prove', 200, {
    workspace_id: toBase64Url(pending.workspaceId),
    device_id: toBase64Url(pending.deviceId),
    auth_token: toBase64Url(pending.authToken),
    proof: toBase64Url(canonicalProof),
  }));
  if (proved.state !== 'pending_approval') throw new Error('Membership proof returned an invalid state');
}

type RegistrationResponse = {
  workspace_id: string; device_id: string; auth_token: string; authority_public_key: string;
  challenge_enc: string; challenge_ciphertext: string;
};
type StateResponse = {
  state: 'pending_proof' | 'pending_approval' | 'approved'; authority_public_key: string;
  signed_certificate?: string; authority_transitions: string[]; rosters: string[]; latest_roster_epoch: string;
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
    ? ['authority_public_key', 'authority_transitions', 'latest_roster_epoch', 'rosters', 'state']
    : ['authority_public_key', 'authority_transitions', 'latest_roster_epoch', 'rosters', 'signed_certificate', 'state'];
  if (Object.keys(record).sort().join(',') !== expected.join(',')) throw new Error('Membership state returned unexpected fields');
  if ((record.state !== 'pending_proof' && record.state !== 'pending_approval' && record.state !== 'approved') ||
      typeof record.authority_public_key !== 'string' || typeof record.latest_roster_epoch !== 'string' ||
      (record.signed_certificate !== undefined && typeof record.signed_certificate !== 'string') ||
      !Array.isArray(record.authority_transitions) || record.authority_transitions.length > 256 ||
      record.authority_transitions.some((item) => typeof item !== 'string') ||
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
function equalBytes(left: Uint8Array, right: Uint8Array): boolean { return left.byteLength === right.byteLength && left.every((item, index) => item === right[index]); }
function copyPending(value: PendingChromeMembership): PendingChromeMembership { return { serverOrigin: value.serverOrigin, workspaceId: value.workspaceId.slice(), deviceId: value.deviceId.slice(), authToken: value.authToken.slice(), identityKeyId: value.identityKeyId.slice() }; }

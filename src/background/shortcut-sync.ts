import {
  validateNotificationShortcutPreferences,
  type NotificationShortcutPreferences,
} from './notification-shortcuts';
import { fromBase64Url, toBase64Url } from '../transport/workspace-preferences-client';

export const SHORTCUT_SYNC_STORAGE_KEY = 'notificationShortcutSyncV1';

/** The server preference key the encrypted shortcut rules live under. */
export const SHORTCUT_PREFERENCE_SERVER_KEY = 'notification-shortcuts';

const SYNC_PURPOSE = 'SevenMirror notification shortcuts v1';
const PBKDF2_ITERATIONS = 600_000;
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 10_000_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const DERIVED_KEY_BYTES = 32;
const MAX_PASSPHRASE_BYTES = 1024;
const MAX_ENVELOPE_BYTES = 256 * 1024;

/** The device-local half of the synchronization: everything needed to decrypt again. */
export interface ShortcutSyncState {
  salt: Uint8Array;
  iterations: number;
  /** The derived AES-GCM key. Stored because the local rules are already stored in the clear. */
  key: Uint8Array;
  /** The server revision this device last observed. */
  revision: number;
  lastSyncedAtMs?: number;
}

export interface ShortcutSyncStatus {
  enabled: boolean;
  revision: number;
  lastSyncedAtMs?: number;
}

/** The sealed value as it travels to and from the server. */
interface ShortcutSyncEnvelope {
  v: 1;
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  salt: string;
  iv: string;
  ciphertext: string;
}

export interface ShortcutSyncStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

export class WrongShortcutPassphraseError extends Error {
  constructor() {
    super('The workspace rules were sealed with a different passphrase');
    this.name = 'WrongShortcutPassphraseError';
  }
}

export class ShortcutSyncStore {
  constructor(private readonly storage: ShortcutSyncStorage = chrome.storage.local) {}

  async load(): Promise<ShortcutSyncState | undefined> {
    const stored = await this.storage.get(SHORTCUT_SYNC_STORAGE_KEY);
    const value = stored[SHORTCUT_SYNC_STORAGE_KEY];
    if (value === undefined) return undefined;
    return validateShortcutSyncState(value);
  }

  async save(state: ShortcutSyncState): Promise<void> {
    await this.storage.set({
      [SHORTCUT_SYNC_STORAGE_KEY]: {
        v: 1,
        salt: toBase64Url(state.salt),
        iterations: state.iterations,
        key: toBase64Url(state.key),
        revision: state.revision,
        ...(state.lastSyncedAtMs === undefined ? {} : { lastSyncedAtMs: state.lastSyncedAtMs }),
      },
    });
  }

  async clear(): Promise<void> {
    await this.storage.remove(SHORTCUT_SYNC_STORAGE_KEY);
  }
}

/**
 * Seals the rules with a key derived from the user-supplied passphrase. The
 * server stores only these bytes, so the passphrase must never come from the
 * server and the workspace ID is bound as additional data to stop a sealed rule
 * set from being replayed under another workspace.
 */
export async function sealShortcutPreferences(
  state: ShortcutSyncState,
  workspaceId: Uint8Array,
  preferences: NotificationShortcutPreferences,
): Promise<Uint8Array> {
  const key = await importAesKey(state.key);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plaintext = new TextEncoder().encode(JSON.stringify(preferences));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: arrayBuffer(iv), additionalData: arrayBuffer(syncAdditionalData(workspaceId)) },
    key,
    arrayBuffer(plaintext),
  ));
  const envelope: ShortcutSyncEnvelope = {
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iterations: state.iterations,
    salt: toBase64Url(state.salt),
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext),
  };
  return new TextEncoder().encode(JSON.stringify(envelope));
}

export async function openShortcutPreferences(
  state: ShortcutSyncState,
  workspaceId: Uint8Array,
  payload: Uint8Array,
): Promise<NotificationShortcutPreferences> {
  if (payload.byteLength === 0 || payload.byteLength > MAX_ENVELOPE_BYTES) {
    throw new Error('The sealed rules are not a bounded envelope');
  }
  const envelope = validateEnvelope(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload)) as unknown);
  const salt = fromBase64Url(envelope.salt);
  if (!bytesEqual(salt, state.salt) || envelope.iterations !== state.iterations) {
    // A different salt means another device reset the passphrase. Reporting the
    // passphrase as wrong is accurate: this device cannot open the value.
    throw new WrongShortcutPassphraseError();
  }
  const key = await importAesKey(state.key);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: arrayBuffer(fromBase64Url(envelope.iv)),
        additionalData: arrayBuffer(syncAdditionalData(workspaceId)),
      },
      key,
      arrayBuffer(fromBase64Url(envelope.ciphertext)),
    );
  } catch {
    throw new WrongShortcutPassphraseError();
  }
  const decoded: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
  return validateNotificationShortcutPreferences(decoded);
}

/**
 * Reads the key-derivation parameters before a key exists. A device that joins an
 * already-synced workspace must adopt the salt the first device chose, otherwise
 * the same passphrase would derive a different key and nothing would open.
 */
export function readShortcutSyncKdf(payload: Uint8Array): { salt: Uint8Array; iterations: number } {
  if (payload.byteLength === 0 || payload.byteLength > MAX_ENVELOPE_BYTES) {
    throw new Error('The sealed rules are not a bounded envelope');
  }
  const envelope = validateEnvelope(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload)) as unknown);
  return { salt: fromBase64Url(envelope.salt), iterations: envelope.iterations };
}

/** Derives the AES-GCM key for one passphrase and salt. Deterministic across devices. */
export async function deriveShortcutSyncKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const encoded = new TextEncoder().encode(passphrase.normalize('NFKC'));
  if (encoded.byteLength === 0 || encoded.byteLength > MAX_PASSPHRASE_BYTES) {
    throw new Error('The synchronization passphrase must be 1 to 1024 encoded bytes');
  }
  if (salt.byteLength !== SALT_BYTES) throw new Error('The salt must be 16 bytes');
  validateIterations(iterations);
  const material = await crypto.subtle.importKey('raw', arrayBuffer(encoded), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: arrayBuffer(salt), iterations },
    material,
    DERIVED_KEY_BYTES * 8,
  );
  return new Uint8Array(bits);
}

export function newShortcutSyncSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SALT_BYTES));
}

export function defaultShortcutSyncIterations(): number {
  return PBKDF2_ITERATIONS;
}

export function describeShortcutSyncStatus(state: ShortcutSyncState | undefined): ShortcutSyncStatus {
  if (state === undefined) return { enabled: false, revision: 0 };
  return {
    enabled: true,
    revision: state.revision,
    ...(state.lastSyncedAtMs === undefined ? {} : { lastSyncedAtMs: state.lastSyncedAtMs }),
  };
}

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.byteLength !== DERIVED_KEY_BYTES) throw new Error('The synchronization key must be 32 bytes');
  return crypto.subtle.importKey('raw', arrayBuffer(raw), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

function syncAdditionalData(workspaceId: Uint8Array): Uint8Array {
  if (workspaceId.byteLength !== 16) throw new Error('The workspace ID must be 16 bytes');
  const prefix = new TextEncoder().encode(`${SYNC_PURPOSE}\0`);
  const bound = new Uint8Array(prefix.byteLength + workspaceId.byteLength);
  bound.set(prefix, 0);
  bound.set(workspaceId, prefix.byteLength);
  return bound;
}

function validateEnvelope(value: unknown): ShortcutSyncEnvelope {
  if (typeof value !== 'object' || value === null) throw new Error('The sealed rules are not an envelope');
  const candidate = value as Record<string, unknown>;
  if (candidate.v !== 1 || candidate.kdf !== 'PBKDF2-SHA256') {
    throw new Error('The sealed rules use an unsupported envelope version');
  }
  const iterations = candidate.iterations;
  if (typeof iterations !== 'number' || !Number.isSafeInteger(iterations)) {
    throw new Error('The sealed rules carry an invalid iteration count');
  }
  validateIterations(iterations);
  for (const field of ['salt', 'iv', 'ciphertext'] as const) {
    if (typeof candidate[field] !== 'string' || candidate[field].length === 0) {
      throw new Error(`The sealed rules are missing their ${field}`);
    }
  }
  const salt = fromBase64Url(candidate.salt as string);
  if (salt.byteLength !== SALT_BYTES) throw new Error('The sealed rules carry an invalid salt');
  const iv = fromBase64Url(candidate.iv as string);
  if (iv.byteLength !== IV_BYTES) throw new Error('The sealed rules carry an invalid nonce');
  fromBase64Url(candidate.ciphertext as string);
  return {
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iterations,
    salt: candidate.salt as string,
    iv: candidate.iv as string,
    ciphertext: candidate.ciphertext as string,
  };
}

function validateIterations(iterations: number): void {
  if (!Number.isSafeInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new Error(`The iteration count must be between ${MIN_ITERATIONS} and ${MAX_ITERATIONS}`);
  }
}

function validateShortcutSyncState(value: unknown): ShortcutSyncState {
  if (typeof value !== 'object' || value === null) throw new Error('The synchronization state is invalid');
  const candidate = value as Record<string, unknown>;
  if (candidate.v !== 1 || typeof candidate.salt !== 'string' || typeof candidate.key !== 'string' ||
      typeof candidate.iterations !== 'number') {
    throw new Error('The synchronization state is invalid');
  }
  const salt = fromBase64Url(candidate.salt);
  if (salt.byteLength !== SALT_BYTES) throw new Error('The synchronization state has an invalid salt');
  const key = fromBase64Url(candidate.key);
  if (key.byteLength !== DERIVED_KEY_BYTES) throw new Error('The synchronization state has an invalid key');
  validateIterations(candidate.iterations);
  const revision = candidate.revision;
  if (typeof revision !== 'number' || !Number.isSafeInteger(revision) || revision < 0) {
    throw new Error('The synchronization state has an invalid revision');
  }
  const lastSyncedAtMs = candidate.lastSyncedAtMs;
  if (lastSyncedAtMs !== undefined &&
      (typeof lastSyncedAtMs !== 'number' || !Number.isSafeInteger(lastSyncedAtMs))) {
    throw new Error('The synchronization state has an invalid timestamp');
  }
  return {
    salt,
    iterations: candidate.iterations,
    key,
    revision,
    ...(lastSyncedAtMs === undefined ? {} : { lastSyncedAtMs: lastSyncedAtMs as number }),
  };
}

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((item, index) => item === right[index]);
}

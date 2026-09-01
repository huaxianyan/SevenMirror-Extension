import 'fake-indexeddb/auto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { IndexedDbIdentityStore } from '../crypto/indexeddb-identity-store';
import { IndexedDbNotificationStateStore } from '../crypto/indexeddb-notification-state-store';
import {
  createNotificationUpsertPayload,
  encodeEncryptedPayloadV1,
} from '../protocol/encrypted-payload';
import {
  IndexedDbTransportCredentialStore,
  normalizeServerOrigin,
  type StoredTransportCredential,
} from '../transport/indexeddb-transport-credential-store';

const textEncoder = new TextEncoder();
const databasesToDelete = new Set<string>();

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all([...databasesToDelete].map(deleteDatabase));
  databasesToDelete.clear();
});

describe('Chrome sensitive-data canary boundary', () => {
  it('confines transport tokens, keeps HPKE private keys non-extractable, and classifies notification plaintext', async () => {
    const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const credentialDatabase = `canary-transport-${suffix}`;
    const identityDatabase = `canary-identity-${suffix}`;
    const notificationDatabase = `canary-notification-${suffix}`;
    databasesToDelete.add(credentialDatabase);
    databasesToDelete.add(identityDatabase);
    databasesToDelete.add(notificationDatabase);

    const currentTokenText = 'chrome-current-token-canary-0001';
    const pendingTokenText = 'chrome-pending-token-canary-0001';
    const titleCanary = 'CHROME_EXPECTED_LOCAL_TITLE_CANARY';
    const bodyCanary = 'CHROME_EXPECTED_LOCAL_BODY_CANARY';
    const currentToken = textEncoder.encode(currentTokenText);
    const pendingToken = textEncoder.encode(pendingTokenText);
    expect(currentToken).toHaveLength(32);
    expect(pendingToken).toHaveLength(32);

    const consoleSpies = (['debug', 'error', 'info', 'log', 'warn'] as const)
      .map((method) => vi.spyOn(console, method).mockImplementation(() => undefined));
    const observedErrors: string[] = [];
    const credentialStore = new IndexedDbTransportCredentialStore(credentialDatabase);
    const identityStore = new IndexedDbIdentityStore(identityDatabase);
    const notificationStore = new IndexedDbNotificationStateStore(notificationDatabase);

    const credential: StoredTransportCredential = {
      serverOrigin: 'https://notify.example',
      workspaceId: new Uint8Array(16).fill(1),
      deviceId: new Uint8Array(16).fill(2),
      authToken: currentToken,
      identityKeyId: new Uint8Array(32).fill(3),
    };
    await credentialStore.saveNew(credential);
    await credentialStore.prepareRotation(pendingToken);

    const restoredIdentity = await identityStore.loadOrCreate();
    expect(restoredIdentity.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('pkcs8', restoredIdentity.privateKey)).rejects.toThrow();
    const reconstructedIdentity = await new IndexedDbIdentityStore(identityDatabase).loadExisting();
    expect(reconstructedIdentity?.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('pkcs8', reconstructedIdentity!.privateKey)).rejects.toThrow();

    const upsert = createNotificationUpsertPayload({
      notificationId: 'canary.notification/1',
      notificationRevision: 1n,
      sourceApplicationId: 'canary.application',
      sourceApplicationName: 'Canary application',
      title: titleCanary,
      body: bodyCanary,
      containsContentImage: false,
      actions: [],
    });
    expect(upsert.body.case).toBe('notificationUpsert');
    if (upsert.body.case !== 'notificationUpsert') throw new Error('Unexpected canary payload');
    const canonicalUpsert = encodeEncryptedPayloadV1(upsert);
    await notificationStore.reconcileUpsert(
      new Uint8Array(16).fill(4),
      upsert.body.value,
      canonicalUpsert,
    );

    await captureError(observedErrors, () => credentialStore.saveNew({
      ...credential,
      authToken: new Uint8Array(32).fill(9),
    }));
    await captureError(observedErrors, () => credentialStore.prepareRotation(currentToken));
    captureSynchronousError(observedErrors, () =>
      normalizeServerOrigin(`https://user:${currentTokenText}@notify.example`));

    const credentialRecords = await readAllRecords(credentialDatabase);
    const identityRecords = await readAllRecords(identityDatabase);
    const notificationRecords = await readAllRecords(notificationDatabase);
    const allRecords = [...credentialRecords, ...identityRecords, ...notificationRecords];

    // Raw current/pending bearer secrets are intentionally durable only in the dedicated
    // extension-origin credential record. Encoded copies are not expected anywhere.
    expect(containsBytes(credentialRecords, currentToken)).toBe(true);
    expect(containsBytes(credentialRecords, pendingToken)).toBe(true);
    expect(containsBytes([...identityRecords, ...notificationRecords], currentToken)).toBe(false);
    expect(containsBytes([...identityRecords, ...notificationRecords], pendingToken)).toBe(false);
    for (const encoded of [
      Buffer.from(currentToken).toString('base64'),
      Buffer.from(currentToken).toString('base64url'),
      Buffer.from(pendingToken).toString('base64'),
      Buffer.from(pendingToken).toString('base64url'),
    ]) {
      expect(containsString(allRecords, encoded)).toBe(false);
      expect(observedErrors.join('\n')).not.toContain(encoded);
    }

    // Decrypted notification fields are expected endpoint-local plaintext required for
    // presentation and revision reconciliation; they must not be misreported as a leak.
    expect(containsString(notificationRecords, titleCanary)).toBe(true);
    expect(containsString(notificationRecords, bodyCanary)).toBe(true);
    expect(containsString([...credentialRecords, ...identityRecords], titleCanary)).toBe(false);
    expect(containsString([...credentialRecords, ...identityRecords], bodyCanary)).toBe(false);

    const diagnosticText = observedErrors.join('\n');
    expect(diagnosticText).not.toContain(currentTokenText);
    expect(diagnosticText).not.toContain(pendingTokenText);
    expect(diagnosticText).not.toContain(titleCanary);
    expect(diagnosticText).not.toContain(bodyCanary);
    expect(consoleSpies.every((spy) => spy.mock.calls.length === 0)).toBe(true);

    await credentialStore.clear();
    await identityStore.clear();
    await notificationStore.clear();
    expect(await readAllRecords(credentialDatabase)).toEqual([]);
    expect(await readAllRecords(identityDatabase)).toEqual([]);
  });
});

async function captureError(errors: string[], operation: () => Promise<unknown>): Promise<void> {
  try {
    await operation();
  } catch (error) {
    errors.push(error instanceof Error ? `${error.name}: ${error.message}` : String(error));
    return;
  }
  throw new Error('Expected canary operation to fail');
}

function captureSynchronousError(errors: string[], operation: () => unknown): void {
  try {
    operation();
  } catch (error) {
    errors.push(error instanceof Error ? `${error.name}: ${error.message}` : String(error));
    return;
  }
  throw new Error('Expected canary operation to fail');
}

async function readAllRecords(databaseName: string): Promise<unknown[]> {
  const database = await openDatabase(databaseName);
  try {
    const records: unknown[] = [];
    for (const storeName of Array.from(database.objectStoreNames)) {
      const transaction = database.transaction(storeName, 'readonly');
      records.push(...await requestResult(transaction.objectStore(storeName).getAll()));
      await transactionCompleted(transaction);
    }
    return records;
  } finally {
    database.close();
  }
}

function openDatabase(name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('Unable to open canary database'));
  });
}

function deleteDatabase(name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error ?? new Error('Unable to delete canary database'));
    request.onblocked = () => reject(new Error(`Canary database deletion was blocked: ${name}`));
  });
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('Canary IndexedDB request failed'));
  });
}

function transactionCompleted(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error ?? new Error('Canary transaction aborted'));
    transaction.onerror = () => reject(transaction.error ?? new Error('Canary transaction failed'));
  });
}

function containsBytes(value: unknown, needle: Uint8Array): boolean {
  if (value instanceof ArrayBuffer) return byteSequenceIncludes(new Uint8Array(value), needle);
  if (ArrayBuffer.isView(value)) {
    return byteSequenceIncludes(
      new Uint8Array(value.buffer, value.byteOffset, value.byteLength),
      needle,
    );
  }
  if (Array.isArray(value)) return value.some((entry) => containsBytes(entry, needle));
  if (isRecord(value)) return Object.values(value).some((entry) => containsBytes(entry, needle));
  return false;
}

function containsString(value: unknown, needle: string): boolean {
  if (typeof value === 'string') return value.includes(needle);
  if (Array.isArray(value)) return value.some((entry) => containsString(entry, needle));
  if (isRecord(value)) return Object.values(value).some((entry) => containsString(entry, needle));
  return false;
}

function byteSequenceIncludes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.byteLength === 0 || needle.byteLength > haystack.byteLength) return false;
  outer: for (let offset = 0; offset <= haystack.byteLength - needle.byteLength; offset += 1) {
    for (let index = 0; index < needle.byteLength; index += 1) {
      if (haystack[offset + index] !== needle[index]) continue outer;
    }
    return true;
  }
  return false;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

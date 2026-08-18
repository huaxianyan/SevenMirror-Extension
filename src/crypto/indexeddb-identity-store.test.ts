import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import {
  openWithIdentity,
  sealWithIdentity,
  serializeIdentityPublicKey,
} from './auth-hpke';
import { IndexedDbIdentityStore } from './indexeddb-identity-store';

const text = new TextEncoder();

describe('IndexedDbIdentityStore', () => {
  it('restores a non-extractable identity usable by authenticated HPKE', async () => {
    const suffix = `${Date.now()}-${Math.random()}`;
    const senderStore = new IndexedDbIdentityStore(`sender-${suffix}`);
    const recipientStore = new IndexedDbIdentityStore(`recipient-${suffix}`);

    expect(await senderStore.loadExisting()).toBeUndefined();
    const sender = await senderStore.loadOrCreate();
    const senderReloaded = await senderStore.loadOrCreate();
    const recipient = await recipientStore.loadOrCreate();
    const recipientReloaded = await recipientStore.loadOrCreate();

    expect(await senderStore.loadExisting()).toBeDefined();
    expect(sender.privateKey.extractable).toBe(false);
    expect(recipient.privateKey.extractable).toBe(false);
    expect(await serializeIdentityPublicKey(senderReloaded)).toEqual(
      await serializeIdentityPublicKey(sender),
    );
    expect(await serializeIdentityPublicKey(recipientReloaded)).toEqual(
      await serializeIdentityPublicKey(recipient),
    );

    const plaintext = text.encode('non-extractable persisted Chrome identity');
    const aad = text.encode('workspace|sender|recipient|message|expiry');
    const encrypted = await sealWithIdentity(
      await serializeIdentityPublicKey(recipientReloaded),
      senderReloaded,
      plaintext,
      aad,
    );
    const opened = await openWithIdentity(
      recipientReloaded,
      await serializeIdentityPublicKey(senderReloaded),
      encrypted,
      aad,
    );
    expect(opened).toEqual(plaintext);

    await senderStore.clear();
    await recipientStore.clear();
  });

  it('durably prepares exactly one pending identity without replacing current', async () => {
    const databaseName = `identity-rotation-${Date.now()}-${Math.random()}`;
    const store = new IndexedDbIdentityStore(databaseName);
    const current = await store.loadOrCreate();
    const currentPublic = await serializeIdentityPublicKey(current);

    const [first, concurrent] = await Promise.all([
      store.prepareRotation(),
      new IndexedDbIdentityStore(databaseName).prepareRotation(),
    ]);
    const restored = await new IndexedDbIdentityStore(databaseName).loadRotation();

    expect(restored).toBeDefined();
    expect(await serializeIdentityPublicKey(first.current)).toEqual(currentPublic);
    expect(await serializeIdentityPublicKey(concurrent.current)).toEqual(currentPublic);
    expect(await serializeIdentityPublicKey(restored!.current)).toEqual(currentPublic);
    const pendingPublic = await serializeIdentityPublicKey(first.pending);
    expect(pendingPublic).not.toEqual(currentPublic);
    expect(await serializeIdentityPublicKey(concurrent.pending)).toEqual(pendingPublic);
    expect(await serializeIdentityPublicKey(restored!.pending)).toEqual(pendingPublic);
    expect(restored!.pending.privateKey.extractable).toBe(false);

    const sender = await generateTestSender();
    const plaintext = text.encode('pending identity survived Worker reconstruction');
    const aad = text.encode('identity-transition-pending-recipient');
    const encrypted = await sealWithIdentity(pendingPublic, sender, plaintext, aad);
    expect(await openWithIdentity(
      restored!.pending,
      await serializeIdentityPublicKey(sender),
      encrypted,
      aad,
    )).toEqual(plaintext);

    expect(await store.loadExisting()).toBeDefined();
    await store.clear();
  });

  it('fails closed when a pending slot silently reuses current identity', async () => {
    const databaseName = `identity-corrupt-${Date.now()}-${Math.random()}`;
    const store = new IndexedDbIdentityStore(databaseName);
    const current = await store.loadOrCreate();
    const database = await openIdentityDatabase(databaseName);
    const transaction = database.transaction('identities', 'readwrite');
    const completed = transactionCompleted(transaction);
    await requestCompleted(
      transaction.objectStore('identities').put({
        formatVersion: 1,
        current,
        pending: current,
      }, 'primary-hpke-auth-v1'),
    );
    await completed;
    database.close();

    await expect(new IndexedDbIdentityStore(databaseName).loadExisting())
      .rejects.toThrow(/differ/i);
    await store.clear();
  });
});

async function generateTestSender() {
  const store = new IndexedDbIdentityStore(`identity-sender-${Date.now()}-${Math.random()}`);
  return store.loadOrCreate();
}

function openIdentityDatabase(name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function requestCompleted(request: IDBRequest): Promise<void> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

function transactionCompleted(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
}

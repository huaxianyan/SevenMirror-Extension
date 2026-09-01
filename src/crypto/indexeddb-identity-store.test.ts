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

  it('fails closed when a retired pending identity record remains', async () => {
    const databaseName = `retired-pending-${Date.now()}-${Math.random()}`;
    const store = new IndexedDbIdentityStore(databaseName);
    const current = await store.loadOrCreate();
    const pendingStore = new IndexedDbIdentityStore(`${databaseName}-pending`);
    const pending = await pendingStore.loadOrCreate();
    const database = await openIdentityDatabase(databaseName);
    const transaction = database.transaction('identities', 'readwrite');
    const completed = transactionCompleted(transaction);
    transaction.objectStore('identities').put({
      formatVersion: 1,
      current,
      pending,
    }, 'primary-hpke-auth-v1');
    await completed;
    database.close();

    await expect(store.loadExisting()).rejects.toThrow(/revocation and re-enrollment/i);
    await store.clear();
    await pendingStore.clear();
  });
});

function openIdentityDatabase(name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onsuccess = () => resolve(request.result);
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

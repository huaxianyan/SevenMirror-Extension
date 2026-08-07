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
});

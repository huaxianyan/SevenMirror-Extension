import { describe, expect, it } from 'vitest';
import {
  deriveKeyPair,
  openAuthenticated,
  sealAuthenticated,
} from './auth-hpke';
import vector from '../../protocol/test-vectors/hpke-auth-p256-aes128gcm.json';

const bytes = (start: number): Uint8Array =>
  Uint8Array.from({ length: 32 }, (_, index) => (start + index) & 0xff);

const text = new TextEncoder();
const hex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);

// Fixed IKM values are test vectors only. Production uses a non-extractable identity.
const senderIkm = bytes(1);
const recipientIkm = bytes(65);
const attackerIkm = bytes(129);
const ephemeralIkm = bytes(193);

const aad = text.encode('workspace-1|sender-android|recipient-chrome|message-1|sequence-1');
const plaintext = text.encode('notification payload: hello from Android');

describe('RFC 9180 authenticated HPKE candidate', () => {
  it('round-trips with sender authentication and AAD', async () => {
    const sender = await deriveKeyPair(senderIkm);
    const recipient = await deriveKeyPair(recipientIkm);
    const encrypted = await sealAuthenticated(
      recipient.publicKey,
      sender,
      plaintext,
      aad,
      ephemeralIkm,
    );

    const opened = await openAuthenticated(recipient, sender.publicKey, encrypted, aad);
    expect(opened).toEqual(plaintext);
  });

  it('matches and opens the canonical deterministic cross-platform vector', async () => {
    const sender = await deriveKeyPair(fromHex(vector.senderIkm));
    const recipient = await deriveKeyPair(fromHex(vector.recipientIkm));
    const encrypted = await sealAuthenticated(
      recipient.publicKey,
      sender,
      fromHex(vector.plaintext),
      fromHex(vector.aad),
      fromHex(vector.ephemeralIkm),
    );

    expect(hex(sender.publicKey)).toBe(vector.senderPublicKey);
    expect(hex(recipient.publicKey)).toBe(vector.recipientPublicKey);
    expect(hex(encrypted.encapsulatedKey)).toBe(vector.encapsulatedKey);
    expect(hex(encrypted.ciphertext)).toBe(vector.ciphertext);

    const opened = await openAuthenticated(
      {
        publicKey: fromHex(vector.recipientPublicKey),
        privateKey: fromHex(vector.recipientPrivateKey),
      },
      fromHex(vector.senderPublicKey),
      {
        encapsulatedKey: fromHex(vector.encapsulatedKey),
        ciphertext: fromHex(vector.ciphertext),
      },
      fromHex(vector.aad),
    );
    expect(hex(opened)).toBe(vector.plaintext);
  });

  it('opens the Android-generated cross-platform vector', async () => {
    const android = vector.androidProduced;
    const opened = await openAuthenticated(
      {
        publicKey: fromHex(android.recipientPublicKey),
        privateKey: fromHex(android.recipientPrivateKey),
      },
      fromHex(android.senderPublicKey),
      {
        encapsulatedKey: fromHex(android.encapsulatedKey),
        ciphertext: fromHex(android.ciphertext),
      },
      fromHex(android.aad),
    );

    expect(hex(opened)).toBe(android.plaintext);
  });

  it('rejects a substituted sender identity', async () => {
    const sender = await deriveKeyPair(senderIkm);
    const recipient = await deriveKeyPair(recipientIkm);
    const attacker = await deriveKeyPair(attackerIkm);
    const encrypted = await sealAuthenticated(
      recipient.publicKey,
      sender,
      plaintext,
      aad,
      ephemeralIkm,
    );

    await expect(
      openAuthenticated(recipient, attacker.publicKey, encrypted, aad),
    ).rejects.toThrow();
  });

  it('rejects modified ciphertext', async () => {
    const sender = await deriveKeyPair(senderIkm);
    const recipient = await deriveKeyPair(recipientIkm);
    const encrypted = await sealAuthenticated(
      recipient.publicKey,
      sender,
      plaintext,
      aad,
      ephemeralIkm,
    );
    encrypted.ciphertext[0] ^= 0x01;

    await expect(
      openAuthenticated(recipient, sender.publicKey, encrypted, aad),
    ).rejects.toThrow();
  });

  it('rejects modified routing metadata', async () => {
    const sender = await deriveKeyPair(senderIkm);
    const recipient = await deriveKeyPair(recipientIkm);
    const encrypted = await sealAuthenticated(
      recipient.publicKey,
      sender,
      plaintext,
      aad,
      ephemeralIkm,
    );

    await expect(
      openAuthenticated(recipient, sender.publicKey, encrypted, text.encode('modified-aad')),
    ).rejects.toThrow();
  });
});

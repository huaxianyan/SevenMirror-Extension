import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from '@hpke/core';

export const HPKE_SUITE = Object.freeze({
  mode: 'auth',
  kem: 'DHKEM_P256_HKDF_SHA256',
  kdf: 'HKDF_SHA256',
  aead: 'AES_128_GCM',
  protocolInfo: 'SyncNotifications-E2EE-v1',
});

export interface SerializedHpkeKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface AuthenticatedCiphertext {
  encapsulatedKey: Uint8Array;
  ciphertext: Uint8Array;
}

export type HpkeIdentity = CryptoKeyPair;

const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm(),
});

const protocolInfo = new TextEncoder().encode(HPKE_SUITE.protocolInfo);

export async function deriveKeyPair(ikm: Uint8Array): Promise<SerializedHpkeKeyPair> {
  const pair = await suite.kem.deriveKeyPair(ikm);
  return serializeKeyPair(pair);
}

export async function generateSerializableTestKeyPair(): Promise<SerializedHpkeKeyPair> {
  const pair = await suite.kem.generateKeyPair();
  return serializeKeyPair(pair);
}

export async function generateNonExtractableIdentity(): Promise<HpkeIdentity> {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
}

export async function serializeIdentityPublicKey(identity: HpkeIdentity): Promise<Uint8Array> {
  return new Uint8Array(await suite.kem.serializePublicKey(identity.publicKey));
}

export async function deriveIdentityKeyId(publicKey: Uint8Array): Promise<Uint8Array> {
  const digestInput = Uint8Array.from(publicKey).buffer;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', digestInput));
}

export async function sealAuthenticated(
  recipientPublicKey: Uint8Array,
  sender: SerializedHpkeKeyPair,
  plaintext: Uint8Array,
  aad: Uint8Array,
  deterministicEphemeralIkm?: Uint8Array,
): Promise<AuthenticatedCiphertext> {
  return sealWithIdentity(
    recipientPublicKey,
    await deserializeKeyPair(sender),
    plaintext,
    aad,
    deterministicEphemeralIkm,
  );
}

export async function openAuthenticated(
  recipient: SerializedHpkeKeyPair,
  senderPublicKey: Uint8Array,
  encrypted: AuthenticatedCiphertext,
  aad: Uint8Array,
): Promise<Uint8Array> {
  return openWithIdentity(
    await deserializeKeyPair(recipient),
    senderPublicKey,
    encrypted,
    aad,
  );
}

export async function sealWithIdentity(
  recipientPublicKey: Uint8Array,
  senderIdentity: HpkeIdentity,
  plaintext: Uint8Array,
  aad: Uint8Array,
  deterministicEphemeralIkm?: Uint8Array,
): Promise<AuthenticatedCiphertext> {
  const recipientKey = await suite.kem.deserializePublicKey(recipientPublicKey);
  const ephemeralKey = deterministicEphemeralIkm
    ? await suite.kem.deriveKeyPair(deterministicEphemeralIkm)
    : undefined;
  const context = await suite.createSenderContext({
    recipientPublicKey: recipientKey,
    senderKey: senderIdentity,
    info: protocolInfo,
    ekm: ephemeralKey,
  });
  return {
    encapsulatedKey: new Uint8Array(context.enc),
    ciphertext: new Uint8Array(await context.seal(plaintext, aad)),
  };
}

export async function openWithIdentity(
  recipientIdentity: HpkeIdentity,
  senderPublicKey: Uint8Array,
  encrypted: AuthenticatedCiphertext,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const senderKey = await suite.kem.deserializePublicKey(senderPublicKey);
  const context = await suite.createRecipientContext({
    recipientKey: recipientIdentity,
    senderPublicKey: senderKey,
    enc: encrypted.encapsulatedKey,
    info: protocolInfo,
  });
  return new Uint8Array(await context.open(encrypted.ciphertext, aad));
}

async function serializeKeyPair(pair: CryptoKeyPair): Promise<SerializedHpkeKeyPair> {
  return {
    publicKey: new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey)),
    privateKey: new Uint8Array(await suite.kem.serializePrivateKey(pair.privateKey)),
  };
}

async function deserializeKeyPair(serialized: SerializedHpkeKeyPair): Promise<CryptoKeyPair> {
  return {
    publicKey: await suite.kem.deserializePublicKey(serialized.publicKey),
    privateKey: await suite.kem.deserializePrivateKey(serialized.privateKey),
  };
}

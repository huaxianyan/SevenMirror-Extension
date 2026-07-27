import {
  openWithIdentity,
  sealWithIdentity,
  serializeIdentityPublicKey,
} from '../crypto/auth-hpke';
import { IndexedDbIdentityStore } from '../crypto/indexeddb-identity-store';

export interface E2eePersistenceResult {
  fingerprint: string;
  privateKeyExtractable: boolean;
  roundTripPassed: boolean;
  runAtUnixMs: number;
}

const store = new IndexedDbIdentityStore();
const text = new TextEncoder();

export async function runE2eePersistenceSpike(): Promise<E2eePersistenceResult> {
  const identity = await store.loadOrCreate();
  const publicKey = await serializeIdentityPublicKey(identity);
  const aad = text.encode('SPIKE-004|local-browser-runtime-test');
  const plaintext = crypto.getRandomValues(new Uint8Array(32));
  const encrypted = await sealWithIdentity(publicKey, identity, plaintext, aad);
  const opened = await openWithIdentity(identity, publicKey, encrypted, aad);
  const digestInput = new Uint8Array(publicKey.byteLength);
  digestInput.set(publicKey);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', digestInput));

  return {
    fingerprint: toHex(digest),
    privateKeyExtractable: identity.privateKey.extractable,
    roundTripPassed: arraysEqual(plaintext, opened),
    runAtUnixMs: Date.now(),
  };
}

function arraysEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

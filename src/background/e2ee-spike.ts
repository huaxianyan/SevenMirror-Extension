import {
  openWithIdentity,
  sealWithIdentity,
  serializeIdentityPublicKey,
} from '../crypto/auth-hpke';
import { IndexedDbIdentityStore } from '../crypto/indexeddb-identity-store';
import {
  IndexedDbReplayLedger,
  type PersistentReplayDecision,
} from '../crypto/indexeddb-replay-ledger';

export interface E2eePersistenceResult {
  fingerprint: string;
  privateKeyExtractable: boolean;
  roundTripPassed: boolean;
  replayDecision: PersistentReplayDecision;
  runAtUnixMs: number;
}

const store = new IndexedDbIdentityStore();
const replayLedger = new IndexedDbReplayLedger('runtime-spike');
const text = new TextEncoder();
const replayTestMessageId = Uint8Array.from([
  0x53, 0x50, 0x49, 0x4b, 0x45, 0x2d, 0x30, 0x30,
  0x34, 0x2d, 0x52, 0x45, 0x50, 0x4c, 0x41, 0x59,
]);

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
  const nowUnixMs = Date.now();
  const replayDecision = await replayLedger.checkAndRecord(
    digest,
    replayTestMessageId,
    nowUnixMs + 30 * 24 * 60 * 60 * 1000,
    nowUnixMs,
  );

  return {
    fingerprint: toHex(digest),
    privateKeyExtractable: identity.privateKey.extractable,
    roundTripPassed: arraysEqual(plaintext, opened),
    replayDecision,
    runAtUnixMs: nowUnixMs,
  };
}

function arraysEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

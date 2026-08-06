import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import envelopeVector from '../../protocol/test-vectors/encrypted-envelope-v1.json';
import hpkeVector from '../../protocol/test-vectors/hpke-auth-p256-aes128gcm.json';
import {
  generateNonExtractableIdentity,
  openAuthenticated,
  sealWithIdentity,
  serializeIdentityPublicKey,
} from '../crypto/auth-hpke';
import { EnvelopeRejectedError, openEnvelopeOnce } from '../crypto/envelope-receiver';
import { IndexedDbReplayLedger } from '../crypto/indexeddb-replay-ledger';
import {
  decodeEncryptedEnvelopeV1,
  encodeEncryptedEnvelopeV1,
} from './encrypted-envelope';
import { decodeEncryptedPayloadV1 } from './encrypted-payload';
import { encodeRoutingHeaderV1 } from './routing-header';

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);
const toHex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  const input = new Uint8Array(value.byteLength);
  input.set(value);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input));
}

describe('Encrypted Envelope v1', () => {
  it('matches and opens the canonical cross-platform frame', async () => {
    const encoded = encodeEncryptedEnvelopeV1({
      routingHeader: fromHex(envelopeVector.routingHeader),
      encapsulatedKey: fromHex(envelopeVector.encapsulatedKey),
      ciphertext: fromHex(envelopeVector.ciphertext),
    });
    expect(toHex(encoded)).toBe(envelopeVector.frameHex);

    const decoded = decodeEncryptedEnvelopeV1(encoded);
    expect(toHex(decoded.routingHeaderBytes)).toBe(envelopeVector.routingHeader);
    const plaintext = await openAuthenticated(
        {
          publicKey: fromHex(hpkeVector.recipientPublicKey),
          privateKey: fromHex(hpkeVector.recipientPrivateKey),
        },
        fromHex(hpkeVector.senderPublicKey),
        {
          encapsulatedKey: decoded.encapsulatedKey,
          ciphertext: decoded.ciphertext,
        },
        decoded.routingHeaderBytes,
      );
    expect(plaintext).toEqual(fromHex(envelopeVector.plaintext));
    const payload = decodeEncryptedPayloadV1(plaintext);
    expect(payload.body.case).toBe('actionInvoke');
  });

  it('rejects truncation, trailing bytes, bad magic, and invalid point encoding', () => {
    const valid = fromHex(envelopeVector.frameHex);
    const invalid = [
      valid.slice(0, -1),
      Uint8Array.from([...valid, 0]),
      valid.slice().fill(0, 0, 1),
      valid.slice().fill(3, 164, 165),
    ];
    for (const frame of invalid) {
      expect(() => decodeEncryptedEnvelopeV1(frame)).toThrow();
    }
  });

  it('authenticates before atomically consuming replay state', async () => {
    const now = 1_800_000_000_000;
    const sender = await generateNonExtractableIdentity();
    const recipient = await generateNonExtractableIdentity();
    const senderPublicKey = await serializeIdentityPublicKey(sender);
    const recipientPublicKey = await serializeIdentityPublicKey(recipient);
    const workspaceId = new Uint8Array(16).fill(1);
    const recipientDeviceId = new Uint8Array(16).fill(3);
    const routingHeader = encodeRoutingHeaderV1({
      workspaceId,
      senderDeviceId: new Uint8Array(16).fill(2),
      recipientDeviceId,
      senderKeyId: await sha256(senderPublicKey),
      recipientKeyId: await sha256(recipientPublicKey),
      messageId: new Uint8Array(16).fill(4),
      sequence: 1n,
      createdAtUnixMs: now,
      expiresAtUnixMs: now + 60_000,
    });
    const plaintext = new TextEncoder().encode('mark as read');
    const encrypted = await sealWithIdentity(
      recipientPublicKey,
      sender,
      plaintext,
      routingHeader,
    );
    const frame = encodeEncryptedEnvelopeV1({
      routingHeader,
      encapsulatedKey: encrypted.encapsulatedKey,
      ciphertext: encrypted.ciphertext,
    });
    const ledger = new IndexedDbReplayLedger(`envelope-${Date.now()}-${Math.random()}`);
    const context = {
      workspaceId,
      recipientDeviceId,
      recipientIdentity: recipient,
      pinnedSenderPublicKey: senderPublicKey,
    };

    try {
      const tampered = frame.slice();
      tampered[tampered.length - 1] ^= 1;
      await expect(openEnvelopeOnce(tampered, context, ledger, now)).rejects.toThrow();

      await expect(openEnvelopeOnce(frame, context, ledger, now)).resolves.toMatchObject({
        plaintext,
      });
      await expect(openEnvelopeOnce(frame, context, ledger, now)).rejects.toMatchObject({
        code: 'DUPLICATE',
      } satisfies Partial<EnvelopeRejectedError>);
    } finally {
      await ledger.clear();
    }
  });
});

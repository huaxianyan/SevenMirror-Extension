import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/encrypted-payload-v1.json';
import {
  createActionInvokePayload,
  decodeEncryptedPayloadV1,
  encodeEncryptedPayloadV1,
} from './encrypted-payload';

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));

const validPayload = () => createActionInvokePayload({
  notificationId: vector.notificationId,
  notificationRevision: BigInt(vector.notificationRevision),
  actionId: fromHex(vector.actionIdHex),
  idempotencyKey: fromHex(vector.idempotencyKeyHex),
  replyText: vector.replyText,
});

describe('Encrypted Payload v1', () => {
  it('matches the canonical cross-platform action.invoke vector', () => {
    const encoded = encodeEncryptedPayloadV1(validPayload());
    expect(encoded).toEqual(fromHex(vector.encodedHex));
    const decoded = decodeEncryptedPayloadV1(encoded);
    expect(decoded.body.case).toBe('actionInvoke');
    if (decoded.body.case === 'actionInvoke') {
      expect(decoded.body.value.notificationRevision).toBe(7n);
      expect(decoded.body.value.replyText).toBe('acknowledged');
    }
  });

  it('rejects duplicate, unknown and invalid semantic fields', () => {
    const encoded = fromHex(vector.encodedHex);
    expect(() => decodeEncryptedPayloadV1(Uint8Array.from([8, 1, ...encoded]))).toThrow();
    expect(() => decodeEncryptedPayloadV1(Uint8Array.from([...encoded, 0x78, 1]))).toThrow();

    const invalid = validPayload();
    if (invalid.body.case === 'actionInvoke') {
      invalid.body.value.notificationRevision = 0n;
    }
    expect(() => encodeEncryptedPayloadV1(invalid)).toThrow(/revision/i);
  });
});

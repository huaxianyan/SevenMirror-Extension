import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/encrypted-payload-v1.json';
import {
  createActionInvokePayload,
  createActionResultPayload,
  decodeEncryptedPayloadV1,
  encodeEncryptedPayloadV1,
} from './encrypted-payload';
import { ActionResultStatus } from './generated/notification/v1/payload_pb';

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

  it('round-trips a canonical action result', () => {
    const encoded = encodeEncryptedPayloadV1(createActionResultPayload({
      idempotencyKey: fromHex(vector.idempotencyKeyHex),
      status: ActionResultStatus.STALE_NOTIFICATION_VERSION,
      detail: 'revision changed',
    }));
    expect(encoded).toEqual(fromHex(vector.actionResultEncodedHex));
    const decoded = decodeEncryptedPayloadV1(encoded);
    expect(decoded.body.case).toBe('actionResult');
    if (decoded.body.case === 'actionResult') {
      expect(decoded.body.value.status).toBe(ActionResultStatus.STALE_NOTIFICATION_VERSION);
      expect(decoded.body.value.detail).toBe('revision changed');
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

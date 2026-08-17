import { describe, expect, it } from 'vitest';
import {
  createActionInvokePayload,
  encodeEncryptedPayloadV1,
} from '../protocol/encrypted-payload';
import { isAppOwnedSyntheticInvoke } from './synthetic-ack-hold';

function invoke(notificationId: string, idempotencyKey: Uint8Array): Uint8Array {
  return encodeEncryptedPayloadV1(createActionInvokePayload({
    notificationId,
    notificationRevision: 1n,
    actionId: new Uint8Array(16).fill(2),
    idempotencyKey,
  }));
}

describe('synthetic ACK hold boundary', () => {
  it('accepts only the app-owned synthetic invoke bound to the exact business key', () => {
    const key = new Uint8Array(16).fill(3);
    const appOwned = invoke(
      '0|dev.notificationmirroring.android|10001|null|12345',
      key,
    );
    expect(isAppOwnedSyntheticInvoke(appOwned, key)).toBe(true);
    expect(isAppOwnedSyntheticInvoke(appOwned, new Uint8Array(16).fill(4))).toBe(false);
    expect(isAppOwnedSyntheticInvoke(
      invoke('0|com.example.realapp|42|null|12345', key),
      key,
    )).toBe(false);
  });
});

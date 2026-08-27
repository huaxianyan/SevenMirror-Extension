import { describe, expect, it } from 'vitest';
import envelopeVector from '../../protocol/test-vectors/encrypted-envelope-v1.json';
import deliveryVector from '../../protocol/test-vectors/relay-delivery-v1.json';
import {
  decodeRelayServerMessage,
  encodeDurableSubmission,
  encodeRelayAcknowledgement,
  encodeRelayResume,
} from './relay-delivery';

describe('Relay Delivery v1 codec', () => {
  it('matches the server-owned wrapper vector and preserves the encrypted envelope', () => {
    const envelope = fromHex(envelopeVector.frameHex);
    expect(toHex(encodeDurableSubmission(envelope))).toBe(deliveryVector.durableSubmissionHex);
    expect(toHex(encodeRelayResume(0n))).toBe(deliveryVector.resumeZeroHex);
    expect(toHex(encodeRelayAcknowledgement(7n))).toBe(deliveryVector.acknowledgementHex);

    const delivery = decodeRelayServerMessage(arrayBuffer(fromHex(deliveryVector.deliveryHex)));
    expect(delivery).toEqual({ kind: 'delivery', deliveryId: 7n, envelope });
    expect(decodeRelayServerMessage(arrayBuffer(fromHex(deliveryVector.caughtUpHex)))).toEqual({
      kind: 'caught-up', highWater: 7n,
    });
    expect(decodeRelayServerMessage(arrayBuffer(fromHex(deliveryVector.resetRequiredHex)))).toEqual({
      kind: 'snapshot-required', highWater: 9n,
    });
    expect(decodeRelayServerMessage(arrayBuffer(envelope))).toEqual({
      kind: 'online-envelope', envelope,
    });
  });

  it('rejects malformed controls and zero delivery acknowledgements', () => {
    expect(() => encodeRelayAcknowledgement(0n)).toThrow('out of range');
    expect(() => decodeRelayServerMessage(arrayBuffer(fromHex('534e44310000000000000000'))))
      .toThrow('missing its encrypted envelope');
    expect(() => decodeRelayServerMessage(arrayBuffer(fromHex('534e52318000000000000000'))))
      .toThrow('out of range');
  });
});

function fromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error('Fixture hex is invalid');
  return Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

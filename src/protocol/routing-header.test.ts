import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/routing-header-v1.json';
import { deriveKeyPair, openAuthenticated, sealAuthenticated } from '../crypto/auth-hpke';
import {
  decodeRoutingHeaderV1,
  encodeRoutingHeaderV1,
  type RoutingHeaderV1,
} from './routing-header';

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);
const toHex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');

function vectorHeader(): RoutingHeaderV1 {
  return {
    workspaceId: fromHex(vector.workspaceId),
    senderDeviceId: fromHex(vector.senderDeviceId),
    recipientDeviceId: fromHex(vector.recipientDeviceId),
    senderKeyId: fromHex(vector.senderKeyId),
    recipientKeyId: fromHex(vector.recipientKeyId),
    messageId: fromHex(vector.messageId),
    sequence: BigInt(vector.sequence),
    createdAtUnixMs: vector.createdAtUnixMs,
    expiresAtUnixMs: vector.expiresAtUnixMs,
  };
}

describe('Routing Header v1', () => {
  it('matches the canonical 160-byte cross-platform vector', () => {
    const header = vectorHeader();
    const encoded = encodeRoutingHeaderV1(header);
    expect(encoded).toHaveLength(160);
    expect(toHex(encoded)).toBe(vector.headerHex);
    expect(decodeRoutingHeaderV1(encoded)).toEqual(header);
  });

  it('rejects malformed and semantically invalid headers', () => {
    const valid = fromHex(vector.headerHex);
    const mutations: Array<(value: Uint8Array) => Uint8Array> = [
      (value) => value.slice(0, -1),
      (value) => { value[0] ^= 0xff; return value; },
      (value) => { value[5] = 2; return value; },
      (value) => { value[7] = 1; return value; },
      (value) => { value.fill(0, 8, 24); return value; },
      (value) => { value.fill(0, 136, 144); return value; },
      (value) => { value.copyWithin(152, 144, 152); return value; },
    ];

    for (const mutate of mutations) {
      expect(() => decodeRoutingHeaderV1(mutate(valid.slice()))).toThrow();
    }
  });

  it('authenticates the original header bytes as HPKE AAD', async () => {
    const sender = await deriveKeyPair(new Uint8Array(32).fill(1));
    const recipient = await deriveKeyPair(new Uint8Array(32).fill(2));
    const aad = encodeRoutingHeaderV1(vectorHeader());
    const plaintext = new TextEncoder().encode('encrypted action.invoke test payload');
    const encrypted = await sealAuthenticated(
      recipient.publicKey,
      sender,
      plaintext,
      aad,
      new Uint8Array(32).fill(3),
    );

    await expect(
      openAuthenticated(recipient, sender.publicKey, encrypted, aad),
    ).resolves.toEqual(plaintext);

    const modifiedHeader = aad.slice();
    modifiedHeader[40] ^= 1; // recipient device ID
    await expect(
      openAuthenticated(recipient, sender.publicKey, encrypted, modifiedHeader),
    ).rejects.toThrow();
  });
});

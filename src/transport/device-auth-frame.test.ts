import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  decodeDeviceAuthFrameV1,
  encodeDeviceAuthFrameV1,
  encodeTransportAuthenticationSuccessV1,
  isTransportAuthenticationSuccessV1,
} from './device-auth-frame';

interface Vector {
  workspaceId: string;
  deviceId: string;
  authToken: string;
  frameHex: string;
  successAckHex: string;
}

const vector = JSON.parse(readFileSync(
  new URL('../../protocol/test-vectors/device-auth-frame-v1.json', import.meta.url),
  'utf8',
)) as Vector;

describe('Device Auth Frame v1', () => {
  it('matches the canonical Go vector', () => {
    const encoded = encodeDeviceAuthFrameV1({
      workspaceId: fromHex(vector.workspaceId),
      deviceId: fromHex(vector.deviceId),
      authToken: fromHex(vector.authToken),
    });
    expect(toHex(encoded)).toBe(vector.frameHex);
    expect(toHex(encodeTransportAuthenticationSuccessV1())).toBe(vector.successAckHex);
    expect(isTransportAuthenticationSuccessV1(fromHex(vector.successAckHex))).toBe(true);
    expect(decodeDeviceAuthFrameV1(encoded)).toEqual({
      workspaceId: fromHex(vector.workspaceId),
      deviceId: fromHex(vector.deviceId),
      authToken: fromHex(vector.authToken),
    });
  });

  it('rejects malformed frames and identifiers', () => {
    expect(() => decodeDeviceAuthFrameV1(new Uint8Array(67))).toThrow('68 bytes');
    const badMagic = fromHex(vector.frameHex);
    badMagic[0] ^= 1;
    expect(() => decodeDeviceAuthFrameV1(badMagic)).toThrow('magic/version');
    expect(() => encodeDeviceAuthFrameV1({
      workspaceId: new Uint8Array(16),
      deviceId: fromHex(vector.deviceId),
      authToken: fromHex(vector.authToken),
    })).toThrow('workspaceId');
  });
});

function fromHex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

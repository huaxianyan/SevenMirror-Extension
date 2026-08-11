import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  decodeTrustApprovalV1,
  decodeTrustOfferV1,
  decodeTrustQr,
  encodeTrustApprovalV1,
  encodeTrustOfferV1,
  encodeTrustQr,
  trustSafetyCode,
  validateTrustPair,
  validateTrustRecordActive,
} from './trusted-device-pairing';

interface Vector {
  offer: { encoded: string; qr: string; createdAtUnixMs: number; expiresAtUnixMs: number };
  approval: { encoded: string; qr: string };
  safetyCode: string;
}

const vector = JSON.parse(readFileSync(
  new URL('../../protocol/test-vectors/trusted-device-pairing-v1.json', import.meta.url),
  'utf8',
)) as Vector;
const offer = hex(vector.offer.encoded);
const approval = hex(vector.approval.encoded);

describe('Trusted Device Pairing v1', () => {
  it('matches canonical offer, approval, QR, and safety-code vectors', async () => {
    expect(encodeTrustOfferV1(decodeTrustOfferV1(offer))).toEqual(offer);
    expect(encodeTrustApprovalV1(decodeTrustApprovalV1(approval))).toEqual(approval);
    expect(encodeTrustQr(offer)).toBe(vector.offer.qr);
    expect(encodeTrustQr(approval)).toBe(vector.approval.qr);
    expect(decodeTrustQr(vector.offer.qr)).toEqual(offer);
    expect(await trustSafetyCode(offer, approval)).toBe(vector.safetyCode);
  });

  it('rejects mutation, wrong binding, invalid points, and non-canonical QR text', async () => {
    const mutatedOffer = offer.slice();
    mutatedOffer[10] ^= 1;
    await expect(validateTrustPair(mutatedOffer, approval)).rejects.toThrow('exact trust offer');
    const wrongApproval = approval.slice();
    wrongApproval[4] ^= 1;
    await expect(validateTrustPair(offer, wrongApproval)).rejects.toThrow('exact trust offer');
    const invalidPoint = offer.slice();
    invalidPoint.fill(0, 36, 101);
    invalidPoint[36] = 4;
    expect(() => decodeTrustOfferV1(invalidPoint)).toThrow('valid P-256 point');
    expect(() => decodeTrustQr(`${vector.offer.qr}=`)).toThrow();
    expect(() => decodeTrustQr(` ${vector.offer.qr}`)).toThrow();
  });

  it('checks active time without extending record expiry', () => {
    validateTrustRecordActive(
      vector.offer.createdAtUnixMs,
      vector.offer.expiresAtUnixMs,
      vector.offer.createdAtUnixMs,
    );
    expect(() => validateTrustRecordActive(
      vector.offer.createdAtUnixMs,
      vector.offer.expiresAtUnixMs,
      vector.offer.expiresAtUnixMs,
    )).toThrow('expired');
  });
});

function hex(value: string): Uint8Array {
  return Uint8Array.from({ length: value.length / 2 }, (_, index) =>
    Number.parseInt(value.slice(index * 2, index * 2 + 2), 16));
}

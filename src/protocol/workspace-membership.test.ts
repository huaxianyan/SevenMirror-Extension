import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/workspace-membership-v1.json';
import {
  createPendingIdentityProof,
  decodeIdentityPossessionChallenge,
  decodePendingIdentityProof,
  decodeSignedDeviceCertificate,
  decodeSignedWorkspaceRoster,
  encodePendingIdentityProof,
  openIdentityPossessionChallenge,
  verifySignedDeviceCertificate,
  verifySignedWorkspaceRoster,
} from './workspace-membership';

const fromHex = (value: string): Uint8Array => Uint8Array.from(value.match(/../g) ?? [], (item) => Number.parseInt(item, 16));

describe('Workspace Membership v1', () => {
  it('opens the Base HPKE challenge and matches the canonical proof', async () => {
    const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
    const privateKey = await suite.kem.deserializePrivateKey(fromHex(vector.identityPrivateScalarHex));
    const binding = { workspaceId: fromHex(vector.workspaceIdHex), deviceId: fromHex(vector.deviceIdHex), identityKeyId: fromHex(vector.identityKeyIdHex) };
    const challenge = await openIdentityPossessionChallenge(privateKey, binding, fromHex(vector.possessionHpkeEncapsulatedKeyHex), fromHex(vector.possessionHpkeCiphertextHex));
    expect(challenge).toEqual(decodeIdentityPossessionChallenge(fromHex(vector.challengeEncodedHex)));
    const proof = decodePendingIdentityProof(fromHex(vector.proofEncodedHex));
    expect(await createPendingIdentityProof(fromHex(vector.challengeEncodedHex)))
      .toEqual(fromHex(vector.proofEncodedHex));
    expect(encodePendingIdentityProof(proof)).toEqual(fromHex(vector.proofEncodedHex));
    expect(proof.challengeSecret).toEqual(challenge.challengeSecret);
  });

  it('verifies the canonical certificate and linked roster signatures', async () => {
    const authority = fromHex(vector.authorityPublicKeyHex);
    const certificate = decodeSignedDeviceCertificate(fromHex(vector.certificateEncodedHex));
    await expect(verifySignedDeviceCertificate(certificate, authority)).resolves.toBeUndefined();
    expect(certificate.certificateId).toEqual(fromHex(vector.certificateIdHex));

    const initial = decodeSignedWorkspaceRoster(fromHex(vector.initialRosterEncodedHex));
    const revoked = decodeSignedWorkspaceRoster(fromHex(vector.revokedRosterEncodedHex));
    await expect(verifySignedWorkspaceRoster(initial, authority)).resolves.toBeUndefined();
    await expect(verifySignedWorkspaceRoster(revoked, authority)).resolves.toBeUndefined();
    expect(revoked.roster?.previousRosterDigest).toEqual(initial.rosterDigest);

    certificate.authoritySignature[0] ^= 1;
    await expect(verifySignedDeviceCertificate(certificate, authority)).rejects.toThrow(/signature/i);
  });
});

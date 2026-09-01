import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import vector from '../../protocol/test-vectors/workspace-membership-v1.json';
import {
  createPendingIdentityProof,
  decodeIdentityPossessionChallenge,
  decodePendingIdentityProof,
  decodeSignedAuthorityKeyTransition,
  decodeSignedDeviceCertificate,
  decodeSignedWorkspaceRoster,
  encodePendingIdentityProof,
  openIdentityPossessionChallenge,
  verifyDisplayNameCertificateTransition,
  verifyRosterCertificateTransitions,
  verifySignedAuthorityKeyTransition,
  verifySignedDeviceCertificate,
  verifySignedWorkspaceRoster,
} from './workspace-membership';

const fromHex = (value: string): Uint8Array => Uint8Array.from(value.match(/../g) ?? [], (item) => Number.parseInt(item, 16));

describe('Workspace Membership v1', () => {
  afterEach(() => vi.restoreAllMocks());

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

    const renamedCertificate = decodeSignedDeviceCertificate(fromHex(vector.renamedCertificateEncodedHex));
    const renameRoster = decodeSignedWorkspaceRoster(fromHex(vector.renameRosterEncodedHex));
    await expect(verifySignedDeviceCertificate(renamedCertificate, authority)).resolves.toBeUndefined();
    await expect(verifySignedWorkspaceRoster(renameRoster, authority)).resolves.toBeUndefined();
    expect(renameRoster.rosterDigest).toEqual(fromHex(vector.renameRosterDigestHex));
    expect(renameRoster.roster?.certificateTransitions).toHaveLength(1);
    expect(() => verifyRosterCertificateTransitions(initial, renameRoster)).not.toThrow();
    expect(() => verifyDisplayNameCertificateTransition(
      certificate,
      renamedCertificate,
      renameRoster.roster!.certificateTransitions[0],
    )).not.toThrow();
    renamedCertificate.certificate!.identityPublicKey[1] ^= 1;
    expect(() => verifyDisplayNameCertificateTransition(
      certificate,
      renamedCertificate,
      renameRoster.roster!.certificateTransitions[0],
    )).toThrow('binding is invalid');

    const transition = decodeSignedAuthorityKeyTransition(fromHex(vector.authorityTransitionEncodedHex));
    await expect(verifySignedAuthorityKeyTransition(transition)).resolves.toBeUndefined();
    expect(transition.transitionDigest).toEqual(fromHex(vector.authorityTransitionDigestHex));
    const activation = decodeSignedWorkspaceRoster(fromHex(vector.authorityActivationRosterEncodedHex));
    await expect(verifySignedWorkspaceRoster(activation, fromHex(vector.newAuthorityPublicKeyHex))).resolves.toBeUndefined();
    expect(activation.roster?.previousRosterDigest).toEqual(initial.rosterDigest);

    certificate.authoritySignature[0] ^= 1;
    await expect(verifySignedDeviceCertificate(certificate, authority)).rejects.toThrow(/signature/i);
  });

  it('uses strict Ed25519 verification when WebCrypto does not support the algorithm', async () => {
    const nativeImportKey = crypto.subtle.importKey.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, 'importKey').mockImplementation(
      (format, keyData, algorithm, extractable, keyUsages) => {
        if (typeof algorithm === 'object' && algorithm.name === 'Ed25519') {
          return Promise.reject(new DOMException('Algorithm: Unrecognized name', 'NotSupportedError'));
        }
        return nativeImportKey(format, keyData, algorithm, extractable, keyUsages);
      },
    );

    const authority = fromHex(vector.authorityPublicKeyHex);
    const certificate = decodeSignedDeviceCertificate(fromHex(vector.certificateEncodedHex));
    const roster = decodeSignedWorkspaceRoster(fromHex(vector.initialRosterEncodedHex));
    await expect(verifySignedDeviceCertificate(certificate, authority)).resolves.toBeUndefined();
    await expect(verifySignedWorkspaceRoster(roster, authority)).resolves.toBeUndefined();

    certificate.authoritySignature[0] ^= 1;
    await expect(verifySignedDeviceCertificate(certificate, authority)).rejects.toThrow(/signature/i);
  });
});

import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { ed25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import vector from '../protocol/test-vectors/workspace-membership-v1.json';
import {
  DeviceCertificateSchema,
  DeviceRole,
  DeviceType,
  SignedDeviceCertificateSchema,
  SignedWorkspaceRosterSchema,
  WorkspaceRosterSchema,
} from '../src/protocol/generated/membership/v1/membership_pb';

const textEncoder = new TextEncoder();
const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g)!.map((byte) => Number.parseInt(byte, 16)));
const toHex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
const concat = (...parts: Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
};
const domain = (value: string): Uint8Array => textEncoder.encode(`${value}\0`);
const authoritySeed = fromHex(vector.authoritySeedHex);
const workspaceId = fromHex(vector.workspaceIdHex);
const androidDeviceId = fromHex('33333333333333333333333333333333');
const androidScalar = fromHex('0000000000000000000000000000000000000000000000000000000000000003');
const androidPublicKey = p256.getPublicKey(androidScalar, false);
const androidKeyId = sha256(androidPublicKey);

function signCertificate(certificate: ReturnType<typeof create<typeof DeviceCertificateSchema>>) {
  const body = toBinary(DeviceCertificateSchema, certificate);
  return create(SignedDeviceCertificateSchema, {
    certificate,
    certificateId: sha256(concat(
      domain('SyncNotifications-membership-device-certificate-id-v1'),
      body,
    )),
    authoritySignature: ed25519.sign(concat(
      domain('SyncNotifications-membership-device-certificate-signature-v1'),
      body,
    ), authoritySeed),
  });
}

const androidCertificate = signCertificate(create(DeviceCertificateSchema, {
  protocolVersion: 1,
  workspaceId,
  deviceId: androidDeviceId,
  deviceType: DeviceType.ANDROID,
  displayName: 'Canary Android',
  roles: [DeviceRole.SEND_NOTIFICATIONS],
  identityPublicKey: androidPublicKey,
  identityKeyId: androidKeyId,
  issuedAtUnixMs: 1710000000000n,
  expiresAtUnixMs: 0n,
  membershipEpoch: 1n,
}));
const vectorLocal = fromBinary(
  SignedDeviceCertificateSchema,
  fromHex(vector.certificateEncodedHex),
).certificate!;
// The canonical protocol vector deliberately starts in 2027. This canary certificate
// keeps the same public test identity but is valid during release-gate execution.
const localCertificate = signCertificate(create(DeviceCertificateSchema, {
  ...vectorLocal,
  issuedAtUnixMs: 1710000000000n,
  expiresAtUnixMs: 0n,
}));
const roster = create(WorkspaceRosterSchema, {
  protocolVersion: 1,
  workspaceId,
  rosterEpoch: 1n,
  previousRosterDigest: new Uint8Array(32),
  activeCertificates: [localCertificate, androidCertificate],
  revocations: [],
});
const rosterBody = toBinary(WorkspaceRosterSchema, roster);
const signedRoster = create(SignedWorkspaceRosterSchema, {
  roster,
  rosterDigest: sha256(concat(
    domain('SyncNotifications-membership-workspace-roster-digest-v1'),
    rosterBody,
  )),
  authoritySignature: ed25519.sign(concat(
    domain('SyncNotifications-membership-workspace-roster-signature-v1'),
    rosterBody,
  ), authoritySeed),
});

console.log(JSON.stringify({
  description: 'Public deterministic fixture extending workspace-membership-v1 for the interaction Worker canary. No production secrets.',
  localSignedCertificateHex: toHex(toBinary(SignedDeviceCertificateSchema, localCertificate)),
  androidDeviceIdHex: toHex(androidDeviceId),
  androidIdentityPublicKeyHex: toHex(androidPublicKey),
  androidIdentityKeyIdHex: toHex(androidKeyId),
  rosterDigestHex: toHex(signedRoster.rosterDigest),
  signedRosterHex: toHex(toBinary(SignedWorkspaceRosterSchema, signedRoster)),
}, null, 2));

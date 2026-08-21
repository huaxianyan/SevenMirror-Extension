import { create, toBinary } from '@bufbuild/protobuf';
import { expect, it } from 'vitest';
import {
  DeviceCertificateSchema,
  DeviceRole,
  DeviceType,
  SignedDeviceCertificateSchema,
  SignedWorkspaceRosterSchema,
  WorkspaceRosterSchema,
} from '../protocol/generated/membership/v1/membership_pb';
import type { WorkspaceMembershipState } from './indexeddb-workspace-membership-store';
import {
  authorizeBusinessSender,
  WorkspaceBusinessSenderResolver,
} from './workspace-business-sender-resolver';

const now = 1_800_000_000_000;

it('uses certified sender and local roles to authorize each Chrome business capability', () => {
  const sender = certificate(DeviceType.ANDROID, [DeviceRole.SEND_NOTIFICATIONS], 2);
  const receiveOnly = certificate(DeviceType.CHROME, [DeviceRole.RECEIVE_NOTIFICATIONS], 3);
  const invokeOnly = certificate(DeviceType.CHROME, [DeviceRole.INVOKE_NOTIFICATION_ACTIONS], 4);

  expect(authorizeBusinessSender(receiveOnly, sender, now)).toMatchObject({
    mayReceiveNotifications: true,
    mayReceiveActionResults: false,
  });
  expect(authorizeBusinessSender(invokeOnly, sender, now)).toMatchObject({
    mayReceiveNotifications: false,
    mayReceiveActionResults: true,
  });
  expect(authorizeBusinessSender(
    receiveOnly,
    certificate(DeviceType.ANDROID, [DeviceRole.MANAGE_DEVICES], 5),
    now,
  )).toBeUndefined();
});

it('resolves only the exact active sender identity from the durable roster', async () => {
  const local = signedCertificate(DeviceType.CHROME, [DeviceRole.RECEIVE_NOTIFICATIONS], 3);
  const sender = signedCertificate(DeviceType.ANDROID, [DeviceRole.SEND_NOTIFICATIONS], 2);
  const signedRoster = toBinary(SignedWorkspaceRosterSchema, create(SignedWorkspaceRosterSchema, {
    roster: create(WorkspaceRosterSchema, {
      protocolVersion: 1,
      workspaceId: new Uint8Array(16).fill(1),
      rosterEpoch: 1n,
      previousRosterDigest: new Uint8Array(32),
      activeCertificates: [sender, local],
    }),
    rosterDigest: new Uint8Array(32).fill(8),
    authoritySignature: new Uint8Array(64).fill(9),
  }));
  const state: WorkspaceMembershipState = {
    workspaceId: new Uint8Array(16).fill(1),
    deviceId: local.certificate!.deviceId,
    authorityPublicKey: new Uint8Array(32).fill(7),
    signedCertificate: toBinary(SignedDeviceCertificateSchema, local),
    rosterEpoch: 1n,
    rosterDigest: new Uint8Array(32).fill(8),
    signedRoster,
    localDeviceActive: true,
  };
  const memberships = { load: async () => state };
  const resolver = new WorkspaceBusinessSenderResolver(memberships);

  await expect(resolver.resolve(
    state.workspaceId,
    state.deviceId,
    sender.certificate!.deviceId,
    sender.certificate!.identityKeyId,
    now,
  )).resolves.toMatchObject({ mayReceiveNotifications: true });
  await expect(resolver.resolve(
    state.workspaceId,
    state.deviceId,
    sender.certificate!.deviceId,
    new Uint8Array(32).fill(6),
    now,
  )).resolves.toBeUndefined();
});

function signedCertificate(
  deviceType: DeviceType,
  roles: DeviceRole[],
  marker: number,
) {
  return create(SignedDeviceCertificateSchema, {
    certificate: certificate(deviceType, roles, marker),
    certificateId: new Uint8Array(32).fill(marker),
    authoritySignature: new Uint8Array(64).fill(marker),
  });
}

function certificate(
  deviceType: DeviceType,
  roles: DeviceRole[],
  marker: number,
) {
  return create(DeviceCertificateSchema, {
    protocolVersion: 1,
    workspaceId: new Uint8Array(16).fill(1),
    deviceId: new Uint8Array(16).fill(marker),
    deviceType,
    displayName: `Device ${marker}`,
    roles,
    identityPublicKey: new Uint8Array([4, ...new Uint8Array(64).fill(marker)]),
    identityKeyId: new Uint8Array(32).fill(marker),
    issuedAtUnixMs: BigInt(now - 1_000),
    expiresAtUnixMs: 0n,
    membershipEpoch: 1n,
  });
}

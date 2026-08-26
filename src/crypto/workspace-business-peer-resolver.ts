import { DeviceRole, DeviceType, type DeviceCertificate } from '../protocol/generated/membership/v1/membership_pb';
import {
  decodeSignedDeviceCertificate,
  decodeSignedWorkspaceRoster,
  encodeSignedDeviceCertificate,
} from '../protocol/workspace-membership';
import type { WorkspaceMembershipState } from './indexeddb-workspace-membership-store';

export interface WorkspaceMembershipReader {
  load(workspaceId: Uint8Array, deviceId: Uint8Array): Promise<WorkspaceMembershipState | undefined>;
}

export interface BusinessSenderAuthorization {
  senderPublicKey: Uint8Array;
  mayReceiveNotifications: boolean;
  mayReceiveActionResults: boolean;
}

export interface BusinessSenderResolver {
  resolve(
    workspaceId: Uint8Array,
    localDeviceId: Uint8Array,
    senderDeviceId: Uint8Array,
    senderKeyId: Uint8Array,
    nowUnixMs: number,
  ): Promise<BusinessSenderAuthorization | undefined>;
}

export interface BusinessActionRecipientResolver {
  resolveActionRecipient(
    workspaceId: Uint8Array,
    localDeviceId: Uint8Array,
    recipientDeviceId: Uint8Array,
    recipientKeyId: Uint8Array,
    nowUnixMs: number,
  ): Promise<Uint8Array | undefined>;
  listActionRecipients(
    workspaceId: Uint8Array,
    localDeviceId: Uint8Array,
    nowUnixMs: number,
  ): Promise<Array<{ deviceId: Uint8Array; keyId: Uint8Array }>>;
}

/** Resolves business peers only from the latest authority-verified durable roster. */
export class WorkspaceBusinessPeerResolver implements BusinessSenderResolver, BusinessActionRecipientResolver {
  constructor(private readonly memberships: WorkspaceMembershipReader) {}

  async resolve(
    workspaceId: Uint8Array,
    localDeviceId: Uint8Array,
    senderDeviceId: Uint8Array,
    senderKeyId: Uint8Array,
    nowUnixMs: number,
  ): Promise<BusinessSenderAuthorization | undefined> {
    if (!Number.isSafeInteger(nowUnixMs) || nowUnixMs < 1) throw new Error('Current time is invalid');
    const state = await this.memberships.load(workspaceId, localDeviceId);
    if (state === undefined || !state.localDeviceActive ||
        state.signedCertificate === undefined || state.signedRoster === undefined) return undefined;
    const localSigned = decodeSignedDeviceCertificate(state.signedCertificate);
    const roster = decodeSignedWorkspaceRoster(state.signedRoster).roster!;
    const local = roster.activeCertificates.find((candidate) =>
      equal(candidate.certificate!.deviceId, localDeviceId) &&
      equal(encodeSignedDeviceCertificate(candidate), state.signedCertificate!));
    const sender = roster.activeCertificates.find((candidate) =>
      equal(candidate.certificate!.deviceId, senderDeviceId) &&
      equal(candidate.certificate!.identityKeyId, senderKeyId));
    if (local?.certificate === undefined || sender?.certificate === undefined) return undefined;
    return authorizeBusinessSender(local.certificate, sender.certificate, nowUnixMs);
  }

  async resolveActionRecipient(
    workspaceId: Uint8Array,
    localDeviceId: Uint8Array,
    recipientDeviceId: Uint8Array,
    recipientKeyId: Uint8Array,
    nowUnixMs: number,
  ): Promise<Uint8Array | undefined> {
    const recipients = await this.actionRecipients(workspaceId, localDeviceId, nowUnixMs);
    return recipients.find((candidate) =>
      equal(candidate.deviceId, recipientDeviceId) && equal(candidate.keyId, recipientKeyId))
      ?.publicKey.slice();
  }

  async listActionRecipients(
    workspaceId: Uint8Array,
    localDeviceId: Uint8Array,
    nowUnixMs: number,
  ): Promise<Array<{ deviceId: Uint8Array; keyId: Uint8Array }>> {
    return (await this.actionRecipients(workspaceId, localDeviceId, nowUnixMs)).map((recipient) => ({
      deviceId: recipient.deviceId.slice(),
      keyId: recipient.keyId.slice(),
    }));
  }

  async resolveNotificationSourceName(
    workspaceId: Uint8Array,
    localDeviceId: Uint8Array,
    sourceDeviceId: Uint8Array,
    nowUnixMs: number,
  ): Promise<string | undefined> {
    if (!Number.isSafeInteger(nowUnixMs) || nowUnixMs < 1) throw new Error('Current time is invalid');
    const state = await this.memberships.load(workspaceId, localDeviceId);
    if (state === undefined || !state.localDeviceActive ||
        state.signedCertificate === undefined || state.signedRoster === undefined) return undefined;
    const roster = decodeSignedWorkspaceRoster(state.signedRoster).roster!;
    const local = roster.activeCertificates.find((candidate) =>
      equal(candidate.certificate!.deviceId, localDeviceId) &&
      equal(encodeSignedDeviceCertificate(candidate), state.signedCertificate!))?.certificate;
    const source = roster.activeCertificates.find((candidate) =>
      equal(candidate.certificate!.deviceId, sourceDeviceId))?.certificate;
    if (local === undefined || source === undefined ||
        authorizeBusinessSender(local, source, nowUnixMs)?.mayReceiveNotifications !== true) return undefined;
    return source.displayName;
  }

  private async actionRecipients(
    workspaceId: Uint8Array,
    localDeviceId: Uint8Array,
    nowUnixMs: number,
  ): Promise<Array<{
    deviceId: Uint8Array;
    keyId: Uint8Array;
    publicKey: Uint8Array;
  }>> {
    if (!Number.isSafeInteger(nowUnixMs) || nowUnixMs < 1) throw new Error('Current time is invalid');
    const state = await this.memberships.load(workspaceId, localDeviceId);
    if (state === undefined || !state.localDeviceActive ||
        state.signedCertificate === undefined || state.signedRoster === undefined) return [];
    const roster = decodeSignedWorkspaceRoster(state.signedRoster).roster!;
    const local = roster.activeCertificates.find((candidate) =>
      equal(candidate.certificate!.deviceId, localDeviceId) &&
      equal(encodeSignedDeviceCertificate(candidate), state.signedCertificate!))?.certificate;
    if (local === undefined || local.deviceType !== DeviceType.CHROME ||
        !local.roles.includes(DeviceRole.INVOKE_NOTIFICATION_ACTIONS) || !current(local, nowUnixMs)) return [];
    return roster.activeCertificates.flatMap((candidate) => {
      const certificate = candidate.certificate!;
      return authorizeBusinessActionRecipient(local, certificate, nowUnixMs)
        ? [{
            deviceId: certificate.deviceId.slice(),
            keyId: certificate.identityKeyId.slice(),
            publicKey: certificate.identityPublicKey.slice(),
          }]
        : [];
    });
  }
}

export function authorizeBusinessActionRecipient(
  local: DeviceCertificate,
  recipient: DeviceCertificate,
  nowUnixMs: number,
): boolean {
  return local.deviceType === DeviceType.CHROME &&
    local.roles.includes(DeviceRole.INVOKE_NOTIFICATION_ACTIONS) && current(local, nowUnixMs) &&
    recipient.deviceType === DeviceType.ANDROID &&
    recipient.roles.includes(DeviceRole.SEND_NOTIFICATIONS) && current(recipient, nowUnixMs);
}

export function authorizeBusinessSender(
  local: DeviceCertificate,
  sender: DeviceCertificate,
  nowUnixMs: number,
): BusinessSenderAuthorization | undefined {
  if (local.deviceType !== DeviceType.CHROME || sender.deviceType !== DeviceType.ANDROID ||
      !current(local, nowUnixMs) || !current(sender, nowUnixMs) ||
      !sender.roles.includes(DeviceRole.SEND_NOTIFICATIONS)) return undefined;
  const mayReceiveNotifications = local.roles.includes(DeviceRole.RECEIVE_NOTIFICATIONS);
  const mayReceiveActionResults = local.roles.includes(DeviceRole.INVOKE_NOTIFICATION_ACTIONS);
  if (!mayReceiveNotifications && !mayReceiveActionResults) return undefined;
  return {
    senderPublicKey: sender.identityPublicKey.slice(),
    mayReceiveNotifications,
    mayReceiveActionResults,
  };
}

function current(certificate: DeviceCertificate, nowUnixMs: number): boolean {
  const now = BigInt(nowUnixMs);
  return certificate.issuedAtUnixMs <= now &&
    (certificate.expiresAtUnixMs === 0n || certificate.expiresAtUnixMs > now);
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

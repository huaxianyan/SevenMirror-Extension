import type { HpkeIdentity } from '../crypto/auth-hpke';
import {
  createAuthenticatedEnvelopeFromCanonicalPayload,
  type ActionEnvelopeContext,
} from '../crypto/action-envelope-sender';
import type { IndexedDbOutboundSequenceStore } from '../crypto/indexeddb-outbound-sequence-store';
import type { WorkspaceBusinessPeerResolver } from '../crypto/workspace-business-peer-resolver';
import {
  createNotificationSnapshotRequestPayload,
  encodeEncryptedPayloadV1,
} from '../protocol/encrypted-payload';
import type { IndexedDbRelayDeliveryCursorStore } from './indexeddb-relay-delivery-cursor-store';
import type { StoredTransportCredential } from './indexeddb-transport-credential-store';

interface CredentialReader {
  load(): Promise<StoredTransportCredential | undefined>;
}

interface IdentityReader {
  loadExisting(): Promise<HpkeIdentity | undefined>;
}

export class SnapshotRecoveryCoordinator {
  constructor(
    private readonly credentials: CredentialReader,
    private readonly identities: IdentityReader,
    private readonly peers: WorkspaceBusinessPeerResolver,
    private readonly sequences: IndexedDbOutboundSequenceStore,
    private readonly cursors: IndexedDbRelayDeliveryCursorStore,
    private readonly sendDurable: (frame: Uint8Array) => boolean,
    private readonly acceptReset: (requestId: Uint8Array) => Promise<boolean>,
    private readonly now: () => number = Date.now,
    private readonly random: (target: Uint8Array) => void = (target) => crypto.getRandomValues(target),
  ) {}

  async begin(highWater: bigint): Promise<void> {
    await this.withCredential(async (credential) => {
      let state = await this.cursors.load(credential.workspaceId, credential.deviceId);
      if (state.snapshotRequiredHighWater !== highWater) {
        throw new Error('Relay reset changed before snapshot recovery started');
      }
      if (state.recovery === undefined) {
        const sources = await this.peers.listNotificationSources(
          credential.workspaceId,
          credential.deviceId,
          this.now(),
        );
        state = await this.cursors.beginSnapshotRecovery(
          credential.workspaceId,
          credential.deviceId,
          highWater,
          this.nextIdentifier(),
          sources.map((source) => source.deviceId),
        );
      }
      if (state.recovery!.completedSourceIds.length ===
          state.recovery!.expectedSourceIds.length) {
        await this.acceptReset(state.recovery!.requestId);
        return;
      }
      await this.sendIncompleteRequests(credential, state.recovery!);
    });
  }

  async retry(): Promise<void> {
    await this.withCredential(async (credential) => {
      const state = await this.cursors.load(credential.workspaceId, credential.deviceId);
      if (state.recovery !== undefined) {
        if (state.recovery.completedSourceIds.length === state.recovery.expectedSourceIds.length) {
          await this.acceptReset(state.recovery.requestId);
        } else {
          await this.sendIncompleteRequests(credential, state.recovery);
        }
      }
    });
  }

  async isActive(): Promise<boolean> {
    let active = false;
    await this.withCredential(async (credential) => {
      active = (await this.cursors.load(credential.workspaceId, credential.deviceId)).recovery !== undefined;
    });
    return active;
  }

  async observeManifest(sourceDeviceId: Uint8Array, requestId: Uint8Array): Promise<void> {
    await this.withCredential(async (credential) => {
      const state = await this.cursors.load(credential.workspaceId, credential.deviceId);
      if (state.recovery === undefined || !equal(state.recovery.requestId, requestId)) return;
      const updated = await this.cursors.recordSnapshotRecoverySource(
        credential.workspaceId,
        credential.deviceId,
        requestId,
        sourceDeviceId,
      );
      if (updated.recovery !== undefined &&
          updated.recovery.completedSourceIds.length === updated.recovery.expectedSourceIds.length) {
        await this.acceptReset(requestId);
      }
    });
  }

  private async sendIncompleteRequests(
    credential: StoredTransportCredential,
    recovery: {
      requestId: Uint8Array;
      expectedSourceIds: Uint8Array[];
      completedSourceIds: Uint8Array[];
    },
  ): Promise<void> {
    const identity = await this.identities.loadExisting();
    if (identity === undefined) throw new Error('Snapshot recovery identity is unavailable');
    const sources = await this.peers.listNotificationSources(
      credential.workspaceId,
      credential.deviceId,
      this.now(),
    );
    const completed = new Set(recovery.completedSourceIds.map(toHex));
    const expected = new Set(recovery.expectedSourceIds.map(toHex));
    const canonicalPayload = encodeEncryptedPayloadV1(createNotificationSnapshotRequestPayload({
      recoveryRequestId: recovery.requestId,
      resetHighWaterDeliveryId: (await this.cursors.load(
        credential.workspaceId,
        credential.deviceId,
      )).snapshotRequiredHighWater!,
    }));
    try {
      for (const source of sources) {
        const sourceId = toHex(source.deviceId);
        if (!expected.has(sourceId) || completed.has(sourceId)) continue;
        const createdAtUnixMs = this.now();
        const context: ActionEnvelopeContext = {
          workspaceId: credential.workspaceId,
          senderDeviceId: credential.deviceId,
          recipientDeviceId: source.deviceId,
          senderIdentity: identity,
          recipientPublicKey: source.publicKey,
          messageId: this.nextIdentifier(),
          sequence: await this.sequences.allocate(source.keyId),
          createdAtUnixMs,
          expiresAtUnixMs: createdAtUnixMs + 5 * 60_000,
        };
        const frame = await createAuthenticatedEnvelopeFromCanonicalPayload(
          context,
          canonicalPayload,
          'notificationSnapshotRequest',
        );
        try {
          this.sendDurable(frame);
        } finally {
          frame.fill(0);
          source.publicKey.fill(0);
        }
      }
    } finally {
      canonicalPayload.fill(0);
    }
  }

  private async withCredential(
    operation: (credential: StoredTransportCredential) => Promise<void>,
  ): Promise<void> {
    const credential = await this.credentials.load();
    if (credential === undefined) return;
    try {
      await operation(credential);
    } finally {
      credential.authToken.fill(0);
    }
  }

  private nextIdentifier(): Uint8Array {
    const value = new Uint8Array(16);
    do {
      this.random(value);
    } while (value.every((byte) => byte === 0));
    return value;
  }
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}

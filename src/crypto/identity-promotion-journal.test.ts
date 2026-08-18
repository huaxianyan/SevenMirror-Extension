import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import {
  createIdentityKeyTransitionAckPayload,
  createIdentityKeyTransitionPayload,
  encodeIdentityKeyLifecyclePayload,
} from '../protocol/identity-key-transition-payload';
import { IndexedDbTransportCredentialStore } from '../transport/indexeddb-transport-credential-store';
import { serializeIdentityPublicKey } from './auth-hpke';
import { IndexedDbIdentityStore } from './indexeddb-identity-store';
import {
  IdentityPromotionCoordinator,
  IndexedDbIdentityPromotionJournal,
} from './identity-promotion-journal';
import { IndexedDbLocalIdentityTransitionStore } from './indexeddb-local-identity-transition-store';

const now = 1_800_000_000_000;
const workspaceId = new Uint8Array(16).fill(1);
const deviceId = new Uint8Array(16).fill(2);
const peerDeviceId = new Uint8Array(16).fill(3);
const peerKeyId = new Uint8Array(32).fill(4);
const transitionId = new Uint8Array(16).fill(5);

describe('IdentityPromotionCoordinator', () => {
  it('promotes exact identity and transport bindings through a durable journal', async () => {
    const fixture = await createFixture();
    try {
      const result = await new IdentityPromotionCoordinator(
        fixture.identities,
        fixture.transport,
        fixture.transitions,
        fixture.journal,
        () => now + 2,
      ).promoteReady();
      expect(result).toBe('promoted');
      await expectPromoted(fixture);
      expect(await fixture.journal.load()).toBeUndefined();
      expect((await fixture.transitions.dueCommits(workspaceId, now + 3))[0]?.session.phase)
        .toBe('promotion-completed');
    } finally {
      await clearFixture(fixture);
    }
  });

  it('recovers when transport rebind committed before journal phase update', async () => {
    const fixture = await createFixture();
    try {
      const session = await fixture.transitions.promotionReadiness(now + 2);
      expect(session).toBeDefined();
      const record = {
        id: 'active-identity-promotion-v1',
        workspaceId,
        deviceId,
        transitionId,
        previousKeyId: fixture.previousKeyId,
        newKeyId: fixture.newKeyId,
        phase: 'prepared' as const,
      };
      await fixture.journal.create(record);
      await fixture.transport.rebindIdentityKey(fixture.previousKeyId, fixture.newKeyId);

      const recovered = await new IdentityPromotionCoordinator(
        new IndexedDbIdentityStore(fixture.identityDatabase),
        new IndexedDbTransportCredentialStore(fixture.transportDatabase),
        new IndexedDbLocalIdentityTransitionStore(fixture.transitionDatabase),
        new IndexedDbIdentityPromotionJournal(fixture.journalDatabase),
        () => now + 3,
      ).promoteReady();
      expect(recovered).toBe('recovered');
      await expectPromoted(fixture);
      expect(await fixture.journal.load()).toBeUndefined();
    } finally {
      await clearFixture(fixture);
    }
  });

  it('defers a raced transport rotation without stranding its pending credential', async () => {
    const fixture = await createFixture();
    try {
      const record = {
        id: 'active-identity-promotion-v1',
        workspaceId,
        deviceId,
        transitionId,
        previousKeyId: fixture.previousKeyId,
        newKeyId: fixture.newKeyId,
        phase: 'prepared' as const,
      };
      await fixture.journal.create(record);
      const pendingToken = new Uint8Array(32).fill(7);
      await fixture.transport.prepareRotation(pendingToken);
      await expect(new IdentityPromotionCoordinator(
        fixture.identities,
        fixture.transport,
        fixture.transitions,
        fixture.journal,
        () => now + 3,
      ).promoteReady()).resolves.toBe('deferred-transport-rotation');
      expect(await fixture.identities.loadRotation()).toBeDefined();

      await fixture.transport.markRotationAttempted(pendingToken);
      (await fixture.transport.promotePending()).authToken.fill(0);
      await expect(new IdentityPromotionCoordinator(
        fixture.identities,
        fixture.transport,
        fixture.transitions,
        fixture.journal,
        () => now + 4,
      ).promoteReady()).resolves.toBe('recovered');
      await expectPromoted(fixture);
    } finally {
      await clearFixture(fixture);
    }
  });

  it('recovers when both external stores committed before journal phase updates', async () => {
    const fixture = await createFixture();
    try {
      const record = {
        id: 'active-identity-promotion-v1',
        workspaceId,
        deviceId,
        transitionId,
        previousKeyId: fixture.previousKeyId,
        newKeyId: fixture.newKeyId,
        phase: 'prepared' as const,
      };
      await fixture.journal.create(record);
      await fixture.transport.rebindIdentityKey(fixture.previousKeyId, fixture.newKeyId);
      await fixture.identities.promotePending(fixture.previousKeyId, fixture.newKeyId);

      await expect(new IdentityPromotionCoordinator(
        new IndexedDbIdentityStore(fixture.identityDatabase),
        new IndexedDbTransportCredentialStore(fixture.transportDatabase),
        new IndexedDbLocalIdentityTransitionStore(fixture.transitionDatabase),
        new IndexedDbIdentityPromotionJournal(fixture.journalDatabase),
        () => now + 3,
      ).promoteReady()).resolves.toBe('recovered');
      await expectPromoted(fixture);
      expect(await fixture.journal.load()).toBeUndefined();
    } finally {
      await clearFixture(fixture);
    }
  });
});

interface Fixture {
  identityDatabase: string;
  transportDatabase: string;
  transitionDatabase: string;
  journalDatabase: string;
  identities: IndexedDbIdentityStore;
  transport: IndexedDbTransportCredentialStore;
  transitions: IndexedDbLocalIdentityTransitionStore;
  journal: IndexedDbIdentityPromotionJournal;
  previousKeyId: Uint8Array;
  newKeyId: Uint8Array;
}

async function createFixture(): Promise<Fixture> {
  const suffix = `${Date.now()}-${Math.random()}`;
  const identityDatabase = `promotion-identities-${suffix}`;
  const transportDatabase = `promotion-transport-${suffix}`;
  const transitionDatabase = `promotion-transition-${suffix}`;
  const journalDatabase = `promotion-journal-${suffix}`;
  const identities = new IndexedDbIdentityStore(identityDatabase);
  const transport = new IndexedDbTransportCredentialStore(transportDatabase);
  const transitions = new IndexedDbLocalIdentityTransitionStore(transitionDatabase);
  const journal = new IndexedDbIdentityPromotionJournal(journalDatabase);
  const current = await identities.loadOrCreate();
  const rotation = await identities.prepareRotation();
  const currentPublic = await serializeIdentityPublicKey(current);
  const pendingPublic = await serializeIdentityPublicKey(rotation.pending);
  const previousKeyId = await sha256(currentPublic);
  const newKeyId = await sha256(pendingPublic);
  const canonicalTransition = await encodeIdentityKeyLifecyclePayload(
    createIdentityKeyTransitionPayload({
      transitionId,
      previousKeyId,
      newPublicKey: pendingPublic,
      newKeyId,
    }),
  );
  const transitionSha256 = await sha256(canonicalTransition);
  const canonicalAck = await encodeIdentityKeyLifecyclePayload(
    createIdentityKeyTransitionAckPayload({
      transitionId,
      previousKeyId,
      newKeyId,
      transitionSha256,
    }),
  );
  await transitions.create(
    workspaceId,
    deviceId,
    canonicalTransition,
    [{ deviceId: peerDeviceId, keyId: peerKeyId }],
    now,
  );
  await transitions.acceptAck(peerDeviceId, peerKeyId, canonicalAck, now + 1);
  await transport.saveNew({
    serverOrigin: 'https://relay.example',
    workspaceId,
    deviceId,
    authToken: new Uint8Array(32).fill(9),
    identityKeyId: previousKeyId,
  });
  return {
    identityDatabase,
    transportDatabase,
    transitionDatabase,
    journalDatabase,
    identities,
    transport,
    transitions,
    journal,
    previousKeyId,
    newKeyId,
  };
}

async function expectPromoted(fixture: Fixture): Promise<void> {
  expect(await fixture.identities.loadRotation()).toBeUndefined();
  const identity = await fixture.identities.loadExisting();
  expect(identity).toBeDefined();
  expect(await sha256(await serializeIdentityPublicKey(identity!))).toEqual(fixture.newKeyId);
  const credential = await fixture.transport.load();
  expect(credential?.identityKeyId).toEqual(fixture.newKeyId);
  credential?.authToken.fill(0);
}

async function clearFixture(fixture: Fixture): Promise<void> {
  await fixture.journal.clear();
  await fixture.transitions.clear();
  await fixture.transport.clear();
  await fixture.identities.clear();
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value.slice().buffer));
}

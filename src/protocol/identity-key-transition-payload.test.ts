import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/e2ee-identity-key-transition-v1.json';
import {
  createIdentityKeyTransitionAckPayload,
  createIdentityKeyTransitionCommitPayload,
  createIdentityKeyTransitionPayload,
  decodeIdentityKeyLifecyclePayload,
  encodeIdentityKeyLifecyclePayload,
} from './identity-key-transition-payload';
import { createActionInvokePayload } from './encrypted-payload';

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));

const validTransition = () => createIdentityKeyTransitionPayload({
  transitionId: fromHex(vector.transitionIdHex),
  previousKeyId: fromHex(vector.previousKeyIdHex),
  newPublicKey: fromHex(vector.newPublicKeyHex),
  newKeyId: fromHex(vector.newKeyIdHex),
});

describe('E2EE Identity Key Transition v1 payload', () => {
  it('matches all canonical cross-platform vectors', async () => {
    const transition = await encodeIdentityKeyLifecyclePayload(validTransition());
    expect(transition).toEqual(fromHex(vector.transitionEncodedHex));
    expect((await decodeIdentityKeyLifecyclePayload(transition)).body.case)
      .toBe('identityKeyTransition');

    const ack = await encodeIdentityKeyLifecyclePayload(createIdentityKeyTransitionAckPayload({
      transitionId: fromHex(vector.transitionIdHex),
      previousKeyId: fromHex(vector.previousKeyIdHex),
      newKeyId: fromHex(vector.newKeyIdHex),
      transitionSha256: fromHex(vector.transitionSha256Hex),
    }));
    expect(ack).toEqual(fromHex(vector.ackEncodedHex));

    const commit = await encodeIdentityKeyLifecyclePayload(
      createIdentityKeyTransitionCommitPayload({
        transitionId: fromHex(vector.transitionIdHex),
        previousKeyId: fromHex(vector.previousKeyIdHex),
        newKeyId: fromHex(vector.newKeyIdHex),
        transitionSha256: fromHex(vector.transitionSha256Hex),
        ackSha256: fromHex(vector.ackSha256Hex),
      }),
    );
    expect(commit).toEqual(fromHex(vector.commitEncodedHex));
  });

  it('rejects invalid key continuity and schema/body mismatches', async () => {
    const zeroId = validTransition();
    if (zeroId.body.case === 'identityKeyTransition') {
      zeroId.body.value.transitionId = new Uint8Array(16);
    }
    await expect(encodeIdentityKeyLifecyclePayload(zeroId)).rejects.toThrow(/transition id/i);

    const sameKey = validTransition();
    if (sameKey.body.case === 'identityKeyTransition') {
      sameKey.body.value.newKeyId = sameKey.body.value.previousKeyId.slice();
    }
    await expect(encodeIdentityKeyLifecyclePayload(sameKey)).rejects.toThrow(/differ/i);

    const invalidPoint = validTransition();
    if (invalidPoint.body.case === 'identityKeyTransition') {
      invalidPoint.body.value.newPublicKey[0] = 5;
    }
    await expect(encodeIdentityKeyLifecyclePayload(invalidPoint)).rejects.toThrow(/P-256/i);

    const wrongDigest = validTransition();
    if (wrongDigest.body.case === 'identityKeyTransition') {
      wrongDigest.body.value.newKeyId[0] ^= 0xff;
    }
    await expect(encodeIdentityKeyLifecyclePayload(wrongDigest)).rejects.toThrow(/SHA-256/i);

    const schemaV1 = validTransition();
    schemaV1.schemaVersion = 1;
    await expect(encodeIdentityKeyLifecyclePayload(schemaV1)).rejects.toThrow(/schema/i);

    const actionV2 = createActionInvokePayload({
      notificationId: 'test.notification/42',
      notificationRevision: 7n,
      actionId: new Uint8Array(16).fill(0xa1),
      idempotencyKey: new Uint8Array(16).fill(0xb2),
      replyText: 'acknowledged',
    });
    actionV2.schemaVersion = 2;
    await expect(encodeIdentityKeyLifecyclePayload(actionV2)).rejects.toThrow(/body/i);
  });

  it('rejects duplicate, unknown, and non-canonical wire fields', async () => {
    const encoded = fromHex(vector.transitionEncodedHex);
    await expect(decodeIdentityKeyLifecyclePayload(
      Uint8Array.from([8, 2, ...encoded]),
    )).rejects.toThrow();
    await expect(decodeIdentityKeyLifecyclePayload(
      Uint8Array.from([...encoded, 0x78, 1]),
    )).rejects.toThrow();
  });
});

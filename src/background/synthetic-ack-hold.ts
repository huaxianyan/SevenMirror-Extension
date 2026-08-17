import { decodeEncryptedPayloadV1 } from '../protocol/encrypted-payload';

const SYNTHETIC_ANDROID_PACKAGE = 'dev.notificationmirroring.android';

/** Restricts the temporary ACK hold to this app's exported synthetic notification operation. */
export function isAppOwnedSyntheticInvoke(
  canonicalInvokePayload: Uint8Array,
  idempotencyKey: Uint8Array,
): boolean {
  const payload = decodeEncryptedPayloadV1(canonicalInvokePayload);
  return payload.body.case === 'actionInvoke' &&
    bytesEqual(payload.body.value.idempotencyKey, idempotencyKey) &&
    payload.body.value.notificationId.split('|').includes(SYNTHETIC_ANDROID_PACKAGE);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

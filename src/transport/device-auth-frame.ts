export const DEVICE_AUTH_FRAME_SIZE = 68;
export const DEVICE_AUTH_TOKEN_SIZE = 32;
const ID_SIZE = 16;
const MAGIC = Uint8Array.of(0x53, 0x4e, 0x41, 0x31); // SNA1

export interface DeviceTransportCredential {
  workspaceId: Uint8Array;
  deviceId: Uint8Array;
  authToken: Uint8Array;
}

/** Encodes the first WebSocket binary message without converting secrets to text. */
export function encodeDeviceAuthFrameV1(credential: DeviceTransportCredential): Uint8Array {
  validateIdentifier(credential.workspaceId, 'workspaceId');
  validateIdentifier(credential.deviceId, 'deviceId');
  if (!(credential.authToken instanceof Uint8Array) ||
      credential.authToken.byteLength !== DEVICE_AUTH_TOKEN_SIZE) {
    throw new Error(`authToken must be ${DEVICE_AUTH_TOKEN_SIZE} bytes`);
  }
  const frame = new Uint8Array(DEVICE_AUTH_FRAME_SIZE);
  frame.set(MAGIC, 0);
  frame.set(credential.workspaceId, 4);
  frame.set(credential.deviceId, 20);
  frame.set(credential.authToken, 36);
  return frame;
}

/** Test/diagnostic decoder. Production clients only need to encode this frame. */
export function decodeDeviceAuthFrameV1(frame: Uint8Array): DeviceTransportCredential {
  if (!(frame instanceof Uint8Array) || frame.byteLength !== DEVICE_AUTH_FRAME_SIZE) {
    throw new Error(`device auth frame must be ${DEVICE_AUTH_FRAME_SIZE} bytes`);
  }
  if (!MAGIC.every((value, index) => frame[index] === value)) {
    throw new Error('unsupported device auth frame magic/version');
  }
  const credential = {
    workspaceId: frame.slice(4, 20),
    deviceId: frame.slice(20, 36),
    authToken: frame.slice(36, 68),
  };
  validateIdentifier(credential.workspaceId, 'workspaceId');
  validateIdentifier(credential.deviceId, 'deviceId');
  return credential;
}

function validateIdentifier(value: Uint8Array, name: string): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== ID_SIZE ||
      value.every((byte) => byte === 0)) {
    throw new Error(`${name} must be a non-zero ${ID_SIZE}-byte value`);
  }
}

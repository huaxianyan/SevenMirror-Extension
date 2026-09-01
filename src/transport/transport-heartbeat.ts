const REQUEST = Uint8Array.of(0x53, 0x4e, 0x48, 0x31); // SNH1
const RESPONSE = Uint8Array.of(0x53, 0x4e, 0x48, 0x32); // SNH2

export function encodeTransportHeartbeatRequestV1(): Uint8Array {
  return REQUEST.slice();
}

export function isTransportHeartbeatResponseV1(value: unknown): boolean {
  if (!(value instanceof ArrayBuffer) || value.byteLength !== RESPONSE.byteLength) return false;
  const bytes = new Uint8Array(value);
  return bytes.every((byte, index) => byte === RESPONSE[index]);
}

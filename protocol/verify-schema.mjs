import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

async function verify(assetPath, hashPath) {
  const asset = await readFile(new URL(assetPath, import.meta.url));
  const expected = (await readFile(new URL(hashPath, import.meta.url), 'utf8')).trim();
  const actual = createHash('sha256').update(asset).digest('hex');

  if (actual !== expected) {
    console.error(
      `Vendored protocol hash mismatch for ${assetPath}: expected ${expected}, got ${actual}`,
    );
    process.exitCode = 1;
    return;
  }
  console.log(`Protocol asset verified: ${assetPath} ${actual}`);
}

await verify('./vendor/notification/v1/envelope.proto', './SCHEMA_SHA256');
await verify('./vendor/notification/v1/payload.proto', './PAYLOAD_SCHEMA_SHA256');
await verify('./encrypted-payload-v1.md', './PAYLOAD_SPEC_SHA256');
await verify(
  './test-vectors/encrypted-payload-v1.json',
  './PAYLOAD_VECTOR_SHA256',
);
await verify('./routing-header-v1.md', './ROUTING_HEADER_SPEC_SHA256');
await verify(
  './test-vectors/routing-header-v1.json',
  './ROUTING_HEADER_VECTOR_SHA256',
);
await verify('./encrypted-envelope-v1.md', './ENCRYPTED_ENVELOPE_SPEC_SHA256');
await verify(
  './test-vectors/encrypted-envelope-v1.json',
  './ENCRYPTED_ENVELOPE_VECTOR_SHA256',
);
await verify('./device-auth-frame-v1.md', './DEVICE_AUTH_SPEC_SHA256');
await verify('./transport-heartbeat-v1.md', './TRANSPORT_HEARTBEAT_SPEC_SHA256');
await verify(
  './transport-credential-rotation-v1.md',
  './TRANSPORT_CREDENTIAL_ROTATION_SPEC_SHA256',
);
await verify(
  './test-vectors/device-auth-frame-v1.json',
  './DEVICE_AUTH_VECTOR_SHA256',
);
await verify('./trusted-device-pairing-v1.md', './TRUST_PAIRING_SPEC_SHA256');
await verify(
  './test-vectors/trusted-device-pairing-v1.json',
  './TRUST_PAIRING_VECTOR_SHA256',
);

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
await verify('./routing-header-v1.md', './ROUTING_HEADER_SPEC_SHA256');
await verify(
  './test-vectors/routing-header-v1.json',
  './ROUTING_HEADER_VECTOR_SHA256',
);

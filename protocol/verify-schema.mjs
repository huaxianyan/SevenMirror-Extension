import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const schema = await readFile(new URL('./vendor/notification/v1/envelope.proto', import.meta.url));
const expected = (await readFile(new URL('./SCHEMA_SHA256', import.meta.url), 'utf8')).trim();
const actual = createHash('sha256').update(schema).digest('hex');

if (actual !== expected) {
  console.error(`Vendored protocol hash mismatch: expected ${expected}, got ${actual}`);
  process.exit(1);
}
console.log(`Protocol schema verified: ${actual}`);

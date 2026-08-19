import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

interface LocaleMessage {
  message: string;
  placeholders?: Record<string, { content: string }>;
}

type LocaleCatalog = Record<string, LocaleMessage>;

const english = readCatalog('../../public/_locales/en/messages.json');
const simplifiedChinese = readCatalog('../../public/_locales/zh_CN/messages.json');

describe('locale catalogs', () => {
  it('provides the same messages and compatible placeholders in English and Simplified Chinese', () => {
    expect(Object.keys(simplifiedChinese).sort()).toEqual(Object.keys(english).sort());
    for (const key of Object.keys(english)) {
      expect(simplifiedChinese[key]?.placeholders ?? {}).toEqual(
        english[key]?.placeholders ?? {},
      );
      expect(simplifiedChinese[key]?.message).not.toBe('');
      expect(english[key]?.message).not.toBe('');
    }
  });

  it('defines every message referenced by the Manifest and localized HTML', () => {
    const referencedKeys = [
      ...readText('../../public/manifest.json').matchAll(/__MSG_([A-Za-z0-9_]+)__/g),
      ...readText('../popup/index.html').matchAll(/data-i18n(?:-placeholder)?="([A-Za-z0-9_]+)"/g),
      ...readText('../options/index.html').matchAll(/data-i18n(?:-placeholder)?="([A-Za-z0-9_]+)"/g),
    ].map((match) => match[1]!);
    expect(referencedKeys.length).toBeGreaterThan(0);
    for (const key of referencedKeys) expect(english[key]).toBeDefined();
  });
});

function readCatalog(relativePath: string): LocaleCatalog {
  return JSON.parse(readText(relativePath)) as LocaleCatalog;
}

function readText(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), 'utf8');
}

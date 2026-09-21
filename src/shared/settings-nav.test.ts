import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const projectRoot = fileURLToPath(new URL('../..', import.meta.url));

/**
 * The shortcut page sits behind the settings page and renders the same left-hand navigation, but
 * the two are separate documents with no shared component. That is exactly how they drifted apart:
 * the settings page merged Connection and Devices into one entry while the shortcut page kept them
 * separate. Comparing the localized keys of both navigations catches the next drift.
 */
function navigationKeys(page: string): string[] {
  const html = readFileSync(join(projectRoot, 'src', page, 'index.html'), 'utf8');
  const navigation = /<nav\b[\s\S]*?<\/nav>/.exec(html)?.[0] ?? '';
  return [...navigation.matchAll(/data-i18n="([^"]+)"/g)].map((match) => match[1]);
}

describe('Settings navigation', () => {
  it('lists the same sections on the shortcut page and the settings page', () => {
    const settings = navigationKeys('options');
    expect(settings.length).toBeGreaterThan(1);
    expect(navigationKeys('shortcuts')).toEqual(settings);
  });
});

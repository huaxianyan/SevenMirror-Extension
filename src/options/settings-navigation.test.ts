import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { resolveSettingsPage, settingsPageIds } from './settings-navigation';

const projectRoot = fileURLToPath(new URL('../..', import.meta.url));
const settingsHtml = readFileSync(join(projectRoot, 'src', 'options', 'index.html'), 'utf8');

function navigationMarkup(): string {
  return /<nav\b[\s\S]*?<\/nav>/.exec(settingsHtml)?.[0] ?? '';
}

describe('Options navigation', () => {
  it('opens the requested settings page and falls back to connection and devices', () => {
    expect(resolveSettingsPage('#notifications')).toBe('notifications');
    expect(resolveSettingsPage('#shortcut-settings')).toBe('shortcut-settings');
    expect(resolveSettingsPage('#about')).toBe('about');
    expect(resolveSettingsPage('#unknown')).toBe('connection-devices');
    expect(resolveSettingsPage('')).toBe('connection-devices');
  });
});

/**
 * Shortcut settings used to be a second document with its own copy of this navigation, and the two
 * drifted apart: one merged Connection and Devices, the other did not. They are one section of the
 * settings page now, so the links, the sections and the router table are compared here, where all
 * three live. The last case is the one that drifted: a link that leaves the document.
 */
describe('Settings navigation', () => {
  it('links every settings section in the order the router knows them', () => {
    const targets = [...navigationMarkup().matchAll(/data-settings-page="([^"]+)"/g)]
      .map((match) => match[1]);
    expect(targets).toEqual([...settingsPageIds]);
  });

  it('renders a settings section for every link target', () => {
    const pages = [...settingsHtml.matchAll(/<div id="([^"]+)" class="settings-page"/g)]
      .map((match) => match[1]);
    expect(pages).toEqual([...settingsPageIds]);
  });

  it('keeps every navigation entry inside this document', () => {
    expect(navigationMarkup()).not.toMatch(/href="\.\.\//);
  });
});

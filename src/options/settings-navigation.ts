export const settingsPageIds = [
  'connection-devices',
  'notifications',
  'shortcut-settings',
  'data-privacy',
  'about',
] as const;

export type SettingsPageId = typeof settingsPageIds[number];

export function resolveSettingsPage(hash: string): SettingsPageId {
  const requested = hash.startsWith('#') ? hash.slice(1) : hash;
  return settingsPageIds.find((page) => page === requested) ?? 'connection-devices';
}

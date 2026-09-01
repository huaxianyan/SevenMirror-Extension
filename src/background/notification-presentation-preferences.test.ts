import { describe, expect, it } from 'vitest';
import {
  NOTIFICATION_PRESENTATION_PREFERENCES_KEY,
  NotificationPresentationPreferencesStore,
  sourceEnabled,
} from './notification-presentation-preferences';

const defaults = {
  badgeEnabled: true,
  nativeNotificationsEnabled: true,
  showBody: true,
  showImages: true,
  silentNotifications: false,
  mutedSourceDeviceIds: [],
};

describe('NotificationPresentationPreferencesStore', () => {
  it('migrates badge-only settings and persists source and display choices', async () => {
    const values: Record<string, unknown> = {};
    const store = new NotificationPresentationPreferencesStore({
      async get(key) { return { [key]: values[key] }; },
      async set(items) { Object.assign(values, items); },
    });

    await expect(store.load()).resolves.toEqual(defaults);
    values[NOTIFICATION_PRESENTATION_PREFERENCES_KEY] = { badgeEnabled: false };
    await expect(store.load()).resolves.toEqual({ ...defaults, badgeEnabled: false });

    const muted = '01010101010101010101010101010101';
    const preferences = {
      badgeEnabled: false,
      nativeNotificationsEnabled: false,
      showBody: false,
      showImages: false,
      silentNotifications: true,
      mutedSourceDeviceIds: [muted, muted],
    };
    await store.save(preferences);
    await expect(store.load()).resolves.toEqual({
      ...preferences,
      mutedSourceDeviceIds: [muted],
    });
    expect(sourceEnabled(await store.load(), new Uint8Array(16).fill(1))).toBe(false);
    expect(sourceEnabled(await store.load(), new Uint8Array(16).fill(2))).toBe(true);
  });

  it('rejects malformed stored and proposed preferences', async () => {
    const store = new NotificationPresentationPreferencesStore({
      async get(key) { return { [key]: { badgeEnabled: 'yes' } }; },
      async set() {},
    });
    await expect(store.load()).rejects.toThrow('invalid');
    await expect(store.save({ badgeEnabled: true, mutedSourceDeviceIds: ['internal-id'] }))
      .rejects.toThrow('invalid');
  });
});

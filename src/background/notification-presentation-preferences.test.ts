import { describe, expect, it } from 'vitest';
import {
  NOTIFICATION_PRESENTATION_PREFERENCES_KEY,
  NotificationPresentationPreferencesStore,
} from './notification-presentation-preferences';

describe('NotificationPresentationPreferencesStore', () => {
  it('defaults to an enabled badge and persists explicit changes', async () => {
    const values: Record<string, unknown> = {};
    const store = new NotificationPresentationPreferencesStore({
      async get(key) { return { [key]: values[key] }; },
      async set(items) { Object.assign(values, items); },
    });

    await expect(store.load()).resolves.toEqual({ badgeEnabled: true });
    await store.save({ badgeEnabled: false });
    await expect(store.load()).resolves.toEqual({ badgeEnabled: false });
    expect(values[NOTIFICATION_PRESENTATION_PREFERENCES_KEY])
      .toEqual({ badgeEnabled: false });
  });

  it('rejects malformed stored and proposed preferences', async () => {
    const store = new NotificationPresentationPreferencesStore({
      async get(key) { return { [key]: { badgeEnabled: 'yes' } }; },
      async set() {},
    });
    await expect(store.load()).rejects.toThrow('invalid');
    await expect(store.save({ badgeEnabled: 1 })).rejects.toThrow('invalid');
  });
});

export const NOTIFICATION_PRESENTATION_PREFERENCES_KEY = 'notificationPresentationPreferencesV1';

export interface NotificationPresentationPreferences {
  badgeEnabled: boolean;
}

interface PreferencesStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

export class NotificationPresentationPreferencesStore {
  constructor(private readonly storage: PreferencesStorage = chrome.storage.local) {}

  async load(): Promise<NotificationPresentationPreferences> {
    const stored = await this.storage.get(NOTIFICATION_PRESENTATION_PREFERENCES_KEY);
    const value = stored[NOTIFICATION_PRESENTATION_PREFERENCES_KEY];
    if (value === undefined) return { badgeEnabled: true };
    if (!isRecord(value) || typeof value.badgeEnabled !== 'boolean') {
      throw new Error('Notification presentation preferences are invalid');
    }
    return { badgeEnabled: value.badgeEnabled };
  }

  async save(value: unknown): Promise<void> {
    if (!isRecord(value) || typeof value.badgeEnabled !== 'boolean') {
      throw new Error('Notification presentation preferences are invalid');
    }
    await this.storage.set({
      [NOTIFICATION_PRESENTATION_PREFERENCES_KEY]: { badgeEnabled: value.badgeEnabled },
    });
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

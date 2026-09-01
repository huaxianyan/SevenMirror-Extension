export const NOTIFICATION_PRESENTATION_PREFERENCES_KEY = 'notificationPresentationPreferencesV1';
const MAX_MUTED_SOURCES = 256;

export interface NotificationPresentationPreferences {
  badgeEnabled: boolean;
  nativeNotificationsEnabled: boolean;
  showBody: boolean;
  showImages: boolean;
  silentNotifications: boolean;
  mutedSourceDeviceIds: string[];
}

export const DEFAULT_NOTIFICATION_PRESENTATION_PREFERENCES: NotificationPresentationPreferences = {
  badgeEnabled: true,
  nativeNotificationsEnabled: true,
  showBody: true,
  showImages: true,
  silentNotifications: false,
  mutedSourceDeviceIds: [],
};

export const FAIL_CLOSED_NOTIFICATION_PRESENTATION_PREFERENCES: NotificationPresentationPreferences = {
  badgeEnabled: false,
  nativeNotificationsEnabled: false,
  showBody: false,
  showImages: false,
  silentNotifications: true,
  mutedSourceDeviceIds: [],
};

interface PreferencesStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

export class NotificationPresentationPreferencesStore {
  constructor(private readonly storage: PreferencesStorage = chrome.storage.local) {}

  async load(): Promise<NotificationPresentationPreferences> {
    const stored = await this.storage.get(NOTIFICATION_PRESENTATION_PREFERENCES_KEY);
    const value = stored[NOTIFICATION_PRESENTATION_PREFERENCES_KEY];
    return value === undefined
      ? copyPreferences(DEFAULT_NOTIFICATION_PRESENTATION_PREFERENCES)
      : validateNotificationPresentationPreferences(value);
  }

  async save(value: unknown): Promise<void> {
    const preferences = validateNotificationPresentationPreferences(value);
    await this.storage.set({ [NOTIFICATION_PRESENTATION_PREFERENCES_KEY]: preferences });
  }
}

export function sourceEnabled(
  preferences: NotificationPresentationPreferences,
  sourceDeviceId: Uint8Array,
): boolean {
  return !preferences.mutedSourceDeviceIds.includes(toHex(sourceDeviceId));
}

export function validateNotificationPresentationPreferences(
  value: unknown,
): NotificationPresentationPreferences {
  if (!isRecord(value) || typeof value.badgeEnabled !== 'boolean') {
    throw new Error('Notification presentation preferences are invalid');
  }
  const nativeNotificationsEnabled = optionalBoolean(value.nativeNotificationsEnabled, true);
  const showBody = optionalBoolean(value.showBody, true);
  const showImages = optionalBoolean(value.showImages, true);
  const silentNotifications = optionalBoolean(value.silentNotifications, false);
  const rawMuted = value.mutedSourceDeviceIds ?? [];
  if (!Array.isArray(rawMuted) || rawMuted.length > MAX_MUTED_SOURCES ||
      rawMuted.some((entry) => typeof entry !== 'string' || !/^[0-9a-f]{32}$/.test(entry))) {
    throw new Error('Notification presentation preferences are invalid');
  }
  return {
    badgeEnabled: value.badgeEnabled,
    nativeNotificationsEnabled,
    showBody,
    showImages,
    silentNotifications,
    mutedSourceDeviceIds: [...new Set(rawMuted)].sort(),
  };
}

function optionalBoolean(value: unknown, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') throw new Error('Notification presentation preferences are invalid');
  return value;
}

function copyPreferences(
  value: NotificationPresentationPreferences,
): NotificationPresentationPreferences {
  return { ...value, mutedSourceDeviceIds: [...value.mutedSourceDeviceIds] };
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

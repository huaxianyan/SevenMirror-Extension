import type {
  MirroredNotificationAction,
  MirroredNotificationState,
} from '../crypto/indexeddb-notification-state-store';

export const SHORTCUT_PREFERENCES_KEY = 'notificationShortcutPreferencesV1';
export const MAX_SHORTCUT_RULES = 64;

export type NotificationShortcutRule = {
  id: string;
  match:
    | { kind: 'reply' }
    | { kind: 'title-exact'; value: string }
    | { kind: 'title-contains'; value: string };
  sourceApplicationId?: string;
  sourceApplicationName?: string;
};

export interface NotificationShortcutPreferences {
  pinDismiss: boolean;
  rules: NotificationShortcutRule[];
}

export type NotificationButton =
  | { kind: 'action'; title: string; action: MirroredNotificationAction }
  | { kind: 'more'; title: string }
  | { kind: 'dismiss'; title: string };

export const DEFAULT_SHORTCUT_PREFERENCES: NotificationShortcutPreferences = {
  pinDismiss: true,
  rules: [],
};

export interface ShortcutPreferencesStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

export class NotificationShortcutPreferencesStore {
  constructor(private readonly storage: ShortcutPreferencesStorage = chrome.storage.local) {}

  async load(): Promise<NotificationShortcutPreferences> {
    const stored = await this.storage.get(SHORTCUT_PREFERENCES_KEY);
    const value = stored[SHORTCUT_PREFERENCES_KEY];
    if (value === undefined) return copyPreferences(DEFAULT_SHORTCUT_PREFERENCES);
    return validateNotificationShortcutPreferences(value);
  }

  async save(preferences: unknown): Promise<void> {
    const validated = validateNotificationShortcutPreferences(preferences);
    await this.storage.set({ [SHORTCUT_PREFERENCES_KEY]: validated });
  }
}

export function notificationButtons(
  state: MirroredNotificationState,
  preferences: NotificationShortcutPreferences,
  labels: { dismiss: string; more: string },
): NotificationButton[] {
  const actions = state.actions ?? [];
  const dynamicCapacity = preferences.pinDismiss ? 1 : 2;
  const selected: MirroredNotificationAction[] = [];

  if (actions.length === 1) {
    selected.push(actions[0]);
  } else {
    for (const rule of preferences.rules) {
      if (selected.length >= dynamicCapacity) break;
      for (const action of actions) {
        if (selected.length >= dynamicCapacity) break;
        if (selected.includes(action) || !matchesRule(action, state.sourceApplicationId, rule)) continue;
        selected.push(action);
      }
    }
  }

  const buttons: NotificationButton[] = selected.map((action) => ({
    kind: 'action',
    title: action.title,
    action: { ...action, actionId: action.actionId.slice() },
  }));
  if (buttons.length < dynamicCapacity && selected.length < actions.length) {
    buttons.push({ kind: 'more', title: labels.more });
  }
  if (preferences.pinDismiss) buttons.push({ kind: 'dismiss', title: labels.dismiss });
  return buttons;
}

export function normalizeShortcutText(value: string): string {
  return value.normalize('NFKC').trim().toLowerCase();
}

export function validateNotificationShortcutPreferences(
  value: unknown,
): NotificationShortcutPreferences {
  if (!isRecord(value) || typeof value.pinDismiss !== 'boolean' || !Array.isArray(value.rules) ||
      value.rules.length > MAX_SHORTCUT_RULES) {
    throw new Error('Notification shortcut preferences are invalid');
  }
  const ruleIds = new Set<string>();
  const rules = value.rules.map((candidate) => {
    if (!isRecord(candidate) || typeof candidate.id !== 'string' ||
        !/^[0-9a-f]{32}$/.test(candidate.id) || ruleIds.has(candidate.id) ||
        !isRecord(candidate.match)) {
      throw new Error('Notification shortcut rule is invalid');
    }
    ruleIds.add(candidate.id);
    const sourceApplicationId = candidate.sourceApplicationId;
    const sourceApplicationName = candidate.sourceApplicationName;
    if ((sourceApplicationId === undefined) !== (sourceApplicationName === undefined)) {
      throw new Error('Notification shortcut application scope is invalid');
    }
    if (sourceApplicationId !== undefined && sourceApplicationName !== undefined) {
      validateBoundedText(sourceApplicationId, 255, 'source application id');
      validateBoundedText(sourceApplicationName, 512, 'source application name');
    }
    const kind = candidate.match.kind;
    let match: NotificationShortcutRule['match'];
    if (kind === 'reply') {
      match = { kind };
    } else if (kind === 'title-exact' || kind === 'title-contains') {
      const text = candidate.match.value;
      if (typeof text !== 'string') throw new Error('Notification shortcut title is invalid');
      validateBoundedText(text.trim(), 256, 'title');
      match = { kind, value: text.trim() };
    } else {
      throw new Error('Notification shortcut match kind is invalid');
    }
    return {
      id: candidate.id,
      match,
      ...(sourceApplicationId === undefined ? {} : {
        sourceApplicationId,
        sourceApplicationName,
      }),
    };
  });
  return { pinDismiss: value.pinDismiss, rules };
}

function matchesRule(
  action: MirroredNotificationAction,
  sourceApplicationId: string | undefined,
  rule: NotificationShortcutRule,
): boolean {
  if (rule.sourceApplicationId !== undefined && rule.sourceApplicationId !== sourceApplicationId) {
    return false;
  }
  if (rule.match.kind === 'reply') {
    return action.requiresTextInput && action.allowsFreeFormInput;
  }
  const title = normalizeShortcutText(action.title);
  const expected = normalizeShortcutText(rule.match.value);
  return rule.match.kind === 'title-exact' ? title === expected : title.includes(expected);
}

function validateBoundedText(value: string, maxBytes: number, field: string): void {
  const bytes = new TextEncoder().encode(value).byteLength;
  if (bytes < 1 || bytes > maxBytes) throw new Error(`Notification shortcut ${field} is invalid`);
}

function copyPreferences(value: NotificationShortcutPreferences): NotificationShortcutPreferences {
  return {
    pinDismiss: value.pinDismiss,
    rules: value.rules.map((rule) => ({
      ...rule,
      match: { ...rule.match },
    })),
  };
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === 'object' && value !== null;
}

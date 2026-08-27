import { describe, expect, it } from 'vitest';
import type { MirroredNotificationState } from '../crypto/indexeddb-notification-state-store';
import {
  DEFAULT_SHORTCUT_PREFERENCES,
  NotificationShortcutPreferencesStore,
  notificationButtons,
  validateNotificationShortcutPreferences,
  type NotificationShortcutPreferences,
} from './notification-shortcuts';

const action = (byte: number, title: string, reply = false) => ({
  actionId: new Uint8Array(16).fill(byte),
  title,
  requiresTextInput: reply,
  allowsFreeFormInput: reply,
});

const state = (actions: ReturnType<typeof action>[], sourceApplicationId = 'app.example'):
MirroredNotificationState => ({
  tuple: 'source:notification',
  sourceDeviceId: new Uint8Array(16).fill(1),
  notificationId: 'notification',
  chromeNotificationId: 'sn1:test',
  revision: '7',
  phase: 'visible',
  payloadSha256: new Uint8Array(32).fill(2),
  sourceApplicationId,
  sourceApplicationName: 'Example',
  actions,
});

const rule = (
  byte: number,
  match: NotificationShortcutPreferences['rules'][number]['match'],
  sourceApplicationId?: string,
) => ({
  id: byte.toString(16).padStart(32, '0'),
  match,
  ...(sourceApplicationId === undefined ? {} : {
    sourceApplicationId,
    sourceApplicationName: 'Example',
  }),
});

const titles = (buttons: ReturnType<typeof notificationButtons>) =>
  buttons.map((button) => [button.kind, button.title]);

describe('notification shortcut allocation', () => {
  it('uses clear only when there are no source actions', () => {
    expect(titles(notificationButtons(state([]), DEFAULT_SHORTCUT_PREFERENCES, {
      dismiss: '清除', more: '更多',
    }))).toEqual([['dismiss', '清除']]);
  });

  it('shows the sole source action without requiring a rule', () => {
    expect(titles(notificationButtons(state([action(1, 'Archive')]), DEFAULT_SHORTCUT_PREFERENCES, {
      dismiss: 'Clear', more: 'More',
    }))).toEqual([['action', 'Archive'], ['dismiss', 'Clear']]);
  });

  it('uses a lowest-priority More button instead of arbitrary unmatched actions', () => {
    expect(titles(notificationButtons(state([
      action(1, 'Archive'), action(2, 'Delete'), action(3, 'Reply', true),
    ]), DEFAULT_SHORTCUT_PREFERENCES, { dismiss: 'Clear', more: 'More' })))
      .toEqual([['more', 'More'], ['dismiss', 'Clear']]);
  });

  it('matches reply structurally and routes title rules by priority then source order', () => {
    const preferences: NotificationShortcutPreferences = {
      pinDismiss: false,
      rules: [
        rule(1, { kind: 'reply' }),
        rule(2, { kind: 'title-exact', value: ' ARCHIVE ' }),
      ],
    };
    expect(titles(notificationButtons(state([
      action(1, 'Archive'), action(2, 'Reply', true), action(3, 'archive'),
    ]), preferences, { dismiss: 'Clear', more: 'More' })))
      .toEqual([['action', 'Reply'], ['action', 'Archive']]);
  });

  it('supports explicit Unicode-normalized contains matching and application scope', () => {
    const preferences: NotificationShortcutPreferences = {
      pinDismiss: false,
      rules: [
        rule(1, { kind: 'title-contains', value: 'ＡＲＣＨ' }, 'other.app'),
        rule(2, { kind: 'title-contains', value: 'ＡＲＣＨ' }, 'app.example'),
      ],
    };
    expect(titles(notificationButtons(state([
      action(1, 'Quick Archive'), action(2, 'Delete'), action(3, 'Archive all'),
    ]), preferences, { dismiss: 'Clear', more: 'More' })))
      .toEqual([['action', 'Quick Archive'], ['action', 'Archive all']]);
  });

  it('does not duplicate an action matched by multiple rules and appends More when space remains', () => {
    const preferences: NotificationShortcutPreferences = {
      pinDismiss: false,
      rules: [
        rule(1, { kind: 'title-exact', value: 'Archive' }),
        rule(2, { kind: 'title-contains', value: 'arch' }),
      ],
    };
    expect(titles(notificationButtons(state([
      action(1, 'Archive'), action(2, 'Delete'), action(3, 'Reply', true),
    ]), preferences, { dismiss: 'Clear', more: 'More' })))
      .toEqual([['action', 'Archive'], ['more', 'More']]);
  });

  it('copies action identifiers returned to presentation code', () => {
    const source = action(1, 'Archive');
    const buttons = notificationButtons(state([source]), DEFAULT_SHORTCUT_PREFERENCES, {
      dismiss: 'Clear', more: 'More',
    });
    expect(buttons[0]?.kind).toBe('action');
    if (buttons[0]?.kind === 'action') expect(buttons[0].action.actionId).not.toBe(source.actionId);
  });
});

describe('notification shortcut preferences', () => {
  it('loads defaults and persists validated rules', async () => {
    const values: Record<string, unknown> = {};
    const store = new NotificationShortcutPreferencesStore({
      get: async (key) => ({ [key]: values[key] }),
      set: async (items) => { Object.assign(values, items); },
    });
    expect(await store.load()).toEqual(DEFAULT_SHORTCUT_PREFERENCES);
    const preferences: NotificationShortcutPreferences = {
      pinDismiss: false,
      rules: [rule(1, { kind: 'title-exact', value: 'Archive' })],
    };
    await store.save(preferences);
    expect(await store.load()).toEqual(preferences);
  });

  it('rejects duplicate ids, implicit contains and empty titles', () => {
    const duplicate = rule(1, { kind: 'reply' });
    expect(() => validateNotificationShortcutPreferences({
      pinDismiss: true, rules: [duplicate, duplicate],
    })).toThrow(/rule/i);
    expect(() => validateNotificationShortcutPreferences({
      pinDismiss: true, rules: [rule(2, { kind: 'title-exact', value: ' ' })],
    })).toThrow(/title/i);
    expect(() => validateNotificationShortcutPreferences({
      pinDismiss: true,
      rules: [{ id: '3'.padStart(32, '0'), match: { kind: 'title', value: 'Archive' } }],
    })).toThrow(/kind/i);
  });
});

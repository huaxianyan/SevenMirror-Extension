import type { NotificationButton } from './notification-shortcuts';

const KEY_PREFIX = 'notificationButtonBindingV1:';

export type NotificationButtonBinding =
  | { kind: 'action'; actionId: Uint8Array; requiresTextInput: boolean }
  | { kind: 'more' }
  | { kind: 'dismiss' };

interface StoredNotificationButtonBindingRecord {
  version: 1;
  notificationRevision: string;
  buttons: Array<
    | { kind: 'action'; actionIdHex: string; requiresTextInput: boolean }
    | { kind: 'more' }
    | { kind: 'dismiss' }
  >;
}

export interface ButtonBindingStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

export class NotificationButtonBindingStore {
  constructor(private readonly storage: ButtonBindingStorage = chrome.storage.local) {}

  async save(
    chromeNotificationId: string,
    notificationRevision: string,
    buttons: NotificationButton[],
  ): Promise<void> {
    validateRevision(notificationRevision);
    const record: StoredNotificationButtonBindingRecord = {
      version: 1,
      notificationRevision,
      buttons: buttons.map((button) => button.kind === 'action'
        ? {
          kind: 'action',
          actionIdHex: toHex(button.action.actionId),
          requiresTextInput: button.action.requiresTextInput,
        }
        : { kind: button.kind }),
    };
    await this.storage.set({ [key(chromeNotificationId)]: record });
  }

  async load(
    chromeNotificationId: string,
    notificationRevision: string,
  ): Promise<NotificationButtonBinding[] | undefined> {
    validateRevision(notificationRevision);
    const stored = await this.storage.get(key(chromeNotificationId));
    const value = stored[key(chromeNotificationId)];
    if (!isRecord(value) || value.version !== 1 ||
        value.notificationRevision !== notificationRevision || !Array.isArray(value.buttons) ||
        value.buttons.length > 2) {
      return undefined;
    }
    const result: NotificationButtonBinding[] = [];
    for (const button of value.buttons) {
      if (!isRecord(button)) return undefined;
      if (button.kind === 'more' || button.kind === 'dismiss') {
        result.push({ kind: button.kind });
      } else if (button.kind === 'action' && typeof button.actionIdHex === 'string' &&
          /^[0-9a-f]{32}$/.test(button.actionIdHex) &&
          typeof button.requiresTextInput === 'boolean') {
        result.push({
          kind: 'action',
          actionId: fromHex(button.actionIdHex),
          requiresTextInput: button.requiresTextInput,
        });
      } else {
        return undefined;
      }
    }
    return result;
  }

  async remove(chromeNotificationId: string): Promise<void> {
    await this.storage.remove(key(chromeNotificationId));
  }
}

function key(notificationId: string): string {
  return `${KEY_PREFIX}${notificationId}`;
}

function validateRevision(revision: string): void {
  if (!/^[1-9][0-9]*$/.test(revision)) throw new Error('Notification revision is invalid');
}

function toHex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function fromHex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === 'object' && value !== null;
}

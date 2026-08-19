import {
  consumeProgrammaticCloseMarker,
  markProgrammaticClose,
} from './lifecycle-spike';
import type { NotificationReceipt } from '../crypto/notification-receiver';

export interface NotificationsApi {
  getAll(callback: (notifications: Object) => void): void;
  create(
    notificationId: string,
    options: chrome.notifications.NotificationOptions<true>,
    callback?: (notificationId: string) => void,
  ): void;
  update(
    notificationId: string,
    options: chrome.notifications.NotificationOptions<true>,
    callback?: (wasUpdated: boolean) => void,
  ): void;
  clear(notificationId: string, callback?: (wasCleared: boolean) => void): void;
}

export class NotificationPresenter {
  constructor(
    private readonly notifications: NotificationsApi = chrome.notifications,
    private readonly markProgrammatic = markProgrammaticClose,
    private readonly consumeProgrammatic = consumeProgrammaticCloseMarker,
    private readonly notificationIconUrl = () => chrome.runtime.getURL('icons/notification.png'),
  ) {}

  async present(receipt: NotificationReceipt): Promise<void> {
    if (receipt.kind === 'snapshot') {
      for (const state of receipt.reconciliation.closedStates) {
        await this.closeProgrammatically(state.chromeNotificationId, 'snapshot-reconciliation');
      }
      return;
    }

    const { disposition, state } = receipt.reconciliation;
    if (disposition === 'stale') return;
    if (state.phase === 'removed') {
      await this.closeProgrammatically(state.chromeNotificationId, 'source-notification-removed');
      return;
    }

    const sourceRef = toHex(state.sourceDeviceId).slice(0, 12);
    const options: chrome.notifications.NotificationOptions<true> = {
      type: 'basic',
      iconUrl: this.notificationIconUrl(),
      title: `${state.title ?? 'Notification'} · Android ${sourceRef}`,
      message: state.body ?? '',
      priority: 0,
    };
    const existing = await this.getAll();
    if (existing[state.chromeNotificationId]) {
      const updated = await this.update(state.chromeNotificationId, options);
      if (!updated) await this.create(state.chromeNotificationId, options);
    } else {
      await this.create(state.chromeNotificationId, options);
    }
  }

  private async closeProgrammatically(notificationId: string, reason: string): Promise<void> {
    await this.markProgrammatic(notificationId, reason);
    const cleared = await this.clear(notificationId);
    if (!cleared) {
      // No onClosed event will consume this marker when the notification is already absent.
      await this.consumeProgrammatic(notificationId);
    }
  }

  private getAll(): Promise<Record<string, boolean>> {
    return new Promise((resolve) => {
      this.notifications.getAll((notifications) => {
        resolve(notifications as Record<string, boolean>);
      });
    });
  }

  private create(
    notificationId: string,
    options: chrome.notifications.NotificationOptions<true>,
  ): Promise<void> {
    return new Promise((resolve) => {
      this.notifications.create(notificationId, options, () => resolve());
    });
  }

  private update(
    notificationId: string,
    options: chrome.notifications.NotificationOptions<true>,
  ): Promise<boolean> {
    return new Promise((resolve) => {
      this.notifications.update(notificationId, options, resolve);
    });
  }

  private clear(notificationId: string): Promise<boolean> {
    return new Promise((resolve) => this.notifications.clear(notificationId, resolve));
  }
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

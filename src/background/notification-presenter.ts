import {
  consumeProgrammaticCloseMarker,
  markProgrammaticClose,
} from './lifecycle-spike';
import type { NotificationReceipt } from '../crypto/notification-receiver';
import type {
  MirroredNotificationMedia,
  MirroredNotificationState,
} from '../crypto/indexeddb-notification-state-store';
import { NotificationMediaMimeType } from '../protocol/generated/notification/v1/payload_pb';
import {
  DEFAULT_SHORTCUT_PREFERENCES,
  notificationButtons,
  type NotificationButton,
  type NotificationShortcutPreferences,
} from './notification-shortcuts';

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

export interface NotificationPresenterOptions {
  notifications?: NotificationsApi;
  markProgrammatic?: typeof markProgrammaticClose;
  consumeProgrammatic?: typeof consumeProgrammaticCloseMarker;
  notificationIconUrl?: () => string;
  mediaIconUrl?: typeof notificationMediaDataUrl;
  dismissButtonTitle?: () => string;
  moreButtonTitle?: () => string;
  loadShortcutPreferences?: () => Promise<NotificationShortcutPreferences>;
  saveButtonBindings?: (
    chromeNotificationId: string,
    revision: string,
    buttons: NotificationButton[],
  ) => Promise<void>;
  removeButtonBindings?: (chromeNotificationId: string) => Promise<void>;
}

export class NotificationPresenter {
  private readonly notifications: NotificationsApi;
  private readonly markProgrammatic: typeof markProgrammaticClose;
  private readonly consumeProgrammatic: typeof consumeProgrammaticCloseMarker;
  private readonly notificationIconUrl: () => string;
  private readonly mediaIconUrl: typeof notificationMediaDataUrl;
  private readonly dismissButtonTitle: () => string;
  private readonly moreButtonTitle: () => string;
  private readonly loadShortcutPreferences: () => Promise<NotificationShortcutPreferences>;
  private readonly saveButtonBindings: NotificationPresenterOptions['saveButtonBindings'];
  private readonly removeButtonBindings: NotificationPresenterOptions['removeButtonBindings'];

  constructor(options: NotificationPresenterOptions = {}) {
    this.notifications = options.notifications ?? chrome.notifications;
    this.markProgrammatic = options.markProgrammatic ?? markProgrammaticClose;
    this.consumeProgrammatic = options.consumeProgrammatic ?? consumeProgrammaticCloseMarker;
    this.notificationIconUrl = options.notificationIconUrl ??
      (() => chrome.runtime.getURL('icons/notification.png'));
    this.mediaIconUrl = options.mediaIconUrl ?? notificationMediaDataUrl;
    this.dismissButtonTitle = options.dismissButtonTitle ??
      (() => chrome.i18n.getMessage('notificationDismissButton') || 'Clear');
    this.moreButtonTitle = options.moreButtonTitle ??
      (() => chrome.i18n.getMessage('notificationMoreButton') || 'More');
    this.loadShortcutPreferences = options.loadShortcutPreferences ??
      (async () => DEFAULT_SHORTCUT_PREFERENCES);
    this.saveButtonBindings = options.saveButtonBindings;
    this.removeButtonBindings = options.removeButtonBindings;
  }

  async present(receipt: NotificationReceipt): Promise<void> {
    if (receipt.kind === 'snapshot') {
      for (const state of receipt.reconciliation.closedStates) {
        await this.removeButtonBindings?.(state.chromeNotificationId);
        await this.closeProgrammatically(state.chromeNotificationId, 'snapshot-reconciliation');
      }
      return;
    }

    const { disposition, state } = receipt.reconciliation;
    if (disposition === 'stale') return;
    if (state.phase === 'removed') {
      await this.removeButtonBindings?.(state.chromeNotificationId);
      await this.closeProgrammatically(state.chromeNotificationId, 'source-notification-removed');
      return;
    }
    await this.presentState(state);
  }

  async presentState(state: MirroredNotificationState): Promise<void> {
    if (state.phase !== 'visible') return;
    const sourceRef = toHex(state.sourceDeviceId).slice(0, 12);
    const preferences = await this.loadShortcutPreferences()
      .catch(() => DEFAULT_SHORTCUT_PREFERENCES);
    const buttons = notificationButtons(state, preferences, {
      dismiss: this.dismissButtonTitle(),
      more: this.moreButtonTitle(),
    });
    await this.saveButtonBindings?.(state.chromeNotificationId, state.revision, buttons);
    const applicationName = state.sourceApplicationName ?? 'Android';
    const options: chrome.notifications.NotificationOptions<true> = {
      type: 'basic',
      iconUrl: await this.resolveIconUrl(state.avatar, state.appIcon),
      title: `${state.title ?? 'Notification'} · ${applicationName} · Android ${sourceRef}`,
      message: state.body ?? '',
      priority: 0,
      requireInteraction: true,
      buttons: buttons.map((button) => ({ title: button.title })),
    };
    const existing = await this.getAll();
    if (existing[state.chromeNotificationId]) {
      const updated = await this.update(state.chromeNotificationId, options);
      if (!updated) await this.create(state.chromeNotificationId, options);
    } else {
      await this.create(state.chromeNotificationId, options);
    }
  }

  private async resolveIconUrl(
    avatar: MirroredNotificationMedia | undefined,
    appIcon: MirroredNotificationMedia | undefined,
  ): Promise<string> {
    for (const media of [avatar, appIcon]) {
      if (media === undefined) continue;
      try {
        const resolved = await this.mediaIconUrl(media);
        if (resolved !== undefined) return resolved;
      } catch {
        // Invalid or unsupported media falls through to the next local icon.
      }
    }
    return this.notificationIconUrl();
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

interface DecodedImage {
  width: number;
  height: number;
  close(): void;
}

export async function notificationMediaDataUrl(
  media: MirroredNotificationMedia,
  decode: (blob: Blob) => Promise<DecodedImage> = (blob) => createImageBitmap(blob),
): Promise<string | undefined> {
  const dimensions = encodedDimensions(media);
  if (dimensions === undefined || dimensions.width !== media.width || dimensions.height !== media.height) {
    return undefined;
  }
  const mimeType = media.mimeType === NotificationMediaMimeType.PNG ? 'image/png' : 'image/webp';
  try {
    const image = await decode(new Blob([media.encodedBytes.slice().buffer as ArrayBuffer], { type: mimeType }));
    try {
      if (image.width !== media.width || image.height !== media.height) return undefined;
    } finally {
      image.close();
    }
    return `data:${mimeType};base64,${toBase64(media.encodedBytes)}`;
  } catch {
    return undefined;
  }
}

function encodedDimensions(media: MirroredNotificationMedia): { width: number; height: number } | undefined {
  const bytes = media.encodedBytes;
  if (media.mimeType === NotificationMediaMimeType.PNG) {
    if (bytes.byteLength < 24 || bytes[0] !== 0x89 || !hasAscii(bytes, 1, 'PNG') ||
        bytes[4] !== 0x0d || bytes[5] !== 0x0a || bytes[6] !== 0x1a || bytes[7] !== 0x0a ||
        readUint32BigEndian(bytes, 8) !== 13 || !hasAscii(bytes, 12, 'IHDR')) return undefined;
    return { width: readUint32BigEndian(bytes, 16), height: readUint32BigEndian(bytes, 20) };
  }
  if (media.mimeType !== NotificationMediaMimeType.WEBP || bytes.byteLength < 30 ||
      !hasAscii(bytes, 0, 'RIFF') || !hasAscii(bytes, 8, 'WEBP')) return undefined;
  if (hasAscii(bytes, 12, 'VP8X')) {
    return {
      width: 1 + readUint24LittleEndian(bytes, 24),
      height: 1 + readUint24LittleEndian(bytes, 27),
    };
  }
  if (hasAscii(bytes, 12, 'VP8L') && bytes[20] === 0x2f) {
    return {
      width: 1 + bytes[21] + ((bytes[22] & 0x3f) << 8),
      height: 1 + (bytes[22] >> 6) + (bytes[23] << 2) + ((bytes[24] & 0x0f) << 10),
    };
  }
  if (hasAscii(bytes, 12, 'VP8 ') && bytes[23] === 0x9d && bytes[24] === 0x01 && bytes[25] === 0x2a) {
    return {
      width: (bytes[26] | (bytes[27] << 8)) & 0x3fff,
      height: (bytes[28] | (bytes[29] << 8)) & 0x3fff,
    };
  }
  return undefined;
}

function readUint32BigEndian(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) |
    (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function readUint24LittleEndian(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16);
}

function hasAscii(bytes: Uint8Array, offset: number, expected: string): boolean {
  return offset + expected.length <= bytes.byteLength &&
    [...expected].every((value, index) => bytes[offset + index] === value.charCodeAt(0));
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let offset = 0; offset < bytes.byteLength; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

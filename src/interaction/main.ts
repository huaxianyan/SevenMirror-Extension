import { localizeDocument } from '../shared/i18n';
import { mountNotificationDetail } from '../shared/notification-detail';
import { MARK_NOTIFICATIONS_VIEWED, openedNotificationReference } from '../shared/viewed-notifications';
import { interactionWindowPlacement } from '../background/notification-interaction';
import type {
  NotificationInteractionSummary,
  ScreenWorkArea,
} from '../background/notification-interaction';

interface InteractionResponse {
  notification?: NotificationInteractionSummary;
}

const detail = requireElement<HTMLElement>('notification-detail');
const empty = requireElement<HTMLElement>('empty');
const status = requireElement<HTMLParagraphElement>('status');

placeInteractionWindow();
localizeDocument();
void loadNotification();

/**
 * The service worker already places this window before creating it, so the common case
 * leaves it untouched. This is the fallback for when it cannot: a browser build without
 * the display permission, or a display lookup that failed.
 *
 * It moves only when the position actually differs, because an unconditional moveTo would
 * reintroduce the very jump the pre-creation placement exists to remove. The tolerance
 * absorbs the one-pixel difference between the requested bounds and the settled frame.
 */
function placeInteractionWindow(): void {
  const { left, top } = interactionWindowPlacement(workArea());
  if (Math.abs(window.screenX - left) <= 2 && Math.abs(window.screenY - top) <= 2) return;
  window.moveTo(left, top);
}

/**
 * Chromium reports the work area origin through availLeft/availTop, which the standard
 * DOM typings do not declare. Both default to the primary display origin.
 */
function workArea(): ScreenWorkArea {
  const currentScreen = window.screen as Screen & { availLeft?: number; availTop?: number };
  return {
    left: currentScreen.availLeft ?? 0,
    top: currentScreen.availTop ?? 0,
    width: currentScreen.availWidth,
    height: currentScreen.availHeight,
  };
}

async function loadNotification(): Promise<void> {
  const chromeNotificationId = new URL(location.href).searchParams.get('notification');
  if (chromeNotificationId === null || chromeNotificationId.length === 0) {
    showUnavailable();
    return;
  }
  const response = await chrome.runtime.sendMessage({
    type: 'get-notification-interaction',
    chromeNotificationId,
  }) as InteractionResponse;
  if (response.notification === undefined) {
    showUnavailable();
    return;
  }
  document.title = response.notification.title || document.title;
  mountNotificationDetail(detail, response.notification);
  detail.hidden = false;
  status.textContent = '';
  await markViewed(response.notification);
}

/**
 * This window shows the detail of one notification, so opening it counts as viewing that
 * notification and drops it from the toolbar badge.
 */
async function markViewed(notification: NotificationInteractionSummary): Promise<void> {
  try {
    await chrome.runtime.sendMessage({
      type: MARK_NOTIFICATIONS_VIEWED,
      notifications: openedNotificationReference(
        notification.chromeNotificationId,
        notification.revision,
      ),
    });
  } catch {
    // A failed badge update must not hide a detail view the user already opened.
  }
}

function showUnavailable(): void {
  detail.hidden = true;
  empty.hidden = false;
  status.textContent = '';
}

function requireElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`Missing interaction element: ${id}`);
  return element as T;
}

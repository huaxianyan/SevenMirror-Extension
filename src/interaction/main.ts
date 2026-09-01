import { localizeDocument } from '../shared/i18n';
import { mountNotificationDetail } from '../shared/notification-detail';
import type { NotificationInteractionSummary } from '../background/notification-interaction';

interface InteractionResponse {
  notification?: NotificationInteractionSummary;
}

const detail = requireElement<HTMLElement>('notification-detail');
const empty = requireElement<HTMLElement>('empty');
const status = requireElement<HTMLParagraphElement>('status');

localizeDocument();
void loadNotification();

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

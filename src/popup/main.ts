import type { ConnectionState } from '../shared/status';
import type { NotificationInteractionSummary } from '../background/notification-interaction';
import { localizeDocument, message } from '../shared/i18n';
import { mountNotificationDetail } from '../shared/notification-detail';

interface PopupNotification extends NotificationInteractionSummary {
  isNew: boolean;
  updatedAtUnixMs: number;
}

interface PopupResponse {
  state: ConnectionState;
  notifications: PopupNotification[];
}

const connectionStatus = requireElement<HTMLParagraphElement>('connection-status');
const count = requireElement<HTMLSpanElement>('notification-count');
const list = requireElement<HTMLDivElement>('notification-list');
const empty = requireElement<HTMLDivElement>('empty');
const emptyTitle = requireElement<HTMLHeadingElement>('empty-title');
const emptyBody = requireElement<HTMLParagraphElement>('empty-body');
const openOptions = requireElement<HTMLButtonElement>('open-options');

localizeDocument();
openOptions.addEventListener('click', () => chrome.runtime.openOptionsPage());
void render();

async function render(): Promise<void> {
  const response = await chrome.runtime.sendMessage({ type: 'get-popup-notifications' }) as PopupResponse;
  connectionStatus.textContent = connectionStateLabel(response.state);
  count.textContent = message('popupNotificationCount', response.notifications.length.toString());
  if (response.notifications.length === 0) {
    renderEmpty(response.state);
    return;
  }

  list.replaceChildren(...response.notifications.map(renderNotification));
  list.hidden = false;
  empty.hidden = true;
  await chrome.runtime.sendMessage({
    type: 'mark-popup-notifications-viewed',
    notifications: response.notifications.map((notification) => ({
      chromeNotificationId: notification.chromeNotificationId,
      revision: notification.revision,
    })),
  });
}

function renderNotification(notification: PopupNotification): HTMLElement {
  const item = document.createElement('details');
  item.className = 'notification-item';
  const summary = document.createElement('summary');
  const heading = document.createElement('span');
  heading.className = 'notification-heading';
  const title = document.createElement('strong');
  title.textContent = notification.title || message('interactionUntitledNotification');
  const meta = document.createElement('span');
  meta.className = 'notification-meta';
  meta.textContent = [
    notification.sourceApplicationName,
    notification.sourceName,
    formatTime(notification.updatedAtUnixMs),
  ].filter((value) => value.length > 0).join(' · ');
  heading.append(title, meta);
  const indicator = document.createElement('span');
  indicator.className = notification.isNew ? 'new-indicator' : 'new-indicator viewed';
  indicator.textContent = notification.isNew ? message('popupNewNotification') : '';
  summary.append(heading, indicator);
  const excerpt = document.createElement('p');
  excerpt.className = 'notification-excerpt';
  excerpt.textContent = notification.body;
  excerpt.hidden = notification.body.length === 0;
  const detail = document.createElement('div');
  detail.className = 'notification-detail';
  item.append(summary, excerpt, detail);
  item.addEventListener('toggle', () => {
    if (item.open && detail.childElementCount === 0) {
      mountNotificationDetail(detail, notification);
    }
  });
  return item;
}

function renderEmpty(state: ConnectionState): void {
  list.hidden = true;
  empty.hidden = false;
  if (state === 'not-configured') {
    emptyTitle.textContent = message('popupSetupRequiredTitle');
    emptyBody.textContent = message('popupSetupRequiredBody');
    return;
  }
  if (state === 'offline') {
    emptyTitle.textContent = message('popupConnectionUnavailableTitle');
    emptyBody.textContent = message('popupConnectionUnavailableBody');
    return;
  }
  emptyTitle.textContent = message('popupNoNotificationsTitle');
  emptyBody.textContent = message(
    state === 'connecting' ? 'popupConnectingBody' : 'popupNoNotificationsBody',
  );
}

function connectionStateLabel(state: ConnectionState): string {
  switch (state) {
    case 'not-configured': return message('connectionNotConfigured');
    case 'offline': return message('connectionOffline');
    case 'connecting': return message('connectionConnecting');
    case 'online': return message('connectionOnline');
  }
}

function formatTime(timestamp: number): string {
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0) return '';
  return new Intl.DateTimeFormat(chrome.i18n.getUILanguage(), {
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(timestamp));
}

function requireElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`Missing popup element: ${id}`);
  return element as T;
}

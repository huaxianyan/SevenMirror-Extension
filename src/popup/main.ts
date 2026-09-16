import type { ConnectionState } from '../shared/status';
import type { NotificationInteractionSummary } from '../background/notification-interaction';
import { localizeDocument, message } from '../shared/i18n';
import { mountNotificationDetail } from '../shared/notification-detail';
import { formatClockTime } from '../shared/time';
import { filterBySource, sourceChoices } from './source-filter';

interface PopupNotification extends NotificationInteractionSummary {
  sourceKey: string;
  isNew: boolean;
  updatedAtUnixMs: number;
}

interface PopupResponse {
  state: ConnectionState;
  notifications: PopupNotification[];
}

const connectionStatus = requireElement<HTMLParagraphElement>('connection-status');
const count = requireElement<HTMLSpanElement>('notification-count');
const sourceFilter = requireElement<HTMLSelectElement>('source-filter');
const listView = requireElement<HTMLElement>('list-view');
const list = requireElement<HTMLDivElement>('notification-list');
const empty = requireElement<HTMLDivElement>('empty');
const emptyTitle = requireElement<HTMLHeadingElement>('empty-title');
const emptyBody = requireElement<HTMLParagraphElement>('empty-body');
const detailView = requireElement<HTMLElement>('detail-view');
const detail = requireElement<HTMLDivElement>('notification-detail');
const backToList = requireElement<HTMLButtonElement>('back-to-list');
const openOptions = requireElement<HTMLButtonElement>('open-options');
let current: PopupResponse = { state: 'connecting', notifications: [] };
let listScrollTop = 0;

localizeDocument();
// 图标按钮没有可见文字，悬停提示补上它去哪，和 aria-label 用同一个键。
backToList.title = message('popupBackToNotifications');
openOptions.addEventListener('click', () => chrome.runtime.openOptionsPage());
sourceFilter.addEventListener('change', renderList);
backToList.addEventListener('click', showList);
void render();

async function render(): Promise<void> {
  current = await chrome.runtime.sendMessage({ type: 'get-popup-notifications' }) as PopupResponse;
  connectionStatus.textContent = connectionStateLabel(current.state);
  renderSourceFilter(current.notifications);
  renderList();
  await chrome.runtime.sendMessage({
    type: 'mark-popup-notifications-viewed',
    notifications: current.notifications.map((notification) => ({
      chromeNotificationId: notification.chromeNotificationId,
      revision: notification.revision,
    })),
  });
}

function renderSourceFilter(notifications: PopupNotification[]): void {
  const previous = sourceFilter.value;
  const sources = sourceChoices(notifications);
  sourceFilter.replaceChildren(option('all', message('popupAllSources')),
    ...sources.map((source) => option(source.key, source.name)));
  sourceFilter.value = sources.some((source) => source.key === previous) ? previous : 'all';
  sourceFilter.disabled = sources.length < 2;
}

function renderList(): void {
  const notifications = filterBySource(current.notifications, sourceFilter.value);
  count.textContent = message('popupNotificationCount', notifications.length.toString());
  list.replaceChildren(...notifications.map(renderNotification));
  list.hidden = notifications.length === 0;
  empty.hidden = notifications.length !== 0;
  if (notifications.length === 0) renderEmpty(current.state, current.notifications.length > 0);
}

function renderNotification(notification: PopupNotification): HTMLElement {
  const item = document.createElement('button');
  item.className = 'notification-item';
  item.type = 'button';
  const heading = document.createElement('span');
  heading.className = 'notification-heading';
  const title = document.createElement('strong');
  title.textContent = notification.title || message('interactionUntitledNotification');
  const meta = document.createElement('span');
  meta.className = 'notification-meta';
  meta.textContent = [
    notification.sourceName,
    notification.sourceApplicationName,
    formatClockTime(notification.updatedAtUnixMs),
  ].filter((value) => value.length > 0).join(' · ');
  const excerpt = document.createElement('span');
  excerpt.className = 'notification-excerpt';
  excerpt.textContent = notification.body;
  excerpt.hidden = notification.body.length === 0;
  heading.append(meta, title, excerpt);
  const indicator = document.createElement('span');
  indicator.className = notification.isNew ? 'new-indicator' : 'new-indicator viewed';
  indicator.textContent = notification.isNew ? message('popupNewNotification') : '';
  item.append(heading, indicator);
  item.addEventListener('click', () => showDetail(notification));
  return item;
}

function showDetail(notification: PopupNotification): void {
  listScrollTop = document.documentElement.scrollTop;
  mountNotificationDetail(detail, notification);
  listView.hidden = true;
  detailView.hidden = false;
  document.documentElement.scrollTop = 0;
  backToList.focus();
}

function showList(): void {
  detailView.hidden = true;
  listView.hidden = false;
  detail.replaceChildren();
  document.documentElement.scrollTop = listScrollTop;
}

function renderEmpty(state: ConnectionState, filtered: boolean): void {
  if (filtered) {
    emptyTitle.textContent = message('popupNoMatchingNotificationsTitle');
    emptyBody.textContent = message('popupNoMatchingNotificationsBody');
    return;
  }
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

function option(value: string, label: string): HTMLOptionElement {
  const result = document.createElement('option');
  result.value = value;
  result.textContent = label;
  return result;
}

function requireElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`Missing popup element: ${id}`);
  return element as T;
}

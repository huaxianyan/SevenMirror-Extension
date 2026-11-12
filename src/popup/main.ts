import type { ConnectionState } from '../shared/status';
import type { NotificationInteractionSummary } from '../background/notification-interaction';
import { localizeDocument, message } from '../shared/i18n';
import { mountNotificationDetail } from '../shared/notification-detail';
import { formatClockTime } from '../shared/time';
import { MARK_NOTIFICATIONS_VIEWED, notificationsToMarkViewed } from '../shared/viewed-notifications';
import { applyCustomCss } from '../shared/custom-css';

interface PopupNotification extends NotificationInteractionSummary {
  sourceKey: string;
  isNew: boolean;
  updatedAtUnixMs: number;
}

interface PopupResponse {
  state: ConnectionState;
  notifications: PopupNotification[];
}

interface HistoryEntry {
  chromeNotificationId: string;
  revision: string;
  sourceKey: string;
  sourceName: string;
  title?: string;
  body?: string;
  applicationName?: string;
  iconKey?: string;
  receivedAtUnixMs: number;
  read: boolean;
  live: boolean;
}

interface HistoryResponse {
  history: HistoryEntry[];
  keepReadHistory: boolean;
  icons: Record<string, string>;
}

type Tab = 'unread' | 'history';

const connectionStatus = requireElement<HTMLParagraphElement>('connection-status');
const searchInput = requireElement<HTMLInputElement>('search-input');
const searchClear = requireElement<HTMLButtonElement>('search-clear');
const resultSummary = requireElement<HTMLParagraphElement>('result-summary');
const listView = requireElement<HTMLElement>('list-view');
const list = requireElement<HTMLDivElement>('notification-list');
const empty = requireElement<HTMLDivElement>('empty');
const emptyTitle = requireElement<HTMLHeadingElement>('empty-title');
const emptyBody = requireElement<HTMLParagraphElement>('empty-body');
const detailView = requireElement<HTMLElement>('detail-view');
const detail = requireElement<HTMLDivElement>('notification-detail');
const openOptions = requireElement<HTMLButtonElement>('open-options');
const markAllRead = requireElement<HTMLButtonElement>('mark-all-read');
const clearHistory = requireElement<HTMLButtonElement>('clear-history');
const tabUnread = requireElement<HTMLButtonElement>('tab-unread');
const tabHistory = requireElement<HTMLButtonElement>('tab-history');
const viewToggle = requireElement<HTMLElement>('tab-unread').parentElement as HTMLElement;

let live: PopupResponse = { state: 'connecting', notifications: [] };
let icons: Record<string, string> = {};
let history: HistoryEntry[] = [];
let tab: Tab = 'unread';
let query = '';
let listScrollTop = 0;

/**
 * A popup is sized to its content, so the panel asks for a fixed height in CSS and then clamps it
 * to the height the window actually got: on a short screen the window caps below the asked-for
 * height, and a body taller than its viewport is what puts a scrollbar beside the header and hands
 * scrolling back to the document.
 */
function clampPopupHeight(): void {
  const height = window.innerHeight;
  if (height > 0) document.documentElement.style.setProperty('--popup-height', `${height}px`);
}

clampPopupHeight();
void applyCustomCss();
localizeDocument();
openOptions.title = message('popupTabSettings');

openOptions.addEventListener('click', () => chrome.runtime.openOptionsPage());
tabUnread.addEventListener('click', () => void switchTab('unread'));
tabHistory.addEventListener('click', () => void switchTab('history'));
searchInput.addEventListener('input', () => {
  query = searchInput.value.trim();
  searchClear.hidden = query.length === 0;
  renderList();
});
searchClear.addEventListener('click', () => {
  searchInput.value = '';
  query = '';
  searchClear.hidden = true;
  searchInput.focus();
  renderList();
});
markAllRead.addEventListener('click', () => void runAction('mark-all-notifications-read'));
clearHistory.addEventListener('click', () => void runAction('clear-notification-history'));
void reload();

async function reload(): Promise<void> {
  const [popup, stored] = await Promise.all([
    chrome.runtime.sendMessage({ type: 'get-popup-notifications' }) as Promise<PopupResponse>,
    chrome.runtime.sendMessage({ type: 'get-popup-history' }) as Promise<HistoryResponse>,
  ]);
  live = popup;
  history = stored.history;
  icons = stored.icons ?? {};
  connectionStatus.textContent = connectionStateLabel(live.state);
  renderList();
}

async function runAction(type: string): Promise<void> {
  await chrome.runtime.sendMessage({ type });
  await reload();
}

async function switchTab(next: Tab): Promise<void> {
  // Switching views has to close the detail first; otherwise the highlight moves while the
  // detail stays on screen.
  if (!detailView.hidden) showList();
  tab = next;
  tabUnread.setAttribute('aria-pressed', next === 'unread' ? 'true' : 'false');
  tabHistory.setAttribute('aria-pressed', next === 'history' ? 'true' : 'false');
  renderList();
}

function renderList(): void {
  const matches = query.length === 0 ? history : searchHistory(history, query);
  const unread = matches.filter((entry) => !entry.read);
  const read = matches.filter((entry) => entry.read);

  markAllRead.hidden = !(tab === 'unread' && query.length === 0 && unread.length > 0);
  clearHistory.hidden = !(tab === 'history' && query.length === 0 && read.length > 0);
  resultSummary.hidden = query.length === 0;
  resultSummary.textContent = query.length === 0
    ? ''
    : message('popupSearchSummary', [String(matches.length), String(unread.length)]);

  const sections = query.length > 0
    ? [
        ...(unread.length === 0 ? [] : [section(message('popupTabUnread'), unread)]),
        ...groupByDay(read).map(([label, entries]) =>
          section(message('popupSearchHistoryGroup', label), entries)),
      ]
    : tab === 'unread'
      ? (unread.length === 0 ? [] : [section(message('popupTabUnread'), unread)])
      : groupByDay(read).map(([label, entries]) => section(label, entries));

  const nodes = sections.flatMap(({ heading, entries }) => [
    groupHeading(heading, message('popupHistoryCount', String(entries.length))),
    ...entries.map((entry) => renderEntry(entry)),
  ]);
  list.replaceChildren(...nodes);
  list.hidden = nodes.length === 0;
  empty.hidden = nodes.length !== 0;
  if (nodes.length === 0) renderEmpty();
}

function section(heading: string, entries: HistoryEntry[]): { heading: string; entries: HistoryEntry[] } {
  return { heading, entries };
}

function groupByDay(entries: HistoryEntry[]): Array<[string, HistoryEntry[]]> {
  const groups = new Map<string, HistoryEntry[]>();
  for (const entry of entries) {
    const label = dayLabel(entry.receivedAtUnixMs);
    const bucket = groups.get(label);
    if (bucket === undefined) groups.set(label, [entry]);
    else bucket.push(entry);
  }
  return [...groups.entries()];
}

function dayLabel(timestamp: number): string {
  const date = new Date(timestamp);
  const today = new Date();
  const yesterday = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
  const sameDay = (left: Date, right: Date): boolean => left.getFullYear() === right.getFullYear() &&
    left.getMonth() === right.getMonth() && left.getDate() === right.getDate();
  if (sameDay(date, today)) return message('popupDayToday');
  if (sameDay(date, yesterday)) return message('popupDayYesterday');
  return new Intl.DateTimeFormat(chrome.i18n.getUILanguage(), {
    month: 'short',
    day: 'numeric',
  }).format(date);
}

function groupHeading(heading: string, count: string): HTMLElement {
  const row = document.createElement('div');
  row.className = 'group-head';
  const name = document.createElement('span');
  name.textContent = heading;
  const total = document.createElement('span');
  total.textContent = count;
  row.append(name, total);
  return row;
}

function renderEntry(entry: HistoryEntry): HTMLElement {
  const card = document.createElement('button');
  card.className = entry.read ? 'card' : 'card unread';
  card.type = 'button';

  const app = document.createElement('span');
  app.className = 'app';
  const iconUrl = entry.iconKey === undefined ? undefined : icons[entry.iconKey];
  if (iconUrl === undefined) {
    app.textContent = appInitial(entry);
  } else {
    // The application icon comes with the notification; the letter stays as the fallback for
    // notifications that never carried one.
    const image = document.createElement('img');
    image.className = 'app-icon';
    image.src = iconUrl;
    image.alt = '';
    app.append(image);
  }

  const body = document.createElement('div');
  body.className = 'card-body';
  const title = document.createElement('div');
  title.className = 'title';
  title.textContent = entry.title || message('interactionUntitledNotification');
  body.append(title);
  if ((entry.body ?? '').length > 0) {
    const preview = document.createElement('div');
    preview.className = 'preview';
    preview.textContent = entry.body ?? '';
    body.append(preview);
  }

  const meta = document.createElement('span');
  meta.className = 'meta';
  meta.textContent = formatClockTime(entry.receivedAtUnixMs);

  card.append(app, body, meta);
  card.addEventListener('click', () => openDetail(entry));
  return card;
}

function appInitial(entry: HistoryEntry): string {
  const name = entry.applicationName ?? entry.sourceName;
  return [...name].slice(0, 1).join('').toUpperCase();
}

function renderEmpty(): void {
  if (live.state === 'not-configured') {
    emptyTitle.textContent = message('popupSetupRequiredTitle');
    emptyBody.textContent = message('popupSetupRequiredBody');
    return;
  }
  if (query.length > 0) {
    emptyTitle.textContent = message('popupSearchEmptyTitle');
    emptyBody.textContent = message('popupSearchEmptyBody');
    return;
  }
  if (tab === 'history') {
    emptyTitle.textContent = message('popupHistoryEmptyTitle');
    emptyBody.textContent = message('popupHistoryEmptyBody');
    return;
  }
  emptyTitle.textContent = message('popupUnreadEmptyTitle');
  emptyBody.textContent = message('popupUnreadEmptyBody');
}

/**
 * The detail sheet opens on the same icon the row showed, so a notification read in the panel does
 * not look like it came from nowhere.
 */
function prependDetailIcon(entry: HistoryEntry): void {
  const iconUrl = entry.iconKey === undefined ? undefined : icons[entry.iconKey];
  if (iconUrl === undefined) return;
  const image = document.createElement('img');
  image.className = 'app-icon';
  image.src = iconUrl;
  image.alt = '';
  // The sheet reads as one notification: icon on the left, and the application line, title and body
  // stacked beside it. Left as separate blocks the icon drifted away from the text it belongs to.
  const column = document.createElement('div');
  column.className = 'detail-column';
  for (const node of Array.from(detail.children).slice(0, 3)) column.append(node);
  const head = document.createElement('div');
  head.className = 'detail-head';
  head.append(image, column);
  detail.prepend(head);
}

function openDetail(entry: HistoryEntry): void {
  const notification = live.notifications.find((candidate) =>
    candidate.chromeNotificationId === entry.chromeNotificationId);
  listScrollTop = listView.scrollTop;
  detailView.hidden = false;
  listView.hidden = true;
  viewToggle.hidden = true;
  detailView.scrollTop = 0;
  if (notification === undefined) {
    // The phone already dropped this one: show what we stored, without reply or dismiss.
    mountNotificationDetail(detail, {
      chromeNotificationId: entry.chromeNotificationId,
      revision: entry.revision,
      sourceName: entry.sourceName,
      sourceApplicationName: entry.applicationName ?? '',
      title: entry.title ?? '',
      body: entry.body ?? '',
      updatedAtUnixMs: entry.receivedAtUnixMs,
      actions: [],
    }, { readOnly: true, onBack: showList });
    prependDetailIcon(entry);
    return;
  }
  mountNotificationDetail(detail, notification, { onBack: showList });
  prependDetailIcon(entry);
  void markViewed(notification);
}

function showList(): void {
  detailView.hidden = true;
  listView.hidden = false;
  viewToggle.hidden = false;
  listView.scrollTop = listScrollTop;
  void reload();
}

/**
 * Opening a notification is what marks it read, and a read notification moves out of the unread
 * list into history. The badge keeps counting what is still unread.
 */
async function markViewed(notification: PopupNotification): Promise<void> {
  const notifications = notificationsToMarkViewed(
    live.notifications,
    notification.chromeNotificationId,
  );
  if (notifications.length === 0) return;
  notification.isNew = false;
  await chrome.runtime.sendMessage({ type: MARK_NOTIFICATIONS_VIEWED, notifications });
  await reload();
}

function searchHistory(entries: HistoryEntry[], needle: string): HistoryEntry[] {
  const lowered = needle.toLocaleLowerCase();
  return entries.filter((entry) =>
    (entry.title ?? '').toLocaleLowerCase().includes(lowered) ||
    (entry.body ?? '').toLocaleLowerCase().includes(lowered));
}

function connectionStateLabel(state: ConnectionState): string {
  switch (state) {
    case 'online': return message('statusOnline');
    case 'connecting': return message('statusConnecting');
    case 'offline': return message('statusOffline');
    default: return message('statusNotConfigured');
  }
}

function requireElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`Missing element: ${id}`);
  return element as T;
}

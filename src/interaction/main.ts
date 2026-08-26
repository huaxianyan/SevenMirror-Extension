import { localizeDocument, message } from '../shared/i18n';
import type { NotificationInteractionSummary } from '../background/notification-interaction';

interface InteractionResponse {
  notification?: NotificationInteractionSummary;
}

interface OperationResponse {
  outcome: 'sent' | 'queued' | 'unavailable' | 'changed';
}

const source = requireElement<HTMLParagraphElement>('source');
const notificationCard = requireElement<HTMLElement>('notification');
const notificationTitle = requireElement<HTMLHeadingElement>('notification-title');
const notificationBody = requireElement<HTMLParagraphElement>('notification-body');
const actionsSection = requireElement<HTMLElement>('actions-section');
const actions = requireElement<HTMLDivElement>('actions');
const dismiss = requireElement<HTMLButtonElement>('dismiss');
const empty = requireElement<HTMLElement>('empty');
const status = requireElement<HTMLParagraphElement>('status');
let current: NotificationInteractionSummary | undefined;

localizeDocument();

void loadNotification();

async function loadNotification(): Promise<void> {
  const chromeNotificationId = new URL(location.href).searchParams.get('notification');
  if (chromeNotificationId === null || chromeNotificationId.length === 0) {
    showUnavailable();
    return;
  }
  const response = (await chrome.runtime.sendMessage({
    type: 'get-notification-interaction',
    chromeNotificationId,
  })) as InteractionResponse;
  if (response.notification === undefined) {
    showUnavailable();
    return;
  }
  current = response.notification;
  renderNotification(response.notification);
}

function renderNotification(notification: NotificationInteractionSummary): void {
  document.title = notification.title || message('interactionPageTitle');
  source.textContent = message('interactionSource', notification.sourceName);
  notificationTitle.textContent = notification.title || message('interactionUntitledNotification');
  notificationBody.textContent = notification.body;
  notificationBody.hidden = notification.body.length === 0;
  actions.replaceChildren(...notification.actions.map(renderAction));
  if (notification.actions.length === 0) {
    const noActions = document.createElement('p');
    noActions.className = 'status';
    noActions.textContent = message('interactionNoSourceActions');
    actions.append(noActions);
  }
  dismiss.addEventListener('click', () => void invoke({ operation: 'dismiss' }));
  notificationCard.hidden = false;
  actionsSection.hidden = false;
  status.textContent = '';
}

function renderAction(action: NotificationInteractionSummary['actions'][number]): HTMLElement {
  if (action.requiresTextInput) {
    const container = document.createElement('div');
    container.className = 'input-action';
    const title = document.createElement('strong');
    title.textContent = action.title;
    const hint = document.createElement('p');
    hint.textContent = message('interactionReplyNextStep');
    container.append(title, hint);
    return container;
  }
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = action.title;
  button.addEventListener('click', () => void invoke({
    operation: 'action',
    actionId: action.actionId,
  }));
  return button;
}

async function invoke(
  operation: { operation: 'dismiss' } | { operation: 'action'; actionId: string },
): Promise<void> {
  if (current === undefined) return;
  setControlsDisabled(true);
  status.textContent = message('interactionSending');
  const response = (await chrome.runtime.sendMessage({
    type: 'invoke-notification-interaction',
    chromeNotificationId: current.chromeNotificationId,
    revision: current.revision,
    ...operation,
  })) as OperationResponse;
  switch (response.outcome) {
    case 'sent':
      status.textContent = message('interactionRequestSent');
      return;
    case 'queued':
      status.textContent = message('interactionRequestQueued');
      return;
    case 'changed':
      current = undefined;
      notificationCard.hidden = true;
      actionsSection.hidden = true;
      empty.hidden = false;
      status.textContent = message('interactionChanged');
      return;
    case 'unavailable':
      status.textContent = message('interactionRequestUnavailable');
      setControlsDisabled(false);
  }
}

function showUnavailable(): void {
  current = undefined;
  notificationCard.hidden = true;
  actionsSection.hidden = true;
  empty.hidden = false;
  status.textContent = '';
}

function setControlsDisabled(disabled: boolean): void {
  actions.querySelectorAll<HTMLButtonElement>('button').forEach((button) => {
    button.disabled = disabled;
  });
  dismiss.disabled = disabled;
}

function requireElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`Missing interaction element: ${id}`);
  return element as T;
}

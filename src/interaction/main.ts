import { localizeDocument, message } from '../shared/i18n';
import {
  validateReplyText,
  type NotificationInteractionSummary,
} from '../background/notification-interaction';

interface InteractionResponse {
  notification?: NotificationInteractionSummary;
}

interface OperationResponse {
  outcome: 'sent' | 'queued' | 'awaiting-result' | 'unavailable' | 'changed';
  idempotencyKey?: string;
}

interface ReplyOperationResponse {
  state: 'pending' | 'succeeded' | 'changed' | 'failed' | 'unknown' | 'unavailable';
}

const source = requireElement<HTMLParagraphElement>('source');
const sourceApplication = requireElement<HTMLParagraphElement>('source-application');
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
  sourceApplication.textContent = notification.sourceApplicationName;
  sourceApplication.hidden = notification.sourceApplicationName.length === 0;
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
    const container = document.createElement('form');
    container.className = 'input-action';
    const label = document.createElement('label');
    label.textContent = action.title;
    const input = document.createElement('textarea');
    input.rows = 3;
    input.placeholder = message('interactionReplyPlaceholder');
    input.disabled = !action.allowsFreeFormInput;
    if (!action.allowsFreeFormInput) input.dataset.permanentlyDisabled = 'true';
    label.append(input);
    const hint = document.createElement('p');
    hint.textContent = action.allowsFreeFormInput
      ? message('interactionReplyLimit')
      : message('interactionReplyOnAndroid');
    const submit = document.createElement('button');
    submit.type = 'submit';
    submit.textContent = message('interactionSendReply');
    submit.disabled = !action.allowsFreeFormInput;
    if (!action.allowsFreeFormInput) submit.dataset.permanentlyDisabled = 'true';
    container.addEventListener('submit', (event) => {
      event.preventDefault();
      const validation = validateReplyText(input.value);
      if (validation !== 'valid') {
        status.textContent = message(validation === 'too-long'
          ? 'interactionReplyTooLong'
          : 'interactionReplyRequired');
        input.focus();
        return;
      }
      void invoke({
        operation: 'reply',
        actionId: action.actionId,
        replyText: input.value,
      });
    });
    container.append(label, hint, submit);
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
  operation:
    | { operation: 'dismiss' }
    | { operation: 'action'; actionId: string }
    | { operation: 'reply'; actionId: string; replyText: string },
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
    case 'awaiting-result':
      if (response.idempotencyKey === undefined) {
        status.textContent = message('interactionReplyUnknown');
        return;
      }
      status.textContent = message('interactionReplyWaiting');
      await waitForReplyResult(response.idempotencyKey);
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

async function waitForReplyResult(idempotencyKey: string): Promise<void> {
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    const response = (await chrome.runtime.sendMessage({
      type: 'get-notification-interaction-operation',
      idempotencyKey,
    })) as ReplyOperationResponse;
    switch (response.state) {
      case 'pending':
        await new Promise((resolve) => setTimeout(resolve, 250));
        continue;
      case 'succeeded':
        status.textContent = message('interactionReplySucceeded');
        return;
      case 'changed':
        status.textContent = message('interactionChanged');
        return;
      case 'failed':
        status.textContent = message('interactionReplyFailed');
        return;
      case 'unknown':
      case 'unavailable':
        status.textContent = message('interactionReplyUnknown');
        return;
    }
  }
  status.textContent = message('interactionReplyUnknown');
}

function showUnavailable(): void {
  current = undefined;
  notificationCard.hidden = true;
  actionsSection.hidden = true;
  empty.hidden = false;
  status.textContent = '';
}

function setControlsDisabled(disabled: boolean): void {
  actions.querySelectorAll<HTMLButtonElement | HTMLTextAreaElement>('button, textarea')
    .forEach((control) => {
      control.disabled = disabled || control.dataset.permanentlyDisabled === 'true';
    });
  dismiss.disabled = disabled;
}

function requireElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`Missing interaction element: ${id}`);
  return element as T;
}

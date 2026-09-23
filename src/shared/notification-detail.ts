import type {
  NotificationInteractionSummary,
  NotificationOperationLookup,
  NotificationOutcome,
  NotificationPresence,
} from '../background/notification-interaction';
import {
  validateReplyText,
  waitForNotificationOutcome,
} from '../background/notification-interaction';
import { message } from './i18n';
import { notificationActionFailureKey } from './notification-action-failure';
import { formatClockTime } from './time';

type NotificationOperation =
  | { operation: 'dismiss' }
  | { operation: 'action'; actionId: string }
  | { operation: 'reply'; actionId: string; replyText: string };

interface OperationResponse {
  outcome: 'sent' | 'queued' | 'awaiting-result' | 'unavailable' | 'changed';
  idempotencyKey?: string;
}

interface InteractionLookupResponse {
  notification?: NotificationInteractionSummary;
  lookupFailed?: boolean;
}

export function mountNotificationDetail(
  container: HTMLElement,
  notification: NotificationInteractionSummary,
): void {
  container.classList.add('notification-detail');
  const source = element('p', 'notification-detail-source');
  source.textContent = message('interactionSource', notification.sourceName);
  // Application and arrival time share one line. The row is otherwise empty for a mirror
  // with neither, and a third grey line above the title was too much.
  const application = element('p', 'notification-detail-application');
  const meta = [
    notification.sourceApplicationName,
    formatClockTime(notification.updatedAtUnixMs),
  ].filter((part) => part.length > 0);
  application.textContent = meta.join(' · ');
  application.hidden = meta.length === 0;
  const title = element('h2', 'notification-detail-title');
  title.textContent = notification.title || message('interactionUntitledNotification');
  const body = element('p', 'notification-detail-body');
  body.textContent = notification.body;
  body.hidden = notification.body.length === 0;
  const actions = element('div', 'notification-detail-actions');
  const status = element('p', 'notification-detail-status');
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');

  const controls: Array<HTMLButtonElement | HTMLTextAreaElement> = [];
  const lookupPresence = async (): Promise<NotificationPresence> => {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'get-notification-interaction',
        chromeNotificationId: notification.chromeNotificationId,
      }) as InteractionLookupResponse;
      if (response.lookupFailed) return 'lookup-failed';
      return response.notification === undefined ? 'removed' : 'present';
    } catch {
      return 'lookup-failed';
    }
  };
  const lookupOperation = async (idempotencyKey: string): Promise<NotificationOperationLookup> => {
    try {
      return await chrome.runtime.sendMessage({
        type: 'get-notification-interaction-operation',
        idempotencyKey,
      }) as NotificationOperationLookup;
    } catch {
      return { state: 'unavailable' };
    }
  };
  /**
   * Says what the phone answered. A refusal is the only outcome that re-enables the controls,
   * because it is the phone's final word: acting again is then a new operation instead of a
   * repeat of one that may still be on its way. The remaining outcomes all mean "the phone has
   * not finished", which a second click would only duplicate.
   */
  const reportOutcome = (outcome: NotificationOutcome): void => {
    switch (outcome.kind) {
      case 'removed':
        window.close();
        return;
      case 'failed':
        status.textContent = message(notificationActionFailureKey(outcome.detail));
        setDisabled(controls, false);
        return;
      case 'changed':
        status.textContent = message('interactionChanged');
        return;
      case 'unknown':
        status.textContent = message('interactionResultUnknown');
        return;
      case 'timeout':
        status.textContent = message('interactionResultPending');
        return;
    }
  };
  const watchOutcome = (idempotencyKey?: string): void => {
    void waitForNotificationOutcome(
      lookupPresence,
      idempotencyKey === undefined ? undefined : () => lookupOperation(idempotencyKey),
      () => new Promise((resolve) => window.setTimeout(resolve, 250)),
    ).then(reportOutcome);
  };
  const invoke = async (operation: NotificationOperation): Promise<void> => {
    setDisabled(controls, true);
    status.textContent = message('interactionSending');
    const response = await chrome.runtime.sendMessage({
      type: 'invoke-notification-interaction',
      chromeNotificationId: notification.chromeNotificationId,
      revision: notification.revision,
      ...operation,
    }) as OperationResponse;
    switch (response.outcome) {
      case 'sent':
        status.textContent = message('interactionRequestSent');
        watchOutcome(response.idempotencyKey);
        return;
      case 'queued':
        status.textContent = message('interactionRequestQueued');
        watchOutcome(response.idempotencyKey);
        return;
      case 'changed':
        status.textContent = message('interactionChanged');
        return;
      case 'unavailable':
        status.textContent = message('interactionRequestUnavailable');
        setDisabled(controls, false);
        return;
      case 'awaiting-result': {
        if (response.idempotencyKey === undefined) {
          status.textContent = message('interactionReplyUnknown');
          return;
        }
        status.textContent = message('interactionReplyWaiting');
        const result = await waitForReplyResult(response.idempotencyKey);
        status.textContent = message(result);
        if (result === 'interactionReplySucceeded') watchOutcome();
        else if (result === 'interactionReplyFailed') setDisabled(controls, false);
        return;
      }
    }
  };

  for (const action of notification.actions) {
    if (action.requiresTextInput) {
      const form = document.createElement('form');
      form.className = 'notification-detail-reply';
      const label = document.createElement('label');
      label.textContent = action.title;
      const input = document.createElement('textarea');
      input.rows = 3;
      input.placeholder = message('interactionReplyPlaceholder');
      input.disabled = !action.allowsFreeFormInput;
      input.dataset.permanentlyDisabled = String(!action.allowsFreeFormInput);
      label.append(input);
      const hint = element('p', 'notification-detail-hint');
      hint.textContent = action.allowsFreeFormInput
        ? message('interactionReplyLimit')
        : message('interactionReplyOnAndroid');
      const submit = document.createElement('button');
      submit.type = 'submit';
      submit.textContent = message('interactionSendReply');
      submit.disabled = !action.allowsFreeFormInput;
      submit.dataset.permanentlyDisabled = String(!action.allowsFreeFormInput);
      controls.push(input, submit);
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        const validation = validateReplyText(input.value);
        if (validation !== 'valid') {
          status.textContent = message(validation === 'too-long'
            ? 'interactionReplyTooLong'
            : 'interactionReplyRequired');
          input.focus();
          return;
        }
        const replyText = input.value;
        input.value = '';
        void invoke({ operation: 'reply', actionId: action.actionId, replyText });
      });
      form.append(label, hint, submit);
      actions.append(form);
      continue;
    }
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = action.title;
    button.addEventListener('click', () => void invoke({
      operation: 'action',
      actionId: action.actionId,
    }));
    controls.push(button);
    actions.append(button);
  }
  if (notification.actions.length === 0) {
    const empty = element('p', 'notification-detail-hint');
    empty.textContent = message('interactionNoSourceActions');
    actions.append(empty);
  }
  const dismiss = document.createElement('button');
  dismiss.type = 'button';
  dismiss.className = 'notification-detail-dismiss';
  dismiss.textContent = message('notificationDismissButton');
  dismiss.addEventListener('click', () => void invoke({ operation: 'dismiss' }));
  controls.push(dismiss);

  container.replaceChildren(source, application, title, body, actions, dismiss, status);
}

async function waitForReplyResult(idempotencyKey: string): Promise<string> {
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    const response = await chrome.runtime.sendMessage({
      type: 'get-notification-interaction-operation',
      idempotencyKey,
    }) as NotificationOperationLookup;
    switch (response.state) {
      case 'pending':
        await new Promise((resolve) => setTimeout(resolve, 250));
        continue;
      case 'succeeded': return 'interactionReplySucceeded';
      case 'changed': return 'interactionChanged';
      case 'failed': return 'interactionReplyFailed';
      case 'unknown':
      case 'unavailable': return 'interactionReplyUnknown';
    }
  }
  return 'interactionReplyUnknown';
}

function setDisabled(
  controls: Array<HTMLButtonElement | HTMLTextAreaElement>,
  disabled: boolean,
): void {
  for (const control of controls) {
    control.disabled = disabled || control.dataset.permanentlyDisabled === 'true';
  }
}

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className: string,
): HTMLElementTagNameMap[K] {
  const value = document.createElement(tag);
  value.className = className;
  return value;
}

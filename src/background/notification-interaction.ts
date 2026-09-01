import type {
  MirroredNotificationAction,
  MirroredNotificationState,
} from '../crypto/indexeddb-notification-state-store';

export interface NotificationInteractionSummary {
  chromeNotificationId: string;
  revision: string;
  sourceName: string;
  sourceApplicationName: string;
  title: string;
  body: string;
  actions: Array<{
    actionId: string;
    title: string;
    requiresTextInput: boolean;
    allowsFreeFormInput: boolean;
  }>;
}

export function interactionPageUrl(extensionBaseUrl: string, chromeNotificationId: string): string {
  const url = new URL('interaction/index.html', extensionBaseUrl);
  url.searchParams.set('notification', chromeNotificationId);
  return url.href;
}

export function interactionSummary(
  state: MirroredNotificationState,
  sourceName: string,
): NotificationInteractionSummary {
  return {
    chromeNotificationId: state.chromeNotificationId,
    revision: state.revision,
    sourceName,
    sourceApplicationName: state.sourceApplicationName ?? '',
    title: state.title ?? '',
    body: state.body ?? '',
    actions: (state.actions ?? []).map((action) => ({
      actionId: toHex(action.actionId),
      title: action.title,
      requiresTextInput: action.requiresTextInput,
      allowsFreeFormInput: action.allowsFreeFormInput,
    })),
  };
}

export function validateReplyText(value: string): 'valid' | 'required' | 'too-long' {
  if (value.trim().length === 0) return 'required';
  return new TextEncoder().encode(value).byteLength <= 4_000 ? 'valid' : 'too-long';
}

export function resolveCurrentAction(
  state: MirroredNotificationState,
  expectedRevision: string,
  actionIdHex: string,
): MirroredNotificationAction | undefined {
  if (state.phase !== 'visible' || state.revision !== expectedRevision ||
      !/^[0-9a-f]{32}$/.test(actionIdHex)) return undefined;
  return (state.actions ?? []).find((action) => toHex(action.actionId) === actionIdHex);
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

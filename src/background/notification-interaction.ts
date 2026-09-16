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
  /**
   * When the mirror arrived, from the same field the popup list sorts and prints by
   * (`MirroredNotificationPresentation.updatedAtUnixMs` is this same value), so the detail
   * view cannot disagree with the row the user clicked.
   */
  updatedAtUnixMs: number;
  actions: Array<{
    actionId: string;
    title: string;
    requiresTextInput: boolean;
    allowsFreeFormInput: boolean;
  }>;
}

export interface WindowSize {
  width: number;
  height: number;
}

export interface ScreenWorkArea {
  left: number;
  top: number;
  width: number;
  height: number;
}

export interface InteractionWindowPlacement {
  left: number;
  top: number;
}

/** The part of a display description that window placement depends on. */
export interface DisplayWorkArea {
  isPrimary: boolean;
  workArea: ScreenWorkArea;
}

/** Gap kept between the interaction window and the work area edges. */
export const interactionWindowMargin = 16;

export const interactionWindowSize: WindowSize = { width: 440, height: 680 };

export function interactionPageUrl(extensionBaseUrl: string, chromeNotificationId: string): string {
  const url = new URL('interaction/index.html', extensionBaseUrl);
  url.searchParams.set('notification', chromeNotificationId);
  return url.href;
}

/**
 * Resolves the work area the interaction window anchors to, so the service worker can
 * place the window before it is created instead of letting it appear top-left first.
 */
export function interactionWorkArea(
  displays: readonly DisplayWorkArea[],
): ScreenWorkArea | undefined {
  return (displays.find((display) => display.isPrimary) ?? displays[0])?.workArea;
}

export function interactionWindowOptions(
  url: string,
  workArea?: ScreenWorkArea,
): chrome.windows.CreateData {
  const options: chrome.windows.CreateData = {
    url,
    type: 'popup',
    focused: true,
    ...interactionWindowSize,
  };
  if (workArea === undefined) return options;
  return { ...options, ...interactionWindowPlacement(workArea) };
}

/**
 * Anchors the interaction window to the bottom-right corner of the work area, so it
 * opens next to the notification that was just clicked instead of the default
 * top-left cascade. A window larger than the work area falls back to its origin,
 * which keeps the title bar reachable and satisfies the minimum-visible-bounds
 * requirement Chromium enforces on window creation and moves.
 */
export function interactionWindowPlacement(
  workArea: ScreenWorkArea,
  windowSize: WindowSize = interactionWindowSize,
  margin = interactionWindowMargin,
): InteractionWindowPlacement {
  return {
    left: workArea.left + Math.max(0, workArea.width - windowSize.width - margin),
    top: workArea.top + Math.max(0, workArea.height - windowSize.height - margin),
  };
}

export type NotificationPresence = 'present' | 'removed' | 'lookup-failed';

export async function waitForNotificationRemoval(
  lookup: () => Promise<NotificationPresence>,
  pause: () => Promise<void>,
  maximumAttempts = 120,
): Promise<boolean> {
  for (let attempt = 0; attempt < maximumAttempts; attempt += 1) {
    const presence = await lookup();
    if (presence === 'removed') return true;
    await pause();
  }
  return false;
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
    updatedAtUnixMs: state.receivedAtUnixMs ?? 0,
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

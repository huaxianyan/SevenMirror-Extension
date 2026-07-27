import { decideClose, type CloseDecision } from '../shared/close-policy';

const LAST_DEBUG_NOTIFICATION_KEY = 'spike003.lastDebugNotificationId';
const PROGRAMMATIC_MARKERS_KEY = 'spike003.programmaticCloseMarkers';
const LAST_CLOSE_AUDIT_KEY = 'spike003.lastCloseAudit';
const WORKER_START_COUNT_KEY = 'spike003.workerStartCount';
const MARKER_TTL_MS = 5 * 60 * 1_000;

interface ProgrammaticMarker {
  reason: string;
  createdAt: number;
}

type ProgrammaticMarkers = Record<string, ProgrammaticMarker>;

export interface CloseAudit {
  notificationId: string;
  byUser: boolean;
  hadProgrammaticMarker: boolean;
  decision: CloseDecision;
  observedAt: number;
}

export async function recordWorkerStart(): Promise<void> {
  const stored = await chrome.storage.local.get(WORKER_START_COUNT_KEY);
  const current = Number(stored[WORKER_START_COUNT_KEY] ?? 0);
  await chrome.storage.local.set({ [WORKER_START_COUNT_KEY]: current + 1 });
  await pruneExpiredMarkers();
}

export async function createLifecycleTestNotification(): Promise<string> {
  const id = `spike003:lifecycle:${Date.now()}`;
  await chrome.notifications.create(id, {
    type: 'basic',
    iconUrl: chrome.runtime.getURL('icons/notification.png'),
    title: 'Phase 0 lifecycle test',
    message: 'Close this notification manually, or clear it from the extension popup.',
    priority: 0,
  });
  await chrome.storage.local.set({ [LAST_DEBUG_NOTIFICATION_KEY]: id });
  return id;
}

export async function clearLifecycleTestNotification(): Promise<boolean> {
  const stored = await chrome.storage.local.get(LAST_DEBUG_NOTIFICATION_KEY);
  const id = stored[LAST_DEBUG_NOTIFICATION_KEY];
  if (typeof id !== 'string') {
    return false;
  }

  await markProgrammaticClose(id, 'popup-test-clear');
  const cleared = await clearNotification(id);
  if (!cleared) {
    await consumeProgrammaticMarker(id);
  }
  return cleared;
}

export async function handleNotificationClosed(notificationId: string, byUser: boolean): Promise<void> {
  if (!notificationId.startsWith('spike003:')) {
    return;
  }

  const marker = await consumeProgrammaticMarker(notificationId);
  const decision = decideClose({
    byUser,
    hasProgrammaticMarker: marker !== undefined,
  });
  const audit: CloseAudit = {
    notificationId,
    byUser,
    hadProgrammaticMarker: marker !== undefined,
    decision,
    observedAt: Date.now(),
  };
  await chrome.storage.local.set({ [LAST_CLOSE_AUDIT_KEY]: audit });
}

export async function getLifecycleSpikeStatus(): Promise<{
  workerStartCount: number;
  lastCloseAudit?: CloseAudit;
}> {
  const stored = await chrome.storage.local.get([WORKER_START_COUNT_KEY, LAST_CLOSE_AUDIT_KEY]);
  return {
    workerStartCount: Number(stored[WORKER_START_COUNT_KEY] ?? 0),
    lastCloseAudit: stored[LAST_CLOSE_AUDIT_KEY] as CloseAudit | undefined,
  };
}

function clearNotification(notificationId: string): Promise<boolean> {
  return new Promise((resolve) => {
    chrome.notifications.clear(notificationId, resolve);
  });
}

async function markProgrammaticClose(notificationId: string, reason: string): Promise<void> {
  const stored = await chrome.storage.local.get(PROGRAMMATIC_MARKERS_KEY);
  const markers = asMarkers(stored[PROGRAMMATIC_MARKERS_KEY]);
  markers[notificationId] = { reason, createdAt: Date.now() };
  await chrome.storage.local.set({ [PROGRAMMATIC_MARKERS_KEY]: markers });
}

async function consumeProgrammaticMarker(
  notificationId: string,
): Promise<ProgrammaticMarker | undefined> {
  const stored = await chrome.storage.local.get(PROGRAMMATIC_MARKERS_KEY);
  const markers = asMarkers(stored[PROGRAMMATIC_MARKERS_KEY]);
  const marker = markers[notificationId];
  if (marker) {
    delete markers[notificationId];
    await chrome.storage.local.set({ [PROGRAMMATIC_MARKERS_KEY]: markers });
  }
  return marker;
}

async function pruneExpiredMarkers(): Promise<void> {
  const stored = await chrome.storage.local.get(PROGRAMMATIC_MARKERS_KEY);
  const markers = asMarkers(stored[PROGRAMMATIC_MARKERS_KEY]);
  const cutoff = Date.now() - MARKER_TTL_MS;
  const retained = Object.fromEntries(
    Object.entries(markers).filter(([, marker]) => marker.createdAt >= cutoff),
  );
  await chrome.storage.local.set({ [PROGRAMMATIC_MARKERS_KEY]: retained });
}

function asMarkers(value: unknown): ProgrammaticMarkers {
  return typeof value === 'object' && value !== null
    ? { ...(value as ProgrammaticMarkers) }
    : {};
}

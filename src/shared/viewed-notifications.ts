/**
 * The toolbar badge counts new notifications the user has not actually opened, so a reference
 * is produced only for a notification the user opened. Listing the Popup is not opening:
 * `notificationsToMarkViewed` returns nothing when no notification was opened, which is what
 * keeps a visit to the Popup from clearing the badge for rows the user never looked at.
 *
 * The rule comes from PRODUCT_REDESIGN.md — "only a notification the user actually saw is
 * marked viewed" — and PRD CHR-007, which requires that opening the Popup must not clear the
 * count of notifications that are not visible.
 */
export const MARK_NOTIFICATIONS_VIEWED = 'mark-notifications-viewed';

export interface ViewedNotificationCandidate {
  chromeNotificationId: string;
  revision: string;
  isNew: boolean;
}

export interface ViewedNotificationReference {
  chromeNotificationId: string;
  revision: string;
}

/**
 * References to mark viewed for one popup visit or one opened detail view.
 *
 * `openedChromeNotificationId` is the notification the user opened, or `undefined` while the
 * user is only looking at the list. A reference is returned only when that notification is
 * still in the list, is not already viewed, and the caller can name its current revision: the
 * store drops a reference whose revision moved on, and reporting the viewed revision for a
 * stale row would hide the newer one the user has not seen yet.
 */
export function notificationsToMarkViewed(
  notifications: readonly ViewedNotificationCandidate[],
  openedChromeNotificationId: string | undefined,
): ViewedNotificationReference[] {
  if (openedChromeNotificationId === undefined) return [];
  const opened = notifications.find(
    (notification) => notification.chromeNotificationId === openedChromeNotificationId,
  );
  if (opened === undefined || !opened.isNew) return [];
  return [{ chromeNotificationId: opened.chromeNotificationId, revision: opened.revision }];
}

/**
 * The single reference for a detail view that was opened outside the Popup list, where no
 * `isNew` flag is known. Marking an already viewed notification is idempotent in the store.
 */
export function openedNotificationReference(
  chromeNotificationId: string,
  revision: string,
): ViewedNotificationReference[] {
  return [{ chromeNotificationId, revision }];
}

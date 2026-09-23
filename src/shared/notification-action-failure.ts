/**
 * Translates the refusal Android reports in `ActionResult.detail` into the localized message
 * that explains it. Details are protocol identifiers, never user-facing text, so every one of
 * them has to be mapped here before it can be shown.
 */
export function notificationActionFailureKey(detail: string | undefined): string {
  switch (detail) {
    case 'NOTIFICATION_STILL_ONGOING':
      return 'interactionClearRefusedOngoing';
    case 'LISTENER_NOT_CONNECTED':
      return 'interactionClearRefusedListener';
    default:
      return 'interactionClearRefused';
  }
}

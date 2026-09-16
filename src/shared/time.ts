/**
 * The popup list and the notification detail show the same arrival time, so both format
 * it through here. A non-positive or non-integer stamp yields an empty string rather than
 * "Invalid Date" — mirrors can arrive with no receive time recorded.
 */
export function formatClockTime(timestamp: number): string {
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0) return '';
  return new Intl.DateTimeFormat(chrome.i18n.getUILanguage(), {
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(timestamp));
}

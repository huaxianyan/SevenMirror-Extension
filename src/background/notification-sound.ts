import { PLAY_NOTIFICATION_SOUND } from '../shared/notification-sound';

const OFFSCREEN_PAGE = 'offscreen/index.html';
let creating: Promise<void> | undefined;

/** Sound failures leave notification delivery available; preview reports the outcome. */
export async function playNotificationSound(): Promise<boolean> {
  try {
    const contexts = await chrome.runtime.getContexts({
      contextTypes: [chrome.runtime.ContextType.OFFSCREEN_DOCUMENT],
      documentUrls: [chrome.runtime.getURL(OFFSCREEN_PAGE)],
    });
    if (contexts.length === 0) {
      creating ??= chrome.offscreen.createDocument({
        url: OFFSCREEN_PAGE,
        reasons: [chrome.offscreen.Reason.AUDIO_PLAYBACK],
        justification: 'Play the notification sound selected by the user.',
      }).finally(() => { creating = undefined; });
      await creating;
    }
    const response = await chrome.runtime.sendMessage({ type: PLAY_NOTIFICATION_SOUND });
    return response?.played === true;
  } catch {
    return false;
  }
}

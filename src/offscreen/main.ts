import { NOTIFICATION_SOUND_FILE, PLAY_NOTIFICATION_SOUND } from '../shared/notification-sound';

const audio = new Audio(chrome.runtime.getURL(NOTIFICATION_SOUND_FILE));
let starting: Promise<void> | undefined;

async function play(): Promise<void> {
  if (starting !== undefined) return starting;
  if (!audio.paused) return;
  audio.currentTime = 0;
  starting = audio.play().finally(() => { starting = undefined; });
  await starting;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || request?.type !== PLAY_NOTIFICATION_SOUND) return false;
  void play().then(
    () => sendResponse({ played: true }),
    () => sendResponse({ played: false }),
  );
  return true;
});

import { DEFAULT_CONNECTION_STATE } from '../shared/status';

const CONNECTION_STATE_KEY = 'connectionState';

chrome.runtime.onInstalled.addListener(async () => {
  const stored = await chrome.storage.local.get(CONNECTION_STATE_KEY);
  if (stored[CONNECTION_STATE_KEY] === undefined) {
    await chrome.storage.local.set({ [CONNECTION_STATE_KEY]: DEFAULT_CONNECTION_STATE });
  }
});

chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
  if (typeof message === 'object' && message !== null && 'type' in message && message.type === 'get-status') {
    chrome.storage.local.get(CONNECTION_STATE_KEY).then((stored) => {
      sendResponse({ state: stored[CONNECTION_STATE_KEY] ?? DEFAULT_CONNECTION_STATE });
    });
    return true;
  }
  return false;
});

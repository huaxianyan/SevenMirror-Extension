import { connectionLabel, type ConnectionState } from '../shared/status';

const status = document.querySelector<HTMLParagraphElement>('#status');
const openOptions = document.querySelector<HTMLButtonElement>('#open-options');

async function renderStatus(): Promise<void> {
  const response = (await chrome.runtime.sendMessage({ type: 'get-status' })) as {
    state: ConnectionState;
  };
  if (status) {
    status.textContent = `Status: ${connectionLabel(response.state)}`;
  }
}

openOptions?.addEventListener('click', () => chrome.runtime.openOptionsPage());

void renderStatus();

import { connectionLabel, type ConnectionState } from '../shared/status';
import type { CloseAudit } from '../background/lifecycle-spike';

interface StatusResponse {
  state: ConnectionState;
  lifecycle: {
    workerStartCount: number;
    lastCloseAudit?: CloseAudit;
  };
}

const status = document.querySelector<HTMLParagraphElement>('#status');
const workerStarts = document.querySelector<HTMLParagraphElement>('#worker-starts');
const closeAudit = document.querySelector<HTMLElement>('#close-audit');
const openOptions = document.querySelector<HTMLButtonElement>('#open-options');
const createTest = document.querySelector<HTMLButtonElement>('#create-test');
const clearTest = document.querySelector<HTMLButtonElement>('#clear-test');

async function renderStatus(): Promise<void> {
  const response = (await chrome.runtime.sendMessage({ type: 'get-status' })) as StatusResponse;
  if (status) {
    status.textContent = `Status: ${connectionLabel(response.state)}`;
  }
  if (workerStarts) {
    workerStarts.textContent = `Worker starts observed: ${response.lifecycle.workerStartCount}`;
  }
  if (closeAudit && response.lifecycle.lastCloseAudit) {
    const audit = response.lifecycle.lastCloseAudit;
    closeAudit.textContent = [
      `Decision: ${audit.decision}`,
      `byUser: ${audit.byUser}`,
      `programmatic marker: ${audit.hadProgrammaticMarker}`,
      `notification: ${audit.notificationId}`,
    ].join('\n');
  }
}

openOptions?.addEventListener('click', () => chrome.runtime.openOptionsPage());
createTest?.addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'create-lifecycle-test' });
  window.close();
});
clearTest?.addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'clear-lifecycle-test' });
  await renderStatus();
});

void renderStatus();

export type ConnectionState = 'not-configured' | 'offline' | 'connecting' | 'online';

/** `chrome.storage.local` key the worker publishes the live connection state under. */
export const CONNECTION_STATE_STORAGE_KEY = 'connectionState';

export const DEFAULT_CONNECTION_STATE: ConnectionState = 'not-configured';

export function connectionLabel(state: ConnectionState): string {
  switch (state) {
    case 'not-configured':
      return 'Not configured';
    case 'offline':
      return 'Offline';
    case 'connecting':
      return 'Connecting';
    case 'online':
      return 'Online';
  }
}

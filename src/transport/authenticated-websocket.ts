import {
  encodeDeviceAuthFrameV1,
  isTransportAuthenticationSuccessV1,
} from './device-auth-frame';
import type { StoredTransportCredential } from './indexeddb-transport-credential-store';
import {
  encodeTransportHeartbeatRequestV1,
  isTransportHeartbeatResponseV1,
} from './transport-heartbeat';
import { FAIL_CLOSED_WEBSOCKET_CODE } from './websocket-close-policy';

export type TransportDiagnosticEvent =
  | 'socket-open'
  | 'auth-frame-sent'
  | 'authenticated'
  | 'socket-error'
  | 'socket-closed';

export type TransportDiagnosticObserver = (event: TransportDiagnosticEvent) => void;

type WebSocketFactory = (url: string) => WebSocket;

/** Opens a relay socket and sends the binary credential as its first message. */
export function openAuthenticatedWebSocket(
  credential: StoredTransportCredential,
  observe: TransportDiagnosticObserver = () => undefined,
  createSocket: WebSocketFactory = (url) => new WebSocket(url),
): WebSocket {
  const origin = new URL(credential.serverOrigin);
  origin.protocol = origin.protocol === 'https:' ? 'wss:' : 'ws:';
  origin.pathname = '/v1/relay';
  const relayUrl = origin.toString();
  const authenticationFrame = encodeDeviceAuthFrameV1(credential);
  let socket: WebSocket;
  try {
    socket = createSocket(relayUrl);
  } catch (error) {
    authenticationFrame.fill(0);
    throw error;
  }
  socket.binaryType = 'arraybuffer';
  let authenticationSent = false;
  let authenticated = false;
  let acknowledgementTimeout: ReturnType<typeof setTimeout> | undefined;
  let heartbeatInterval: ReturnType<typeof setInterval> | undefined;
  let heartbeatResponseTimeout: ReturnType<typeof setTimeout> | undefined;
  const clearHeartbeat = () => {
    if (heartbeatInterval !== undefined) clearInterval(heartbeatInterval);
    if (heartbeatResponseTimeout !== undefined) clearTimeout(heartbeatResponseTimeout);
    heartbeatInterval = undefined;
    heartbeatResponseTimeout = undefined;
  };
  const sendHeartbeat = () => {
    if (!authenticated || heartbeatResponseTimeout !== undefined) return;
    try {
      socket.send(encodeTransportHeartbeatRequestV1());
    } catch {
      observe('socket-error');
      socket.close(FAIL_CLOSED_WEBSOCKET_CODE, 'heartbeat send failed');
      return;
    }
    heartbeatResponseTimeout = setTimeout(() => {
      heartbeatResponseTimeout = undefined;
      observe('socket-error');
      socket.close(FAIL_CLOSED_WEBSOCKET_CODE, 'heartbeat response timeout');
    }, HEARTBEAT_RESPONSE_TIMEOUT_MS);
  };
  socket.addEventListener('message', (event) => {
    if (!authenticated) {
      if (!authenticationSent) {
        event.stopImmediatePropagation();
        if (acknowledgementTimeout !== undefined) clearTimeout(acknowledgementTimeout);
        acknowledgementTimeout = undefined;
        observe('socket-error');
        socket.close(FAIL_CLOSED_WEBSOCKET_CODE, 'authentication acknowledgement out of order');
        return;
      }
      event.stopImmediatePropagation();
      if (!isTransportAuthenticationSuccessV1(event.data)) {
        if (acknowledgementTimeout !== undefined) clearTimeout(acknowledgementTimeout);
        acknowledgementTimeout = undefined;
        observe('socket-error');
        socket.close(FAIL_CLOSED_WEBSOCKET_CODE, 'invalid authentication acknowledgement');
        return;
      }
      authenticated = true;
      if (acknowledgementTimeout !== undefined) clearTimeout(acknowledgementTimeout);
      acknowledgementTimeout = undefined;
      heartbeatInterval = setInterval(sendHeartbeat, HEARTBEAT_INTERVAL_MS);
      observe('authenticated');
      return;
    }
    if (isTransportHeartbeatResponseV1(event.data)) {
      event.stopImmediatePropagation();
      if (heartbeatResponseTimeout !== undefined) clearTimeout(heartbeatResponseTimeout);
      heartbeatResponseTimeout = undefined;
      return;
    }
    if (isTransportAuthenticationSuccessV1(event.data)) {
      event.stopImmediatePropagation();
      observe('socket-error');
      socket.close(FAIL_CLOSED_WEBSOCKET_CODE, 'duplicate authentication acknowledgement');
    }
  });
  socket.addEventListener('open', () => {
    observe('socket-open');
    if (socket.url !== relayUrl) {
      observe('socket-error');
      authenticationFrame.fill(0);
      socket.close(FAIL_CLOSED_WEBSOCKET_CODE, 'relay endpoint changed');
      return;
    }
    try {
      socket.send(authenticationFrame);
      authenticationSent = true;
      observe('auth-frame-sent');
      acknowledgementTimeout = setTimeout(() => {
        if (!authenticated) {
          observe('socket-error');
          socket.close(FAIL_CLOSED_WEBSOCKET_CODE, 'authentication acknowledgement timeout');
        }
      }, 5_000);
    } finally {
      // WebSocket.send synchronously copies BufferSource data per browser API.
      authenticationFrame.fill(0);
    }
  }, { once: true });
  socket.addEventListener('error', () => {
    clearHeartbeat();
    if (!authenticationSent) authenticationFrame.fill(0);
    if (acknowledgementTimeout !== undefined) clearTimeout(acknowledgementTimeout);
    acknowledgementTimeout = undefined;
    observe('socket-error');
  });
  socket.addEventListener('close', () => {
    clearHeartbeat();
    if (acknowledgementTimeout !== undefined) clearTimeout(acknowledgementTimeout);
    acknowledgementTimeout = undefined;
    observe('socket-closed');
  });
  return socket;
}

const HEARTBEAT_INTERVAL_MS = 20_000;
const HEARTBEAT_RESPONSE_TIMEOUT_MS = 10_000;

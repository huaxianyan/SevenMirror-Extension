import {
  encodeDeviceAuthFrameV1,
  isTransportAuthenticationSuccessV1,
} from './device-auth-frame';
import type { StoredTransportCredential } from './indexeddb-transport-credential-store';

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
  socket.addEventListener('message', (event) => {
    if (!authenticated) {
      if (!authenticationSent) {
        event.stopImmediatePropagation();
        if (acknowledgementTimeout !== undefined) clearTimeout(acknowledgementTimeout);
        acknowledgementTimeout = undefined;
        observe('socket-error');
        socket.close(1008, 'authentication acknowledgement out of order');
        return;
      }
      event.stopImmediatePropagation();
      if (!isTransportAuthenticationSuccessV1(event.data)) {
        if (acknowledgementTimeout !== undefined) clearTimeout(acknowledgementTimeout);
        acknowledgementTimeout = undefined;
        observe('socket-error');
        socket.close(1008, 'invalid authentication acknowledgement');
        return;
      }
      authenticated = true;
      if (acknowledgementTimeout !== undefined) clearTimeout(acknowledgementTimeout);
      acknowledgementTimeout = undefined;
      observe('authenticated');
      return;
    }
    if (isTransportAuthenticationSuccessV1(event.data)) {
      event.stopImmediatePropagation();
      observe('socket-error');
      socket.close(1008, 'duplicate authentication acknowledgement');
    }
  });
  socket.addEventListener('open', () => {
    observe('socket-open');
    if (socket.url !== relayUrl) {
      observe('socket-error');
      authenticationFrame.fill(0);
      socket.close(1008, 'relay endpoint changed');
      return;
    }
    try {
      socket.send(authenticationFrame);
      authenticationSent = true;
      observe('auth-frame-sent');
      acknowledgementTimeout = setTimeout(() => {
        if (!authenticated) {
          observe('socket-error');
          socket.close(1008, 'authentication acknowledgement timeout');
        }
      }, 5_000);
    } finally {
      // WebSocket.send synchronously copies BufferSource data per browser API.
      authenticationFrame.fill(0);
    }
  }, { once: true });
  socket.addEventListener('error', () => {
    if (!authenticationSent) authenticationFrame.fill(0);
    if (acknowledgementTimeout !== undefined) clearTimeout(acknowledgementTimeout);
    acknowledgementTimeout = undefined;
    observe('socket-error');
  });
  socket.addEventListener('close', () => {
    if (acknowledgementTimeout !== undefined) clearTimeout(acknowledgementTimeout);
    acknowledgementTimeout = undefined;
    observe('socket-closed');
  });
  return socket;
}

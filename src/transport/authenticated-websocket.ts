import { encodeDeviceAuthFrameV1 } from './device-auth-frame';
import type { StoredTransportCredential } from './indexeddb-transport-credential-store';

export type TransportDiagnosticEvent =
  | 'socket-open'
  | 'auth-frame-sent'
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
  const socket = createSocket(relayUrl);
  socket.binaryType = 'arraybuffer';
  socket.addEventListener('open', () => {
    observe('socket-open');
    if (socket.url !== relayUrl) {
      observe('socket-error');
      socket.close(1008, 'relay endpoint changed');
      return;
    }
    const frame = encodeDeviceAuthFrameV1(credential);
    try {
      socket.send(frame);
      observe('auth-frame-sent');
    } finally {
      // WebSocket.send synchronously copies BufferSource data per browser API.
      frame.fill(0);
    }
  }, { once: true });
  socket.addEventListener('error', () => observe('socket-error'));
  socket.addEventListener('close', () => observe('socket-closed'));
  return socket;
}

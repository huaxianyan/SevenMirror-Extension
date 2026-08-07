import {
  deriveIdentityKeyId,
  serializeIdentityPublicKey,
  type HpkeIdentity,
} from '../crypto/auth-hpke';
import type { ConnectionState } from '../shared/status';
import {
  openAuthenticatedWebSocket,
  type TransportDiagnosticEvent,
} from './authenticated-websocket';
import type { StoredTransportCredential } from './indexeddb-transport-credential-store';

interface CredentialStore {
  load(): Promise<StoredTransportCredential | undefined>;
}

interface IdentityStore {
  loadExisting(): Promise<HpkeIdentity | undefined>;
}

type StateWriter = (state: ConnectionState) => Promise<void>;
type SocketOpener = (
  credential: StoredTransportCredential,
  observe: (event: TransportDiagnosticEvent) => void,
) => WebSocket;

/** Owns one authenticated socket without creating identities or replacing credentials. */
export class TransportRuntime {
  private generation = 0;
  private socket?: WebSocket;

  constructor(
    private readonly credentialStore: CredentialStore,
    private readonly identityStore: IdentityStore,
    private readonly writeState: StateWriter,
    private readonly onEnvelope: ((frame: ArrayBuffer) => void) | undefined,
    private readonly openSocket: SocketOpener = openAuthenticatedWebSocket,
  ) {}

  async connect(): Promise<void> {
    const generation = ++this.generation;
    this.socket?.close(1000, 'replaced by new connection');
    this.socket = undefined;

    const credential = await this.credentialStore.load();
    if (generation !== this.generation) return;
    if (credential === undefined) {
      await this.writeState('not-configured');
      return;
    }

    try {
      const identity = await this.identityStore.loadExisting();
      if (identity === undefined) {
        throw new Error('Transport credential exists without its bound E2EE identity');
      }
      const publicKey = await serializeIdentityPublicKey(identity);
      const keyId = await deriveIdentityKeyId(publicKey);
      if (!bytesEqual(keyId, credential.identityKeyId)) {
        throw new Error('Transport credential E2EE identity binding does not match');
      }
      if (generation !== this.generation) return;

      await this.writeState('connecting');
      const socket = this.openSocket(credential, (event) => {
        if (generation !== this.generation) return;
        if (event === 'authenticated') {
          void this.writeState('online');
        } else if (event === 'socket-error' || event === 'socket-closed') {
          void this.writeState('offline');
        }
      });
      credential.authToken.fill(0);
      if (generation !== this.generation) {
        socket.close(1000, 'superseded connection');
        return;
      }
      socket.addEventListener('message', (event) => {
        if (generation !== this.generation) return;
        if (!(event.data instanceof ArrayBuffer)) {
          socket.close(1008, 'relay messages must be binary');
          return;
        }
        if (this.onEnvelope === undefined) {
          socket.close(1008, 'encrypted envelope handler unavailable');
          return;
        }
        this.onEnvelope(event.data.slice(0));
      });
      this.socket = socket;
    } catch (error) {
      credential.authToken.fill(0);
      if (generation === this.generation) await this.writeState('offline');
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    ++this.generation;
    this.socket?.close(1000, 'local disconnect');
    this.socket = undefined;
    await this.writeState('offline');
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

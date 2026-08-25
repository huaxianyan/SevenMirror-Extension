import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/encrypted-payload-v1.json';
import { NotificationMediaMimeType } from '../protocol/generated/notification/v1/payload_pb';
import type { MirroredNotificationMedia } from '../crypto/indexeddb-notification-state-store';
import { notificationMediaDataUrl } from './notification-presenter';

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));

const appIcon = (): MirroredNotificationMedia => ({
  contentSha256: fromHex(vector.notificationAppIcon.contentSha256Hex),
  mimeType: NotificationMediaMimeType.PNG,
  width: vector.notificationAppIcon.width,
  height: vector.notificationAppIcon.height,
  encodedBytes: fromHex(vector.notificationAppIcon.encodedHex),
});

describe('Notification media presentation', () => {
  it('uses only media whose encoded and decoded dimensions match the bounded declaration', async () => {
    let closed = false;
    const resolved = await notificationMediaDataUrl(appIcon(), async (blob) => {
      expect(blob.type).toBe('image/png');
      return {
        width: 2,
        height: 1,
        close: () => { closed = true; },
      };
    });
    expect(resolved).toMatch(/^data:image\/png;base64,/);
    expect(closed).toBe(true);

    let decodedMismatchClosed = false;
    expect(await notificationMediaDataUrl(appIcon(), async () => ({
      width: 1,
      height: 1,
      close: () => { decodedMismatchClosed = true; },
    }))).toBeUndefined();
    expect(decodedMismatchClosed).toBe(true);

    let decoderCalled = false;
    const falseDeclaration = { ...appIcon(), width: 1 };
    expect(await notificationMediaDataUrl(falseDeclaration, async () => {
      decoderCalled = true;
      throw new Error('must not decode');
    })).toBeUndefined();
    expect(decoderCalled).toBe(false);
  });
});

import { describe, expect, it } from 'vitest';
import vector from '../../protocol/test-vectors/encrypted-payload-v1.json';
import { NotificationMediaMimeType } from '../protocol/generated/notification/v1/payload_pb';
import type {
  MirroredNotificationMedia,
  MirroredNotificationState,
} from '../crypto/indexeddb-notification-state-store';
import { notificationButtons, notificationMediaDataUrl } from './notification-presenter';

const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));

const appIcon = (): MirroredNotificationMedia => ({
  contentSha256: fromHex(vector.notificationAppIcon.contentSha256Hex),
  mimeType: NotificationMediaMimeType.PNG,
  width: vector.notificationAppIcon.width,
  height: vector.notificationAppIcon.height,
  encodedBytes: fromHex(vector.notificationAppIcon.encodedHex),
});

describe('Notification presentation', () => {
  it('reserves one native slot for clear and never exposes reply without an input UI', () => {
    const state: MirroredNotificationState = {
      tuple: 'source:notification',
      sourceDeviceId: new Uint8Array(16).fill(1),
      notificationId: 'notification',
      chromeNotificationId: 'sn1:test',
      revision: '7',
      phase: 'visible',
      payloadSha256: new Uint8Array(32).fill(2),
      actions: [
        {
          actionId: new Uint8Array(16).fill(3),
          title: 'Reply',
          requiresTextInput: true,
          allowsFreeFormInput: true,
        },
        {
          actionId: new Uint8Array(16).fill(4),
          title: 'Mark handled',
          requiresTextInput: false,
          allowsFreeFormInput: false,
        },
      ],
    };

    const buttons = notificationButtons(state, '清除');
    expect(buttons.map((button) => [button.kind, button.title])).toEqual([
      ['action', 'Mark handled'],
      ['dismiss', '清除'],
    ]);
    expect(buttons[0]?.kind === 'action' ? buttons[0].action.actionId : undefined)
      .not.toBe(state.actions?.[1]?.actionId);
  });

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

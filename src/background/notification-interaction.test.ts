import { describe, expect, it } from 'vitest';
import type { MirroredNotificationState } from '../crypto/indexeddb-notification-state-store';
import {
  interactionPageUrl,
  interactionSummary,
  interactionWindowMargin,
  interactionWindowOptions,
  interactionWindowPlacement,
  interactionWorkArea,
  resolveCurrentAction,
  validateReplyText,
  waitForNotificationRemoval,
} from './notification-interaction';

const state = (): MirroredNotificationState => ({
  tuple: 'source:notification',
  sourceDeviceId: new Uint8Array(16).fill(1),
  notificationId: 'notification',
  chromeNotificationId: 'sn1:notification',
  revision: '7',
  phase: 'visible',
  payloadSha256: new Uint8Array(32).fill(2),
  sourceApplicationId: 'chat.example',
  sourceApplicationName: 'Example Chat',
  title: 'New message',
  body: 'Hello',
  actions: [
    {
      actionId: new Uint8Array(16).fill(3),
      title: 'Reply',
      requiresTextInput: true,
      allowsFreeFormInput: true,
    },
    {
      actionId: new Uint8Array(16).fill(4),
      title: 'Mark read',
      requiresTextInput: false,
      allowsFreeFormInput: false,
    },
  ],
});

describe('Notification interaction window', () => {
  it('opens one notification without exposing internal source identifiers', () => {
    const url = interactionPageUrl('chrome-extension://example/', 'sn1:notification');
    expect(url).toBe('chrome-extension://example/interaction/index.html?notification=sn1%3Anotification');
    expect(interactionWindowOptions(url)).toEqual({
      url,
      type: 'popup',
      focused: true,
      width: 440,
      height: 680,
    });

    const summary = interactionSummary(state(), 'Pixel');
    expect(summary).toMatchObject({
      sourceName: 'Pixel',
      sourceApplicationName: 'Example Chat',
      title: 'New message',
      body: 'Hello',
      revision: '7',
    });
    expect(summary.actions.map((action) => [action.title, action.requiresTextInput])).toEqual([
      ['Reply', true],
      ['Mark read', false],
    ]);
    expect(JSON.stringify(summary)).not.toContain('0101010101010101');
  });

  it('places the window in one step when the work area is known', () => {
    const url = interactionPageUrl('chrome-extension://example/', 'sn1:notification');
    expect(interactionWindowOptions(url, { left: 0, top: 0, width: 1_986, height: 1_152 }))
      .toEqual({
        url,
        type: 'popup',
        focused: true,
        width: 440,
        height: 680,
        left: 1_530,
        top: 456,
      });
  });

  it('opens without an explicit position when the work area is unknown', () => {
    const url = interactionPageUrl('chrome-extension://example/', 'sn1:notification');
    const options = interactionWindowOptions(url, undefined);
    expect(options.left).toBeUndefined();
    expect(options.top).toBeUndefined();
  });

  it('anchors to the primary display work area', () => {
    const secondary = { isPrimary: false, workArea: { left: 2_048, top: 0, width: 1_986, height: 1_152 } };
    const primary = { isPrimary: true, workArea: { left: 0, top: 0, width: 1_986, height: 1_152 } };
    expect(interactionWorkArea([secondary, primary])).toEqual(primary.workArea);
    expect(interactionWorkArea([secondary])).toEqual(secondary.workArea);
    expect(interactionWorkArea([])).toBeUndefined();
  });

  it('anchors the interaction window to the bottom-right corner of the work area', () => {
    expect(interactionWindowPlacement(
      { left: 0, top: 0, width: 1_986, height: 1_152 },
      { width: 442, height: 682 },
    )).toEqual({
      left: 1_986 - 442 - interactionWindowMargin,
      top: 1_152 - 682 - interactionWindowMargin,
    });
  });

  it('places the default window size without an explicit size argument', () => {
    expect(interactionWindowPlacement({ left: 0, top: 0, width: 1_986, height: 1_152 }))
      .toEqual({ left: 1_530, top: 456 });
  });

  it('keeps a non-primary display origin when placing the window', () => {
    expect(interactionWindowPlacement(
      { left: 2_048, top: 120, width: 1_986, height: 1_152 },
      { width: 442, height: 682 },
    )).toEqual({ left: 2_048 + 1_528, top: 120 + 454 });
  });

  it('falls back to the work area origin when the window does not fit', () => {
    expect(interactionWindowPlacement(
      { left: 120, top: 40, width: 300, height: 300 },
      { width: 442, height: 682 },
    )).toEqual({ left: 120, top: 40 });
  });

  it('accepts only non-blank replies within the protocol byte limit', () => {
    expect(validateReplyText('hello')).toBe('valid');
    expect(validateReplyText('  \n')).toBe('required');
    expect(validateReplyText('你'.repeat(1_334))).toBe('too-long');
  });

  it('closes after an operation removes its notification despite a transient lookup failure', async () => {
    const states = ['lookup-failed', 'present', 'removed'] as const;
    let lookups = 0;
    let pauses = 0;

    const removed = await waitForNotificationRemoval(
      async () => states[lookups++] ?? 'present',
      async () => { pauses += 1; },
    );

    expect(removed).toBe(true);
    expect(lookups).toBe(3);
    expect(pauses).toBe(2);
  });

  it('retains the interaction window while its notification still exists', async () => {
    let pauses = 0;

    const removed = await waitForNotificationRemoval(
      async () => 'present',
      async () => { pauses += 1; },
      2,
    );

    expect(removed).toBe(false);
    expect(pauses).toBe(2);
  });

  it('resolves an action only while the interaction page revision is current', () => {
    const current = state();
    const actionId = '04'.repeat(16);
    expect(resolveCurrentAction(current, '7', actionId)?.title).toBe('Mark read');
    expect(resolveCurrentAction(current, '6', actionId)).toBeUndefined();
    expect(resolveCurrentAction({ ...current, phase: 'removed' }, '7', actionId)).toBeUndefined();
  });
});

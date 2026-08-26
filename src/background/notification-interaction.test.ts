import { describe, expect, it } from 'vitest';
import type { MirroredNotificationState } from '../crypto/indexeddb-notification-state-store';
import {
  interactionPageUrl,
  interactionSummary,
  resolveCurrentAction,
  validateReplyText,
} from './notification-interaction';

const state = (): MirroredNotificationState => ({
  tuple: 'source:notification',
  sourceDeviceId: new Uint8Array(16).fill(1),
  notificationId: 'notification',
  chromeNotificationId: 'sn1:notification',
  revision: '7',
  phase: 'visible',
  payloadSha256: new Uint8Array(32).fill(2),
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

    const summary = interactionSummary(state(), 'Pixel');
    expect(summary).toMatchObject({
      sourceName: 'Pixel',
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

  it('accepts only non-blank replies within the protocol byte limit', () => {
    expect(validateReplyText('hello')).toBe('valid');
    expect(validateReplyText('  \n')).toBe('required');
    expect(validateReplyText('你'.repeat(1_334))).toBe('too-long');
  });

  it('resolves an action only while the interaction page revision is current', () => {
    const current = state();
    const actionId = '04'.repeat(16);
    expect(resolveCurrentAction(current, '7', actionId)?.title).toBe('Mark read');
    expect(resolveCurrentAction(current, '6', actionId)).toBeUndefined();
    expect(resolveCurrentAction({ ...current, phase: 'removed' }, '7', actionId)).toBeUndefined();
  });
});

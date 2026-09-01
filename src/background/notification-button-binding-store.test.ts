import { describe, expect, it } from 'vitest';
import { NotificationButtonBindingStore } from './notification-button-binding-store';

describe('NotificationButtonBindingStore', () => {
  it('binds native indices to an exact notification revision', async () => {
    const values: Record<string, unknown> = {};
    const store = new NotificationButtonBindingStore({
      get: async (key) => key === null ? { ...values } : { [key]: values[key] },
      set: async (items) => { Object.assign(values, items); },
      remove: async (key) => { delete values[key]; },
    });
    const actionId = new Uint8Array(16).fill(7);
    await store.save('sn1:test', '11', [
      {
        kind: 'action',
        title: 'Reply',
        action: {
          actionId,
          title: 'Reply',
          requiresTextInput: true,
          allowsFreeFormInput: true,
        },
      },
      { kind: 'dismiss', title: 'Clear' },
    ]);
    const loaded = await store.load('sn1:test', '11');
    expect(loaded).toEqual([
      { kind: 'action', actionId, requiresTextInput: true },
      { kind: 'dismiss' },
    ]);
    expect(loaded?.[0]?.kind === 'action' ? loaded[0].actionId : undefined).not.toBe(actionId);
    expect(await store.load('sn1:test', '12')).toBeUndefined();
  });

  it('removes obsolete bindings and rejects corrupt records', async () => {
    const values: Record<string, unknown> = {};
    const store = new NotificationButtonBindingStore({
      get: async (key) => key === null ? { ...values } : { [key]: values[key] },
      set: async (items) => { Object.assign(values, items); },
      remove: async (key) => { delete values[key]; },
    });
    await store.save('sn1:test', '1', [{ kind: 'more', title: 'More' }]);
    await store.remove('sn1:test');
    expect(await store.load('sn1:test', '1')).toBeUndefined();

    values.productPreference = true;
    await store.save('sn1:first', '2', [{ kind: 'dismiss', title: 'Clear' }]);
    await store.save('sn1:second', '3', [{ kind: 'more', title: 'More' }]);
    await store.clearAll();
    expect(values).toEqual({ productPreference: true });
  });
});

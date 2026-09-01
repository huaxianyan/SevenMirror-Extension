import { beforeEach, describe, expect, it, vi } from 'vitest';

const values: Record<string, unknown> = {};

beforeEach(() => {
  for (const key of Object.keys(values)) delete values[key];
  vi.resetModules();
  vi.stubGlobal('chrome', {
    storage: {
      local: {
        get: async (keys: string | string[]) => {
          const requested = Array.isArray(keys) ? keys : [keys];
          return Object.fromEntries(requested.map((key) => [key, values[key]]));
        },
        set: async (incoming: Record<string, unknown>) => {
          Object.assign(values, incoming);
        },
      },
    },
  });
});

describe('durable notification close suppression', () => {
  it('suppresses a user-close event even when it races the marker write', async () => {
    const lifecycle = await import('./lifecycle-spike');
    const marking = lifecycle.markProgrammaticClose('sn1:notification', 'action-click');
    const audit = await lifecycle.handleNotificationClosed('sn1:notification', true);
    await marking;

    expect(audit?.decision).toBe('ignore-programmatic');
    expect(audit?.hadProgrammaticMarker).toBe(true);
  });

  it('requests remote dismissal only for an unmarked user close', async () => {
    const lifecycle = await import('./lifecycle-spike');
    const audit = await lifecycle.handleNotificationClosed('sn1:notification', true);
    expect(audit?.decision).toBe('request-remote-dismiss');
  });
});

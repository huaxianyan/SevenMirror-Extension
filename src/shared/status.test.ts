import { describe, expect, it } from 'vitest';
import { connectionLabel } from './status';

describe('connectionLabel', () => {
  it('returns an explicit label for each state', () => {
    expect(connectionLabel('not-configured')).toBe('Not configured');
    expect(connectionLabel('offline')).toBe('Offline');
    expect(connectionLabel('connecting')).toBe('Connecting');
    expect(connectionLabel('online')).toBe('Online');
  });
});

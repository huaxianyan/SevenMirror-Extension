import { describe, expect, it } from 'vitest';
import { decideClose } from './close-policy';

describe('decideClose', () => {
  it('requests a remote dismiss only for an unmarked user close', () => {
    expect(decideClose({ byUser: true, hasProgrammaticMarker: false })).toBe(
      'request-remote-dismiss',
    );
  });

  it('ignores programmatic closes even if the platform reports byUser', () => {
    expect(decideClose({ byUser: true, hasProgrammaticMarker: true })).toBe(
      'ignore-programmatic',
    );
    expect(decideClose({ byUser: false, hasProgrammaticMarker: true })).toBe(
      'ignore-programmatic',
    );
  });

  it('conservatively ignores an ambiguous non-user close', () => {
    expect(decideClose({ byUser: false, hasProgrammaticMarker: false })).toBe(
      'ignore-ambiguous',
    );
  });
});

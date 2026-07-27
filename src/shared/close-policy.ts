export type CloseDecision = 'request-remote-dismiss' | 'ignore-programmatic' | 'ignore-ambiguous';

export interface CloseContext {
  byUser: boolean;
  hasProgrammaticMarker: boolean;
}

/**
 * A phone notification may only be dismissed when Chrome explicitly reports a
 * user close and the extension did not initiate the close itself.
 */
export function decideClose(context: CloseContext): CloseDecision {
  if (context.hasProgrammaticMarker) {
    return 'ignore-programmatic';
  }
  if (context.byUser) {
    return 'request-remote-dismiss';
  }
  return 'ignore-ambiguous';
}

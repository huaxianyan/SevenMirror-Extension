import { describe, expect, it } from 'vitest';
import { ActionResultStatus } from '../protocol/generated/notification/v1/payload_pb';
import { presentActionResultStatus } from './action-result-status';

describe('action result status presentation', () => {
  it('does not present PendingIntent acceptance as third-party business success', () => {
    const result = presentActionResultStatus(ActionResultStatus.SUCCEEDED);
    expect(result.headline).toBe('Succeeded');
    expect(result.explanation).toContain('does not prove');
    expect(result.uncertain).toBe(false);
  });

  it('makes OUTCOME_UNKNOWN terminal, non-repeatable, and distinct from ACK success', () => {
    const result = presentActionResultStatus(ActionResultStatus.OUTCOME_UNKNOWN);
    expect(result.headline).toContain('Outcome unknown');
    expect(result.headline).toContain('do not repeat');
    expect(result.explanation).toContain('may or may not have occurred');
    expect(result.explanation).toContain('never execute this operation again');
    expect(result.explanation).toContain('does not turn the outcome into success');
    expect(result.uncertain).toBe(true);
    expect(result.resendLabel).toContain('no re-execution');
  });

  it('fails closed for absent or unsupported status values', () => {
    expect(presentActionResultStatus(undefined).headline).toBe('Unsupported result status');
    expect(presentActionResultStatus(99).explanation).toContain('failed closed');
  });
});

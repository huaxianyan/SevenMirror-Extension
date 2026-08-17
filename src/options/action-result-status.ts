import { ActionResultStatus } from '../protocol/generated/notification/v1/payload_pb';

export interface ActionResultPresentation {
  headline: string;
  explanation: string;
  uncertain: boolean;
  resendLabel: string;
}

export function presentActionResultStatus(status: number | undefined): ActionResultPresentation {
  switch (status) {
    case ActionResultStatus.SUCCEEDED:
      return presentation('Succeeded', 'Android reported that PendingIntent.send() returned successfully. This does not prove the third-party service completed its business action.');
    case ActionResultStatus.NOTIFICATION_NOT_FOUND:
      return presentation('Notification not found', 'Android no longer had the referenced notification.');
    case ActionResultStatus.STALE_NOTIFICATION_VERSION:
      return presentation('Stale notification version', 'The action targeted an older notification revision and was not executed.');
    case ActionResultStatus.ACTION_NOT_FOUND:
      return presentation('Action not found', 'The opaque action capability was unavailable and was not executed.');
    case ActionResultStatus.TEXT_REQUIRED:
      return presentation('Reply text required', 'The notification action required reply text and was not executed.');
    case ActionResultStatus.TEXT_NOT_SUPPORTED:
      return presentation('Reply text not supported', 'Reply text was supplied to an action that did not accept it.');
    case ActionResultStatus.PENDING_INTENT_CANCELLED:
      return presentation('PendingIntent cancelled', 'Android reported that the original PendingIntent was cancelled.');
    case ActionResultStatus.INTERNAL_ERROR:
      return presentation('Android internal error', 'Android failed before it could report successful local invocation.');
    case ActionResultStatus.OUTCOME_UNKNOWN:
      return {
        headline: 'Outcome unknown — do not repeat as a new operation',
        explanation: 'Android durably reserved this operation, but process interruption prevented a reliable local result. The original side effect may or may not have occurred. Android will never execute this operation again. ACK confirms only that Chrome durably reconciled this uncertainty; it does not turn the outcome into success.',
        uncertain: true,
        resendLabel: 'Request exact result again (no re-execution)',
      };
    default:
      return presentation('Unsupported result status', 'The stored terminal status is unavailable or unsupported. Treat it as failed closed.');
  }
}

function presentation(headline: string, explanation: string): ActionResultPresentation {
  return {
    headline,
    explanation,
    uncertain: false,
    resendLabel: 'Resend exact completed action',
  };
}

const RESET_RECORD = 'reenrollment-reset';

interface ResetIntentStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

export class CertifiedReEnrollmentResetStore {
  constructor(private readonly storage: ResetIntentStorage = chrome.storage.local) {}

  async isPending(): Promise<boolean> {
    const stored = await this.storage.get(RESET_RECORD);
    const value = stored[RESET_RECORD];
    if (value === undefined) return false;
    if (!isRecord(value) || value.version !== 1 || value.pending !== true) {
      throw new Error('Certified re-enrollment reset intent is invalid');
    }
    return true;
  }

  async begin(): Promise<void> {
    await this.storage.set({ [RESET_RECORD]: { version: 1, pending: true } });
  }

  async finish(): Promise<void> {
    await this.storage.remove(RESET_RECORD);
  }
}

export interface CertifiedReEnrollmentResetOperations {
  stopTransport(): Promise<void>;
  clearSchedules(): Promise<void>;
  clearNativeNotifications(): Promise<void>;
  clearHostPermissions(): Promise<void>;
  clearWorkspaceState(): Promise<void>;
  clearConnectionState(): Promise<void>;
}

/** Completes an already-authorized reset. Every operation must be safe to repeat after suspension. */
export async function completeCertifiedReEnrollmentReset(
  intentStore: CertifiedReEnrollmentResetStore,
  operations: CertifiedReEnrollmentResetOperations,
): Promise<boolean> {
  if (!await intentStore.isPending()) return false;
  await operations.stopTransport();
  await operations.clearSchedules();
  await operations.clearNativeNotifications();
  await operations.clearHostPermissions();
  await operations.clearWorkspaceState();
  await operations.clearConnectionState();
  await intentStore.finish();
  return true;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

import { describe, expect, it } from 'vitest';
import {
  CertifiedReEnrollmentResetStore,
  completeCertifiedReEnrollmentReset,
  type CertifiedReEnrollmentResetOperations,
} from './certified-re-enrollment-reset';

describe('certified re-enrollment reset', () => {
  it('retains its durable intent across an interrupted reset and completes on restart', async () => {
    const values: Record<string, unknown> = {};
    const intent = new CertifiedReEnrollmentResetStore({
      async get(key) { return { [key]: values[key] }; },
      async set(items) { Object.assign(values, items); },
      async remove(key) { delete values[key]; },
    });
    const completed: string[] = [];
    let interrupt = true;
    const operations: CertifiedReEnrollmentResetOperations = {
      async stopTransport() { completed.push('transport'); },
      async clearSchedules() { completed.push('schedules'); },
      async clearNativeNotifications() { completed.push('notifications'); },
      async clearHostPermissions() { completed.push('permissions'); },
      async clearWorkspaceState() {
        if (interrupt) {
          interrupt = false;
          throw new Error('worker suspended');
        }
        completed.push('workspace');
      },
      async clearConnectionState() { completed.push('connection'); },
    };

    await intent.begin();
    await expect(completeCertifiedReEnrollmentReset(intent, operations))
      .rejects.toThrow('worker suspended');
    await expect(intent.isPending()).resolves.toBe(true);

    await expect(completeCertifiedReEnrollmentReset(intent, operations)).resolves.toBe(true);
    await expect(intent.isPending()).resolves.toBe(false);
    expect(completed).toEqual([
      'transport', 'schedules', 'notifications', 'permissions',
      'transport', 'schedules', 'notifications', 'permissions', 'workspace', 'connection',
    ]);
  });
});

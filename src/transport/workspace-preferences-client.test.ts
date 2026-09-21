import { describe, expect, it } from 'vitest';
import {
  WorkspacePreferenceConflictError,
  WorkspacePreferenceDeniedError,
  readWorkspacePreference,
  toBase64Url,
  writeWorkspacePreference,
} from './workspace-preferences-client';
import type { StoredTransportCredential } from './indexeddb-transport-credential-store';

const CREDENTIAL: StoredTransportCredential = {
  serverOrigin: 'https://relay.test',
  workspaceId: new Uint8Array(16).fill(0x11),
  deviceId: new Uint8Array(16).fill(0x22),
  authToken: new Uint8Array(32).fill(0x33),
  identityKeyId: new Uint8Array(32).fill(0x44),
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function capturingFetch(response: () => Response): {
  calls: Array<{ url: string; body: Record<string, unknown> }>;
  fetcher: typeof fetch;
} {
  const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
  const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), body: JSON.parse(String(init?.body)) as Record<string, unknown> });
    return response();
  }) as unknown as typeof fetch;
  return { calls, fetcher };
}

describe('workspace preference client', () => {
  it('reports an unwritten key without a payload', async () => {
    const { calls, fetcher } = capturingFetch(() => jsonResponse({ revision: '0', payload: '', updated_at_ms: '0' }));
    await expect(readWorkspacePreference(CREDENTIAL, 'notification-shortcuts', fetcher))
      .resolves.toEqual({ revision: 0, updatedAtMs: 0 });
    expect(calls[0].url).toBe('https://relay.test/v1/workspace/preferences/read');
    expect(calls[0].body).toEqual({
      workspace_id: toBase64Url(CREDENTIAL.workspaceId),
      device_id: toBase64Url(CREDENTIAL.deviceId),
      auth_token: toBase64Url(CREDENTIAL.authToken),
      key: 'notification-shortcuts',
    });
  });

  it('decodes a stored payload', async () => {
    const payload = new Uint8Array([0, 255, 16]);
    const { fetcher } = capturingFetch(() => jsonResponse({
      revision: '3',
      payload: toBase64Url(payload),
      updated_at_ms: '1800000000000',
    }));
    const value = await readWorkspacePreference(CREDENTIAL, 'notification-shortcuts', fetcher);
    expect(value.revision).toBe(3);
    expect(value.updatedAtMs).toBe(1_800_000_000_000);
    expect([...value.payload!]).toEqual([...payload]);
  });

  it('returns the stored revision after a write', async () => {
    const { calls, fetcher } = capturingFetch(() => jsonResponse({ revision: '2' }));
    const revision = await writeWorkspacePreference(
      CREDENTIAL, 'notification-shortcuts', 1, new Uint8Array([7]), fetcher);
    expect(revision).toBe(2);
    expect(calls[0].url).toBe('https://relay.test/v1/workspace/preferences/write');
    expect(calls[0].body.expected_revision).toBe('1');
    expect(calls[0].body.payload).toBe(toBase64Url(new Uint8Array([7])));
  });

  it('surfaces a revision conflict instead of overwriting', async () => {
    const { fetcher } = capturingFetch(() => new Response('preference revision conflict', { status: 409 }));
    await expect(writeWorkspacePreference(CREDENTIAL, 'notification-shortcuts', 1, new Uint8Array([7]), fetcher))
      .rejects.toBeInstanceOf(WorkspacePreferenceConflictError);
  });

  it('surfaces a denied device tuple', async () => {
    const { fetcher } = capturingFetch(() => new Response('preference access denied', { status: 403 }));
    await expect(readWorkspacePreference(CREDENTIAL, 'notification-shortcuts', fetcher))
      .rejects.toBeInstanceOf(WorkspacePreferenceDeniedError);
  });

  it('rejects a non-canonical revision', async () => {
    const { fetcher } = capturingFetch(() => jsonResponse({ revision: '01', payload: '', updated_at_ms: '0' }));
    await expect(readWorkspacePreference(CREDENTIAL, 'notification-shortcuts', fetcher))
      .rejects.toThrow(/not canonical/);
  });

  it('refuses to publish an empty payload', async () => {
    const { fetcher } = capturingFetch(() => jsonResponse({ revision: '1' }));
    await expect(writeWorkspacePreference(CREDENTIAL, 'notification-shortcuts', 0, new Uint8Array(0), fetcher))
      .rejects.toThrow(/non-empty/);
  });
});

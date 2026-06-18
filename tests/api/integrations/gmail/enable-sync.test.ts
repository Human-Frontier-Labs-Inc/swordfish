/**
 * Tests for PATCH /api/integrations/gmail/enable-sync.
 *
 * Regression: the toggle 400'd for a connected Gmail integration that has no
 * nango_connection_id — the route gated on it AND passed it to
 * getGmailAccessToken, which actually takes a tenantId (tokens come from the
 * OAuth token manager now, not Nango). These tests pin both halves of the fix.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@clerk/nextjs/server', () => ({ auth: vi.fn() }));
vi.mock('@/lib/db', () => ({ sql: vi.fn() }));
vi.mock('@/lib/integrations/gmail', () => ({ getGmailAccessToken: vi.fn() }));
vi.mock('@/lib/webhooks/subscriptions', () => ({ createGmailSubscription: vi.fn() }));

import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { getGmailAccessToken } from '@/lib/integrations/gmail';
import { createGmailSubscription } from '@/lib/webhooks/subscriptions';
import { PATCH } from '@/app/api/integrations/gmail/enable-sync/route';

type Mock = ReturnType<typeof vi.fn>;
const mocks = {
  auth: auth as unknown as Mock,
  sql: sql as unknown as Mock,
  getGmailAccessToken: getGmailAccessToken as unknown as Mock,
  createGmailSubscription: createGmailSubscription as unknown as Mock,
};

/** sql mock: the SELECT returns the given integration row, everything else (UPDATE) resolves to []. */
function sqlReturnsIntegration(integration: Record<string, unknown>): void {
  mocks.sql.mockImplementation(async (strings: TemplateStringsArray) => {
    const q = strings.join('');
    if (/SELECT/i.test(q) && /FROM integrations/i.test(q)) return [integration];
    return [];
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.auth.mockResolvedValue({ userId: 'u1', orgId: 'org_1' });
  mocks.getGmailAccessToken.mockResolvedValue('access-token');
  mocks.createGmailSubscription.mockResolvedValue({
    expiresAt: new Date('2026-07-01T00:00:00Z'),
    historyId: '123',
  });
});

describe('PATCH /api/integrations/gmail/enable-sync', () => {
  it('succeeds for a connected Gmail WITHOUT a nango_connection_id (was 400) and resolves the token by tenantId', async () => {
    sqlReturnsIntegration({
      id: 'int-1',
      tenant_id: 'org_1',
      config: { email: 'a@b.com' }, // no watchExpiration -> registers a push watch
      nango_connection_id: null, // the state that used to 400
      status: 'connected',
    });

    const res = await PATCH();
    expect(res.status).toBe(200);

    // Token resolved by TENANT ID, not the (null) nango connection id.
    expect(mocks.getGmailAccessToken).toHaveBeenCalledWith('org_1');
    expect(mocks.createGmailSubscription).toHaveBeenCalledWith(
      expect.objectContaining({
        integrationId: 'int-1',
        tenantId: 'org_1',
        accessToken: 'access-token',
      })
    );
  });

  it('returns 404 when no Gmail integration exists', async () => {
    mocks.sql.mockResolvedValue([]);
    const res = await PATCH();
    expect(res.status).toBe(404);
    expect(mocks.getGmailAccessToken).not.toHaveBeenCalled();
  });

  it('returns 400 when the integration is not connected', async () => {
    sqlReturnsIntegration({
      id: 'int-1',
      tenant_id: 'org_1',
      config: {},
      nango_connection_id: null,
      status: 'error',
    });
    const res = await PATCH();
    expect(res.status).toBe(400);
    expect(mocks.getGmailAccessToken).not.toHaveBeenCalled();
  });

  it('returns 200 and skips registration when the push watch is already active', async () => {
    sqlReturnsIntegration({
      id: 'int-1',
      tenant_id: 'org_1',
      config: { watchExpiration: new Date(Date.now() + 86_400_000).toISOString() },
      nango_connection_id: null,
      status: 'connected',
    });
    const res = await PATCH();
    expect(res.status).toBe(200);
    expect(mocks.createGmailSubscription).not.toHaveBeenCalled();
  });
});

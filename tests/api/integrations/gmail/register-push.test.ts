/**
 * Tests for POST /api/integrations/gmail/register-push.
 *
 * Same regression class as enable-sync: the route used to 500 when
 * nango_connection_id was absent and passed it to getGmailAccessToken (which
 * takes a tenantId). Pins the tenantId resolution + the no-nango path.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';

vi.mock('@clerk/nextjs/server', () => ({ auth: vi.fn() }));
vi.mock('@/lib/db', () => ({ sql: vi.fn() }));
vi.mock('@/lib/integrations/gmail', () => ({ getGmailAccessToken: vi.fn() }));
vi.mock('@/lib/webhooks/subscriptions', () => ({ createGmailSubscription: vi.fn() }));

import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { getGmailAccessToken } from '@/lib/integrations/gmail';
import { createGmailSubscription } from '@/lib/webhooks/subscriptions';
import { POST } from '@/app/api/integrations/gmail/register-push/route';

type Mock = ReturnType<typeof vi.fn>;
const mocks = {
  auth: auth as unknown as Mock,
  sql: sql as unknown as Mock,
  getGmailAccessToken: getGmailAccessToken as unknown as Mock,
  createGmailSubscription: createGmailSubscription as unknown as Mock,
};

const req = () => new NextRequest('http://localhost/api/integrations/gmail/register-push', { method: 'POST' });

beforeEach(() => {
  vi.clearAllMocks();
  mocks.auth.mockResolvedValue({ userId: 'u1', orgId: 'org_1' });
  process.env.GOOGLE_PUBSUB_TOPIC = 'test-topic';
  mocks.getGmailAccessToken.mockResolvedValue('access-token');
  mocks.createGmailSubscription.mockResolvedValue({
    expiresAt: new Date('2026-07-01T00:00:00Z'),
    historyId: '1',
  });
});

describe('POST /api/integrations/gmail/register-push', () => {
  it('registers push by resolving the token via tenantId (no nango_connection_id required)', async () => {
    mocks.sql.mockImplementation(async (strings: TemplateStringsArray) => {
      if (/SELECT/i.test(strings.join(''))) {
        return [{ id: 'int-1', config: {}, nango_connection_id: null }];
      }
      return [];
    });

    const res = await POST(req());
    expect(res.status).toBe(200);
    expect(mocks.getGmailAccessToken).toHaveBeenCalledWith('org_1');
    expect(mocks.createGmailSubscription).toHaveBeenCalledWith(
      expect.objectContaining({ integrationId: 'int-1', tenantId: 'org_1', accessToken: 'access-token' })
    );
  });

  it('returns already_active when the push watch is still active', async () => {
    mocks.sql.mockImplementation(async (strings: TemplateStringsArray) => {
      if (/SELECT/i.test(strings.join(''))) {
        return [{
          id: 'int-1',
          config: { watchExpiration: new Date(Date.now() + 86_400_000).toISOString() },
          nango_connection_id: null,
        }];
      }
      return [];
    });
    const res = await POST(req());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('already_active');
    expect(mocks.getGmailAccessToken).not.toHaveBeenCalled();
  });

  it('returns 404 when no connected Gmail integration exists', async () => {
    mocks.sql.mockResolvedValue([]);
    const res = await POST(req());
    expect(res.status).toBe(404);
  });
});

/**
 * Microsoft (M365) Token Round-Trip Tests — P0-7
 *
 * Verifies the consolidated token path: the Microsoft OAuth route stores
 * ENCRYPTED tokens in the `integrations` table under provider type `o365`,
 * and the SAME tokens are retrievable through the token manager's read path
 * (the path the webhook + sync worker use).
 *
 * This guards against the split-brain regression where the route wrote
 * UNENCRYPTED tokens to `provider_connections` while the webhook read
 * encrypted tokens from `integrations`.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// --- In-memory fake of the integrations table to model UPDATE/SELECT --------
interface IntegrationRow {
  tenant_id: string;
  type: string;
  status: string;
  oauth_access_token: string | null;
  oauth_refresh_token: string | null;
  oauth_token_expires_at: string | null;
  oauth_scopes: string | null;
  connected_email: string | null;
}

const store = new Map<string, IntegrationRow>();
const key = (tenantId: string, type: string) => `${tenantId}:${type}`;

// Mock the db with a tiny SQL interpreter that understands the queries
// token-manager issues (UPDATE integrations ... / SELECT ... FROM integrations).
vi.mock('@/lib/db', () => {
  const sql = (strings: TemplateStringsArray, ...values: unknown[]) => {
    const query = strings.join('?').replace(/\s+/g, ' ').trim();

    // storeTokens: UPDATE integrations SET oauth_access_token = ... WHERE tenant_id = ... AND type = ...
    if (query.startsWith('UPDATE integrations SET oauth_access_token')) {
      const [accessTok, refreshTok, expiresAt, scopes, email, , tenantId, type] = values as string[];
      store.set(key(tenantId, type), {
        tenant_id: tenantId,
        type,
        status: 'connected',
        oauth_access_token: accessTok,
        oauth_refresh_token: refreshTok,
        oauth_token_expires_at: String(expiresAt),
        oauth_scopes: scopes,
        connected_email: email,
      });
      return Promise.resolve([]);
    }

    // getAccessToken: SELECT oauth_access_token, ... FROM integrations WHERE tenant_id AND type AND status='connected'
    if (query.includes('FROM integrations') && query.startsWith('SELECT')) {
      // The tenant_id and type are the last two interpolated values.
      const tenantId = values[values.length - 2] as string;
      const type = values[values.length - 1] as string;
      const row = store.get(key(tenantId, type));
      if (row && row.status === 'connected') {
        return Promise.resolve([row]);
      }
      return Promise.resolve([]);
    }

    return Promise.resolve([]);
  };

  return { sql, default: sql };
});

vi.mock('@/lib/logging/logger', () => ({
  loggers: {
    integration: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  },
}));

// Token refresh shouldn't be triggered (token not near expiry) but mock anyway.
vi.mock('@/lib/integrations/gmail', () => ({
  refreshGmailToken: vi.fn(),
}));
vi.mock('@/lib/integrations/o365', () => ({
  refreshO365Token: vi.fn(),
}));

describe('M365 token round-trip (P0-7)', () => {
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    store.clear();
    vi.resetModules();
    process.env = {
      ...ORIGINAL_ENV,
      ENCRYPTION_KEY: 'test-encryption-key-32-bytes-ok!', // 32 bytes
    };
  });

  it('stores o365 tokens ENCRYPTED and reads back the original plaintext', async () => {
    const { storeTokens, getAccessToken } = await import('@/lib/oauth/token-manager');

    const tenantId = 'org_msp_acme';
    const accessToken = 'EwBwA8l6BAAU...microsoft-access-token';
    const refreshToken = 'M.C507_BAY...microsoft-refresh-token';

    await storeTokens({
      tenantId,
      provider: 'o365',
      accessToken,
      refreshToken,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1h out, no refresh needed
      scopes: 'Mail.Read offline_access',
      connectedEmail: 'user@acme.com',
      providerUserId: 'aad-user-id',
    });

    // The stored value must NOT be the plaintext (it is encrypted at rest).
    const row = store.get('org_msp_acme:o365')!;
    expect(row.oauth_access_token).toBeTruthy();
    expect(row.oauth_access_token).not.toBe(accessToken);
    // And it should be in our versioned ciphertext format.
    expect(row.oauth_access_token!.startsWith('v1:')).toBe(true);

    // Reading through the token manager (webhook's path) returns the original.
    const fetched = await getAccessToken(tenantId, 'o365');
    expect(fetched).toBe(accessToken);
  });

  it('returns no token for a tenant that has not connected o365', async () => {
    const { getAccessToken } = await import('@/lib/oauth/token-manager');
    await expect(getAccessToken('org_unknown', 'o365')).rejects.toThrow(
      /No connected o365 integration/
    );
  });

  it('isolates tokens per tenant (no cross-tenant leakage)', async () => {
    const { storeTokens, getAccessToken } = await import('@/lib/oauth/token-manager');

    await storeTokens({
      tenantId: 'org_a',
      provider: 'o365',
      accessToken: 'token-A',
      refreshToken: 'refresh-A',
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      scopes: 'Mail.Read',
      connectedEmail: 'a@a.com',
    });
    await storeTokens({
      tenantId: 'org_b',
      provider: 'o365',
      accessToken: 'token-B',
      refreshToken: 'refresh-B',
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      scopes: 'Mail.Read',
      connectedEmail: 'b@b.com',
    });

    expect(await getAccessToken('org_a', 'o365')).toBe('token-A');
    expect(await getAccessToken('org_b', 'o365')).toBe('token-B');
  });
});

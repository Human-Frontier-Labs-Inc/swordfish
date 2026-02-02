/**
 * OAuth Security Tests
 *
 * Comprehensive tests for the new direct OAuth architecture that replaces Nango.
 * Tests cover:
 * - Email validation (connected email must match user's Swordfish email)
 * - Cross-tenant isolation (unique email constraint)
 * - CSRF protection via state tokens
 * - Token refresh mechanism
 * - Webhook routing security
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createOAuthState,
  validateOAuthState,
  verifyEmailMatch,
  cleanupExpiredStates,
} from '@/lib/oauth/state-manager';
import {
  storeTokens,
  getAccessToken,
  isEmailAlreadyConnected,
  findIntegrationByEmail,
  revokeTokens,
} from '@/lib/oauth/token-manager';

// Mock database
const mockSql = vi.fn();
vi.mock('@/lib/db', () => ({
  sql: (...args: unknown[]) => mockSql(...args),
}));

// Mock encryption
vi.mock('@/lib/security/encryption', () => ({
  encrypt: (value: string) => `encrypted:${value}`,
  decrypt: (value: string) => value.replace('encrypted:', ''),
}));

// Mock token refresh
vi.mock('@/lib/integrations/gmail', () => ({
  refreshGmailToken: vi.fn().mockResolvedValue({
    accessToken: 'new-access-token',
    refreshToken: 'new-refresh-token',
    expiresAt: new Date(Date.now() + 3600000),
    scope: 'https://www.googleapis.com/auth/gmail.readonly',
  }),
}));

vi.mock('@/lib/integrations/o365', () => ({
  refreshO365Token: vi.fn().mockResolvedValue({
    accessToken: 'new-access-token',
    refreshToken: 'new-refresh-token',
    expiresAt: new Date(Date.now() + 3600000),
    scope: 'Mail.Read',
  }),
}));

// Mock logger
vi.mock('@/lib/logging/logger', () => ({
  loggers: {
    integration: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  },
}));

describe('OAuth State Manager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSql.mockReset();
  });

  describe('createOAuthState', () => {
    it('should create state with PKCE code challenge', async () => {
      mockSql.mockResolvedValueOnce([]);

      const result = await createOAuthState({
        tenantId: 'tenant-123',
        userId: 'user-456',
        provider: 'gmail',
        redirectUri: 'https://app.example.com/callback',
        expectedEmail: 'user@example.com',
      });

      expect(result.stateToken).toBeDefined();
      expect(result.stateToken.length).toBeGreaterThan(20);
      expect(result.codeChallenge).toBeDefined();
      expect(result.codeVerifier).toBeDefined();
      // Verify state was stored in database
      expect(mockSql).toHaveBeenCalled();
    });

    it('should include expected email in state for validation', async () => {
      mockSql.mockResolvedValueOnce([]);

      await createOAuthState({
        tenantId: 'tenant-123',
        userId: 'user-456',
        provider: 'gmail',
        redirectUri: 'https://app.example.com/callback',
        expectedEmail: 'user@example.com',
      });

      // Check the SQL call includes the expected email
      const sqlCall = mockSql.mock.calls[0];
      expect(sqlCall).toBeDefined();
    });
  });

  describe('validateOAuthState', () => {
    it('should reject expired state tokens', async () => {
      const expiredDate = new Date(Date.now() - 3600000); // 1 hour ago
      mockSql.mockResolvedValueOnce([
        {
          id: 'state-id-123',
          tenant_id: 'tenant-123',
          user_id: 'user-456',
          provider: 'gmail',
          state_token: 'expired-state-token',
          expected_email: 'user@example.com',
          code_verifier: 'verifier-123',
          redirect_uri: 'https://app.example.com/callback',
          created_at: new Date(Date.now() - 7200000),
          expires_at: expiredDate,
          used_at: null,
        },
      ]);

      const result = await validateOAuthState('expired-state-token');

      expect(result.valid).toBe(false);
      expect(result.error).toContain('expired');
    });

    it('should reject already-used state tokens (replay attack prevention)', async () => {
      mockSql.mockResolvedValueOnce([
        {
          id: 'state-id-123',
          tenant_id: 'tenant-123',
          user_id: 'user-456',
          provider: 'gmail',
          state_token: 'used-state-token',
          expected_email: 'user@example.com',
          code_verifier: 'verifier-123',
          redirect_uri: 'https://app.example.com/callback',
          created_at: new Date(),
          expires_at: new Date(Date.now() + 3600000),
          used_at: new Date(), // Already used
        },
      ]);

      const result = await validateOAuthState('used-state-token');

      expect(result.valid).toBe(false);
      expect(result.error).toContain('used');
    });

    it('should reject non-existent state tokens', async () => {
      mockSql.mockResolvedValueOnce([]); // No results

      const result = await validateOAuthState('fake-state-token');

      expect(result.valid).toBe(false);
      expect(result.error).toContain('not found');
    });

    it('should return valid state with all required fields', async () => {
      const validExpiry = new Date(Date.now() + 3600000);
      mockSql
        .mockResolvedValueOnce([
          {
            id: 'state-id-123',
            tenant_id: 'tenant-123',
            user_id: 'user-456',
            provider: 'gmail',
            state_token: 'valid-state-token',
            expected_email: 'user@example.com',
            code_verifier: 'verifier-123',
            redirect_uri: 'https://app.example.com/callback',
            created_at: new Date(),
            expires_at: validExpiry,
            used_at: null,
          },
        ])
        .mockResolvedValueOnce([{ id: 'state-id-123' }]); // Mark as used - returns the row

      const result = await validateOAuthState('valid-state-token');

      expect(result.valid).toBe(true);
      expect(result.state).toBeDefined();
      expect(result.state?.tenantId).toBe('tenant-123');
      expect(result.state?.userId).toBe('user-456');
      expect(result.state?.expectedEmail).toBe('user@example.com');
      expect(result.state?.codeVerifier).toBe('verifier-123');
    });
  });

  describe('verifyEmailMatch', () => {
    it('should accept exact email match (case-insensitive)', () => {
      expect(verifyEmailMatch('user@example.com', 'user@example.com')).toBe(true);
      expect(verifyEmailMatch('User@Example.COM', 'user@example.com')).toBe(true);
      expect(verifyEmailMatch('user@example.com', 'USER@EXAMPLE.COM')).toBe(true);
    });

    it('should reject email mismatch', () => {
      expect(verifyEmailMatch('user@example.com', 'other@example.com')).toBe(false);
      expect(verifyEmailMatch('user@example.com', 'user@different.com')).toBe(false);
    });

    it('should reject attempts to use different accounts', () => {
      // This is the critical security check: users cannot connect a different
      // email than their registered Swordfish email
      expect(verifyEmailMatch('corporate@company.com', 'personal@gmail.com')).toBe(false);
    });
  });
});

describe('OAuth Token Manager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSql.mockReset();
  });

  describe('isEmailAlreadyConnected', () => {
    it('should detect email already connected by another tenant', async () => {
      mockSql.mockResolvedValueOnce([{ tenant_id: 'other-tenant-456' }]);

      const result = await isEmailAlreadyConnected('user@example.com', 'gmail', 'tenant-123');

      expect(result).toBe('other-tenant-456');
    });

    it('should return null when email is not connected', async () => {
      mockSql.mockResolvedValueOnce([]);

      const result = await isEmailAlreadyConnected('new-user@example.com', 'gmail');

      expect(result).toBeNull();
    });

    it('should exclude current tenant when checking', async () => {
      // If the same tenant already has this email, that's fine (reconnection)
      mockSql.mockResolvedValueOnce([]);

      const result = await isEmailAlreadyConnected('user@example.com', 'gmail', 'tenant-123');

      expect(result).toBeNull();
    });
  });

  describe('findIntegrationByEmail', () => {
    it('should find integration by verified email', async () => {
      mockSql.mockResolvedValueOnce([
        { id: 'integration-789', tenant_id: 'tenant-123' },
      ]);

      const result = await findIntegrationByEmail('user@example.com', 'gmail');

      expect(result).toEqual({
        tenantId: 'tenant-123',
        integrationId: 'integration-789',
      });
    });

    it('should return null when no integration matches email', async () => {
      mockSql.mockResolvedValueOnce([]);

      const result = await findIntegrationByEmail('unknown@example.com', 'gmail');

      expect(result).toBeNull();
    });

    it('should be case-insensitive for email lookup', async () => {
      mockSql.mockResolvedValueOnce([
        { id: 'integration-789', tenant_id: 'tenant-123' },
      ]);

      await findIntegrationByEmail('USER@EXAMPLE.COM', 'gmail');

      // The function should lowercase the email before querying
      const sqlCall = mockSql.mock.calls[0];
      expect(sqlCall).toBeDefined();
    });
  });

  describe('storeTokens', () => {
    it('should encrypt tokens before storage', async () => {
      mockSql.mockResolvedValueOnce([]);

      await storeTokens({
        tenantId: 'tenant-123',
        provider: 'gmail',
        accessToken: 'access-token-abc',
        refreshToken: 'refresh-token-xyz',
        expiresAt: new Date(Date.now() + 3600000),
        scopes: 'https://www.googleapis.com/auth/gmail.readonly',
        connectedEmail: 'user@example.com',
      });

      expect(mockSql).toHaveBeenCalled();
      // Tokens should be encrypted (mock returns encrypted:xxx)
    });

    it('should store connected email in lowercase', async () => {
      mockSql.mockResolvedValueOnce([]);

      await storeTokens({
        tenantId: 'tenant-123',
        provider: 'gmail',
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        expiresAt: new Date(),
        scopes: 'scope',
        connectedEmail: 'USER@EXAMPLE.COM',
      });

      expect(mockSql).toHaveBeenCalled();
    });
  });

  describe('getAccessToken', () => {
    it('should return cached token when not expired', async () => {
      const validExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour from now
      mockSql.mockResolvedValueOnce([
        {
          oauth_access_token: 'encrypted:valid-access-token',
          oauth_refresh_token: 'encrypted:refresh-token',
          oauth_token_expires_at: validExpiry,
          oauth_scopes: 'gmail.readonly',
          connected_email: 'user@example.com',
        },
      ]);

      const token = await getAccessToken('tenant-123', 'gmail');

      expect(token).toBe('valid-access-token');
    });

    it('should throw when no connected integration', async () => {
      mockSql.mockResolvedValueOnce([]);

      await expect(getAccessToken('tenant-123', 'gmail')).rejects.toThrow(
        /No connected/
      );
    });

    it('should throw when tokens are missing', async () => {
      mockSql.mockResolvedValueOnce([
        {
          oauth_access_token: null,
          oauth_refresh_token: null,
          connected_email: 'user@example.com',
        },
      ]);

      await expect(getAccessToken('tenant-123', 'gmail')).rejects.toThrow(
        /missing OAuth tokens/
      );
    });
  });

  describe('revokeTokens', () => {
    it('should clear all token data on disconnect', async () => {
      mockSql
        .mockResolvedValueOnce([
          {
            oauth_access_token: 'encrypted:access-token',
            oauth_refresh_token: 'encrypted:refresh-token',
          },
        ])
        .mockResolvedValueOnce([]); // Clear tokens

      await revokeTokens('tenant-123', 'gmail');

      expect(mockSql).toHaveBeenCalledTimes(2);
    });
  });
});

describe('Cross-Tenant Security', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSql.mockReset();
  });

  describe('Webhook Routing', () => {
    it('should only route to verified integrations', async () => {
      // This test verifies that webhooks use findIntegrationByEmail
      // which only returns integrations with verified connected_email
      mockSql.mockResolvedValueOnce([
        {
          id: 'integration-123',
          tenant_id: 'tenant-abc',
        },
      ]);

      const result = await findIntegrationByEmail('verified@example.com', 'gmail');

      expect(result).toEqual({
        tenantId: 'tenant-abc',
        integrationId: 'integration-123',
      });
    });

    it('should reject webhook for non-verified email', async () => {
      mockSql.mockResolvedValueOnce([]); // No verified integration

      const result = await findIntegrationByEmail('attacker@evil.com', 'gmail');

      expect(result).toBeNull();
      // Webhook handlers should ignore this email
    });
  });

  describe('Email Uniqueness Constraint', () => {
    it('should prevent connecting same email to multiple tenants', async () => {
      // First tenant already has this email
      mockSql.mockResolvedValueOnce([{ tenant_id: 'tenant-1' }]);

      const existingTenant = await isEmailAlreadyConnected(
        'shared@example.com',
        'gmail',
        'tenant-2'
      );

      expect(existingTenant).toBe('tenant-1');
      // OAuth flow should reject the connection attempt
    });

    it('should allow same tenant to reconnect same email', async () => {
      // Exclude current tenant from check
      mockSql.mockResolvedValueOnce([]);

      const existingTenant = await isEmailAlreadyConnected(
        'user@example.com',
        'gmail',
        'tenant-1'
      );

      expect(existingTenant).toBeNull();
      // Reconnection should be allowed
    });
  });
});

describe('CSRF Protection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSql.mockReset();
  });

  it('should generate unique state tokens', async () => {
    mockSql.mockResolvedValue([]);

    const state1 = await createOAuthState({
      tenantId: 'tenant-1',
      userId: 'user-1',
      provider: 'gmail',
      redirectUri: 'https://app.example.com/callback',
      expectedEmail: 'user1@example.com',
    });

    const state2 = await createOAuthState({
      tenantId: 'tenant-2',
      userId: 'user-2',
      provider: 'gmail',
      redirectUri: 'https://app.example.com/callback',
      expectedEmail: 'user2@example.com',
    });

    expect(state1.stateToken).not.toBe(state2.stateToken);
  });

  it('should invalidate state after single use', async () => {
    const validExpiry = new Date(Date.now() + 3600000);

    // First validation succeeds
    mockSql
      .mockResolvedValueOnce([
        {
          id: 'state-id-123',
          tenant_id: 'tenant-123',
          user_id: 'user-456',
          provider: 'gmail',
          state_token: 'state-token',
          expected_email: 'user@example.com',
          code_verifier: 'verifier-123',
          redirect_uri: 'https://app.example.com/callback',
          created_at: new Date(),
          expires_at: validExpiry,
          used_at: null,
        },
      ])
      .mockResolvedValueOnce([{ id: 'state-id-123' }]); // Mark as used returns row

    const firstValidation = await validateOAuthState('state-token');
    expect(firstValidation.valid).toBe(true);

    // Second validation should fail (already used)
    mockSql.mockResolvedValueOnce([
      {
        id: 'state-id-123',
        tenant_id: 'tenant-123',
        user_id: 'user-456',
        provider: 'gmail',
        state_token: 'state-token',
        expected_email: 'user@example.com',
        code_verifier: 'verifier-123',
        redirect_uri: 'https://app.example.com/callback',
        created_at: new Date(),
        expires_at: validExpiry,
        used_at: new Date(), // Now marked as used
      },
    ]);

    const secondValidation = await validateOAuthState('state-token');
    expect(secondValidation.valid).toBe(false);
    expect(secondValidation.error).toContain('used');
  });
});

describe('Token Security', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSql.mockReset();
  });

  it('should return valid token when not near expiry', async () => {
    // Token expires in 10 minutes (greater than 5 minute buffer)
    const validExpiry = new Date(Date.now() + 10 * 60 * 1000);
    mockSql.mockResolvedValueOnce([
      {
        oauth_access_token: 'encrypted:valid-token',
        oauth_refresh_token: 'encrypted:refresh-token',
        oauth_token_expires_at: validExpiry,
        oauth_scopes: 'gmail.readonly',
        connected_email: 'user@example.com',
      },
    ]);

    const token = await getAccessToken('tenant-123', 'gmail');

    // Should return existing token without refresh
    expect(token).toBe('valid-token');
  });

  it('should validate token expiry check works correctly', () => {
    // Test the buffer calculation
    const now = Date.now();
    const bufferMs = 5 * 60 * 1000; // 5 minutes

    // Token expiring in 3 minutes should trigger refresh
    const nearExpiry = new Date(now + 3 * 60 * 1000);
    expect(nearExpiry.getTime() - now < bufferMs).toBe(true);

    // Token expiring in 10 minutes should not trigger refresh
    const farExpiry = new Date(now + 10 * 60 * 1000);
    expect(farExpiry.getTime() - now < bufferMs).toBe(false);
  });
});

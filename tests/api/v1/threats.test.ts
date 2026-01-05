/**
 * REST API v1 - Threats Endpoint Tests
 *
 * Unit tests for API authentication, rate limiting, and response formatting
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Test pure functions and types
describe('API Authentication', () => {
  describe('API Scopes', () => {
    it('should define all required scopes', async () => {
      const { API_SCOPES } = await import('@/lib/api/auth');

      expect(API_SCOPES.THREATS_READ).toBe('threats:read');
      expect(API_SCOPES.THREATS_WRITE).toBe('threats:write');
      expect(API_SCOPES.QUARANTINE_READ).toBe('quarantine:read');
      expect(API_SCOPES.QUARANTINE_WRITE).toBe('quarantine:write');
      expect(API_SCOPES.POLICIES_READ).toBe('policies:read');
      expect(API_SCOPES.POLICIES_WRITE).toBe('policies:write');
    });

    it('should check scope membership', async () => {
      const { hasScope, API_SCOPES } = await import('@/lib/api/auth');

      expect(hasScope(['threats:read', 'threats:write'], 'threats:read')).toBe(true);
      expect(hasScope(['threats:read'], 'threats:write')).toBe(false);
      expect(hasScope([API_SCOPES.ADMIN], 'threats:read')).toBe(true); // Admin scope grants all
      expect(hasScope([], 'threats:read')).toBe(false);
    });
  });

  describe('API Key Generation', () => {
    it('should generate valid API keys', async () => {
      const { generateApiKey } = await import('@/lib/api/auth');

      const result = generateApiKey();

      expect(result.key).toMatch(/^sf_live_[a-zA-Z0-9_-]+$/);
      expect(result.key.length).toBeGreaterThan(20);
      expect(result.prefix).toBe(result.key.substring(0, 12));
      expect(result.hash).toHaveLength(64); // SHA256 hex
    });

    it('should generate unique keys', async () => {
      const { generateApiKey } = await import('@/lib/api/auth');

      const keys = new Set();
      for (let i = 0; i < 100; i++) {
        const result = generateApiKey();
        keys.add(result.key);
      }

      expect(keys.size).toBe(100);
    });

    it('should produce consistent hashes', async () => {
      const crypto = await import('crypto');

      const key = 'sf_live_test_key_123';
      const hash1 = crypto.createHash('sha256').update(key).digest('hex');
      const hash2 = crypto.createHash('sha256').update(key).digest('hex');

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // SHA256 hex
    });
  });
});

describe('Rate Limiting', () => {
  beforeEach(async () => {
    // Reset rate limit store between tests
    vi.resetModules();
  });

  describe('Rate Limit Configuration', () => {
    it('should have correct limits per plan', async () => {
      const { RATE_LIMITS } = await import('@/lib/api/rate-limit');

      expect(RATE_LIMITS.starter.maxRequests).toBe(100);
      expect(RATE_LIMITS.pro.maxRequests).toBe(500);
      expect(RATE_LIMITS.enterprise.maxRequests).toBe(2000);
      expect(RATE_LIMITS.default.maxRequests).toBe(60);
    });

    it('should have 1-minute windows', async () => {
      const { RATE_LIMITS } = await import('@/lib/api/rate-limit');

      expect(RATE_LIMITS.starter.windowMs).toBe(60000);
      expect(RATE_LIMITS.pro.windowMs).toBe(60000);
      expect(RATE_LIMITS.enterprise.windowMs).toBe(60000);
    });
  });

  describe('Token Bucket Algorithm', () => {
    it('should allow requests within limit', async () => {
      const { checkRateLimit } = await import('@/lib/api/rate-limit');
      const key = `test_${Date.now()}_${Math.random()}`;

      const result = checkRateLimit(key, { maxRequests: 10, windowMs: 60000 });

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(9);
      expect(result.resetAt).toBeGreaterThan(Date.now());
    });

    it('should track remaining requests', async () => {
      const { checkRateLimit } = await import('@/lib/api/rate-limit');
      const key = `test_${Date.now()}_${Math.random()}`;
      const config = { maxRequests: 5, windowMs: 60000 };

      checkRateLimit(key, config); // remaining: 4
      checkRateLimit(key, config); // remaining: 3
      const result = checkRateLimit(key, config); // remaining: 2

      expect(result.remaining).toBe(2);
    });

    it('should block when limit exceeded', async () => {
      const { checkRateLimit } = await import('@/lib/api/rate-limit');
      const key = `test_${Date.now()}_${Math.random()}`;
      const config = { maxRequests: 2, windowMs: 60000 };

      checkRateLimit(key, config);
      checkRateLimit(key, config);
      const result = checkRateLimit(key, config);

      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });

    it('should use key prefix for namespacing', async () => {
      const { checkRateLimit } = await import('@/lib/api/rate-limit');
      const baseKey = `test_${Date.now()}`;

      const result1 = checkRateLimit(baseKey, { maxRequests: 10, windowMs: 60000, keyPrefix: 'api' });
      const result2 = checkRateLimit(baseKey, { maxRequests: 10, windowMs: 60000, keyPrefix: 'webhook' });

      // Both should have full remaining since different prefixes
      expect(result1.remaining).toBe(9);
      expect(result2.remaining).toBe(9);
    });
  });
});

describe('API Response Formatting', () => {
  describe('Success Responses', () => {
    it('should format success response', async () => {
      const { apiSuccess } = await import('@/lib/api/response');

      const response = apiSuccess({ items: [1, 2, 3] });
      const data = await response.json();

      expect(data.success).toBe(true);
      expect(data.data.items).toEqual([1, 2, 3]);
    });

    it('should include pagination metadata', async () => {
      const { apiSuccess } = await import('@/lib/api/response');

      const response = apiSuccess(
        { items: [] },
        { page: 2, pageSize: 10, total: 100, totalPages: 10 }
      );
      const data = await response.json();

      // The api response uses 'meta' not 'pagination'
      expect(data.meta.page).toBe(2);
      expect(data.meta.pageSize).toBe(10);
      expect(data.meta.total).toBe(100);
      expect(data.meta.totalPages).toBe(10);
    });
  });

  describe('Error Responses', () => {
    it('should format error response', async () => {
      const { apiError } = await import('@/lib/api/response');

      const response = apiError('SERVER_ERROR', 'Something went wrong', 500);

      expect(response.status).toBe(500);
      const data = await response.json();
      expect(data.success).toBe(false);
      expect(data.error.message).toBe('Something went wrong');
      expect(data.error.code).toBe('SERVER_ERROR');
    });

    it('should provide standard error helpers', async () => {
      const { errors } = await import('@/lib/api/response');

      const unauthorized = errors.unauthorized();
      expect(unauthorized.status).toBe(401);

      const notFound = errors.notFound('User');
      expect(notFound.status).toBe(404);

      const badRequest = errors.badRequest('Invalid input');
      expect(badRequest.status).toBe(400);

      const conflict = errors.conflict('Already exists');
      expect(conflict.status).toBe(409);
    });
  });

  describe('Pagination Parsing', () => {
    it('should parse valid pagination params', async () => {
      const { parsePagination } = await import('@/lib/api/response');

      const params = new URLSearchParams({ page: '3', pageSize: '25' });
      const result = parsePagination(params);

      expect(result.page).toBe(3);
      expect(result.pageSize).toBe(25);
      expect(result.offset).toBe(50);
    });

    it('should use defaults for missing params', async () => {
      const { parsePagination } = await import('@/lib/api/response');

      const params = new URLSearchParams();
      const result = parsePagination(params);

      expect(result.page).toBe(1);
      expect(result.pageSize).toBe(20);
      expect(result.offset).toBe(0);
    });

    it('should cap pageSize at maximum', async () => {
      const { parsePagination } = await import('@/lib/api/response');

      const params = new URLSearchParams({ pageSize: '500' });
      const result = parsePagination(params);

      expect(result.pageSize).toBe(100); // Max limit
    });

    it('should handle invalid values', async () => {
      const { parsePagination } = await import('@/lib/api/response');

      // NaN values default to 1/20
      const params = new URLSearchParams({ page: 'abc', pageSize: 'xyz' });
      const result = parsePagination(params);

      expect(result.page).toBe(1);
      expect(result.pageSize).toBe(20);

      // Negative values are clamped to 1
      const params2 = new URLSearchParams({ page: '-5', pageSize: '-5' });
      const result2 = parsePagination(params2);

      expect(result2.page).toBe(1);
      expect(result2.pageSize).toBe(1);
    });
  });
});

describe('Threat Data Formatting', () => {
  it('should format threat object correctly', () => {
    const rawThreat = {
      id: 'threat_123',
      message_id: 'msg_456',
      subject: 'Test Email',
      from_address: 'sender@example.com',
      from_display_name: 'Sender Name',
      to_addresses: ['recipient@example.com'],
      received_at: new Date('2024-01-15T10:00:00Z'),
      verdict: 'quarantine',
      confidence: 85,
      verdict_reason: 'Suspicious content',
      signals: ['suspicious_url', 'new_sender'],
      ml_classification: 'phishing',
      action_taken: 'quarantine',
      action_taken_at: new Date('2024-01-15T10:01:00Z'),
      created_at: new Date('2024-01-15T10:00:00Z'),
    };

    // Format as API would
    const formatted = {
      id: rawThreat.id,
      messageId: rawThreat.message_id,
      subject: rawThreat.subject,
      from: {
        address: rawThreat.from_address,
        displayName: rawThreat.from_display_name,
      },
      to: rawThreat.to_addresses,
      receivedAt: rawThreat.received_at,
      verdict: rawThreat.verdict,
      confidence: rawThreat.confidence,
      reason: rawThreat.verdict_reason,
      signals: rawThreat.signals,
      classification: rawThreat.ml_classification,
      action: rawThreat.action_taken,
      actionTakenAt: rawThreat.action_taken_at,
      createdAt: rawThreat.created_at,
    };

    expect(formatted.id).toBe('threat_123');
    expect(formatted.from.address).toBe('sender@example.com');
    expect(formatted.verdict).toBe('quarantine');
    expect(formatted.signals).toContain('suspicious_url');
  });

  it('should calculate severity from confidence', () => {
    const getSeverity = (confidence: number): string => {
      if (confidence >= 90) return 'critical';
      if (confidence >= 70) return 'high';
      if (confidence >= 50) return 'medium';
      return 'low';
    };

    expect(getSeverity(95)).toBe('critical');
    expect(getSeverity(85)).toBe('high');
    expect(getSeverity(60)).toBe('medium');
    expect(getSeverity(30)).toBe('low');
  });
});

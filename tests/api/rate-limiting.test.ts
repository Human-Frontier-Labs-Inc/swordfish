/**
 * Rate Limiting Tests
 * TDD: Prevent API abuse through rate limiting
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import {
  RateLimiter,
  createRateLimiter,
  RateLimitConfig,
  RateLimitResult,
  RateLimitExceededError,
} from '@/lib/api/rate-limiter';

describe('Rate Limiting', () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    vi.useFakeTimers();
    // Default: 100 requests per minute
    limiter = createRateLimiter({ maxRequests: 100, windowMs: 60000 });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('RateLimiter', () => {
    describe('check', () => {
      it('should allow requests under the limit', async () => {
        const result = await limiter.check('user-123');

        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(99);
        expect(result.limit).toBe(100);
      });

      it('should track requests per identifier', async () => {
        await limiter.check('user-1');
        await limiter.check('user-1');
        await limiter.check('user-1');

        const result = await limiter.check('user-1');

        expect(result.remaining).toBe(96); // 100 - 4 requests
      });

      it('should allow different users independently', async () => {
        // User 1 makes 50 requests
        for (let i = 0; i < 50; i++) {
          await limiter.check('user-1');
        }

        // User 2 should still have full quota
        const result = await limiter.check('user-2');

        expect(result.remaining).toBe(99);
      });

      it('should deny requests when limit exceeded', async () => {
        // Exhaust the limit
        for (let i = 0; i < 100; i++) {
          await limiter.check('user-123');
        }

        // Next request should be denied
        const result = await limiter.check('user-123');

        expect(result.allowed).toBe(false);
        expect(result.remaining).toBe(0);
      });

      it('should reset after window expires', async () => {
        // Exhaust the limit
        for (let i = 0; i < 100; i++) {
          await limiter.check('user-123');
        }

        // Should be denied
        let result = await limiter.check('user-123');
        expect(result.allowed).toBe(false);

        // Fast forward past the window
        vi.advanceTimersByTime(61000);

        // Should be allowed again
        result = await limiter.check('user-123');
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(99);
      });

      it('should include retryAfter when rate limited', async () => {
        // Exhaust the limit
        for (let i = 0; i < 100; i++) {
          await limiter.check('user-123');
        }

        const result = await limiter.check('user-123');

        expect(result.allowed).toBe(false);
        expect(result.retryAfter).toBeDefined();
        expect(result.retryAfter).toBeGreaterThan(0);
        expect(result.retryAfter).toBeLessThanOrEqual(60); // Max window in seconds
      });
    });

    describe('consume', () => {
      it('should increment counter and return result', async () => {
        const result = await limiter.consume('user-123');

        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(99);
      });

      it('should throw when limit exceeded (if throwOnLimit option)', async () => {
        const strictLimiter = createRateLimiter({
          maxRequests: 5,
          windowMs: 60000,
          throwOnLimit: true,
        });

        // Exhaust the limit
        for (let i = 0; i < 5; i++) {
          await strictLimiter.consume('user-123');
        }

        // Should throw
        await expect(strictLimiter.consume('user-123')).rejects.toThrow(RateLimitExceededError);
      });
    });

    describe('reset', () => {
      it('should reset counter for identifier', async () => {
        // Make some requests
        for (let i = 0; i < 50; i++) {
          await limiter.check('user-123');
        }

        // Reset
        await limiter.reset('user-123');

        // Should have full quota again
        const result = await limiter.check('user-123');
        expect(result.remaining).toBe(99);
      });
    });
  });

  describe('Different rate limit tiers', () => {
    it('should support different limits for different endpoints', async () => {
      const apiLimiter = createRateLimiter({ maxRequests: 1000, windowMs: 60000 });
      const authLimiter = createRateLimiter({ maxRequests: 10, windowMs: 60000 });

      // API endpoint allows 1000
      const apiResult = await apiLimiter.check('user-123');
      expect(apiResult.limit).toBe(1000);

      // Auth endpoint allows only 10
      const authResult = await authLimiter.check('user-123');
      expect(authResult.limit).toBe(10);
    });

    it('should support per-tenant limits', async () => {
      const freeLimiter = createRateLimiter({ maxRequests: 100, windowMs: 60000 });
      const proLimiter = createRateLimiter({ maxRequests: 10000, windowMs: 60000 });

      const freeResult = await freeLimiter.check('free-user');
      const proResult = await proLimiter.check('pro-user');

      expect(freeResult.limit).toBe(100);
      expect(proResult.limit).toBe(10000);
    });
  });

  describe('Sliding window behavior', () => {
    it('should use sliding window (not fixed window)', async () => {
      // Make 60 requests in the first 30 seconds
      for (let i = 0; i < 60; i++) {
        await limiter.check('user-123');
      }

      // Advance 30 seconds (half the window)
      vi.advanceTimersByTime(30000);

      // Make another 40 requests (total 100 in last 60 seconds = at limit)
      for (let i = 0; i < 40; i++) {
        await limiter.check('user-123');
      }

      // Should be at or near limit
      const result = await limiter.check('user-123');
      expect(result.allowed).toBe(false);
    });
  });

  describe('Rate limit headers', () => {
    it('should provide headers for HTTP response', async () => {
      const result = await limiter.check('user-123');

      const headers = {
        'X-RateLimit-Limit': String(result.limit),
        'X-RateLimit-Remaining': String(result.remaining),
        'X-RateLimit-Reset': String(result.resetAt),
      };

      expect(headers['X-RateLimit-Limit']).toBe('100');
      expect(headers['X-RateLimit-Remaining']).toBe('99');
      expect(Number(headers['X-RateLimit-Reset'])).toBeGreaterThan(0);
    });

    it('should include Retry-After header when rate limited', async () => {
      // Exhaust the limit
      for (let i = 0; i < 100; i++) {
        await limiter.check('user-123');
      }

      const result = await limiter.check('user-123');

      expect(result.retryAfter).toBeDefined();
      // Retry-After should be in seconds
      expect(result.retryAfter).toBeGreaterThan(0);
    });
  });

  describe('RateLimitExceededError', () => {
    it('should be an Error instance', () => {
      const error = new RateLimitExceededError('Rate limit exceeded', 60);

      expect(error).toBeInstanceOf(Error);
      expect(error.name).toBe('RateLimitExceededError');
    });

    it('should include retryAfter', () => {
      const error = new RateLimitExceededError('Rate limit exceeded', 30);

      expect(error.retryAfter).toBe(30);
    });

    it('should have correct HTTP status code', () => {
      const error = new RateLimitExceededError('Rate limit exceeded', 30);

      expect(error.statusCode).toBe(429);
    });
  });

  describe('Edge cases', () => {
    it('should handle empty identifier', async () => {
      const result = await limiter.check('');

      expect(result.allowed).toBe(true);
    });

    it('should handle special characters in identifier', async () => {
      const result = await limiter.check('user@example.com:api-key');

      expect(result.allowed).toBe(true);
    });

    it('should handle concurrent requests correctly', async () => {
      // Simulate 10 concurrent requests
      const promises = Array(10)
        .fill(null)
        .map(() => limiter.check('user-123'));

      const results = await Promise.all(promises);

      // All should be allowed (under 100)
      expect(results.every((r) => r.allowed)).toBe(true);

      // Total remaining should be 100 - 10 = 90
      const lastResult = await limiter.check('user-123');
      expect(lastResult.remaining).toBe(89);
    });
  });

  describe('Custom configuration', () => {
    it('should support custom window size', async () => {
      const hourlyLimiter = createRateLimiter({
        maxRequests: 1000,
        windowMs: 3600000, // 1 hour
      });

      const result = await hourlyLimiter.check('user-123');
      expect(result.limit).toBe(1000);
    });

    it('should support very low limits for sensitive endpoints', async () => {
      const passwordResetLimiter = createRateLimiter({
        maxRequests: 3,
        windowMs: 3600000, // 3 per hour
      });

      // Use all 3
      await passwordResetLimiter.check('user-123');
      await passwordResetLimiter.check('user-123');
      await passwordResetLimiter.check('user-123');

      // 4th should be denied
      const result = await passwordResetLimiter.check('user-123');
      expect(result.allowed).toBe(false);
    });

    it('should support burst mode with higher initial limit', async () => {
      const burstLimiter = createRateLimiter({
        maxRequests: 100,
        windowMs: 60000,
        burstLimit: 20, // Allow 20 requests burst
      });

      // Make burst of 15 requests
      const burstResults = await Promise.all(
        Array(15)
          .fill(null)
          .map(() => burstLimiter.check('user-123'))
      );

      // All should be allowed
      expect(burstResults.every((r) => r.allowed)).toBe(true);
    });
  });
});

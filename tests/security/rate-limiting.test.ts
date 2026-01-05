/**
 * Rate Limiting Tests
 *
 * TDD tests for API rate limiting and security headers
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import {
  RateLimiter,
  RateLimitConfig,
  RateLimitResult,
  SecurityHeaders,
  generateSecurityHeaders,
  validateRequestOrigin,
  CsrfProtection,
} from '@/lib/security/rate-limiting';

describe('Rate Limiter', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Basic Rate Limiting', () => {
    it('should allow requests within limit', async () => {
      const limiter = new RateLimiter({
        windowMs: 60000, // 1 minute
        maxRequests: 10,
      });

      for (let i = 0; i < 10; i++) {
        const result = await limiter.check('user-1');
        expect(result.allowed).toBe(true);
      }
    });

    it('should block requests exceeding limit', async () => {
      const limiter = new RateLimiter({
        windowMs: 60000,
        maxRequests: 5,
      });

      // Use up the limit
      for (let i = 0; i < 5; i++) {
        await limiter.check('user-1');
      }

      // Next request should be blocked
      const result = await limiter.check('user-1');
      expect(result.allowed).toBe(false);
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    it('should reset after window expires', async () => {
      const limiter = new RateLimiter({
        windowMs: 60000,
        maxRequests: 5,
      });

      // Use up the limit
      for (let i = 0; i < 5; i++) {
        await limiter.check('user-1');
      }

      // Advance time past the window
      vi.advanceTimersByTime(61000);

      // Should be allowed again
      const result = await limiter.check('user-1');
      expect(result.allowed).toBe(true);
    });

    it('should track limits per key', async () => {
      const limiter = new RateLimiter({
        windowMs: 60000,
        maxRequests: 5,
      });

      // Use up limit for user-1
      for (let i = 0; i < 5; i++) {
        await limiter.check('user-1');
      }

      // user-2 should still be allowed
      const result = await limiter.check('user-2');
      expect(result.allowed).toBe(true);
    });
  });

  describe('Sliding Window', () => {
    it('should implement sliding window algorithm', async () => {
      const limiter = new RateLimiter({
        windowMs: 60000,
        maxRequests: 10,
        algorithm: 'sliding',
      });

      // Make 10 requests
      for (let i = 0; i < 10; i++) {
        await limiter.check('user-1');
        vi.advanceTimersByTime(5000); // 5 seconds between each
      }

      // After 50 seconds, early requests should start expiring
      vi.advanceTimersByTime(15000); // Total 65 seconds from first

      // Should be allowed (early requests expired)
      const result = await limiter.check('user-1');
      expect(result.allowed).toBe(true);
    });
  });

  describe('Token Bucket', () => {
    it('should implement token bucket algorithm', async () => {
      const limiter = new RateLimiter({
        windowMs: 60000,
        maxRequests: 10,
        algorithm: 'token-bucket',
        refillRate: 1, // 1 token per second
      });

      // Use all tokens
      for (let i = 0; i < 10; i++) {
        await limiter.check('user-1');
      }

      // Should be blocked
      let result = await limiter.check('user-1');
      expect(result.allowed).toBe(false);

      // Wait for refill
      vi.advanceTimersByTime(5000);

      // Should have 5 tokens now
      result = await limiter.check('user-1');
      expect(result.allowed).toBe(true);
    });

    it('should allow burst traffic', async () => {
      const limiter = new RateLimiter({
        windowMs: 60000,
        maxRequests: 10,
        algorithm: 'token-bucket',
        burstSize: 10,
      });

      // Burst 10 requests instantly
      for (let i = 0; i < 10; i++) {
        const result = await limiter.check('user-1');
        expect(result.allowed).toBe(true);
      }
    });
  });

  describe('Rate Limit Headers', () => {
    it('should return remaining requests', async () => {
      const limiter = new RateLimiter({
        windowMs: 60000,
        maxRequests: 10,
      });

      const result = await limiter.check('user-1');

      expect(result.remaining).toBe(9);
      expect(result.limit).toBe(10);
    });

    it('should return reset time', async () => {
      const limiter = new RateLimiter({
        windowMs: 60000,
        maxRequests: 10,
      });

      const result = await limiter.check('user-1');

      expect(result.reset).toBeDefined();
      expect(result.reset).toBeGreaterThan(Date.now());
    });
  });

  describe('Different Limits by Tier', () => {
    it('should apply different limits per tier', async () => {
      const limiter = new RateLimiter({
        windowMs: 60000,
        maxRequests: 10, // Default
        tierLimits: {
          free: 10,
          pro: 100,
          enterprise: 1000,
        },
      });

      // Free user hits limit quickly
      for (let i = 0; i < 10; i++) {
        await limiter.check('free-user', { tier: 'free' });
      }
      expect((await limiter.check('free-user', { tier: 'free' })).allowed).toBe(false);

      // Pro user has higher limit
      for (let i = 0; i < 100; i++) {
        await limiter.check('pro-user', { tier: 'pro' });
      }
      expect((await limiter.check('pro-user', { tier: 'pro' })).allowed).toBe(false);
    });
  });

  describe('IP-based Rate Limiting', () => {
    it('should rate limit by IP address', async () => {
      const limiter = new RateLimiter({
        windowMs: 60000,
        maxRequests: 5,
        keyType: 'ip',
      });

      // Same IP should share limit
      for (let i = 0; i < 5; i++) {
        await limiter.check('192.168.1.1');
      }

      const result = await limiter.check('192.168.1.1');
      expect(result.allowed).toBe(false);

      // Different IP allowed
      const result2 = await limiter.check('192.168.1.2');
      expect(result2.allowed).toBe(true);
    });
  });
});

describe('Security Headers', () => {
  it('should generate standard security headers', () => {
    const headers = generateSecurityHeaders();

    expect(headers['X-Content-Type-Options']).toBe('nosniff');
    expect(headers['X-Frame-Options']).toBe('DENY');
    expect(headers['X-XSS-Protection']).toBe('1; mode=block');
    expect(headers['Referrer-Policy']).toBe('strict-origin-when-cross-origin');
  });

  it('should include HSTS header', () => {
    const headers = generateSecurityHeaders({ hsts: true });

    expect(headers['Strict-Transport-Security']).toBe(
      'max-age=31536000; includeSubDomains; preload'
    );
  });

  it('should include CSP header', () => {
    const headers = generateSecurityHeaders({
      csp: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
      },
    });

    expect(headers['Content-Security-Policy']).toContain("default-src 'self'");
    expect(headers['Content-Security-Policy']).toContain("script-src 'self' 'unsafe-inline'");
  });

  it('should include CORS headers when configured', () => {
    const headers = generateSecurityHeaders({
      cors: {
        allowOrigin: 'https://example.com',
        allowMethods: ['GET', 'POST'],
        allowHeaders: ['Content-Type', 'Authorization'],
      },
    });

    expect(headers['Access-Control-Allow-Origin']).toBe('https://example.com');
    expect(headers['Access-Control-Allow-Methods']).toBe('GET, POST');
    expect(headers['Access-Control-Allow-Headers']).toBe('Content-Type, Authorization');
  });

  it('should set permissions policy', () => {
    const headers = generateSecurityHeaders({
      permissions: {
        camera: [],
        microphone: [],
        geolocation: ['self'],
      },
    });

    expect(headers['Permissions-Policy']).toContain('camera=()');
    expect(headers['Permissions-Policy']).toContain('microphone=()');
    expect(headers['Permissions-Policy']).toContain('geolocation=(self)');
  });
});

describe('Request Origin Validation', () => {
  it('should accept valid origins', () => {
    const allowedOrigins = ['https://app.swordfish.com', 'https://admin.swordfish.com'];

    expect(validateRequestOrigin('https://app.swordfish.com', allowedOrigins)).toBe(true);
    expect(validateRequestOrigin('https://admin.swordfish.com', allowedOrigins)).toBe(true);
  });

  it('should reject invalid origins', () => {
    const allowedOrigins = ['https://app.swordfish.com'];

    expect(validateRequestOrigin('https://evil.com', allowedOrigins)).toBe(false);
    expect(validateRequestOrigin('http://app.swordfish.com', allowedOrigins)).toBe(false); // Wrong protocol
  });

  it('should handle wildcard subdomains', () => {
    const allowedOrigins = ['https://*.swordfish.com'];

    expect(validateRequestOrigin('https://app.swordfish.com', allowedOrigins)).toBe(true);
    expect(validateRequestOrigin('https://api.swordfish.com', allowedOrigins)).toBe(true);
    expect(validateRequestOrigin('https://evil.com', allowedOrigins)).toBe(false);
  });
});

describe('CSRF Protection', () => {
  it('should generate CSRF tokens', () => {
    const csrf = new CsrfProtection({ secret: 'test-secret' });

    const token = csrf.generateToken('session-123');

    expect(token).toBeDefined();
    expect(token.length).toBeGreaterThan(20);
  });

  it('should validate correct CSRF tokens', () => {
    const csrf = new CsrfProtection({ secret: 'test-secret' });

    const token = csrf.generateToken('session-123');
    const isValid = csrf.validateToken(token, 'session-123');

    expect(isValid).toBe(true);
  });

  it('should reject invalid CSRF tokens', () => {
    const csrf = new CsrfProtection({ secret: 'test-secret' });

    csrf.generateToken('session-123');
    const isValid = csrf.validateToken('invalid-token', 'session-123');

    expect(isValid).toBe(false);
  });

  it('should reject tokens for wrong session', () => {
    const csrf = new CsrfProtection({ secret: 'test-secret' });

    const token = csrf.generateToken('session-123');
    const isValid = csrf.validateToken(token, 'session-456');

    expect(isValid).toBe(false);
  });

  it('should expire old tokens', () => {
    vi.useFakeTimers();

    const csrf = new CsrfProtection({
      secret: 'test-secret',
      tokenTtlMs: 60000, // 1 minute
    });

    const token = csrf.generateToken('session-123');

    // Advance time
    vi.advanceTimersByTime(61000);

    const isValid = csrf.validateToken(token, 'session-123');
    expect(isValid).toBe(false);

    vi.useRealTimers();
  });
});

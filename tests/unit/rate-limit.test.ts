/**
 * Unit tests for rate limiting logic
 * Tests the in-memory rate limiter in /lib/api/rate-limit.ts
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { checkRateLimit, rateLimit, cleanupExpiredEntries } from '@/lib/api/rate-limit';

describe('checkRateLimit', () => {
  beforeEach(() => {
    // Clean all entries before each test so state doesn't leak
    vi.useFakeTimers();
    cleanupExpiredEntries();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should allow requests under the limit', () => {
    const config = { maxRequests: 5, windowMs: 60000 };

    const result1 = checkRateLimit('user-1', config);
    expect(result1.allowed).toBe(true);
    expect(result1.remaining).toBe(4);

    const result2 = checkRateLimit('user-1', config);
    expect(result2.allowed).toBe(true);
    expect(result2.remaining).toBe(3);
  });

  it('should block requests over the limit', () => {
    const config = { maxRequests: 3, windowMs: 60000 };

    // Exhaust the limit
    checkRateLimit('user-block', config); // 1
    checkRateLimit('user-block', config); // 2
    checkRateLimit('user-block', config); // 3

    // Fourth request should be blocked
    const result = checkRateLimit('user-block', config);
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
  });

  it('should reset after the time window expires', () => {
    const config = { maxRequests: 2, windowMs: 10000 };

    // Use up all requests
    checkRateLimit('user-reset', config);
    checkRateLimit('user-reset', config);

    const blocked = checkRateLimit('user-reset', config);
    expect(blocked.allowed).toBe(false);

    // Advance past the window
    vi.advanceTimersByTime(11000);

    const afterReset = checkRateLimit('user-reset', config);
    expect(afterReset.allowed).toBe(true);
    expect(afterReset.remaining).toBe(1);
  });

  it('should track different identifiers independently', () => {
    const config = { maxRequests: 2, windowMs: 60000 };

    // Exhaust limit for user-a
    checkRateLimit('user-a', config);
    checkRateLimit('user-a', config);
    const blockedA = checkRateLimit('user-a', config);
    expect(blockedA.allowed).toBe(false);

    // user-b should still be allowed
    const resultB = checkRateLimit('user-b', config);
    expect(resultB.allowed).toBe(true);
    expect(resultB.remaining).toBe(1);
  });

  it('should support keyPrefix to namespace limiters', () => {
    const config = { maxRequests: 1, windowMs: 60000, keyPrefix: 'api' };

    checkRateLimit('user-prefix', config);
    const blocked = checkRateLimit('user-prefix', config);
    expect(blocked.allowed).toBe(false);

    // Same identifier without prefix should be independent
    const configNoPrefix = { maxRequests: 1, windowMs: 60000 };
    const independent = checkRateLimit('user-prefix', configNoPrefix);
    expect(independent.allowed).toBe(true);
  });
});

describe('rateLimit (simple helper)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    cleanupExpiredEntries();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should return success=true when under the limit', () => {
    const result = rateLimit('simple-user', 5, 60000);
    expect(result.success).toBe(true);
    expect(result.remaining).toBe(4);
  });

  it('should return success=false when over the limit', () => {
    rateLimit('simple-blocked', 2, 60000);
    rateLimit('simple-blocked', 2, 60000);
    const result = rateLimit('simple-blocked', 2, 60000);
    expect(result.success).toBe(false);
    expect(result.remaining).toBe(0);
  });
});

/**
 * API Rate Limiting
 *
 * Token bucket rate limiting for REST API
 */

import { NextRequest, NextResponse } from 'next/server';

interface RateLimitConfig {
  maxRequests: number;  // Max requests per window
  windowMs: number;     // Window size in milliseconds
  keyPrefix?: string;   // Optional key prefix for different limiters
}

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

// In-memory store (use Redis in production)
const store = new Map<string, RateLimitEntry>();

// Default rate limits by plan
export const RATE_LIMITS = {
  starter: { maxRequests: 100, windowMs: 60 * 1000 },    // 100/min
  pro: { maxRequests: 500, windowMs: 60 * 1000 },       // 500/min
  enterprise: { maxRequests: 2000, windowMs: 60 * 1000 }, // 2000/min
  default: { maxRequests: 60, windowMs: 60 * 1000 },     // 60/min for unauthenticated
};

/**
 * Check rate limit for a given key
 */
export function checkRateLimit(
  key: string,
  config: RateLimitConfig
): { allowed: boolean; remaining: number; resetAt: number } {
  const now = Date.now();
  const fullKey = config.keyPrefix ? `${config.keyPrefix}:${key}` : key;

  let entry = store.get(fullKey);

  // If no entry or window has passed, create new entry
  if (!entry || now >= entry.resetAt) {
    entry = {
      count: 1,
      resetAt: now + config.windowMs,
    };
    store.set(fullKey, entry);

    return {
      allowed: true,
      remaining: config.maxRequests - 1,
      resetAt: entry.resetAt,
    };
  }

  // Check if limit exceeded
  if (entry.count >= config.maxRequests) {
    return {
      allowed: false,
      remaining: 0,
      resetAt: entry.resetAt,
    };
  }

  // Increment counter
  entry.count++;
  store.set(fullKey, entry);

  return {
    allowed: true,
    remaining: config.maxRequests - entry.count,
    resetAt: entry.resetAt,
  };
}

/**
 * Rate limit middleware for API routes
 */
export function rateLimitMiddleware(
  request: NextRequest,
  tenantId: string | null,
  plan: string = 'default'
): NextResponse | null {
  // Get rate limit config based on plan
  const config = RATE_LIMITS[plan as keyof typeof RATE_LIMITS] || RATE_LIMITS.default;

  // Use tenant ID or IP as the rate limit key
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0] ||
             request.headers.get('x-real-ip') ||
             'anonymous';
  const key = tenantId || ip;

  const { allowed, remaining, resetAt } = checkRateLimit(key, {
    ...config,
    keyPrefix: 'api',
  });

  // If rate limited, return 429 response
  if (!allowed) {
    return NextResponse.json(
      {
        error: 'Rate limit exceeded',
        message: `Too many requests. Please wait ${Math.ceil((resetAt - Date.now()) / 1000)} seconds.`,
        retryAfter: Math.ceil((resetAt - Date.now()) / 1000),
      },
      {
        status: 429,
        headers: {
          'X-RateLimit-Limit': config.maxRequests.toString(),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset': Math.ceil(resetAt / 1000).toString(),
          'Retry-After': Math.ceil((resetAt - Date.now()) / 1000).toString(),
        },
      }
    );
  }

  // Return null to indicate request is allowed (headers will be added by the route)
  return null;
}

/**
 * Get rate limit headers to add to successful responses
 */
export function getRateLimitHeaders(
  tenantId: string | null,
  plan: string = 'default'
): Record<string, string> {
  const config = RATE_LIMITS[plan as keyof typeof RATE_LIMITS] || RATE_LIMITS.default;
  const key = tenantId || 'anonymous';
  const fullKey = `api:${key}`;

  const entry = store.get(fullKey);
  const now = Date.now();

  if (!entry || now >= entry.resetAt) {
    return {
      'X-RateLimit-Limit': config.maxRequests.toString(),
      'X-RateLimit-Remaining': config.maxRequests.toString(),
      'X-RateLimit-Reset': Math.ceil((now + config.windowMs) / 1000).toString(),
    };
  }

  return {
    'X-RateLimit-Limit': config.maxRequests.toString(),
    'X-RateLimit-Remaining': Math.max(0, config.maxRequests - entry.count).toString(),
    'X-RateLimit-Reset': Math.ceil(entry.resetAt / 1000).toString(),
  };
}

/**
 * Clean up expired entries (call periodically)
 */
export function cleanupExpiredEntries(): number {
  const now = Date.now();
  let cleaned = 0;

  for (const [key, entry] of store.entries()) {
    if (now >= entry.resetAt) {
      store.delete(key);
      cleaned++;
    }
  }

  return cleaned;
}

// Note: In serverless environments, cleanup happens on each request
// For persistent servers, call cleanupExpiredEntries() periodically

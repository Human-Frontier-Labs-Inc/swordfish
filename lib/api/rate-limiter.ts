/**
 * Rate Limiter Module
 *
 * Implements a sliding window rate limiter for API protection.
 * Supports per-identifier limits with configurable windows.
 */

/**
 * Rate limit configuration
 */
export interface RateLimitConfig {
  /** Maximum requests allowed in the window */
  maxRequests: number;
  /** Window size in milliseconds */
  windowMs: number;
  /** Throw error when limit exceeded (default: false) */
  throwOnLimit?: boolean;
  /** Burst limit for initial requests (default: same as maxRequests) */
  burstLimit?: number;
}

/**
 * Result of a rate limit check
 */
export interface RateLimitResult {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Remaining requests in the window */
  remaining: number;
  /** Total limit */
  limit: number;
  /** Unix timestamp when the window resets */
  resetAt: number;
  /** Seconds until retry is allowed (only when rate limited) */
  retryAfter?: number;
}

/**
 * Error thrown when rate limit is exceeded
 */
export class RateLimitExceededError extends Error {
  retryAfter: number;
  statusCode = 429;

  constructor(message: string, retryAfter: number) {
    super(message);
    this.name = 'RateLimitExceededError';
    this.retryAfter = retryAfter;
  }
}

/**
 * Request record for sliding window
 */
interface RequestRecord {
  /** Timestamps of requests in the current window */
  timestamps: number[];
  /** Start of the current window */
  windowStart: number;
}

/**
 * Rate limiter interface
 */
export interface RateLimiter {
  /** Check if request is allowed without consuming quota */
  check(identifier: string): Promise<RateLimitResult>;
  /** Consume a request from the quota */
  consume(identifier: string): Promise<RateLimitResult>;
  /** Reset the counter for an identifier */
  reset(identifier: string): Promise<void>;
}

/**
 * In-memory sliding window rate limiter implementation
 */
class InMemoryRateLimiter implements RateLimiter {
  private records: Map<string, RequestRecord> = new Map();
  private config: Required<RateLimitConfig>;

  constructor(config: RateLimitConfig) {
    this.config = {
      maxRequests: config.maxRequests,
      windowMs: config.windowMs,
      throwOnLimit: config.throwOnLimit ?? false,
      burstLimit: config.burstLimit ?? config.maxRequests,
    };
  }

  /**
   * Get or create a request record for an identifier
   */
  private getRecord(identifier: string): RequestRecord {
    let record = this.records.get(identifier);

    if (!record) {
      record = {
        timestamps: [],
        windowStart: Date.now(),
      };
      this.records.set(identifier, record);
    }

    return record;
  }

  /**
   * Clean up old timestamps outside the window
   */
  private cleanupRecord(record: RequestRecord): void {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;

    // Remove timestamps outside the current window
    record.timestamps = record.timestamps.filter((ts) => ts > windowStart);
    record.windowStart = windowStart;
  }

  /**
   * Check if request is allowed
   */
  async check(identifier: string): Promise<RateLimitResult> {
    const record = this.getRecord(identifier);
    this.cleanupRecord(record);

    const count = record.timestamps.length;
    const allowed = count < this.config.maxRequests;
    const remaining = Math.max(0, this.config.maxRequests - count - 1);
    const resetAt = Math.floor((Date.now() + this.config.windowMs) / 1000);

    // If consuming (check + increment), add timestamp
    record.timestamps.push(Date.now());

    const result: RateLimitResult = {
      allowed,
      remaining: allowed ? remaining : 0,
      limit: this.config.maxRequests,
      resetAt,
    };

    if (!allowed) {
      // Calculate retry after based on oldest timestamp in window
      const oldestTimestamp = record.timestamps[0];
      const retryAfterMs = oldestTimestamp + this.config.windowMs - Date.now();
      result.retryAfter = Math.max(1, Math.ceil(retryAfterMs / 1000));
    }

    return result;
  }

  /**
   * Consume a request from the quota
   */
  async consume(identifier: string): Promise<RateLimitResult> {
    const result = await this.check(identifier);

    if (!result.allowed && this.config.throwOnLimit) {
      throw new RateLimitExceededError('Rate limit exceeded', result.retryAfter ?? 60);
    }

    return result;
  }

  /**
   * Reset the counter for an identifier
   */
  async reset(identifier: string): Promise<void> {
    this.records.delete(identifier);
  }
}

/**
 * Create a rate limiter with the given configuration
 */
export function createRateLimiter(config: RateLimitConfig): RateLimiter {
  return new InMemoryRateLimiter(config);
}

/**
 * Pre-configured rate limiters for common use cases
 */
export const rateLimiters = {
  /** Standard API rate limit: 1000 requests per minute */
  api: () => createRateLimiter({ maxRequests: 1000, windowMs: 60000 }),

  /** Authentication endpoints: 10 requests per minute */
  auth: () => createRateLimiter({ maxRequests: 10, windowMs: 60000, throwOnLimit: true }),

  /** Password reset: 3 requests per hour */
  passwordReset: () => createRateLimiter({ maxRequests: 3, windowMs: 3600000, throwOnLimit: true }),

  /** Webhook delivery: 100 requests per minute */
  webhook: () => createRateLimiter({ maxRequests: 100, windowMs: 60000 }),

  /** Search endpoints: 30 requests per minute */
  search: () => createRateLimiter({ maxRequests: 30, windowMs: 60000 }),

  /** Free tier: 100 requests per minute */
  freeTier: () => createRateLimiter({ maxRequests: 100, windowMs: 60000 }),

  /** Pro tier: 10000 requests per minute */
  proTier: () => createRateLimiter({ maxRequests: 10000, windowMs: 60000 }),
};

/**
 * Generate rate limit headers for HTTP response
 */
export function getRateLimitHeaders(result: RateLimitResult): Record<string, string> {
  const headers: Record<string, string> = {
    'X-RateLimit-Limit': String(result.limit),
    'X-RateLimit-Remaining': String(result.remaining),
    'X-RateLimit-Reset': String(result.resetAt),
  };

  if (result.retryAfter !== undefined) {
    headers['Retry-After'] = String(result.retryAfter);
  }

  return headers;
}

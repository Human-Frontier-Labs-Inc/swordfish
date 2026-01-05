/**
 * Rate Limiting Module
 *
 * API rate limiting and security headers
 */

import crypto from 'crypto';

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  algorithm?: 'fixed' | 'sliding' | 'token-bucket';
  refillRate?: number; // For token bucket
  burstSize?: number; // For token bucket
  keyType?: 'user' | 'ip' | 'api-key';
  tierLimits?: Record<string, number>;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  limit: number;
  reset: number;
  retryAfter?: number;
}

interface RateLimitEntry {
  count: number;
  windowStart: number;
  timestamps?: number[]; // For sliding window
  tokens?: number; // For token bucket
  lastRefill?: number;
}

interface CheckOptions {
  tier?: string;
}

export class RateLimiter {
  private config: RateLimitConfig;
  private store: Map<string, RateLimitEntry> = new Map();

  constructor(config: RateLimitConfig) {
    this.config = {
      algorithm: 'fixed',
      ...config,
    };
  }

  async check(key: string, options: CheckOptions = {}): Promise<RateLimitResult> {
    const limit = this.getLimit(options.tier);
    const now = Date.now();

    switch (this.config.algorithm) {
      case 'sliding':
        return this.checkSlidingWindow(key, limit, now);
      case 'token-bucket':
        return this.checkTokenBucket(key, limit, now);
      default:
        return this.checkFixedWindow(key, limit, now);
    }
  }

  private getLimit(tier?: string): number {
    if (tier && this.config.tierLimits && this.config.tierLimits[tier]) {
      return this.config.tierLimits[tier];
    }
    return this.config.maxRequests;
  }

  private checkFixedWindow(key: string, limit: number, now: number): RateLimitResult {
    let entry = this.store.get(key);

    // Check if window expired
    if (!entry || now - entry.windowStart >= this.config.windowMs) {
      entry = {
        count: 0,
        windowStart: now,
      };
    }

    const reset = entry.windowStart + this.config.windowMs;
    const remaining = Math.max(0, limit - entry.count - 1);

    if (entry.count >= limit) {
      return {
        allowed: false,
        remaining: 0,
        limit,
        reset,
        retryAfter: Math.ceil((reset - now) / 1000),
      };
    }

    entry.count++;
    this.store.set(key, entry);

    return {
      allowed: true,
      remaining,
      limit,
      reset,
    };
  }

  private checkSlidingWindow(key: string, limit: number, now: number): RateLimitResult {
    let entry = this.store.get(key);

    if (!entry) {
      entry = {
        count: 0,
        windowStart: now,
        timestamps: [],
      };
    }

    // Remove expired timestamps
    const windowStart = now - this.config.windowMs;
    entry.timestamps = (entry.timestamps || []).filter(t => t > windowStart);

    const reset = now + this.config.windowMs;
    const remaining = Math.max(0, limit - entry.timestamps.length - 1);

    if (entry.timestamps.length >= limit) {
      return {
        allowed: false,
        remaining: 0,
        limit,
        reset,
        retryAfter: Math.ceil((entry.timestamps[0] + this.config.windowMs - now) / 1000),
      };
    }

    entry.timestamps.push(now);
    entry.count = entry.timestamps.length;
    this.store.set(key, entry);

    return {
      allowed: true,
      remaining,
      limit,
      reset,
    };
  }

  private checkTokenBucket(key: string, limit: number, now: number): RateLimitResult {
    let entry = this.store.get(key);
    const refillRate = this.config.refillRate || 1; // tokens per second
    const burstSize = this.config.burstSize || limit;

    if (!entry) {
      entry = {
        count: 0,
        windowStart: now,
        tokens: burstSize,
        lastRefill: now,
      };
    }

    // Refill tokens based on time passed
    const timePassed = now - (entry.lastRefill || now);
    const tokensToAdd = Math.floor((timePassed / 1000) * refillRate);

    if (tokensToAdd > 0) {
      entry.tokens = Math.min(burstSize, (entry.tokens || 0) + tokensToAdd);
      entry.lastRefill = now;
    }

    const reset = now + this.config.windowMs;

    if ((entry.tokens || 0) <= 0) {
      return {
        allowed: false,
        remaining: 0,
        limit: burstSize,
        reset,
        retryAfter: Math.ceil(1000 / refillRate / 1000), // Time for 1 token
      };
    }

    entry.tokens = (entry.tokens || 0) - 1;
    this.store.set(key, entry);

    return {
      allowed: true,
      remaining: entry.tokens,
      limit: burstSize,
      reset,
    };
  }

  reset(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}

export interface SecurityHeaders {
  [key: string]: string;
}

interface CspConfig {
  defaultSrc?: string[];
  scriptSrc?: string[];
  styleSrc?: string[];
  imgSrc?: string[];
  connectSrc?: string[];
  fontSrc?: string[];
  objectSrc?: string[];
  mediaSrc?: string[];
  frameSrc?: string[];
}

interface CorsConfig {
  allowOrigin: string;
  allowMethods: string[];
  allowHeaders: string[];
  maxAge?: number;
}

interface PermissionsConfig {
  camera?: string[];
  microphone?: string[];
  geolocation?: string[];
  fullscreen?: string[];
  payment?: string[];
}

interface SecurityHeadersOptions {
  hsts?: boolean;
  csp?: CspConfig;
  cors?: CorsConfig;
  permissions?: PermissionsConfig;
}

/**
 * Generate security headers for responses
 */
export function generateSecurityHeaders(options: SecurityHeadersOptions = {}): SecurityHeaders {
  const headers: SecurityHeaders = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  };

  // HSTS
  if (options.hsts) {
    headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
  }

  // Content Security Policy
  if (options.csp) {
    const directives: string[] = [];

    if (options.csp.defaultSrc) {
      directives.push(`default-src ${options.csp.defaultSrc.join(' ')}`);
    }
    if (options.csp.scriptSrc) {
      directives.push(`script-src ${options.csp.scriptSrc.join(' ')}`);
    }
    if (options.csp.styleSrc) {
      directives.push(`style-src ${options.csp.styleSrc.join(' ')}`);
    }
    if (options.csp.imgSrc) {
      directives.push(`img-src ${options.csp.imgSrc.join(' ')}`);
    }
    if (options.csp.connectSrc) {
      directives.push(`connect-src ${options.csp.connectSrc.join(' ')}`);
    }
    if (options.csp.fontSrc) {
      directives.push(`font-src ${options.csp.fontSrc.join(' ')}`);
    }
    if (options.csp.objectSrc) {
      directives.push(`object-src ${options.csp.objectSrc.join(' ')}`);
    }

    headers['Content-Security-Policy'] = directives.join('; ');
  }

  // CORS
  if (options.cors) {
    headers['Access-Control-Allow-Origin'] = options.cors.allowOrigin;
    headers['Access-Control-Allow-Methods'] = options.cors.allowMethods.join(', ');
    headers['Access-Control-Allow-Headers'] = options.cors.allowHeaders.join(', ');
    if (options.cors.maxAge) {
      headers['Access-Control-Max-Age'] = options.cors.maxAge.toString();
    }
  }

  // Permissions Policy
  if (options.permissions) {
    const policies: string[] = [];

    for (const [feature, allowList] of Object.entries(options.permissions)) {
      if (allowList.length === 0) {
        policies.push(`${feature}=()`);
      } else {
        policies.push(`${feature}=(${allowList.join(' ')})`);
      }
    }

    headers['Permissions-Policy'] = policies.join(', ');
  }

  return headers;
}

/**
 * Validate request origin against allowed origins
 */
export function validateRequestOrigin(origin: string, allowedOrigins: string[]): boolean {
  for (const allowed of allowedOrigins) {
    // Exact match
    if (allowed === origin) return true;

    // Wildcard subdomain match
    if (allowed.startsWith('https://*.')) {
      const baseDomain = allowed.replace('https://*.', '');
      const originUrl = new URL(origin);
      if (originUrl.hostname.endsWith(baseDomain) && originUrl.protocol === 'https:') {
        return true;
      }
    }
  }

  return false;
}

interface CsrfConfig {
  secret: string;
  tokenTtlMs?: number;
}

interface TokenData {
  timestamp: number;
  hash: string;
}

/**
 * CSRF Protection
 */
export class CsrfProtection {
  private config: CsrfConfig;
  private tokens: Map<string, TokenData> = new Map();

  constructor(config: CsrfConfig) {
    this.config = {
      tokenTtlMs: 3600000, // 1 hour default
      ...config,
    };
  }

  generateToken(sessionId: string): string {
    const timestamp = Date.now();
    const random = crypto.randomBytes(16).toString('hex');
    const data = `${sessionId}:${timestamp}:${random}`;
    const hash = crypto
      .createHmac('sha256', this.config.secret)
      .update(data)
      .digest('hex');

    const token = `${timestamp}:${random}:${hash}`;
    this.tokens.set(`${sessionId}:${token}`, { timestamp, hash });

    return token;
  }

  validateToken(token: string, sessionId: string): boolean {
    const stored = this.tokens.get(`${sessionId}:${token}`);
    if (!stored) return false;

    // Check expiration
    const now = Date.now();
    if (now - stored.timestamp > (this.config.tokenTtlMs || 3600000)) {
      this.tokens.delete(`${sessionId}:${token}`);
      return false;
    }

    // Verify hash
    const parts = token.split(':');
    if (parts.length !== 3) return false;

    const [timestamp, random, hash] = parts;
    const data = `${sessionId}:${timestamp}:${random}`;
    const expectedHash = crypto
      .createHmac('sha256', this.config.secret)
      .update(data)
      .digest('hex');

    return hash === expectedHash;
  }

  clearExpired(): void {
    const now = Date.now();
    for (const [key, data] of this.tokens.entries()) {
      if (now - data.timestamp > (this.config.tokenTtlMs || 3600000)) {
        this.tokens.delete(key);
      }
    }
  }
}

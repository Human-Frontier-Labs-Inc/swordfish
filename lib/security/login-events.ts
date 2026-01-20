/**
 * Login Event Tracking Module
 *
 * Phase 2.1: Comprehensive login event tracking for security monitoring.
 * Tracks login success/failure events, IP addresses, geolocation,
 * device fingerprinting, session correlation, and tenant isolation.
 */

import crypto from 'crypto';
import { nanoid } from 'nanoid';
import { sql } from '@/lib/db';

/**
 * Login event types
 */
export const LoginEventType = {
  SUCCESS: 'login.success',
  FAILURE: 'login.failure',
  LOGOUT: 'login.logout',
  TOKEN_REFRESH: 'login.token_refresh',
  PASSWORD_RESET: 'login.password_reset',
  PASSWORD_CHANGED: 'login.password_changed',
  MFA_ENROLLED: 'login.mfa_enrolled',
  MFA_DISABLED: 'login.mfa_disabled',
  SESSION_EXPIRED: 'login.session_expired',
} as const;

export type LoginEventTypeValue = (typeof LoginEventType)[keyof typeof LoginEventType];

/**
 * Login failure reasons
 */
export const LoginFailureReason = {
  INVALID_CREDENTIALS: 'invalid_credentials',
  ACCOUNT_LOCKED: 'account_locked',
  ACCOUNT_DISABLED: 'account_disabled',
  MFA_REQUIRED: 'mfa_required',
  MFA_FAILED: 'mfa_failed',
  EXPIRED_PASSWORD: 'expired_password',
  IP_BLOCKED: 'ip_blocked',
  SUSPICIOUS_ACTIVITY: 'suspicious_activity',
  RATE_LIMITED: 'rate_limited',
  SESSION_INVALID: 'session_invalid',
} as const;

export type LoginFailureReasonValue = (typeof LoginFailureReason)[keyof typeof LoginFailureReason];

/**
 * Parsed user agent information
 */
export interface ParsedUserAgent {
  browser: string;
  browserVersion?: string;
  os: string;
  osVersion?: string;
  device: 'Desktop' | 'Mobile' | 'Tablet' | 'Unknown';
  isBot: boolean;
}

/**
 * Geolocation information
 */
export interface GeoLocation {
  country?: string;
  countryName?: string;
  region?: string;
  regionName?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  isp?: string;
}

/**
 * Client hints for device fingerprinting
 */
export interface ClientHints {
  platform?: string;
  platformVersion?: string;
  architecture?: string;
  bitness?: string;
  mobile?: boolean;
  model?: string;
  brands?: Array<{ brand: string; version: string }>;
}

/**
 * Login event interface
 */
export interface LoginEvent {
  id: string;
  type: LoginEventTypeValue;
  userId: string;
  tenantId: string;
  email: string;
  timestamp: string;
  success: boolean;
  failureReason?: LoginFailureReasonValue;
  ipAddress: string;
  userAgent?: string;
  parsedUserAgent?: ParsedUserAgent;
  geoLocation?: GeoLocation;
  deviceFingerprint?: string;
  sessionId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Input for recording login events
 */
export interface LoginEventInput {
  userId: string;
  tenantId: string;
  email: string;
  ipAddress: string;
  userAgent: string;
  sessionId?: string;
  type?: LoginEventTypeValue;
  clientHints?: ClientHints;
  metadata?: Record<string, unknown>;
}

/**
 * Input for recording failure events
 */
export interface FailureEventInput extends LoginEventInput {
  reason: LoginFailureReasonValue;
  errorDetails?: Record<string, unknown>;
}

/**
 * Query options for retrieving events
 */
export interface QueryOptions {
  tenantId?: string;
  from?: Date;
  to?: Date;
  type?: LoginEventTypeValue;
  limit?: number;
  offset?: number;
  sortOrder?: 'asc' | 'desc';
}

/**
 * Service configuration
 */
export interface LoginEventServiceConfig {
  geoIPService?: GeoIPService;
  defaultFailureWindow?: number;
}

/**
 * Validate IPv4 address
 */
function isValidIPv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;

  for (const part of parts) {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255 || part !== String(num)) {
      return false;
    }
  }

  return true;
}

/**
 * Validate IPv6 address
 */
function isValidIPv6(ip: string): boolean {
  // Simple IPv6 validation
  const ipv6Pattern = /^(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,7}:|(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|[a-fA-F0-9]{1,4}:(?:(?::[a-fA-F0-9]{1,4}){1,6})|:(?:(?::[a-fA-F0-9]{1,4}){1,7}|:)|fe80:(?::[a-fA-F0-9]{0,4}){0,4}%[0-9a-zA-Z]+|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])|(?:[a-fA-F0-9]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9]))$/;

  return ipv6Pattern.test(ip);
}

/**
 * Validate IP address (IPv4 or IPv6)
 */
export function isValidIPAddress(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;
  const trimmedIP = ip.trim();
  if (trimmedIP === '') return false;

  return isValidIPv4(trimmedIP) || isValidIPv6(trimmedIP);
}

/**
 * Extract first IP from X-Forwarded-For header
 */
function extractClientIP(ipHeader: string): string {
  if (ipHeader.includes(',')) {
    // X-Forwarded-For format: client, proxy1, proxy2
    return ipHeader.split(',')[0].trim();
  }
  return ipHeader.trim();
}

/**
 * Check if IP is private/local
 */
function isPrivateIP(ip: string): boolean {
  // IPv4 private ranges
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.')) {
    return true;
  }
  // 172.16.0.0 - 172.31.255.255
  if (ip.startsWith('172.')) {
    const secondOctet = parseInt(ip.split('.')[1], 10);
    if (secondOctet >= 16 && secondOctet <= 31) {
      return true;
    }
  }
  // IPv6 loopback
  if (ip === '::1' || ip === '::') {
    return true;
  }
  return false;
}

/**
 * Parse user agent string to extract browser, OS, and device info
 */
export function parseUserAgent(userAgent: string): ParsedUserAgent {
  if (!userAgent || userAgent.trim() === '') {
    return {
      browser: 'Unknown',
      os: 'Unknown',
      device: 'Unknown',
      isBot: false,
    };
  }

  const ua = userAgent.toLowerCase();

  // Detect bots first
  const botPatterns = ['googlebot', 'bingbot', 'baiduspider', 'yandexbot', 'duckduckbot', 'slurp', 'facebookexternalhit', 'twitterbot', 'linkedinbot', 'bot', 'crawler', 'spider'];
  const isBot = botPatterns.some(pattern => ua.includes(pattern));

  if (isBot) {
    return {
      browser: 'Bot',
      os: 'Unknown',
      device: 'Unknown',
      isBot: true,
    };
  }

  // Detect browser
  let browser = 'Unknown';
  let browserVersion: string | undefined;

  if (ua.includes('edg/') || ua.includes('edge/')) {
    browser = 'Edge';
    const match = userAgent.match(/Edg\/(\d+[\d.]*)/i) || userAgent.match(/Edge\/(\d+[\d.]*)/i);
    browserVersion = match?.[1];
  } else if (ua.includes('chrome/') && !ua.includes('chromium/')) {
    browser = 'Chrome';
    const match = userAgent.match(/Chrome\/(\d+[\d.]*)/i);
    browserVersion = match?.[1];
  } else if (ua.includes('firefox/')) {
    browser = 'Firefox';
    const match = userAgent.match(/Firefox\/(\d+[\d.]*)/i);
    browserVersion = match?.[1];
  } else if (ua.includes('safari/') && !ua.includes('chrome/')) {
    browser = 'Safari';
    const match = userAgent.match(/Version\/(\d+[\d.]*)/i);
    browserVersion = match?.[1];
  } else if (ua.includes('opera/') || ua.includes('opr/')) {
    browser = 'Opera';
    const match = userAgent.match(/OPR\/(\d+[\d.]*)/i) || userAgent.match(/Opera\/(\d+[\d.]*)/i);
    browserVersion = match?.[1];
  }

  // Detect OS
  // Note: Order matters! iOS detection must come before Mac OS X because
  // iOS user agents contain "Mac OS X" in them (e.g., "iPhone OS 17_0 like Mac OS X")
  let os = 'Unknown';
  let osVersion: string | undefined;

  if (ua.includes('iphone') || ua.includes('ipad') || (ua.includes('iphone os') || ua.includes('cpu os'))) {
    os = 'iOS';
    const match = userAgent.match(/(?:iPhone OS|CPU OS) (\d+[_.\d]*)/i);
    osVersion = match?.[1]?.replace(/_/g, '.');
  } else if (ua.includes('windows')) {
    os = 'Windows';
    if (ua.includes('windows nt 10')) osVersion = '10';
    else if (ua.includes('windows nt 6.3')) osVersion = '8.1';
    else if (ua.includes('windows nt 6.2')) osVersion = '8';
    else if (ua.includes('windows nt 6.1')) osVersion = '7';
  } else if (ua.includes('android')) {
    os = 'Android';
    const match = userAgent.match(/Android (\d+[\d.]*)/i);
    osVersion = match?.[1];
  } else if (ua.includes('mac os x')) {
    os = 'Mac OS X';
    const match = userAgent.match(/Mac OS X (\d+[_.\d]*)/i);
    osVersion = match?.[1]?.replace(/_/g, '.');
  } else if (ua.includes('linux')) {
    os = 'Linux';
  }

  // Detect device type
  let device: 'Desktop' | 'Mobile' | 'Tablet' | 'Unknown' = 'Desktop';

  if (ua.includes('ipad')) {
    device = 'Tablet';
  } else if (ua.includes('tablet') || ua.includes('tab')) {
    device = 'Tablet';
  } else if (ua.includes('mobile') || ua.includes('iphone') || ua.includes('android')) {
    device = 'Mobile';
  }

  return {
    browser,
    browserVersion,
    os,
    osVersion,
    device,
    isBot,
  };
}

/**
 * Generate device fingerprint from available data
 */
export function generateDeviceFingerprint(data: {
  userAgent?: string;
  platform?: string;
  screenResolution?: string;
  timezone?: string;
  language?: string;
  colorDepth?: number;
  hardwareConcurrency?: number;
  deviceMemory?: number;
  touchPoints?: number;
}): string {
  // Create a deterministic string from all available data
  const components = [
    data.userAgent || '',
    data.platform || '',
    data.screenResolution || '',
    data.timezone || '',
    data.language || '',
    data.colorDepth?.toString() || '',
    data.hardwareConcurrency?.toString() || '',
    data.deviceMemory?.toString() || '',
    data.touchPoints?.toString() || '',
  ];

  const fingerprint = components.join('|');

  // Generate SHA-256 hash
  const hash = crypto.createHash('sha256').update(fingerprint).digest('hex');

  return `fp_${hash}`;
}

/**
 * GeoIP lookup service
 */
export class GeoIPService {
  private cache: Map<string, { data: GeoLocation | null; timestamp: number }> = new Map();
  private cacheTTL: number = 24 * 60 * 60 * 1000; // 24 hours

  /**
   * Lookup geolocation for an IP address
   */
  async lookup(ip: string): Promise<GeoLocation | null> {
    // Return null for private/local IPs
    if (isPrivateIP(ip)) {
      return null;
    }

    // Check cache
    const cached = this.cache.get(ip);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      return cached.data;
    }

    try {
      const result = await this.performLookup(ip);
      this.cache.set(ip, { data: result, timestamp: Date.now() });
      return result;
    } catch (error) {
      // Cache the failure to prevent repeated failed lookups
      this.cache.set(ip, { data: null, timestamp: Date.now() });
      return null;
    }
  }

  /**
   * Perform actual GeoIP lookup
   * In production, this would call an external GeoIP service
   */
  private async performLookup(ip: string): Promise<GeoLocation | null> {
    // This is a placeholder for actual GeoIP service integration
    // In production, integrate with services like:
    // - MaxMind GeoIP
    // - IP2Location
    // - ipstack
    // - IPinfo

    // For now, return null (would need actual service in production)
    return null;
  }

  /**
   * Clear the cache
   */
  clearCache(): void {
    this.cache.clear();
  }
}

/**
 * Login Event Service
 */
export class LoginEventService {
  private geoIPService: GeoIPService;
  private defaultFailureWindow: number;

  constructor(config: LoginEventServiceConfig = {}) {
    this.geoIPService = config.geoIPService || new GeoIPService();
    this.defaultFailureWindow = config.defaultFailureWindow || 15 * 60 * 1000; // 15 minutes
  }

  /**
   * Record a successful login event
   */
  async recordLogin(input: LoginEventInput): Promise<LoginEvent> {
    const clientIP = extractClientIP(input.ipAddress);
    const parsedUA = parseUserAgent(input.userAgent);

    let geoLocation: GeoLocation | undefined;
    try {
      const geo = await this.geoIPService.lookup(clientIP);
      if (geo) {
        geoLocation = geo;
      }
    } catch {
      // Geo lookup failed, continue without it
    }

    const deviceFingerprint = generateDeviceFingerprint({
      userAgent: input.userAgent,
      platform: input.clientHints?.platform,
    });

    const event: LoginEvent = {
      id: 'login_' + nanoid(21),
      type: input.type || LoginEventType.SUCCESS,
      userId: input.userId,
      tenantId: input.tenantId,
      email: input.email,
      timestamp: new Date().toISOString(),
      success: input.type !== LoginEventType.FAILURE,
      ipAddress: clientIP,
      userAgent: input.userAgent,
      parsedUserAgent: parsedUA,
      geoLocation,
      deviceFingerprint,
      sessionId: input.sessionId,
      metadata: input.metadata,
    };

    // Persist to database
    await this.persistEvent(event);

    return event;
  }

  /**
   * Record a login failure event
   */
  async recordFailure(input: FailureEventInput): Promise<LoginEvent> {
    const clientIP = extractClientIP(input.ipAddress);
    const parsedUA = parseUserAgent(input.userAgent);

    let geoLocation: GeoLocation | undefined;
    try {
      const geo = await this.geoIPService.lookup(clientIP);
      if (geo) {
        geoLocation = geo;
      }
    } catch {
      // Geo lookup failed, continue without it
    }

    const deviceFingerprint = generateDeviceFingerprint({
      userAgent: input.userAgent,
      platform: input.clientHints?.platform,
    });

    const event: LoginEvent = {
      id: 'login_' + nanoid(21),
      type: LoginEventType.FAILURE,
      userId: input.userId,
      tenantId: input.tenantId,
      email: input.email,
      timestamp: new Date().toISOString(),
      success: false,
      failureReason: input.reason,
      ipAddress: clientIP,
      userAgent: input.userAgent,
      parsedUserAgent: parsedUA,
      geoLocation,
      deviceFingerprint,
      sessionId: input.sessionId,
      metadata: input.errorDetails ? { errorDetails: input.errorDetails, ...input.metadata } : input.metadata,
    };

    // Persist to database
    await this.persistEvent(event);

    return event;
  }

  /**
   * Persist event to database
   */
  private async persistEvent(event: LoginEvent): Promise<void> {
    await sql`
      INSERT INTO login_events (
        id, tenant_id, user_id, email, type, success,
        failure_reason, ip_address, user_agent, parsed_user_agent,
        geo_location, device_fingerprint, session_id, metadata, created_at
      ) VALUES (
        ${event.id},
        ${event.tenantId},
        ${event.userId},
        ${event.email},
        ${event.type},
        ${event.success},
        ${event.failureReason || null},
        ${event.ipAddress},
        ${event.userAgent || null},
        ${JSON.stringify(event.parsedUserAgent || {})},
        ${JSON.stringify(event.geoLocation || {})},
        ${event.deviceFingerprint || null},
        ${event.sessionId || null},
        ${JSON.stringify(event.metadata || {})},
        ${event.timestamp}
      )
    `;
  }

  /**
   * Get login events for a specific user
   */
  async getEventsForUser(userId: string, options: QueryOptions = {}): Promise<LoginEvent[]> {
    if (!options.tenantId) {
      throw new Error('tenantId is required for user event queries');
    }

    const limit = options.limit || 100;
    const offset = options.offset || 0;
    const sortOrder = options.sortOrder || 'desc';

    const results = await sql`
      SELECT * FROM login_events
      WHERE user_id = ${userId}
        AND tenant_id = ${options.tenantId}
        ${options.type ? sql`AND type = ${options.type}` : sql``}
        ${options.from ? sql`AND created_at >= ${options.from.toISOString()}` : sql``}
        ${options.to ? sql`AND created_at <= ${options.to.toISOString()}` : sql``}
      ORDER BY created_at ${sortOrder === 'asc' ? sql`ASC` : sql`DESC`}
      LIMIT ${limit}
      OFFSET ${offset}
    `;

    return this.mapResultsToEvents(results as unknown[]);
  }

  /**
   * Get login events for a tenant
   */
  async getEventsForTenant(tenantId: string, options: QueryOptions = {}): Promise<LoginEvent[]> {
    const limit = options.limit || 100;
    const offset = options.offset || 0;
    const sortOrder = options.sortOrder || 'desc';

    const results = await sql`
      SELECT * FROM login_events
      WHERE tenant_id = ${tenantId}
        ${options.type ? sql`AND type = ${options.type}` : sql``}
        ${options.from ? sql`AND created_at >= ${options.from.toISOString()}` : sql``}
        ${options.to ? sql`AND created_at <= ${options.to.toISOString()}` : sql``}
      ORDER BY created_at ${sortOrder === 'asc' ? sql`ASC` : sql`DESC`}
      LIMIT ${limit}
      OFFSET ${offset}
    `;

    return this.mapResultsToEvents(results as unknown[]);
  }

  /**
   * Get count of recent login failures for a user
   */
  async getRecentFailures(userId: string, windowMs?: number): Promise<number> {
    const window = windowMs || this.defaultFailureWindow;
    const since = new Date(Date.now() - window).toISOString();

    const results = await sql`
      SELECT COUNT(*) as count FROM login_events
      WHERE user_id = ${userId}
        AND type = ${LoginEventType.FAILURE}
        AND created_at >= ${since}
    `;

    const countResult = (results as unknown[])[0] as { count: string } | undefined;
    return parseInt(countResult?.count || '0', 10);
  }

  /**
   * Get count of recent login failures by IP address
   */
  async getRecentFailuresByIP(ipAddress: string, windowMs?: number): Promise<number> {
    const window = windowMs || this.defaultFailureWindow;
    const since = new Date(Date.now() - window).toISOString();

    const results = await sql`
      SELECT COUNT(*) as count FROM login_events
      WHERE ip_address = ${ipAddress}
        AND type = ${LoginEventType.FAILURE}
        AND created_at >= ${since}
    `;

    const countResult = (results as unknown[])[0] as { count: string } | undefined;
    return parseInt(countResult?.count || '0', 10);
  }

  /**
   * Map database results to LoginEvent objects
   */
  private mapResultsToEvents(results: unknown[]): LoginEvent[] {
    return (results as Array<Record<string, unknown>>).map(row => ({
      id: row.id as string,
      type: row.type as LoginEventTypeValue,
      userId: row.user_id as string,
      tenantId: row.tenant_id as string,
      email: row.email as string,
      timestamp: (row.created_at as Date).toISOString(),
      success: row.success as boolean,
      failureReason: row.failure_reason as LoginFailureReasonValue | undefined,
      ipAddress: row.ip_address as string,
      userAgent: row.user_agent as string | undefined,
      parsedUserAgent: row.parsed_user_agent as ParsedUserAgent | undefined,
      geoLocation: row.geo_location as GeoLocation | undefined,
      deviceFingerprint: row.device_fingerprint as string | undefined,
      sessionId: row.session_id as string | undefined,
      metadata: row.metadata as Record<string, unknown> | undefined,
    }));
  }
}

/**
 * Create a new LoginEventService instance
 */
export function createLoginEventService(config?: LoginEventServiceConfig): LoginEventService {
  return new LoginEventService(config);
}

/**
 * Default service instance
 */
export const defaultLoginEventService = createLoginEventService();

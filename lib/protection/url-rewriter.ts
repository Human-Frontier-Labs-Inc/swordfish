/**
 * URL Rewriter Module
 *
 * Comprehensive URL rewriting system for Swordfish email security platform.
 * Rewrites URLs in emails to route through Swordfish proxy for click-time protection
 * while preserving the original URL display for user transparency.
 */

import { createHash, randomBytes } from 'crypto';
import { sql } from '@/lib/db';
import type { ParsedEmail } from '@/lib/detection/types';

// ============================================================================
// Types & Interfaces
// ============================================================================

export interface RewriterConfig {
  /** Base URL for the click protection service (e.g., "https://protect.swordfish.app") */
  baseUrl: string;
  /** Domains that should never have their URLs rewritten */
  whitelistedDomains: string[];
  /** Whether to rewrite links to internal/company domains */
  rewriteInternalLinks: boolean;
  /** Whether to preserve the original URL as visible text/tooltip */
  preserveDisplayUrl: boolean;
  /** Whether to track clicks on rewritten URLs */
  trackClicks: boolean;
  /** Secret for signing URLs to prevent tampering */
  signatureSecret: string;
  /** URL expiry in days (default: 30) */
  urlExpiryDays: number;
}

export interface RewrittenEmail {
  /** Original email ID */
  emailId: string;
  /** Tenant ID */
  tenantId: string;
  /** Rewritten plain text body (if present) */
  textBody?: string;
  /** Rewritten HTML body (if present) */
  htmlBody?: string;
  /** Statistics about the rewriting operation */
  stats: RewriteStats;
  /** All rewritten URLs with their mappings */
  rewrittenUrls: UrlMapping[];
}

export interface RewriteStats {
  /** Total URLs found in the email */
  totalUrls: number;
  /** Number of URLs that were rewritten */
  rewrittenCount: number;
  /** Number of URLs skipped (whitelisted, non-http, etc.) */
  skippedCount: number;
  /** Number of URLs that were shortened URLs (expanded) */
  expandedShorteners: number;
  /** Processing time in milliseconds */
  processingTimeMs: number;
}

export interface UrlMapping {
  /** Unique click tracking ID */
  trackingId: string;
  /** Original URL from the email */
  originalUrl: string;
  /** Rewritten Swordfish proxy URL */
  rewrittenUrl: string;
  /** Whether the URL was rewritten */
  wasRewritten: boolean;
  /** Reason for rewriting or skipping */
  reason: RewriteReason;
  /** If URL was a shortener, the expanded destination */
  expandedUrl?: string;
}

export type RewriteReason =
  | 'external'           // External domain, rewritten for protection
  | 'shortener'          // URL shortener, expanded and rewritten
  | 'suspicious'         // Flagged as suspicious by detection
  | 'policy'             // Tenant policy requires rewriting
  | 'whitelisted'        // Domain is whitelisted, not rewritten
  | 'internal'           // Internal domain, optionally not rewritten
  | 'non-http'           // mailto:, tel:, data: etc., not rewritten
  | 'safe-domain'        // Known safe domain (Google, Microsoft, etc.)
  | 'malformed'          // Invalid URL format
  | 'already-rewritten'; // URL already points to Swordfish

export interface RewrittenUrlRecord {
  /** Click tracking ID (primary key) */
  id: string;
  /** Tenant ID for isolation */
  tenant_id: string;
  /** Email ID this URL belongs to */
  email_id: string;
  /** Original URL before rewriting */
  original_url: string;
  /** Expanded URL if original was a shortener */
  expanded_url: string | null;
  /** When the URL was rewritten */
  created_at: Date;
  /** When the URL was first clicked (null until clicked) */
  clicked_at: Date | null;
  /** Number of times this URL was clicked */
  click_count: number;
  /** Result of click-time scan */
  click_verdict: ClickVerdict | null;
  /** When this URL mapping expires */
  expires_at: Date;
  /** Additional metadata */
  metadata: Record<string, unknown> | null;
}

export type ClickVerdict = 'safe' | 'suspicious' | 'malicious' | 'blocked' | 'unknown';

// ============================================================================
// Default Configuration
// ============================================================================

const DEFAULT_CONFIG: RewriterConfig = {
  baseUrl: process.env.SWORDFISH_PROTECT_URL || 'https://protect.swordfish.app',
  whitelistedDomains: [],
  rewriteInternalLinks: false,
  preserveDisplayUrl: true,
  trackClicks: true,
  signatureSecret: process.env.URL_SIGNATURE_SECRET || '',
  urlExpiryDays: 30,
};

// Known safe domains that typically shouldn't be rewritten
const KNOWN_SAFE_DOMAINS = [
  // Major tech companies
  'google.com', 'www.google.com', 'accounts.google.com', 'docs.google.com',
  'drive.google.com', 'mail.google.com', 'meet.google.com', 'calendar.google.com',
  'microsoft.com', 'www.microsoft.com', 'login.microsoftonline.com',
  'outlook.office.com', 'outlook.office365.com', 'teams.microsoft.com',
  'apple.com', 'www.apple.com', 'icloud.com',
  'amazon.com', 'www.amazon.com', 'aws.amazon.com',

  // Productivity & collaboration
  'github.com', 'www.github.com', 'gitlab.com',
  'slack.com', 'www.slack.com', 'app.slack.com',
  'zoom.us', 'zoom.com', 'us02web.zoom.us',
  'dropbox.com', 'www.dropbox.com',
  'notion.so', 'www.notion.so',
  'atlassian.com', 'www.atlassian.com', 'atlassian.net',

  // Social & professional
  'linkedin.com', 'www.linkedin.com',
  'twitter.com', 'x.com',
  'facebook.com', 'www.facebook.com',

  // Finance (major banks should be considered case by case)
  'paypal.com', 'www.paypal.com',
  'stripe.com', 'dashboard.stripe.com',
];

// URL shorteners that should always be expanded and rewritten
const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
  'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'short.io',
  'tiny.cc', 'lnkd.in', 'fb.me', 'youtu.be', 'amzn.to',
  'j.mp', 'soo.gd', 'bl.ink', 'shorte.st', 'adf.ly',
  'shorturl.at', 'rb.gy', 'clck.ru', 'trib.al', 'ht.ly',
]);

// Protocols that should never be rewritten
const NON_REWRITABLE_PROTOCOLS = new Set([
  'mailto:', 'tel:', 'sms:', 'data:', 'javascript:', 'file:',
  'ftp:', 'sftp:', 'ssh:', 'magnet:', 'webcal:', 'callto:',
]);

// ============================================================================
// UrlRewriter Class
// ============================================================================

export class UrlRewriter {
  private config: RewriterConfig;
  private tenantWhitelist: Map<string, Set<string>> = new Map();

  constructor(config: Partial<RewriterConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };

    if (!this.config.signatureSecret) {
      console.warn('[UrlRewriter] Warning: URL_SIGNATURE_SECRET not configured. URL signing disabled.');
    }
  }

  // --------------------------------------------------------------------------
  // Main Public Methods
  // --------------------------------------------------------------------------

  /**
   * Rewrite all URLs in an email body (both text and HTML)
   */
  async rewriteEmailBody(
    email: ParsedEmail,
    tenantId: string,
    suspiciousUrls: Set<string> = new Set()
  ): Promise<RewrittenEmail> {
    const startTime = performance.now();
    const rewrittenUrls: UrlMapping[] = [];
    let totalUrls = 0;
    let rewrittenCount = 0;
    let skippedCount = 0;
    let expandedShorteners = 0;

    // Load tenant-specific whitelist
    await this.loadTenantWhitelist(tenantId);

    // Process HTML body
    let htmlBody = email.body.html;
    if (htmlBody) {
      const htmlResult = await this.rewriteHtmlBody(
        htmlBody,
        email.messageId,
        tenantId,
        suspiciousUrls
      );
      htmlBody = htmlResult.html;
      totalUrls += htmlResult.mappings.length;
      rewrittenUrls.push(...htmlResult.mappings);
      rewrittenCount += htmlResult.mappings.filter(m => m.wasRewritten).length;
      skippedCount += htmlResult.mappings.filter(m => !m.wasRewritten).length;
      expandedShorteners += htmlResult.mappings.filter(m => m.expandedUrl).length;
    }

    // Process plain text body
    let textBody = email.body.text;
    if (textBody) {
      const textResult = await this.rewriteTextBody(
        textBody,
        email.messageId,
        tenantId,
        suspiciousUrls
      );
      textBody = textResult.text;

      // Only add unique URLs not already processed from HTML
      const existingUrls = new Set(rewrittenUrls.map(u => u.originalUrl));
      const newMappings = textResult.mappings.filter(m => !existingUrls.has(m.originalUrl));

      totalUrls += newMappings.length;
      rewrittenUrls.push(...newMappings);
      rewrittenCount += newMappings.filter(m => m.wasRewritten).length;
      skippedCount += newMappings.filter(m => !m.wasRewritten).length;
      expandedShorteners += newMappings.filter(m => m.expandedUrl).length;
    }

    // Store rewritten URLs in database for click-time resolution
    if (this.config.trackClicks) {
      await this.storeRewrittenUrls(rewrittenUrls.filter(m => m.wasRewritten), tenantId, email.messageId);
    }

    return {
      emailId: email.messageId,
      tenantId,
      textBody,
      htmlBody,
      stats: {
        totalUrls,
        rewrittenCount,
        skippedCount,
        expandedShorteners,
        processingTimeMs: performance.now() - startTime,
      },
      rewrittenUrls,
    };
  }

  /**
   * Rewrite a single URL
   */
  rewriteUrl(
    originalUrl: string,
    emailId: string,
    tenantId: string,
    isSuspicious: boolean = false
  ): UrlMapping {
    // Check if URL should be rewritten
    const shouldRewriteResult = this.shouldRewrite(originalUrl, tenantId, isSuspicious);

    if (!shouldRewriteResult.shouldRewrite) {
      return {
        trackingId: '',
        originalUrl,
        rewrittenUrl: originalUrl,
        wasRewritten: false,
        reason: shouldRewriteResult.reason,
      };
    }

    // Generate tracking ID and create rewritten URL
    const trackingId = this.generateClickTrackingId(originalUrl, emailId, tenantId);
    const rewrittenUrl = this.buildRewrittenUrl(trackingId, originalUrl);

    return {
      trackingId,
      originalUrl,
      rewrittenUrl,
      wasRewritten: true,
      reason: shouldRewriteResult.reason,
    };
  }

  /**
   * Preserve the original URL for display while rewriting the href
   * Returns HTML anchor tag with rewritten href but original display
   */
  preserveDisplayUrl(originalUrl: string, rewrittenUrl: string): string {
    if (!this.config.preserveDisplayUrl) {
      return `<a href="${this.escapeHtml(rewrittenUrl)}">${this.escapeHtml(originalUrl)}</a>`;
    }

    // Create anchor with rewritten href but original display
    // Add title attribute for hover tooltip showing original URL
    return `<a href="${this.escapeHtml(rewrittenUrl)}" ` +
           `title="${this.escapeHtml(originalUrl)}" ` +
           `data-original-url="${encodeURIComponent(originalUrl)}" ` +
           `class="swordfish-protected-link">${this.escapeHtml(originalUrl)}</a>`;
  }

  /**
   * Generate a unique, cryptographically secure click tracking ID
   */
  generateClickTrackingId(originalUrl: string, emailId: string, tenantId?: string): string {
    // Combine multiple sources for uniqueness
    const timestamp = Date.now().toString(36);
    const random = randomBytes(8).toString('hex');
    const dataHash = createHash('sha256')
      .update(`${originalUrl}|${emailId}|${tenantId || ''}|${timestamp}`)
      .digest('hex')
      .substring(0, 16);

    // Create compact but unique ID: timestamp(6) + random(16) + hash(8)
    return `${timestamp}${random}${dataHash.substring(0, 8)}`;
  }

  /**
   * Check if a URL is whitelisted for a tenant
   */
  async isWhitelisted(url: string, tenantId: string): Promise<boolean> {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();

      // Check tenant-specific whitelist
      await this.loadTenantWhitelist(tenantId);
      const tenantDomains = this.tenantWhitelist.get(tenantId);

      if (tenantDomains) {
        for (const domain of tenantDomains) {
          if (hostname === domain || hostname.endsWith('.' + domain)) {
            return true;
          }
        }
      }

      // Check config whitelist
      for (const domain of this.config.whitelistedDomains) {
        if (hostname === domain || hostname.endsWith('.' + domain)) {
          return true;
        }
      }

      return false;
    } catch {
      return false;
    }
  }

  /**
   * Determine if a URL should be rewritten based on various criteria
   */
  shouldRewrite(
    url: string,
    tenantId: string,
    isSuspicious: boolean = false
  ): { shouldRewrite: boolean; reason: RewriteReason } {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();

      // Never rewrite non-HTTP protocols
      if (NON_REWRITABLE_PROTOCOLS.has(parsed.protocol)) {
        return { shouldRewrite: false, reason: 'non-http' };
      }

      // Only rewrite http:// and https://
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return { shouldRewrite: false, reason: 'non-http' };
      }

      // Don't rewrite URLs that already point to Swordfish
      if (url.startsWith(this.config.baseUrl)) {
        return { shouldRewrite: false, reason: 'already-rewritten' };
      }

      // Always rewrite URL shorteners
      if (this.isUrlShortener(hostname)) {
        return { shouldRewrite: true, reason: 'shortener' };
      }

      // Always rewrite suspicious URLs
      if (isSuspicious) {
        return { shouldRewrite: true, reason: 'suspicious' };
      }

      // Check tenant whitelist (cached)
      const tenantDomains = this.tenantWhitelist.get(tenantId);
      if (tenantDomains) {
        for (const domain of tenantDomains) {
          if (hostname === domain || hostname.endsWith('.' + domain)) {
            return { shouldRewrite: false, reason: 'whitelisted' };
          }
        }
      }

      // Check config whitelist
      for (const domain of this.config.whitelistedDomains) {
        if (hostname === domain || hostname.endsWith('.' + domain)) {
          return { shouldRewrite: false, reason: 'whitelisted' };
        }
      }

      // Check known safe domains
      for (const domain of KNOWN_SAFE_DOMAINS) {
        if (hostname === domain || hostname.endsWith('.' + domain)) {
          return { shouldRewrite: false, reason: 'safe-domain' };
        }
      }

      // Rewrite external URLs
      return { shouldRewrite: true, reason: 'external' };
    } catch {
      // Malformed URL - might be dangerous, so rewrite it
      return { shouldRewrite: true, reason: 'malformed' };
    }
  }

  /**
   * Restore the original URL from a rewritten Swordfish URL
   */
  async restoreOriginalUrl(rewrittenUrl: string): Promise<string | null> {
    try {
      const parsed = new URL(rewrittenUrl);

      // Extract tracking ID from path
      const pathMatch = parsed.pathname.match(/^\/click\/([a-z0-9]+)$/i);
      if (!pathMatch) {
        // Try query parameter fallback
        const urlParam = parsed.searchParams.get('url');
        if (urlParam) {
          return decodeURIComponent(urlParam);
        }
        return null;
      }

      const trackingId = pathMatch[1];

      // Look up in database
      const result = await sql`
        SELECT original_url, expanded_url
        FROM rewritten_urls
        WHERE id = ${trackingId}
          AND expires_at > NOW()
      `;

      if (result.length === 0) {
        return null;
      }

      // Return expanded URL if available (for shorteners), otherwise original
      return result[0].expanded_url || result[0].original_url;
    } catch {
      return null;
    }
  }

  /**
   * Record a click on a rewritten URL and update statistics
   */
  async recordClick(
    trackingId: string,
    verdict: ClickVerdict,
    metadata?: Record<string, unknown>
  ): Promise<boolean> {
    try {
      const result = await sql`
        UPDATE rewritten_urls
        SET
          clicked_at = COALESCE(clicked_at, NOW()),
          click_count = click_count + 1,
          click_verdict = ${verdict},
          metadata = COALESCE(metadata, '{}'::jsonb) || ${JSON.stringify(metadata || {})}::jsonb
        WHERE id = ${trackingId}
        RETURNING id
      `;

      return result.length > 0;
    } catch (error) {
      console.error('[UrlRewriter] Failed to record click:', error);
      return false;
    }
  }

  // --------------------------------------------------------------------------
  // Private Methods
  // --------------------------------------------------------------------------

  /**
   * Rewrite URLs in HTML body
   */
  private async rewriteHtmlBody(
    html: string,
    emailId: string,
    tenantId: string,
    suspiciousUrls: Set<string>
  ): Promise<{ html: string; mappings: UrlMapping[] }> {
    const mappings: UrlMapping[] = [];
    const processedUrls = new Map<string, UrlMapping>();

    // Match href attributes in anchor tags
    const hrefRegex = /<a\s+([^>]*?)href\s*=\s*["']([^"']+)["']([^>]*?)>/gi;

    const newHtml = await this.replaceAsync(html, hrefRegex, async (match, before, url, after) => {
      // Decode HTML entities in URL
      const decodedUrl = this.decodeHtmlEntities(url);

      // Check if we've already processed this URL
      let mapping = processedUrls.get(decodedUrl);
      if (!mapping) {
        // Expand shorteners if needed
        let targetUrl = decodedUrl;
        let expandedUrl: string | undefined;

        if (this.isUrlShortener(this.getHostname(decodedUrl))) {
          const expanded = await this.expandShortUrl(decodedUrl);
          if (expanded) {
            expandedUrl = expanded;
            targetUrl = expanded;
          }
        }

        const isSuspicious = suspiciousUrls.has(decodedUrl) || suspiciousUrls.has(targetUrl);
        mapping = this.rewriteUrl(targetUrl, emailId, tenantId, isSuspicious);

        if (expandedUrl) {
          mapping.expandedUrl = expandedUrl;
          mapping.originalUrl = decodedUrl; // Keep original shortener URL
        }

        processedUrls.set(decodedUrl, mapping);
        mappings.push(mapping);
      }

      if (!mapping.wasRewritten) {
        return match; // Return unchanged
      }

      // Build new anchor tag with rewritten URL
      if (this.config.preserveDisplayUrl) {
        return `<a ${before}href="${this.escapeHtml(mapping.rewrittenUrl)}" ` +
               `title="${this.escapeHtml(mapping.originalUrl)}" ` +
               `data-original-url="${encodeURIComponent(mapping.originalUrl)}"${after}>`;
      }

      return `<a ${before}href="${this.escapeHtml(mapping.rewrittenUrl)}"${after}>`;
    });

    return { html: newHtml, mappings };
  }

  /**
   * Rewrite URLs in plain text body
   */
  private async rewriteTextBody(
    text: string,
    emailId: string,
    tenantId: string,
    suspiciousUrls: Set<string>
  ): Promise<{ text: string; mappings: UrlMapping[] }> {
    const mappings: UrlMapping[] = [];
    const processedUrls = new Map<string, UrlMapping>();

    // Match URLs in plain text
    const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;

    const newText = await this.replaceAsync(text, urlRegex, async (match) => {
      // Clean up trailing punctuation that might be part of sentence
      const cleanUrl = match.replace(/[.,;:!?)]+$/, '');
      const trailing = match.slice(cleanUrl.length);

      // Check if we've already processed this URL
      let mapping = processedUrls.get(cleanUrl);
      if (!mapping) {
        // Expand shorteners if needed
        let targetUrl = cleanUrl;
        let expandedUrl: string | undefined;

        if (this.isUrlShortener(this.getHostname(cleanUrl))) {
          const expanded = await this.expandShortUrl(cleanUrl);
          if (expanded) {
            expandedUrl = expanded;
            targetUrl = expanded;
          }
        }

        const isSuspicious = suspiciousUrls.has(cleanUrl) || suspiciousUrls.has(targetUrl);
        mapping = this.rewriteUrl(targetUrl, emailId, tenantId, isSuspicious);

        if (expandedUrl) {
          mapping.expandedUrl = expandedUrl;
          mapping.originalUrl = cleanUrl;
        }

        processedUrls.set(cleanUrl, mapping);
        mappings.push(mapping);
      }

      if (!mapping.wasRewritten) {
        return match; // Return unchanged
      }

      return mapping.rewrittenUrl + trailing;
    });

    return { text: newText, mappings };
  }

  /**
   * Build the rewritten URL with tracking ID
   */
  private buildRewrittenUrl(trackingId: string, originalUrl: string): string {
    // Primary format: /click/{trackingId}
    // We store the original URL in the database, not in the URL itself
    // This prevents URL manipulation attacks
    const baseRewrittenUrl = `${this.config.baseUrl}/click/${trackingId}`;

    // Add signature if configured
    if (this.config.signatureSecret) {
      const signature = this.signUrl(trackingId, originalUrl);
      return `${baseRewrittenUrl}?sig=${signature}`;
    }

    return baseRewrittenUrl;
  }

  /**
   * Sign a URL to prevent tampering
   */
  private signUrl(trackingId: string, originalUrl: string): string {
    return createHash('sha256')
      .update(`${trackingId}|${originalUrl}|${this.config.signatureSecret}`)
      .digest('hex')
      .substring(0, 16);
  }

  /**
   * Verify URL signature
   */
  verifyUrlSignature(trackingId: string, originalUrl: string, signature: string): boolean {
    const expected = this.signUrl(trackingId, originalUrl);
    return signature === expected;
  }

  /**
   * Check if hostname is a known URL shortener
   */
  private isUrlShortener(hostname: string): boolean {
    const lower = hostname.toLowerCase();
    return URL_SHORTENERS.has(lower) ||
           URL_SHORTENERS.has(lower.replace('www.', ''));
  }

  /**
   * Expand a shortened URL to get the final destination
   */
  private async expandShortUrl(shortUrl: string): Promise<string | null> {
    try {
      // Use HEAD request with redirect following disabled to get final URL
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(shortUrl, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Swordfish-Security-Scanner/1.0',
        },
      });

      clearTimeout(timeoutId);

      // Get the redirect location
      const location = response.headers.get('location');
      if (location) {
        // Handle relative redirects
        if (location.startsWith('/')) {
          const parsed = new URL(shortUrl);
          return `${parsed.protocol}//${parsed.host}${location}`;
        }
        // Recursively expand if still a shortener (max 5 redirects)
        if (this.isUrlShortener(this.getHostname(location))) {
          return await this.expandShortUrlRecursive(location, 4);
        }
        return location;
      }

      return null;
    } catch {
      // Expansion failed, use original URL
      return null;
    }
  }

  /**
   * Recursively expand shortened URLs with a depth limit
   */
  private async expandShortUrlRecursive(url: string, remainingDepth: number): Promise<string | null> {
    if (remainingDepth <= 0) return url;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      const response = await fetch(url, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Swordfish-Security-Scanner/1.0',
        },
      });

      clearTimeout(timeoutId);

      const location = response.headers.get('location');
      if (location) {
        const resolved = location.startsWith('/')
          ? `${new URL(url).origin}${location}`
          : location;

        if (this.isUrlShortener(this.getHostname(resolved))) {
          return await this.expandShortUrlRecursive(resolved, remainingDepth - 1);
        }
        return resolved;
      }

      return url;
    } catch {
      return url;
    }
  }

  /**
   * Extract hostname from URL safely
   */
  private getHostname(url: string): string {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return '';
    }
  }

  /**
   * Load tenant-specific whitelist from database
   */
  private async loadTenantWhitelist(tenantId: string): Promise<void> {
    if (this.tenantWhitelist.has(tenantId)) {
      return; // Already loaded
    }

    try {
      // Load from policies table - domains marked as 'allow' for URLs
      const result = await sql`
        SELECT value
        FROM policies
        WHERE tenant_id = ${tenantId}
          AND type = 'allowlist'
          AND target = 'domain'
          AND is_active = true
      `;

      const domains = new Set<string>();
      for (const row of result) {
        domains.add(row.value.toLowerCase());
      }

      this.tenantWhitelist.set(tenantId, domains);
    } catch (error) {
      console.error('[UrlRewriter] Failed to load tenant whitelist:', error);
      this.tenantWhitelist.set(tenantId, new Set());
    }
  }

  /**
   * Store rewritten URLs in database for click-time resolution
   */
  private async storeRewrittenUrls(
    mappings: UrlMapping[],
    tenantId: string,
    emailId: string
  ): Promise<void> {
    if (mappings.length === 0) return;

    try {
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + this.config.urlExpiryDays);

      // Batch insert all mappings
      for (const mapping of mappings) {
        await sql`
          INSERT INTO rewritten_urls (
            id, tenant_id, email_id, original_url, expanded_url,
            created_at, expires_at, click_count, metadata
          )
          VALUES (
            ${mapping.trackingId},
            ${tenantId},
            ${emailId},
            ${mapping.originalUrl},
            ${mapping.expandedUrl || null},
            NOW(),
            ${expiresAt.toISOString()},
            0,
            ${JSON.stringify({ reason: mapping.reason })}
          )
          ON CONFLICT (id) DO NOTHING
        `;
      }
    } catch (error) {
      console.error('[UrlRewriter] Failed to store rewritten URLs:', error);
      // Don't throw - continue even if storage fails
    }
  }

  /**
   * Async string replace helper
   */
  private async replaceAsync(
    str: string,
    regex: RegExp,
    asyncFn: (...args: string[]) => Promise<string>
  ): Promise<string> {
    const promises: Promise<{ match: string; replacement: string }>[] = [];

    str.replace(regex, (match, ...args) => {
      promises.push(
        asyncFn(match, ...args.slice(0, -2)).then(replacement => ({ match, replacement }))
      );
      return match;
    });

    const replacements = await Promise.all(promises);

    let result = str;
    for (const { match, replacement } of replacements) {
      result = result.replace(match, replacement);
    }

    return result;
  }

  /**
   * Escape HTML special characters
   */
  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Decode HTML entities
   */
  private decodeHtmlEntities(str: string): string {
    return str
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#039;/g, "'")
      .replace(/&#x27;/g, "'")
      .replace(/&#x2F;/g, '/');
  }

  /**
   * Clear tenant whitelist cache
   */
  clearCache(tenantId?: string): void {
    if (tenantId) {
      this.tenantWhitelist.delete(tenantId);
    } else {
      this.tenantWhitelist.clear();
    }
  }

  // --------------------------------------------------------------------------
  // Batch Operations
  // --------------------------------------------------------------------------

  /**
   * Batch rewrite multiple emails
   */
  async batchRewrite(
    emails: EmailContent[],
    tenantId: string,
    suspiciousUrls: Set<string> = new Set()
  ): Promise<EmailRewriteResult[]> {
    const results: EmailRewriteResult[] = [];

    // Process emails in parallel with concurrency limit
    const concurrencyLimit = 5;
    for (let i = 0; i < emails.length; i += concurrencyLimit) {
      const batch = emails.slice(i, i + concurrencyLimit);
      const batchResults = await Promise.all(
        batch.map(async (email) => {
          const startTime = performance.now();
          try {
            const result = await this.rewriteEmailBody(
              {
                messageId: email.messageId,
                subject: email.subject || '',
                from: { address: email.from || '', domain: '' },
                to: [],
                date: new Date(),
                headers: {},
                body: {
                  text: email.textBody,
                  html: email.htmlBody,
                },
                attachments: [],
                rawHeaders: '',
              },
              tenantId,
              suspiciousUrls
            );

            return {
              messageId: email.messageId,
              originalBody: email.textBody || '',
              rewrittenBody: result.textBody || '',
              originalHtml: email.htmlBody,
              rewrittenHtml: result.htmlBody,
              urlsRewritten: result.rewrittenUrls.filter((u) => u.wasRewritten).map((u) => ({
                originalUrl: u.originalUrl,
                rewrittenUrl: u.rewrittenUrl,
                urlId: u.trackingId,
                alreadyScanned: false,
                initialVerdict: undefined,
              })),
              urlsSkipped: result.rewrittenUrls.filter((u) => !u.wasRewritten).map((u) => u.originalUrl),
              processingTimeMs: performance.now() - startTime,
            };
          } catch (error) {
            console.error(`[UrlRewriter] Failed to rewrite email ${email.messageId}:`, error);
            return {
              messageId: email.messageId,
              originalBody: email.textBody || '',
              rewrittenBody: email.textBody || '',
              originalHtml: email.htmlBody,
              rewrittenHtml: email.htmlBody,
              urlsRewritten: [],
              urlsSkipped: [],
              processingTimeMs: performance.now() - startTime,
            };
          }
        })
      );
      results.push(...batchResults);
    }

    return results;
  }

  /**
   * Get rewrite statistics for a tenant
   */
  async getStats(tenantId: string, period?: 'day' | 'week' | 'month' | '90days'): Promise<RewriteStatistics> {
    const intervalMap = {
      day: '1 day',
      week: '7 days',
      month: '30 days',
      '90days': '90 days',
    };
    const interval = intervalMap[period || 'month'];

    try {
      const result = await sql`
        SELECT
          COUNT(*) as total_urls,
          COALESCE(SUM(click_count), 0) as total_clicks,
          COUNT(*) FILTER (WHERE click_count > 0) as urls_clicked,
          COUNT(*) FILTER (WHERE click_verdict = 'malicious') as malicious,
          COUNT(*) FILTER (WHERE click_verdict = 'suspicious') as suspicious,
          COUNT(*) FILTER (WHERE click_verdict = 'blocked') as blocked,
          COUNT(*) FILTER (WHERE click_verdict = 'safe') as safe,
          COUNT(*) FILTER (WHERE expanded_url IS NOT NULL) as shorteners_expanded
        FROM rewritten_urls
        WHERE tenant_id = ${tenantId}
          AND created_at >= NOW() - ${interval}::interval
      `;

      const stats = result[0] || {};

      return {
        period: period || 'month',
        totalUrlsRewritten: Number(stats.total_urls || 0),
        totalClicks: Number(stats.total_clicks || 0),
        urlsClicked: Number(stats.urls_clicked || 0),
        verdicts: {
          safe: Number(stats.safe || 0),
          suspicious: Number(stats.suspicious || 0),
          malicious: Number(stats.malicious || 0),
          blocked: Number(stats.blocked || 0),
        },
        shortenersExpanded: Number(stats.shorteners_expanded || 0),
      };
    } catch (error) {
      console.error('[UrlRewriter] Failed to get stats:', error);
      return {
        period: period || 'month',
        totalUrlsRewritten: 0,
        totalClicks: 0,
        urlsClicked: 0,
        verdicts: { safe: 0, suspicious: 0, malicious: 0, blocked: 0 },
        shortenersExpanded: 0,
      };
    }
  }

  /**
   * Update excluded domains for a tenant
   */
  async updateExclusions(
    tenantId: string,
    exclusions: { addDomains?: string[]; removeDomains?: string[] }
  ): Promise<{ domainsAdded: number; domainsRemoved: number }> {
    const result = { domainsAdded: 0, domainsRemoved: 0 };

    try {
      // Add domains
      if (exclusions.addDomains && exclusions.addDomains.length > 0) {
        for (const domain of exclusions.addDomains) {
          const insertResult = await sql`
            INSERT INTO policies (
              tenant_id, type, target, value, action, priority, is_active
            )
            VALUES (
              ${tenantId}, 'allowlist', 'domain', ${domain.toLowerCase()},
              'allow', 100, true
            )
            ON CONFLICT DO NOTHING
            RETURNING id
          `;
          if (insertResult.length > 0) {
            result.domainsAdded++;
          }
        }
      }

      // Remove domains
      if (exclusions.removeDomains && exclusions.removeDomains.length > 0) {
        const deleteResult = await sql`
          DELETE FROM policies
          WHERE tenant_id = ${tenantId}
            AND type = 'allowlist'
            AND target = 'domain'
            AND LOWER(value) = ANY(${exclusions.removeDomains.map((d) => d.toLowerCase())})
          RETURNING id
        `;
        result.domainsRemoved = deleteResult.length;
      }

      // Clear cache to pick up new exclusions
      this.clearCache(tenantId);

      return result;
    } catch (error) {
      console.error('[UrlRewriter] Failed to update exclusions:', error);
      return result;
    }
  }

  /**
   * Extract all URLs from email content with detailed location info
   */
  extractAllUrls(body: string, htmlBody?: string): ExtractedUrl[] {
    const urls: ExtractedUrl[] = [];
    const seen = new Set<string>();

    // Extract from HTML
    if (htmlBody) {
      const hrefRegex = /<a\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([^<]*)<\/a>/gi;
      let match;
      while ((match = hrefRegex.exec(htmlBody)) !== null) {
        const url = this.decodeHtmlEntities(match[1]);
        if (url.startsWith('http') && !seen.has(url)) {
          seen.add(url);
          urls.push({
            url,
            location: 'html',
            anchorText: match[2] || undefined,
            context: htmlBody.slice(Math.max(0, match.index - 50), match.index + match[0].length + 50),
            position: match.index,
          });
        }
      }
    }

    // Extract from plain text
    if (body) {
      const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
      let match;
      while ((match = urlRegex.exec(body)) !== null) {
        const url = match[0].replace(/[.,;:!?)]+$/, '');
        if (!seen.has(url)) {
          const existingHtml = urls.find((u) => u.url === url);
          if (existingHtml) {
            existingHtml.location = 'both';
          } else {
            urls.push({
              url,
              location: 'text',
              context: body.slice(Math.max(0, match.index - 50), match.index + match[0].length + 50),
              position: match.index,
            });
          }
          seen.add(url);
        }
      }
    }

    return urls;
  }

  /**
   * Generate safe redirect URL from URL ID
   */
  generateSafeUrl(urlId: string): string {
    return this.buildRewrittenUrl(urlId, '');
  }

  /**
   * Lookup original URL from safe URL (delegates to database)
   */
  async lookupOriginalUrlFromSafeUrl(safeUrl: string): Promise<UrlLookupResult | null> {
    try {
      const parsed = new URL(safeUrl);
      const pathMatch = parsed.pathname.match(/^\/click\/([a-z0-9]+)$/i);
      if (!pathMatch) {
        return null;
      }

      const trackingId = pathMatch[1];
      const result = await sql`
        SELECT original_url, expanded_url, tenant_id, email_id, click_count, click_verdict, expires_at
        FROM rewritten_urls
        WHERE id = ${trackingId}
        LIMIT 1
      `;

      if (result.length === 0) {
        return null;
      }

      const row = result[0];
      return {
        found: true,
        expired: new Date(row.expires_at) < new Date(),
        originalUrl: row.original_url,
        expandedUrl: row.expanded_url,
        tenantId: row.tenant_id,
        emailId: row.email_id,
        clickCount: row.click_count,
        verdict: row.click_verdict,
      };
    } catch (error) {
      console.error('[UrlRewriter] Lookup failed:', error);
      return null;
    }
  }
}

// ============================================================================
// Additional Types for Extended Interface
// ============================================================================

export interface EmailContent {
  messageId: string;
  subject?: string;
  from?: string;
  textBody?: string;
  htmlBody?: string;
}

export interface RewriteResult {
  originalUrl: string;
  rewrittenUrl: string;
  urlId: string;
  alreadyScanned: boolean;
  initialVerdict?: 'safe' | 'suspicious' | 'malicious' | 'unknown';
}

export interface EmailRewriteResult {
  messageId: string;
  originalBody: string;
  rewrittenBody: string;
  originalHtml?: string;
  rewrittenHtml?: string;
  urlsRewritten: RewriteResult[];
  urlsSkipped: string[];
  processingTimeMs: number;
}

export interface ExtractedUrl {
  url: string;
  location: 'text' | 'html' | 'both';
  anchorText?: string;
  context?: string;
  position: number;
}

export interface RewriteStatistics {
  period: string;
  totalUrlsRewritten: number;
  totalClicks: number;
  urlsClicked: number;
  verdicts: {
    safe: number;
    suspicious: number;
    malicious: number;
    blocked: number;
  };
  shortenersExpanded: number;
}

export interface UrlLookupResult {
  found: boolean;
  expired: boolean;
  originalUrl: string | null;
  expandedUrl: string | null;
  tenantId: string | null;
  emailId: string | null;
  clickCount: number;
  verdict: string | null;
}

// ============================================================================
// Factory & Singleton
// ============================================================================

let defaultRewriter: UrlRewriter | null = null;

/**
 * Get the default URL rewriter instance
 */
export function getUrlRewriter(config?: Partial<RewriterConfig>): UrlRewriter {
  if (!defaultRewriter || config) {
    defaultRewriter = new UrlRewriter(config);
  }
  return defaultRewriter;
}

/**
 * Create a new URL rewriter with custom config
 */
export function createUrlRewriter(config: Partial<RewriterConfig>): UrlRewriter {
  return new UrlRewriter(config);
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Quick check if a URL needs rewriting (without full processing)
 */
export function quickShouldRewrite(url: string): boolean {
  try {
    const parsed = new URL(url);

    // Non-HTTP protocols never need rewriting
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return false;
    }

    const hostname = parsed.hostname.toLowerCase();

    // URL shorteners always need rewriting
    if (URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(hostname.replace('www.', ''))) {
      return true;
    }

    // Known safe domains don't need rewriting
    for (const domain of KNOWN_SAFE_DOMAINS) {
      if (hostname === domain || hostname.endsWith('.' + domain)) {
        return false;
      }
    }

    // Default to rewriting for external URLs
    return true;
  } catch {
    // Malformed URLs should be rewritten
    return true;
  }
}

/**
 * Extract all URLs from email content
 */
export function extractUrls(content: string): string[] {
  const urls = new Set<string>();

  // Match href attributes
  const hrefRegex = /href\s*=\s*["']([^"']+)["']/gi;
  let match;
  while ((match = hrefRegex.exec(content)) !== null) {
    if (match[1].startsWith('http')) {
      urls.add(match[1]);
    }
  }

  // Match plain URLs
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
  while ((match = urlRegex.exec(content)) !== null) {
    urls.add(match[0].replace(/[.,;:!?)]+$/, ''));
  }

  return Array.from(urls);
}

/**
 * Clean up expired URL mappings from database
 */
export async function cleanupExpiredUrls(): Promise<number> {
  try {
    const result = await sql`
      DELETE FROM rewritten_urls
      WHERE expires_at < NOW()
      RETURNING id
    `;
    return result.length;
  } catch (error) {
    console.error('[UrlRewriter] Failed to cleanup expired URLs:', error);
    return 0;
  }
}

// ============================================================================
// Exports
// ============================================================================

export {
  KNOWN_SAFE_DOMAINS,
  URL_SHORTENERS,
  NON_REWRITABLE_PROTOCOLS,
  DEFAULT_CONFIG as DEFAULT_REWRITER_CONFIG,
};

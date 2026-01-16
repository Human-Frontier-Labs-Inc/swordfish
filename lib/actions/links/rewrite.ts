/**
 * Link Rewriting System
 * Rewrites suspicious URLs to proxy through Swordfish for click-time protection
 */

import { createHash } from 'crypto';

export interface RewriteResult {
  originalUrl: string;
  rewrittenUrl: string;
  wasRewritten: boolean;
  reason?: string;
}

export interface LinkRewriteConfig {
  baseUrl: string;              // e.g., https://app.swordfish.io
  enableForAllExternal: boolean; // Rewrite all external links
  excludeDomains: string[];     // Domains to never rewrite
  signatureSecret: string;      // For URL signing
}

// Safe domains that should never be rewritten
const DEFAULT_SAFE_DOMAINS = [
  'google.com', 'www.google.com',
  'microsoft.com', 'www.microsoft.com',
  'apple.com', 'www.apple.com',
  'github.com', 'www.github.com',
  'linkedin.com', 'www.linkedin.com',
  'dropbox.com', 'www.dropbox.com',
  'zoom.us', 'zoom.com',
  'slack.com', 'www.slack.com',
];

// URL shorteners that should always be rewritten
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
  'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'short.io',
];

/**
 * Generate a secure click ID for a URL
 */
export function generateClickId(
  originalUrl: string,
  emailId: string,
  tenantId: string,
  secret: string
): string {
  const data = `${originalUrl}|${emailId}|${tenantId}|${Date.now()}`;
  const hash = createHash('sha256')
    .update(data + secret)
    .digest('hex')
    .substring(0, 24);

  return hash;
}

/**
 * Check if a URL should be rewritten
 */
export function shouldRewriteUrl(
  url: string,
  isSuspicious: boolean,
  config: LinkRewriteConfig
): { shouldRewrite: boolean; reason?: string } {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();

    // Never rewrite mailto, tel, etc.
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { shouldRewrite: false, reason: 'non-http-protocol' };
    }

    // Check exclusion list
    const excludeDomains = [...DEFAULT_SAFE_DOMAINS, ...config.excludeDomains];
    if (excludeDomains.some(d => hostname === d || hostname.endsWith('.' + d))) {
      return { shouldRewrite: false, reason: 'safe-domain' };
    }

    // Always rewrite URL shorteners
    if (URL_SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s))) {
      return { shouldRewrite: true, reason: 'url-shortener' };
    }

    // Rewrite suspicious URLs
    if (isSuspicious) {
      return { shouldRewrite: true, reason: 'suspicious' };
    }

    // Optionally rewrite all external links
    if (config.enableForAllExternal) {
      return { shouldRewrite: true, reason: 'external' };
    }

    return { shouldRewrite: false };
  } catch {
    // Malformed URL - rewrite to be safe
    return { shouldRewrite: true, reason: 'malformed' };
  }
}

/**
 * Rewrite a single URL
 */
export function rewriteUrl(
  originalUrl: string,
  emailId: string,
  tenantId: string,
  config: LinkRewriteConfig,
  isSuspicious: boolean = false
): RewriteResult {
  const checkResult = shouldRewriteUrl(originalUrl, isSuspicious, config);

  if (!checkResult.shouldRewrite) {
    return {
      originalUrl,
      rewrittenUrl: originalUrl,
      wasRewritten: false,
      reason: checkResult.reason,
    };
  }

  const clickId = generateClickId(originalUrl, emailId, tenantId, config.signatureSecret);
  const rewrittenUrl = `${config.baseUrl}/click/${clickId}`;

  return {
    originalUrl,
    rewrittenUrl,
    wasRewritten: true,
    reason: checkResult.reason,
  };
}

/**
 * Rewrite all URLs in HTML content
 */
export function rewriteLinksInHTML(
  html: string,
  emailId: string,
  tenantId: string,
  config: LinkRewriteConfig,
  suspiciousUrls: Set<string> = new Set()
): { html: string; rewrittenCount: number; links: RewriteResult[] } {
  const links: RewriteResult[] = [];
  let rewrittenCount = 0;

  // Match href attributes
  const urlRegex = /href\s*=\s*["']([^"']+)["']/gi;

  const newHtml = html.replace(urlRegex, (match, url) => {
    const isSuspicious = suspiciousUrls.has(url);
    const result = rewriteUrl(url, emailId, tenantId, config, isSuspicious);
    links.push(result);

    if (result.wasRewritten) {
      rewrittenCount++;
      // Add original URL as data attribute for transparency
      return `href="${result.rewrittenUrl}" data-original-url="${encodeURIComponent(url)}"`;
    }

    return match;
  });

  return { html: newHtml, rewrittenCount, links };
}

/**
 * Rewrite URLs in plain text content
 */
export function rewriteLinksInText(
  text: string,
  emailId: string,
  tenantId: string,
  config: LinkRewriteConfig,
  suspiciousUrls: Set<string> = new Set()
): { text: string; rewrittenCount: number; links: RewriteResult[] } {
  const links: RewriteResult[] = [];
  let rewrittenCount = 0;

  // Match URLs in plain text
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;

  const newText = text.replace(urlRegex, (url) => {
    // Clean up trailing punctuation
    const cleanUrl = url.replace(/[.,;:!?)]+$/, '');
    const trailingPunct = url.slice(cleanUrl.length);

    const isSuspicious = suspiciousUrls.has(cleanUrl);
    const result = rewriteUrl(cleanUrl, emailId, tenantId, config, isSuspicious);
    links.push(result);

    if (result.wasRewritten) {
      rewrittenCount++;
      return result.rewrittenUrl + trailingPunct;
    }

    return url;
  });

  return { text: newText, rewrittenCount, links };
}

/**
 * Store click mapping in database for resolution
 */
export interface ClickMapping {
  id: string;
  originalUrl: string;
  emailId: string;
  tenantId: string;
  createdAt: Date;
  expiresAt: Date;
  clickCount: number;
  lastClickAt?: Date;
  metadata?: {
    reason?: string;
    riskScore?: number;
    suspiciousIndicators?: string[];
  };
}

/**
 * Create click mapping record
 */
export function createClickMapping(
  clickId: string,
  originalUrl: string,
  emailId: string,
  tenantId: string,
  reason?: string,
  riskScore?: number
): ClickMapping {
  const now = new Date();
  const expiresAt = new Date(now);
  expiresAt.setDate(expiresAt.getDate() + 30); // 30 day expiry

  return {
    id: clickId,
    originalUrl,
    emailId,
    tenantId,
    createdAt: now,
    expiresAt,
    clickCount: 0,
    metadata: {
      reason,
      riskScore,
    },
  };
}

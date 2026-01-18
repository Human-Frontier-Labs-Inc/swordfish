/**
 * Click Scanner Module
 *
 * Provides comprehensive click-time URL scanning with:
 * - Real-time URL analysis when users click rewritten links
 * - Redirect chain following and analysis
 * - Multi-source reputation checking (VirusTotal, URLScan, internal)
 * - Domain age verification
 * - SSL certificate validation
 * - Warning page generation
 * - Click analytics tracking
 */

import { sql } from '@/lib/db';
import { VirusTotalClient, type AnalysisStats, AnalysisStatus } from '@/lib/threat-intel/virustotal';
import { UrlScanClient, type ScanResult as UrlScanScanResult, ScanStatus } from '@/lib/threat-intel/urlscan';
import { checkDomainAge, type DomainAgeResult } from '@/lib/threat-intel/domain/age';

// =============================================================================
// Type Definitions
// =============================================================================

export interface ClickScanResult {
  clickId: string;
  originalUrl: string;
  finalUrl: string;
  redirectChain: string[];
  scanTimeMs: number;
  verdict: 'safe' | 'suspicious' | 'malicious' | 'blocked';
  threats: UrlThreat[];
  reputation: ReputationResult;
  shouldWarn: boolean;
  shouldBlock: boolean;
}

export interface UrlThreat {
  type: 'phishing' | 'malware' | 'scam' | 'suspicious_redirect' | 'newly_registered';
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  details: string;
}

export interface ReputationResult {
  score: number;
  sources: {
    virustotal?: { malicious: number; suspicious: number; clean: number };
    urlscan?: { verdict: string; score: number };
    internal?: { previouslyBlocked: boolean; reportCount: number };
  };
  domainAge?: number;
  sslValid?: boolean;
  categories?: string[];
}

export interface ClickFilters {
  startDate?: Date;
  endDate?: Date;
  verdict?: 'safe' | 'suspicious' | 'malicious' | 'blocked';
  urlPattern?: string;
  limit?: number;
  offset?: number;
}

export interface ClickAnalytics {
  totalClicks: number;
  blockedClicks: number;
  warnedClicks: number;
  uniqueUrls: number;
  topBlockedDomains: { domain: string; count: number }[];
  clicksByHour: { hour: number; count: number }[];
  clicksByDay: { date: string; count: number }[];
  topThreatTypes: { type: string; count: number }[];
  averageScanTimeMs: number;
}

export interface ClickEvent {
  urlId: string;
  tenantId: string;
  userId?: string;
  userEmail?: string;
  clickedAt: Date;
  userAgent: string;
  ipAddress: string;
  referrer?: string;
}

export interface ClickScannerScanResult {
  urlId: string;
  originalUrl: string;
  finalUrl: string;
  verdict: 'safe' | 'suspicious' | 'malicious' | 'timeout' | 'error';
  confidence: number;
  scanTimeMs: number;
  redirectChain: string[];
  threats: ThreatIndicator[];
  cachedResult: boolean;
  scannedAt: Date;
}

export interface ThreatIndicator {
  type: 'phishing' | 'malware' | 'scam' | 'suspicious_redirect' | 'newly_registered' | 'bad_reputation';
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  details: string;
}

export interface ClickDecision {
  action: 'allow' | 'warn' | 'block';
  reason: string;
  warningMessage?: string;
  blockMessage?: string;
  originalUrl: string;
  scanResult: ClickScannerScanResult;
}

export interface RedirectResult {
  finalUrl: string;
  chain: string[];
  totalRedirects: number;
  crossDomainRedirects: number;
  suspiciousPatterns: string[];
}

export interface ThreatIntelResult {
  isThreat: boolean;
  threatTypes: string[];
  sources: string[];
  confidence: number;
  lastSeen?: Date;
}

export interface ReputationResult {
  score: number;
  sources: {
    virustotal?: { malicious: number; suspicious: number; clean: number };
    urlscan?: { verdict: string; score: number };
    internal?: { previouslyBlocked: boolean; reportCount: number };
  };
  domainAge?: number;
  sslValid?: boolean;
  categories?: string[];
}

export interface TopUrl {
  urlId: string;
  originalUrl: string;
  clickCount: number;
  lastClickedAt: Date;
  verdict?: string;
}

export interface BlockedClick {
  id: string;
  urlId: string;
  originalUrl: string;
  userId?: string;
  userEmail?: string;
  clickedAt: Date;
  reason: string;
  threatType: string;
}

export interface ClickScannerConfig {
  virusTotalApiKey?: string;
  urlScanApiKey?: string;
  redirectTimeout: number;
  maxRedirects: number;
  scanTimeout: number;
  blockThreshold: number;
  warnThreshold: number;
  newDomainAgeThreshold: number;
  enableVirusTotal: boolean;
  enableUrlScan: boolean;
  enableDomainAge: boolean;
  enableSslCheck: boolean;
  cacheEnabled: boolean;
  cacheTtl: number;
}

interface CacheEntry {
  result: ClickScanResult;
  timestamp: number;
}

// =============================================================================
// Default Configuration
// =============================================================================

const DEFAULT_CONFIG: ClickScannerConfig = {
  redirectTimeout: 5000,
  maxRedirects: 10,
  scanTimeout: 5000,
  blockThreshold: 70,
  warnThreshold: 40,
  newDomainAgeThreshold: 30,
  enableVirusTotal: true,
  enableUrlScan: true,
  enableDomainAge: true,
  enableSslCheck: true,
  cacheEnabled: true,
  cacheTtl: 300000, // 5 minutes
};

// =============================================================================
// Click Scanner Class
// =============================================================================

export class ClickScanner {
  private config: ClickScannerConfig;
  private vtClient: VirusTotalClient | null = null;
  private urlscanClient: UrlScanClient | null = null;
  private cache: Map<string, CacheEntry> = new Map();

  constructor(config: Partial<ClickScannerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };

    // Initialize VirusTotal client if API key provided
    const vtKey = config.virusTotalApiKey || process.env.VIRUSTOTAL_API_KEY;
    if (vtKey && this.config.enableVirusTotal) {
      this.vtClient = new VirusTotalClient({
        apiKey: vtKey,
        timeout: this.config.scanTimeout,
        cacheEnabled: this.config.cacheEnabled,
        cacheTtl: this.config.cacheTtl,
      });
    }

    // Initialize URLScan client if API key provided
    const urlscanKey = config.urlScanApiKey || process.env.URLSCAN_API_KEY;
    if (urlscanKey && this.config.enableUrlScan) {
      this.urlscanClient = new UrlScanClient({
        apiKey: urlscanKey,
        timeout: this.config.scanTimeout,
        visibility: 'private',
        cacheEnabled: this.config.cacheEnabled,
        cacheTtl: this.config.cacheTtl,
      });
    }
  }

  /**
   * Scan URL at click time with comprehensive analysis
   */
  async scanAtClickTime(clickId: string): Promise<ClickScanResult> {
    const startTime = performance.now();
    const threats: UrlThreat[] = [];
    let totalScore = 0;

    // Get the original URL from click mapping
    const mapping = await this.getClickMappingById(clickId);
    if (!mapping) {
      throw new Error(`Click mapping not found: ${clickId}`);
    }

    const originalUrl = mapping.originalUrl;

    // Check cache first
    const cacheKey = `click:${originalUrl.toLowerCase()}`;
    const cached = this.getFromCache(cacheKey);
    if (cached) {
      return {
        ...cached,
        clickId,
        scanTimeMs: performance.now() - startTime,
      };
    }

    // Get redirect chain with timeout
    let finalUrl = originalUrl;
    let redirectChain: string[] = [originalUrl];

    try {
      const redirectResult = await this.getRedirectChainWithTimeout(originalUrl);
      redirectChain = redirectResult;
      finalUrl = redirectResult[redirectResult.length - 1];

      // Check for suspicious redirects
      if (redirectChain.length > 3) {
        threats.push({
          type: 'suspicious_redirect',
          severity: 'medium',
          source: 'internal',
          details: `URL has ${redirectChain.length} redirects which may indicate redirect-based attacks`,
        });
        totalScore += 15;
      }

      // Check if final URL differs significantly from original
      const originalDomain = this.extractDomain(originalUrl);
      const finalDomain = this.extractDomain(finalUrl);
      if (originalDomain !== finalDomain) {
        threats.push({
          type: 'suspicious_redirect',
          severity: 'high',
          source: 'internal',
          details: `URL redirects to different domain: ${originalDomain} -> ${finalDomain}`,
        });
        totalScore += 25;
      }
    } catch (error) {
      console.error('[ClickScanner] Redirect check failed:', error);
    }

    // Run all checks in parallel with timeout
    const [reputationResult, domainAgeResult, sslResult] = await Promise.all([
      this.checkUrlReputation(finalUrl),
      this.config.enableDomainAge ? this.checkDomainAgeForUrl(finalUrl) : null,
      this.config.enableSslCheck ? this.checkSslCertificate(finalUrl) : null,
    ]);

    // Process reputation results
    const reputation: ReputationResult = {
      score: 100 - reputationResult.riskScore, // Convert risk to reputation
      sources: reputationResult.sources,
      categories: reputationResult.categories,
    };

    // Add reputation-based threats
    threats.push(...reputationResult.threats);
    totalScore += reputationResult.riskScore;

    // Process domain age results
    if (domainAgeResult) {
      reputation.domainAge = domainAgeResult.ageInDays ?? undefined;

      if (domainAgeResult.ageInDays !== null &&
          domainAgeResult.ageInDays < this.config.newDomainAgeThreshold) {
        threats.push({
          type: 'newly_registered',
          severity: domainAgeResult.ageInDays < 7 ? 'critical' : 'high',
          source: 'domain_age',
          details: `Domain was registered ${domainAgeResult.ageInDays} days ago (threshold: ${this.config.newDomainAgeThreshold} days)`,
        });
        totalScore += domainAgeResult.ageInDays < 7 ? 30 : 20;
      }
    }

    // Process SSL results
    if (sslResult !== null) {
      reputation.sslValid = sslResult;

      if (!sslResult) {
        threats.push({
          type: 'phishing',
          severity: 'high',
          source: 'ssl_check',
          details: 'URL does not have a valid SSL certificate',
        });
        totalScore += 20;
      }
    }

    // Check internal blocklists
    const internalResult = await this.checkInternalBlocklist(finalUrl);
    if (internalResult.previouslyBlocked || internalResult.reportCount > 0) {
      reputation.sources.internal = internalResult;

      if (internalResult.previouslyBlocked) {
        threats.push({
          type: 'malware',
          severity: 'critical',
          source: 'internal',
          details: 'URL was previously blocked by your organization',
        });
        totalScore += 50;
      } else if (internalResult.reportCount > 2) {
        threats.push({
          type: 'phishing',
          severity: 'high',
          source: 'internal',
          details: `URL has been reported ${internalResult.reportCount} times by users`,
        });
        totalScore += 25;
      }
    }

    // Determine verdict
    const { verdict, shouldWarn, shouldBlock } = this.determineVerdict(totalScore, threats);

    const result: ClickScanResult = {
      clickId,
      originalUrl,
      finalUrl,
      redirectChain,
      scanTimeMs: performance.now() - startTime,
      verdict,
      threats,
      reputation,
      shouldWarn,
      shouldBlock,
    };

    // Cache the result
    this.setCache(cacheKey, result);

    return result;
  }

  /**
   * Follow and record redirect chain with timeout
   */
  async getRedirectChain(url: string): Promise<string[]> {
    return this.getRedirectChainWithTimeout(url);
  }

  /**
   * Internal method for redirect chain with timeout
   */
  private async getRedirectChainWithTimeout(url: string): Promise<string[]> {
    const chain: string[] = [url];
    let currentUrl = url;
    let redirectCount = 0;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.redirectTimeout);

    try {
      while (redirectCount < this.config.maxRedirects) {
        const response = await fetch(currentUrl, {
          method: 'HEAD',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; SwordfishBot/1.0; +https://swordfish.security)',
          },
        });

        // Check for redirect
        if (response.status >= 300 && response.status < 400) {
          const location = response.headers.get('Location');
          if (location) {
            // Handle relative redirects
            const nextUrl = location.startsWith('http')
              ? location
              : new URL(location, currentUrl).href;

            chain.push(nextUrl);
            currentUrl = nextUrl;
            redirectCount++;
          } else {
            break;
          }
        } else {
          break;
        }
      }
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        console.warn('[ClickScanner] Redirect chain check timed out');
      } else {
        console.error('[ClickScanner] Error following redirects:', error);
      }
    } finally {
      clearTimeout(timeoutId);
    }

    return chain;
  }

  /**
   * Check URL reputation against multiple sources
   */
  async checkUrlReputation(url: string): Promise<{
    riskScore: number;
    sources: ReputationResult['sources'];
    threats: UrlThreat[];
    categories: string[];
  }> {
    let riskScore = 0;
    const threats: UrlThreat[] = [];
    const sources: ReputationResult['sources'] = {};
    const categories: string[] = [];

    // Run checks in parallel
    const checks: Promise<void>[] = [];

    // VirusTotal check
    if (this.vtClient) {
      checks.push(
        this.checkVirusTotal(url).then((result) => {
          if (result) {
            sources.virustotal = result.stats;
            riskScore += result.riskScore;
            threats.push(...result.threats);
            categories.push(...result.categories);
          }
        }).catch((error) => {
          console.error('[ClickScanner] VirusTotal check failed:', error);
        })
      );
    }

    // URLScan check
    if (this.urlscanClient) {
      checks.push(
        this.checkUrlScan(url).then((result) => {
          if (result) {
            sources.urlscan = result.verdict;
            riskScore += result.riskScore;
            threats.push(...result.threats);
            categories.push(...result.categories);
          }
        }).catch((error) => {
          console.error('[ClickScanner] URLScan check failed:', error);
        })
      );
    }

    // Wait for all checks with timeout
    await Promise.race([
      Promise.all(checks),
      new Promise<void>((resolve) => setTimeout(resolve, this.config.scanTimeout)),
    ]);

    return {
      riskScore: Math.min(100, riskScore),
      sources,
      threats,
      categories: [...new Set(categories)],
    };
  }

  /**
   * Check VirusTotal for URL reputation
   */
  private async checkVirusTotal(url: string): Promise<{
    stats: { malicious: number; suspicious: number; clean: number };
    riskScore: number;
    threats: UrlThreat[];
    categories: string[];
  } | null> {
    if (!this.vtClient) return null;

    try {
      // Use quick URL lookup instead of full scan for speed
      const result = await this.vtClient.scanUrl(url, {
        maxPolls: 2, // Limited polling for click-time speed
        pollInterval: 1000,
      });

      const stats = {
        malicious: result.stats.malicious,
        suspicious: result.stats.suspicious,
        clean: result.stats.harmless,
      };

      const threats: UrlThreat[] = [];
      let riskScore = 0;

      if (result.stats.malicious > 0) {
        riskScore = Math.min(50, result.stats.malicious * 10);
        threats.push({
          type: 'malware',
          severity: result.stats.malicious >= 5 ? 'critical' : 'high',
          source: 'virustotal',
          details: `${result.stats.malicious} security vendors flagged this URL as malicious`,
        });
      }

      if (result.stats.suspicious > 2) {
        riskScore += Math.min(30, result.stats.suspicious * 5);
        threats.push({
          type: 'phishing',
          severity: 'medium',
          source: 'virustotal',
          details: `${result.stats.suspicious} security vendors flagged this URL as suspicious`,
        });
      }

      // Map categories
      const categories = result.categories.map((c) => c.toString());

      return { stats, riskScore, threats, categories };
    } catch (error) {
      console.error('[ClickScanner] VirusTotal error:', error);
      return null;
    }
  }

  /**
   * Check URLScan for URL reputation
   */
  private async checkUrlScan(url: string): Promise<{
    verdict: { verdict: string; score: number };
    riskScore: number;
    threats: UrlThreat[];
    categories: string[];
  } | null> {
    if (!this.urlscanClient) return null;

    try {
      // Search for existing scans first (faster than new scan)
      const domain = this.extractDomain(url);
      const searchResult = await this.urlscanClient.searchByDomain(domain);

      if (searchResult.results.length > 0) {
        // Get the most recent scan
        const recentUuid = searchResult.results[0].uuid;
        const result = await this.urlscanClient.getResult(recentUuid);

        return this.processUrlScanResult(result);
      }

      // No existing scan - submit new one (may not complete in time)
      const submitResult = await this.urlscanClient.submitScan(url, {
        visibility: 'private',
        maxPolls: 2,
        pollInterval: 1000,
      });

      if (submitResult) {
        return this.processUrlScanResult(submitResult as unknown as UrlScanScanResult);
      }

      return null;
    } catch (error) {
      console.error('[ClickScanner] URLScan error:', error);
      return null;
    }
  }

  /**
   * Process URLScan result into our format
   */
  private processUrlScanResult(result: UrlScanScanResult): {
    verdict: { verdict: string; score: number };
    riskScore: number;
    threats: UrlThreat[];
    categories: string[];
  } {
    const threats: UrlThreat[] = [];
    let riskScore = 0;

    const verdict = {
      verdict: result.verdict.malicious ? 'malicious' : 'safe',
      score: result.verdict.score,
    };

    if (result.verdict.malicious) {
      riskScore = Math.min(50, result.verdict.score);
      threats.push({
        type: 'malware',
        severity: result.verdict.score >= 70 ? 'critical' : 'high',
        source: 'urlscan',
        details: `URLScan detected malicious content (score: ${result.verdict.score})`,
      });
    }

    // Check for phishing patterns
    if (result.indicators.phishingPatterns.length > 0) {
      riskScore += 20;
      threats.push({
        type: 'phishing',
        severity: 'high',
        source: 'urlscan',
        details: result.indicators.phishingPatterns.join('; '),
      });
    }

    return {
      verdict,
      riskScore,
      threats,
      categories: result.verdict.categories || [],
    };
  }

  /**
   * Check domain age for URL
   */
  private async checkDomainAgeForUrl(url: string): Promise<DomainAgeResult | null> {
    try {
      const domain = this.extractDomain(url);
      return await checkDomainAge(domain);
    } catch (error) {
      console.error('[ClickScanner] Domain age check failed:', error);
      return null;
    }
  }

  /**
   * Check SSL certificate validity
   */
  private async checkSslCertificate(url: string): Promise<boolean | null> {
    try {
      const parsed = new URL(url);

      // Only check HTTPS URLs
      if (parsed.protocol !== 'https:') {
        return false; // HTTP is not secure
      }

      // Attempt to connect to validate certificate
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      try {
        await fetch(url, {
          method: 'HEAD',
          signal: controller.signal,
        });
        return true; // Connection successful = valid cert
      } catch (error) {
        // SSL errors will throw
        if (error instanceof Error &&
            (error.message.includes('certificate') ||
             error.message.includes('SSL') ||
             error.message.includes('TLS'))) {
          return false;
        }
        return null; // Other errors - inconclusive
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      console.error('[ClickScanner] SSL check failed:', error);
      return null;
    }
  }

  /**
   * Check internal blocklist
   */
  private async checkInternalBlocklist(url: string): Promise<{
    previouslyBlocked: boolean;
    reportCount: number;
  }> {
    try {
      const domain = this.extractDomain(url);

      // Check for previous blocks
      const blockResult = await sql`
        SELECT COUNT(*) as count
        FROM action_logs
        WHERE type = 'click_blocked'
          AND target_url LIKE ${'%' + domain + '%'}
          AND created_at > NOW() - INTERVAL '90 days'
      `;

      // Check for user reports
      const reportResult = await sql`
        SELECT COUNT(*) as count
        FROM action_logs
        WHERE type = 'threat_reported'
          AND (target_url LIKE ${'%' + domain + '%'} OR metadata::text LIKE ${'%' + domain + '%'})
          AND created_at > NOW() - INTERVAL '90 days'
      `;

      return {
        previouslyBlocked: Number(blockResult[0]?.count || 0) > 0,
        reportCount: Number(reportResult[0]?.count || 0),
      };
    } catch (error) {
      console.error('[ClickScanner] Internal blocklist check failed:', error);
      return { previouslyBlocked: false, reportCount: 0 };
    }
  }

  /**
   * Determine if URL should be blocked based on scan result
   */
  shouldBlock(scanResult: ClickScanResult): boolean {
    return scanResult.shouldBlock;
  }

  /**
   * Generate warning page HTML
   */
  generateWarningPage(scanResult: ClickScanResult): string {
    const isMalicious = scanResult.verdict === 'malicious' || scanResult.verdict === 'blocked';
    const bgColor = isMalicious ? '#fef2f2' : '#fffbeb';
    const borderColor = isMalicious ? '#ef4444' : '#f59e0b';
    const headerColor = isMalicious ? '#dc2626' : '#d97706';
    const headerText = isMalicious ? 'Dangerous Link Detected' : 'Suspicious Link Warning';
    const iconSvg = isMalicious
      ? `<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="${headerColor}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`
      : `<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="${headerColor}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;

    const threatsList = scanResult.threats
      .map((t) => {
        const severityColor = {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#d97706',
          low: '#65a30d',
        }[t.severity];
        return `
          <div style="display: flex; align-items: flex-start; gap: 12px; padding: 12px; background: white; border-radius: 8px; border: 1px solid #e5e7eb;">
            <span style="display: inline-block; padding: 2px 8px; font-size: 12px; font-weight: 600; color: white; background: ${severityColor}; border-radius: 4px; text-transform: uppercase;">${t.severity}</span>
            <div style="flex: 1;">
              <div style="font-weight: 600; color: #374151; text-transform: capitalize;">${t.type.replace('_', ' ')}</div>
              <div style="font-size: 14px; color: #6b7280; margin-top: 4px;">${this.escapeHtml(t.details)}</div>
              <div style="font-size: 12px; color: #9ca3af; margin-top: 2px;">Source: ${t.source}</div>
            </div>
          </div>
        `;
      })
      .join('');

    const reputationScore = scanResult.reputation.score;
    const scoreColor = reputationScore >= 70 ? '#22c55e' : reputationScore >= 40 ? '#f59e0b' : '#ef4444';

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${headerText} | Swordfish Security</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, ${bgColor} 0%, #f8fafc 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      max-width: 640px;
      width: 100%;
      background: white;
      border-radius: 16px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
      border: 2px solid ${borderColor};
      overflow: hidden;
    }
    .header {
      background: ${bgColor};
      padding: 32px;
      text-align: center;
      border-bottom: 2px solid ${borderColor};
    }
    .header svg { margin-bottom: 16px; }
    .header h1 { color: ${headerColor}; font-size: 24px; font-weight: 700; }
    .header p { color: #6b7280; margin-top: 8px; }
    .content { padding: 24px; }
    .url-box {
      background: #f9fafb;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
    }
    .url-box label { font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }
    .url-box code {
      display: block;
      margin-top: 8px;
      font-size: 14px;
      color: #374151;
      word-break: break-all;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    .threats-section { margin-bottom: 24px; }
    .threats-section h2 { font-size: 16px; font-weight: 600; color: #374151; margin-bottom: 12px; }
    .threats-list { display: flex; flex-direction: column; gap: 12px; }
    .reputation-bar {
      margin-bottom: 24px;
      padding: 16px;
      background: #f9fafb;
      border-radius: 8px;
    }
    .reputation-bar label { font-size: 12px; color: #6b7280; text-transform: uppercase; }
    .reputation-score {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-top: 8px;
    }
    .reputation-score .bar {
      flex: 1;
      height: 8px;
      background: #e5e7eb;
      border-radius: 4px;
      overflow: hidden;
    }
    .reputation-score .fill {
      height: 100%;
      background: ${scoreColor};
      border-radius: 4px;
    }
    .reputation-score .value { font-weight: 600; color: ${scoreColor}; }
    .scan-info {
      font-size: 12px;
      color: #9ca3af;
      text-align: center;
      margin-bottom: 24px;
    }
    .actions {
      display: flex;
      gap: 12px;
      flex-direction: column;
    }
    @media (min-width: 480px) {
      .actions { flex-direction: row; }
    }
    .btn {
      flex: 1;
      padding: 12px 24px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      border: none;
      text-decoration: none;
      text-align: center;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      transition: all 0.2s;
    }
    .btn-primary {
      background: #3b82f6;
      color: white;
    }
    .btn-primary:hover { background: #2563eb; }
    .btn-danger {
      background: ${isMalicious ? '#f3f4f6' : '#fef2f2'};
      color: ${isMalicious ? '#6b7280' : '#dc2626'};
      border: 1px solid ${isMalicious ? '#d1d5db' : '#fecaca'};
    }
    .btn-danger:hover {
      background: ${isMalicious ? '#e5e7eb' : '#fee2e2'};
    }
    ${isMalicious ? '.btn-danger { pointer-events: none; opacity: 0.6; }' : ''}
    .footer {
      padding: 16px 24px;
      background: #f9fafb;
      border-top: 1px solid #e5e7eb;
      text-align: center;
    }
    .footer img { height: 24px; opacity: 0.6; }
    .footer p { font-size: 12px; color: #9ca3af; margin-top: 8px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      ${iconSvg}
      <h1>${headerText}</h1>
      <p>Our security analysis has identified potential risks with this link.</p>
    </div>

    <div class="content">
      <div class="url-box">
        <label>Destination URL</label>
        <code>${this.escapeHtml(scanResult.finalUrl)}</code>
      </div>

      ${scanResult.threats.length > 0 ? `
      <div class="threats-section">
        <h2>Risk Factors Detected</h2>
        <div class="threats-list">
          ${threatsList}
        </div>
      </div>
      ` : ''}

      <div class="reputation-bar">
        <label>Security Reputation Score</label>
        <div class="reputation-score">
          <div class="bar">
            <div class="fill" style="width: ${reputationScore}%"></div>
          </div>
          <span class="value">${reputationScore}/100</span>
        </div>
      </div>

      <div class="scan-info">
        Scanned in ${scanResult.scanTimeMs.toFixed(0)}ms | Click ID: ${scanResult.clickId}
      </div>

      <div class="actions">
        <a href="javascript:history.back()" class="btn btn-primary">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 19-7-7 7-7"/><path d="M19 12H5"/></svg>
          Go Back (Recommended)
        </a>
        <a href="${this.escapeHtml(scanResult.originalUrl)}" class="btn btn-danger"
           onclick="return confirmProceed()" ${isMalicious ? 'aria-disabled="true"' : ''}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          ${isMalicious ? 'Blocked' : 'Continue Anyway'}
        </a>
      </div>
    </div>

    <div class="footer">
      <p>Protected by Swordfish Email Security</p>
    </div>
  </div>

  <script>
    function confirmProceed() {
      ${isMalicious ? 'return false;' : `
      const confirmed = confirm(
        'WARNING: You are about to visit a potentially dangerous website.\\n\\n' +
        'This site has been flagged for security concerns. Proceeding may put your ' +
        'device and personal information at risk.\\n\\n' +
        'Are you absolutely sure you want to continue?'
      );
      if (confirmed) {
        // Log the bypass
        fetch('/api/click/${scanResult.clickId}', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ bypassWarning: true })
        }).catch(() => {});
      }
      return confirmed;
      `}
    }
  </script>
</body>
</html>`;
  }

  /**
   * Record click event for analytics
   */
  async recordClick(clickId: string, result: ClickScanResult): Promise<void> {
    try {
      await sql`
        INSERT INTO click_scans (
          click_id,
          original_url,
          final_url,
          redirect_chain,
          scan_time_ms,
          verdict,
          threats,
          reputation_score,
          reputation_sources,
          should_warn,
          should_block,
          scanned_at
        ) VALUES (
          ${clickId},
          ${result.originalUrl},
          ${result.finalUrl},
          ${JSON.stringify(result.redirectChain)},
          ${Math.round(result.scanTimeMs)},
          ${result.verdict},
          ${JSON.stringify(result.threats)},
          ${result.reputation.score},
          ${JSON.stringify(result.reputation.sources)},
          ${result.shouldWarn},
          ${result.shouldBlock},
          NOW()
        )
        ON CONFLICT (click_id) DO UPDATE SET
          final_url = EXCLUDED.final_url,
          redirect_chain = EXCLUDED.redirect_chain,
          scan_time_ms = EXCLUDED.scan_time_ms,
          verdict = EXCLUDED.verdict,
          threats = EXCLUDED.threats,
          reputation_score = EXCLUDED.reputation_score,
          reputation_sources = EXCLUDED.reputation_sources,
          should_warn = EXCLUDED.should_warn,
          should_block = EXCLUDED.should_block,
          scanned_at = EXCLUDED.scanned_at
      `;
    } catch (error) {
      console.error('[ClickScanner] Failed to record click:', error);
    }
  }

  /**
   * Get click analytics for a tenant
   */
  async getClickAnalytics(tenantId: string, filters: ClickFilters = {}): Promise<ClickAnalytics> {
    const { startDate, endDate, limit = 10 } = filters;
    const start = startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days default
    const end = endDate || new Date();

    try {
      // Get total clicks
      const totalResult = await sql`
        SELECT COUNT(*) as total
        FROM click_mappings cm
        WHERE cm.tenant_id = ${tenantId}
          AND cm.created_at BETWEEN ${start.toISOString()} AND ${end.toISOString()}
      `;

      // Get blocked and warned clicks
      const verdictResult = await sql`
        SELECT
          cs.verdict,
          COUNT(*) as count
        FROM click_scans cs
        JOIN click_mappings cm ON cs.click_id = cm.id
        WHERE cm.tenant_id = ${tenantId}
          AND cs.scanned_at BETWEEN ${start.toISOString()} AND ${end.toISOString()}
        GROUP BY cs.verdict
      `;

      // Get unique URLs
      const uniqueResult = await sql`
        SELECT COUNT(DISTINCT original_url) as unique_urls
        FROM click_mappings
        WHERE tenant_id = ${tenantId}
          AND created_at BETWEEN ${start.toISOString()} AND ${end.toISOString()}
      `;

      // Get top blocked domains
      const topBlockedResult = await sql`
        SELECT
          SUBSTRING(cs.final_url FROM '://([^/]+)') as domain,
          COUNT(*) as count
        FROM click_scans cs
        JOIN click_mappings cm ON cs.click_id = cm.id
        WHERE cm.tenant_id = ${tenantId}
          AND cs.verdict IN ('blocked', 'malicious')
          AND cs.scanned_at BETWEEN ${start.toISOString()} AND ${end.toISOString()}
        GROUP BY domain
        ORDER BY count DESC
        LIMIT ${limit}
      `;

      // Get clicks by hour
      const hourlyResult = await sql`
        SELECT
          EXTRACT(HOUR FROM cs.scanned_at) as hour,
          COUNT(*) as count
        FROM click_scans cs
        JOIN click_mappings cm ON cs.click_id = cm.id
        WHERE cm.tenant_id = ${tenantId}
          AND cs.scanned_at BETWEEN ${start.toISOString()} AND ${end.toISOString()}
        GROUP BY hour
        ORDER BY hour
      `;

      // Process results
      let blockedClicks = 0;
      let warnedClicks = 0;
      for (const row of verdictResult) {
        if (row.verdict === 'blocked' || row.verdict === 'malicious') {
          blockedClicks = Number(row.count);
        } else if (row.verdict === 'suspicious') {
          warnedClicks = Number(row.count);
        }
      }

      // Get clicks by day
      const dailyResult = await sql`
        SELECT
          DATE(cs.scanned_at) as date,
          COUNT(*) as count
        FROM click_scans cs
        JOIN click_mappings cm ON cs.click_id = cm.id
        WHERE cm.tenant_id = ${tenantId}
          AND cs.scanned_at BETWEEN ${start.toISOString()} AND ${end.toISOString()}
        GROUP BY DATE(cs.scanned_at)
        ORDER BY date DESC
        LIMIT 30
      `;

      // Get top threat types
      const threatResult = await sql`
        SELECT
          threat_elem->>'type' as threat_type,
          COUNT(*) as count
        FROM click_scans cs
        JOIN click_mappings cm ON cs.click_id = cm.id,
        LATERAL jsonb_array_elements(cs.threats::jsonb) as threat_elem
        WHERE cm.tenant_id = ${tenantId}
          AND cs.scanned_at BETWEEN ${start.toISOString()} AND ${end.toISOString()}
        GROUP BY threat_elem->>'type'
        ORDER BY count DESC
        LIMIT 10
      `;

      // Get average scan time
      const scanTimeResult = await sql`
        SELECT AVG(cs.scan_time_ms) as avg_scan_time
        FROM click_scans cs
        JOIN click_mappings cm ON cs.click_id = cm.id
        WHERE cm.tenant_id = ${tenantId}
          AND cs.scanned_at BETWEEN ${start.toISOString()} AND ${end.toISOString()}
      `;

      return {
        totalClicks: Number(totalResult[0]?.total || 0),
        blockedClicks,
        warnedClicks,
        uniqueUrls: Number(uniqueResult[0]?.unique_urls || 0),
        topBlockedDomains: topBlockedResult.map((r) => ({
          domain: r.domain || 'unknown',
          count: Number(r.count),
        })),
        clicksByHour: Array.from({ length: 24 }, (_, i) => {
          const hourData = hourlyResult.find((r) => Number(r.hour) === i);
          return { hour: i, count: Number(hourData?.count || 0) };
        }),
        clicksByDay: dailyResult.map((r) => ({
          date: r.date ? new Date(r.date).toISOString().split('T')[0] : '',
          count: Number(r.count || 0),
        })),
        topThreatTypes: threatResult.map((r) => ({
          type: r.threat_type || 'unknown',
          count: Number(r.count || 0),
        })),
        averageScanTimeMs: Number(scanTimeResult[0]?.avg_scan_time || 0),
      };
    } catch (error) {
      console.error('[ClickScanner] Failed to get analytics:', error);
      return {
        totalClicks: 0,
        blockedClicks: 0,
        warnedClicks: 0,
        uniqueUrls: 0,
        topBlockedDomains: [],
        clicksByHour: Array.from({ length: 24 }, (_, i) => ({ hour: i, count: 0 })),
        clicksByDay: [],
        topThreatTypes: [],
        averageScanTimeMs: 0,
      };
    }
  }

  // =============================================================================
  // Additional Public Methods (per interface specification)
  // =============================================================================

  /**
   * Main entry point - process a click event and decide action
   */
  async processClick(click: ClickEvent): Promise<ClickDecision> {
    const startTime = performance.now();

    // Get the original URL from click mapping
    const mapping = await this.getClickMappingById(click.urlId);
    if (!mapping) {
      throw new Error(`Click mapping not found: ${click.urlId}`);
    }

    // Scan the URL
    const scanResult = await this.scanUrl(mapping.originalUrl);

    // Record the click event
    await this.recordClickEvent(click, scanResult);

    // Determine action based on scan result
    const action = this.determineAction(scanResult);

    return {
      action: action.action,
      reason: action.reason,
      warningMessage: action.warningMessage,
      blockMessage: action.blockMessage,
      originalUrl: mapping.originalUrl,
      scanResult,
    };
  }

  /**
   * Scan URL using multiple sources
   */
  async scanUrl(url: string): Promise<ClickScannerScanResult> {
    const startTime = performance.now();
    const threats: ThreatIndicator[] = [];
    let totalScore = 0;

    // Check cache first
    const cached = await this.getCachedScan(url);
    if (cached) {
      return cached;
    }

    // Get redirect chain
    let finalUrl = url;
    let redirectChain: string[] = [url];

    try {
      const redirectResult = await this.resolveRedirects(url);
      redirectChain = redirectResult.chain;
      finalUrl = redirectResult.finalUrl;

      // Add threats from redirect analysis
      if (redirectResult.suspiciousPatterns.length > 0) {
        for (const pattern of redirectResult.suspiciousPatterns) {
          threats.push({
            type: 'suspicious_redirect',
            severity: 'medium',
            source: 'internal',
            details: pattern,
          });
          totalScore += 15;
        }
      }

      if (redirectResult.crossDomainRedirects > 1) {
        threats.push({
          type: 'suspicious_redirect',
          severity: 'high',
          source: 'internal',
          details: `URL crosses ${redirectResult.crossDomainRedirects} different domains`,
        });
        totalScore += 25;
      }
    } catch (error) {
      console.error('[ClickScanner] Redirect resolution failed:', error);
    }

    // Check reputation
    const reputationResult = await this.checkUrlReputation(finalUrl);
    totalScore += reputationResult.riskScore;
    threats.push(...reputationResult.threats);

    // Check threat intel feeds
    const threatIntelResult = await this.checkThreatIntel(finalUrl);
    if (threatIntelResult.isThreat) {
      for (const threatType of threatIntelResult.threatTypes) {
        threats.push({
          type: this.mapThreatType(threatType),
          severity: threatIntelResult.confidence > 0.8 ? 'critical' : 'high',
          source: threatIntelResult.sources.join(', '),
          details: `Identified as ${threatType} by threat intelligence`,
        });
      }
      totalScore += Math.round(threatIntelResult.confidence * 50);
    }

    // Determine verdict
    const { verdict } = this.determineVerdict(totalScore, threats as UrlThreat[]);
    const scanTimeMs = performance.now() - startTime;

    const result: ClickScannerScanResult = {
      urlId: this.generateUrlHash(url),
      originalUrl: url,
      finalUrl,
      verdict: verdict === 'blocked' ? 'malicious' : verdict,
      confidence: Math.min(100, totalScore) / 100,
      scanTimeMs,
      redirectChain,
      threats,
      cachedResult: false,
      scannedAt: new Date(),
    };

    // Cache the result
    this.setCache(`scan:${url.toLowerCase()}`, {
      clickId: result.urlId,
      originalUrl: url,
      finalUrl,
      redirectChain,
      scanTimeMs,
      verdict: result.verdict as ClickScanResult['verdict'],
      threats: threats as UrlThreat[],
      reputation: {
        score: 100 - totalScore,
        sources: reputationResult.sources,
      },
      shouldWarn: verdict === 'suspicious',
      shouldBlock: verdict === 'blocked' || verdict === 'malicious',
    });

    return result;
  }

  /**
   * Check cache for existing scan result
   */
  async getCachedScan(url: string): Promise<ClickScannerScanResult | null> {
    const cacheKey = `scan:${url.toLowerCase()}`;
    const cached = this.getFromCache(cacheKey);

    if (cached) {
      // Map ClickScanResult verdict to ClickScannerScanResult verdict
      const mappedVerdict = cached.verdict === 'blocked' ? 'malicious' : cached.verdict;
      return {
        urlId: cached.clickId,
        originalUrl: cached.originalUrl,
        finalUrl: cached.finalUrl,
        verdict: mappedVerdict as ClickScannerScanResult['verdict'],
        confidence: (100 - cached.reputation.score) / 100,
        scanTimeMs: cached.scanTimeMs,
        redirectChain: cached.redirectChain,
        threats: cached.threats as ThreatIndicator[],
        cachedResult: true,
        scannedAt: new Date(),
      };
    }

    // Check database cache
    try {
      const dbResult = await sql`
        SELECT
          original_url,
          final_url,
          redirect_chain,
          scan_time_ms,
          verdict,
          threats,
          reputation_score,
          reputation_sources,
          scanned_at
        FROM click_scans
        WHERE original_url = ${url}
          AND scanned_at > NOW() - INTERVAL '${this.config.cacheTtl / 1000} seconds'
        ORDER BY scanned_at DESC
        LIMIT 1
      `;

      if (dbResult.length > 0) {
        const row = dbResult[0];
        return {
          urlId: this.generateUrlHash(url),
          originalUrl: row.original_url,
          finalUrl: row.final_url,
          verdict: row.verdict,
          confidence: (100 - (row.reputation_score || 0)) / 100,
          scanTimeMs: row.scan_time_ms || 0,
          redirectChain: row.redirect_chain || [url],
          threats: row.threats || [],
          cachedResult: true,
          scannedAt: row.scanned_at,
        };
      }
    } catch (error) {
      console.error('[ClickScanner] Database cache check failed:', error);
    }

    return null;
  }

  /**
   * Follow redirects and get final URL with analysis
   */
  async resolveRedirects(url: string, maxRedirects?: number): Promise<RedirectResult> {
    const max = maxRedirects ?? this.config.maxRedirects;
    const chain = await this.getRedirectChainWithTimeout(url);
    const finalUrl = chain[chain.length - 1];

    // Analyze redirects
    const domains = chain.map((u) => this.extractDomain(u));
    const uniqueDomains = [...new Set(domains)];
    const crossDomainRedirects = uniqueDomains.length - 1;

    const suspiciousPatterns: string[] = [];

    // Check for suspicious patterns
    if (chain.length > 5) {
      suspiciousPatterns.push(`Excessive redirects: ${chain.length} hops`);
    }

    // Check for redirect loops or obfuscation
    const domainCounts = new Map<string, number>();
    for (const domain of domains) {
      domainCounts.set(domain, (domainCounts.get(domain) || 0) + 1);
    }
    for (const [domain, count] of domainCounts) {
      if (count > 2) {
        suspiciousPatterns.push(`Domain ${domain} appears ${count} times in redirect chain`);
      }
    }

    // Check for protocol downgrade
    const hasHttps = chain.some((u) => u.startsWith('https://'));
    const endsWithHttp = finalUrl.startsWith('http://');
    if (hasHttps && endsWithHttp) {
      suspiciousPatterns.push('HTTPS to HTTP downgrade detected');
    }

    // Check for common redirect abuse patterns
    for (const u of chain) {
      if (u.includes('redirect') || u.includes('redir') || u.includes('goto')) {
        suspiciousPatterns.push('Redirect keyword found in URL path');
        break;
      }
    }

    return {
      finalUrl,
      chain,
      totalRedirects: chain.length - 1,
      crossDomainRedirects,
      suspiciousPatterns,
    };
  }

  /**
   * Check URL against threat intelligence feeds
   */
  async checkThreatIntel(url: string): Promise<ThreatIntelResult> {
    const domain = this.extractDomain(url);
    const sources: string[] = [];
    const threatTypes: string[] = [];
    let totalConfidence = 0;
    let sourceCount = 0;

    try {
      // Import threat intel feeds dynamically
      const { checkUrlReputation: checkFeedReputation, checkDomainReputation } =
        await import('@/lib/threat-intel/feeds');

      // Check URL reputation from feeds
      const urlFeedResult = await checkFeedReputation(url);
      if (urlFeedResult.isThreat) {
        // Convert ThreatSource[] to string[] if needed
        const feedSources = (urlFeedResult.sources || ['internal']) as unknown as string[];
        sources.push(...feedSources);
        threatTypes.push(urlFeedResult.verdict);
        totalConfidence += 0.8;
        sourceCount++;
      }

      // Check domain reputation
      const domainFeedResult = await checkDomainReputation(domain);
      if (domainFeedResult.isThreat) {
        sources.push('domain_reputation');
        threatTypes.push(domainFeedResult.verdict);
        totalConfidence += 0.6;
        sourceCount++;
      }
    } catch (error) {
      console.error('[ClickScanner] Threat intel check failed:', error);
    }

    return {
      isThreat: threatTypes.length > 0,
      threatTypes: [...new Set(threatTypes)],
      sources: [...new Set(sources)],
      confidence: sourceCount > 0 ? totalConfidence / sourceCount : 0,
    };
  }

  /**
   * Check URL reputation (public wrapper)
   */
  async checkReputation(url: string): Promise<ReputationResult> {
    const result = await this.checkUrlReputation(url);
    return {
      score: 100 - result.riskScore,
      sources: result.sources,
      categories: result.categories,
    };
  }

  /**
   * Get most clicked URLs for a tenant
   */
  async getTopClickedUrls(tenantId: string, limit: number = 10): Promise<TopUrl[]> {
    try {
      const result = await sql`
        SELECT
          ru.id as url_id,
          ru.original_url,
          ru.click_count,
          ru.clicked_at as last_clicked_at,
          ru.click_verdict as verdict
        FROM rewritten_urls ru
        WHERE ru.tenant_id = ${tenantId}
          AND ru.click_count > 0
        ORDER BY ru.click_count DESC
        LIMIT ${limit}
      `;

      return result.map((row) => ({
        urlId: row.url_id,
        originalUrl: row.original_url,
        clickCount: row.click_count || 0,
        lastClickedAt: row.last_clicked_at || new Date(),
        verdict: row.verdict,
      }));
    } catch (error) {
      console.error('[ClickScanner] Failed to get top clicked URLs:', error);
      return [];
    }
  }

  /**
   * Get blocked click attempts for a tenant
   */
  async getBlockedClicks(tenantId: string, since?: Date): Promise<BlockedClick[]> {
    const sinceDate = since || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days default

    try {
      const result = await sql`
        SELECT
          ce.id,
          ce.url_id,
          ru.original_url,
          ce.user_email,
          ce.clicked_at,
          cs.threats,
          cs.verdict
        FROM click_events ce
        LEFT JOIN rewritten_urls ru ON ce.url_id = ru.id
        LEFT JOIN click_scans cs ON ce.url_id = cs.click_id
        WHERE ce.tenant_id = ${tenantId}
          AND ce.decision = 'block'
          AND ce.clicked_at >= ${sinceDate.toISOString()}
        ORDER BY ce.clicked_at DESC
      `;

      return result.map((row) => {
        const threats = row.threats || [];
        const firstThreat = threats[0];
        return {
          id: row.id,
          urlId: row.url_id,
          originalUrl: row.original_url || 'unknown',
          userEmail: row.user_email,
          clickedAt: row.clicked_at,
          reason: row.verdict || 'blocked',
          threatType: firstThreat?.type || 'unknown',
        };
      });
    } catch (error) {
      console.error('[ClickScanner] Failed to get blocked clicks:', error);
      return [];
    }
  }

  /**
   * Manual URL submission for scanning
   */
  async submitForScan(url: string, tenantId: string): Promise<ClickScannerScanResult> {
    // Force a fresh scan (bypass cache)
    const cacheKey = `scan:${url.toLowerCase()}`;
    this.cache.delete(cacheKey);

    const result = await this.scanUrl(url);

    // Store the submission for tracking
    try {
      await sql`
        INSERT INTO url_scan_submissions (
          tenant_id,
          url,
          verdict,
          confidence,
          scan_time_ms,
          threats,
          submitted_at
        ) VALUES (
          ${tenantId},
          ${url},
          ${result.verdict},
          ${result.confidence},
          ${Math.round(result.scanTimeMs)},
          ${JSON.stringify(result.threats)},
          NOW()
        )
      `;
    } catch (error) {
      // Table might not exist - that's okay, continue
      console.warn('[ClickScanner] Could not record scan submission:', error);
    }

    return result;
  }

  /**
   * Record click event for analytics
   */
  private async recordClickEvent(click: ClickEvent, scanResult: ClickScannerScanResult): Promise<void> {
    const decision = scanResult.verdict === 'malicious' ? 'block' :
                     scanResult.verdict === 'suspicious' ? 'warn' : 'allow';

    try {
      await sql`
        INSERT INTO click_events (
          url_id,
          tenant_id,
          user_email,
          clicked_at,
          user_agent,
          ip_address,
          decision,
          scan_time_ms,
          threat_detected
        ) VALUES (
          ${click.urlId},
          ${click.tenantId},
          ${click.userEmail || null},
          ${click.clickedAt.toISOString()},
          ${click.userAgent},
          ${click.ipAddress},
          ${decision},
          ${Math.round(scanResult.scanTimeMs)},
          ${scanResult.threats.length > 0}
        )
      `;
    } catch (error) {
      console.error('[ClickScanner] Failed to record click event:', error);
    }
  }

  /**
   * Determine action based on scan result
   */
  private determineAction(scanResult: ClickScannerScanResult): {
    action: 'allow' | 'warn' | 'block';
    reason: string;
    warningMessage?: string;
    blockMessage?: string;
  } {
    if (scanResult.verdict === 'malicious') {
      return {
        action: 'block',
        reason: 'URL identified as malicious',
        blockMessage: 'This link has been blocked because it was identified as dangerous. ' +
                      'Please contact your IT security team if you believe this is an error.',
      };
    }

    if (scanResult.verdict === 'suspicious') {
      const threatSummary = scanResult.threats
        .slice(0, 3)
        .map((t) => t.type.replace('_', ' '))
        .join(', ');

      return {
        action: 'warn',
        reason: `Suspicious indicators detected: ${threatSummary}`,
        warningMessage: 'This link shows signs of being potentially unsafe. ' +
                       'Proceed with caution and verify the sender before clicking.',
      };
    }

    if (scanResult.verdict === 'timeout' || scanResult.verdict === 'error') {
      return {
        action: 'warn',
        reason: 'Unable to fully verify link safety',
        warningMessage: 'We were unable to complete our security check. ' +
                       'Exercise caution when proceeding.',
      };
    }

    return {
      action: 'allow',
      reason: 'URL appears safe',
    };
  }

  /**
   * Map threat type string to ThreatIndicator type
   */
  private mapThreatType(type: string): ThreatIndicator['type'] {
    const lower = type.toLowerCase();
    if (lower.includes('phish')) return 'phishing';
    if (lower.includes('malware')) return 'malware';
    if (lower.includes('scam')) return 'scam';
    if (lower.includes('redirect')) return 'suspicious_redirect';
    if (lower.includes('new') || lower.includes('register')) return 'newly_registered';
    return 'bad_reputation';
  }

  /**
   * Generate a hash for URL identification
   */
  private generateUrlHash(url: string): string {
    // Simple hash for URL identification
    let hash = 0;
    for (let i = 0; i < url.length; i++) {
      const char = url.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
  }

  // =============================================================================
  // Private Helper Methods
  // =============================================================================

  /**
   * Determine verdict based on score and threats
   */
  private determineVerdict(score: number, threats: UrlThreat[]): {
    verdict: ClickScanResult['verdict'];
    shouldWarn: boolean;
    shouldBlock: boolean;
  } {
    const hasCritical = threats.some((t) => t.severity === 'critical');
    const hasHigh = threats.some((t) => t.severity === 'high');

    if (score >= this.config.blockThreshold || hasCritical) {
      return { verdict: 'blocked', shouldWarn: true, shouldBlock: true };
    }

    if (score >= this.config.blockThreshold - 10 && hasHigh) {
      return { verdict: 'malicious', shouldWarn: true, shouldBlock: true };
    }

    if (score >= this.config.warnThreshold || hasHigh) {
      return { verdict: 'suspicious', shouldWarn: true, shouldBlock: false };
    }

    if (score > 0) {
      return { verdict: 'suspicious', shouldWarn: false, shouldBlock: false };
    }

    return { verdict: 'safe', shouldWarn: false, shouldBlock: false };
  }

  /**
   * Extract domain from URL
   */
  private extractDomain(url: string): string {
    try {
      const parsed = new URL(url);
      return parsed.hostname.toLowerCase();
    } catch {
      return url;
    }
  }

  /**
   * Escape HTML special characters
   */
  private escapeHtml(text: string): string {
    const map: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;',
    };
    return text.replace(/[&<>"']/g, (m) => map[m] || m);
  }

  /**
   * Get click mapping by ID
   */
  private async getClickMappingById(clickId: string): Promise<{
    originalUrl: string;
    tenantId: string;
    emailId: string;
  } | null> {
    try {
      const result = await sql`
        SELECT original_url, tenant_id, email_id
        FROM click_mappings
        WHERE id = ${clickId}
        LIMIT 1
      `;

      if (result.length === 0) {
        return null;
      }

      return {
        originalUrl: result[0].original_url,
        tenantId: result[0].tenant_id,
        emailId: result[0].email_id,
      };
    } catch (error) {
      console.error('[ClickScanner] Failed to get click mapping:', error);
      return null;
    }
  }

  /**
   * Get from cache
   */
  private getFromCache(key: string): ClickScanResult | null {
    if (!this.config.cacheEnabled) return null;

    const entry = this.cache.get(key);
    if (!entry) return null;

    if (Date.now() - entry.timestamp > this.config.cacheTtl) {
      this.cache.delete(key);
      return null;
    }

    return entry.result;
  }

  /**
   * Set cache entry
   */
  private setCache(key: string, result: ClickScanResult): void {
    if (!this.config.cacheEnabled) return;

    // Limit cache size
    if (this.cache.size > 10000) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) {
        this.cache.delete(oldestKey);
      }
    }

    this.cache.set(key, {
      result,
      timestamp: Date.now(),
    });
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.cache.clear();
  }
}

// =============================================================================
// Singleton Instance
// =============================================================================

let clickScannerInstance: ClickScanner | null = null;

/**
 * Get or create Click Scanner instance
 */
export function getClickScanner(config?: Partial<ClickScannerConfig>): ClickScanner {
  if (!clickScannerInstance || config) {
    clickScannerInstance = new ClickScanner(config);
  }
  return clickScannerInstance;
}

/**
 * Convenience function to scan URL at click time
 */
export async function scanUrlAtClickTime(clickId: string): Promise<ClickScanResult> {
  const scanner = getClickScanner();
  return scanner.scanAtClickTime(clickId);
}

/**
 * Convenience function to generate warning page
 */
export function generateClickWarningPage(scanResult: ClickScanResult): string {
  const scanner = getClickScanner();
  return scanner.generateWarningPage(scanResult);
}

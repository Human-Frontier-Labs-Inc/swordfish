/**
 * Click Scanner Tests
 *
 * Tests for the Click Scanner module which provides real-time URL scanning
 * when users click rewritten links.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  ClickScanner,
  getClickScanner,
  scanUrlAtClickTime,
  type ClickScanResult,
  type ClickEvent,
  type ClickScannerScanResult,
  type ClickDecision,
  type ThreatIndicator,
} from '@/lib/protection/click-scanner';

// Mock the database
vi.mock('@/lib/db', () => ({
  sql: vi.fn().mockImplementation(() => Promise.resolve([])),
}));

// Mock threat intel services
vi.mock('@/lib/threat-intel/virustotal', () => ({
  VirusTotalClient: vi.fn().mockImplementation(() => ({
    scanUrl: vi.fn().mockResolvedValue({
      status: 'completed',
      stats: { malicious: 0, suspicious: 0, harmless: 80, undetected: 10 },
      threatScore: 0,
      isMalicious: false,
      categories: [],
    }),
    getConfig: vi.fn().mockReturnValue({ apiKey: 'test', baseUrl: 'https://test.com' }),
    getRateLimitStatus: vi.fn().mockReturnValue({ remaining: 100, limit: 500 }),
  })),
  AnalysisStatus: {
    QUEUED: 'queued',
    IN_PROGRESS: 'in_progress',
    COMPLETED: 'completed',
    ERROR: 'error',
  },
}));

vi.mock('@/lib/threat-intel/urlscan', () => ({
  UrlScanClient: vi.fn().mockImplementation(() => ({
    scanUrl: vi.fn().mockResolvedValue({
      uuid: 'test-uuid',
      status: 'completed',
      page: { url: 'https://example.com', domain: 'example.com' },
      verdict: { malicious: false, score: 0, categories: [] },
      indicators: { suspiciousUrls: [], suspiciousIps: [], suspiciousDomains: [], phishingPatterns: [] },
      screenshotUrl: 'https://urlscan.io/screenshots/test.png',
    }),
    getConfig: vi.fn().mockReturnValue({ baseUrl: 'https://test.com', visibility: 'public' }),
  })),
  ScanStatus: {
    PENDING: 'pending',
    COMPLETED: 'completed',
    ERROR: 'error',
  },
}));

vi.mock('@/lib/threat-intel/domain/age', () => ({
  checkDomainAge: vi.fn().mockResolvedValue({
    domain: 'example.com',
    ageInDays: 365,
    riskScore: 0,
    riskLevel: 'low',
  }),
}));

vi.mock('@/lib/threat-intel/feeds', () => ({
  checkUrlReputation: vi.fn().mockResolvedValue({
    url: 'https://example.com',
    isThreat: false,
    verdict: 'clean',
    sources: [],
  }),
  checkDomainReputation: vi.fn().mockResolvedValue({
    domain: 'example.com',
    isThreat: false,
    verdict: 'clean',
  }),
}));

describe('ClickScanner', () => {
  let scanner: ClickScanner;

  beforeEach(() => {
    scanner = new ClickScanner({
      virusTotalApiKey: 'test-vt-key',
      urlScanApiKey: 'test-urlscan-key',
      cacheTtl: 300000,
      maxRedirects: 10,
      redirectTimeout: 5000,
    });
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('URL Scanning', () => {
    it('should scan a safe URL and return safe verdict', async () => {
      const result = await scanner.scanUrl('https://google.com');

      expect(result).toBeDefined();
      expect(result.originalUrl).toBe('https://google.com');
      expect(result.verdict).toBe('safe');
      expect(result.threats).toHaveLength(0);
      expect(result.scanTimeMs).toBeGreaterThanOrEqual(0);
    });

    it('should cache scan results', async () => {
      // First scan
      const result1 = await scanner.scanUrl('https://example.com');
      expect(result1.cachedResult).toBe(false);

      // Second scan should be cached
      const result2 = await scanner.getCachedScan('https://example.com');
      expect(result2).not.toBeNull();
      expect(result2?.cachedResult).toBe(true);
    });

    it('should resolve redirects', async () => {
      const result = await scanner.resolveRedirects('https://example.com');

      expect(result).toBeDefined();
      expect(result.finalUrl).toBeDefined();
      expect(result.chain).toBeInstanceOf(Array);
      expect(result.totalRedirects).toBeGreaterThanOrEqual(0);
    });

    it('should detect suspicious redirect patterns', async () => {
      const result = await scanner.resolveRedirects('https://bit.ly/redirect/test');

      expect(result.suspiciousPatterns).toBeInstanceOf(Array);
    });
  });

  describe('Threat Intelligence', () => {
    it('should check threat intel feeds', async () => {
      const result = await scanner.checkThreatIntel('https://example.com');

      expect(result).toBeDefined();
      expect(typeof result.isThreat).toBe('boolean');
      expect(result.threatTypes).toBeInstanceOf(Array);
      expect(result.sources).toBeInstanceOf(Array);
      expect(typeof result.confidence).toBe('number');
    });

    it('should check URL reputation', async () => {
      const result = await scanner.checkReputation('https://example.com');

      expect(result).toBeDefined();
      expect(typeof result.score).toBe('number');
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
    });
  });

  describe('Click Processing', () => {
    beforeEach(() => {
      // Mock the getClickMappingById method
      vi.spyOn(scanner as any, 'getClickMappingById').mockResolvedValue({
        id: 'test-click-id',
        originalUrl: 'https://example.com',
        tenantId: 'tenant-123',
        emailId: 'email-456',
      });
    });

    it('should process a click event', async () => {
      const clickEvent: ClickEvent = {
        urlId: 'test-click-id',
        tenantId: 'tenant-123',
        userEmail: 'user@example.com',
        clickedAt: new Date(),
        userAgent: 'Mozilla/5.0',
        ipAddress: '192.168.1.1',
      };

      const decision = await scanner.processClick(clickEvent);

      expect(decision).toBeDefined();
      expect(decision.action).toMatch(/allow|warn|block/);
      expect(decision.reason).toBeDefined();
      expect(decision.originalUrl).toBe('https://example.com');
      expect(decision.scanResult).toBeDefined();
    });

    it('should return allow action for safe URLs', async () => {
      const clickEvent: ClickEvent = {
        urlId: 'test-click-id',
        tenantId: 'tenant-123',
        clickedAt: new Date(),
        userAgent: 'Mozilla/5.0',
        ipAddress: '192.168.1.1',
      };

      const decision = await scanner.processClick(clickEvent);

      expect(decision.action).toBe('allow');
    });
  });

  describe('Analytics', () => {
    it('should get click analytics', async () => {
      const analytics = await scanner.getClickAnalytics('tenant-123');

      expect(analytics).toBeDefined();
      expect(typeof analytics.totalClicks).toBe('number');
      expect(typeof analytics.blockedClicks).toBe('number');
      expect(typeof analytics.warnedClicks).toBe('number');
      expect(analytics.clicksByHour).toHaveLength(24);
      expect(Array.isArray(analytics.clicksByDay)).toBe(true);
      expect(Array.isArray(analytics.topThreatTypes)).toBe(true);
      expect(typeof analytics.averageScanTimeMs).toBe('number');
    });

    it('should get top clicked URLs', async () => {
      const topUrls = await scanner.getTopClickedUrls('tenant-123', 5);

      expect(topUrls).toBeInstanceOf(Array);
    });

    it('should get blocked clicks', async () => {
      const blockedClicks = await scanner.getBlockedClicks('tenant-123');

      expect(blockedClicks).toBeInstanceOf(Array);
    });
  });

  describe('Manual URL Submission', () => {
    it('should submit URL for scanning', async () => {
      const result = await scanner.submitForScan('https://suspicious.com', 'tenant-123');

      expect(result).toBeDefined();
      expect(result.originalUrl).toBe('https://suspicious.com');
      expect(result.verdict).toBeDefined();
    });

    it('should bypass cache for manual submissions', async () => {
      // First, get a cached result
      await scanner.scanUrl('https://example.com');

      // Submit for fresh scan
      const result = await scanner.submitForScan('https://example.com', 'tenant-123');

      // Should be a fresh scan, not cached
      expect(result.cachedResult).toBe(false);
    });
  });
});

describe('getClickScanner', () => {
  it('should return singleton instance', () => {
    const scanner1 = getClickScanner();
    const scanner2 = getClickScanner();

    expect(scanner1).toBe(scanner2);
  });
});

describe('scanUrlAtClickTime', () => {
  it('should throw error for invalid click ID', async () => {
    await expect(scanUrlAtClickTime('test-id')).rejects.toThrow('Click mapping not found');
  });
});

describe('ThreatIndicator Types', () => {
  it('should have correct threat types', () => {
    const threatTypes: ThreatIndicator['type'][] = [
      'phishing',
      'malware',
      'scam',
      'suspicious_redirect',
      'newly_registered',
      'bad_reputation',
    ];

    expect(threatTypes).toHaveLength(6);
  });

  it('should have correct severity levels', () => {
    const severityLevels: ThreatIndicator['severity'][] = [
      'critical',
      'high',
      'medium',
      'low',
    ];

    expect(severityLevels).toHaveLength(4);
  });
});

describe('ClickScannerScanResult Types', () => {
  it('should have correct verdict types', () => {
    const verdictTypes: ClickScannerScanResult['verdict'][] = [
      'safe',
      'suspicious',
      'malicious',
      'timeout',
      'error',
    ];

    expect(verdictTypes).toHaveLength(5);
  });
});

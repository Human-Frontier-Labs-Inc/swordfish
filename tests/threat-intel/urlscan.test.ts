/**
 * URLScan Integration Tests
 * TDD: RED phase - Write failing tests first
 *
 * Tests for URLScan.io API integration for URL analysis and screenshot capture
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  UrlScanClient,
  UrlScanConfig,
  ScanSubmitResult,
  ScanResult,
  ScanStatus,
  Verdict,
  PageInfo,
  ThreatIndicator,
} from '../../lib/threat-intel/urlscan';

console.log('Test suite starting...');

describe('URLScan Integration', () => {
  let client: UrlScanClient;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockFetch = vi.fn();
    global.fetch = mockFetch;

    client = new UrlScanClient({
      apiKey: 'test-api-key',
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('Configuration', () => {
    it('should accept API key configuration', () => {
      const config: UrlScanConfig = {
        apiKey: 'my-api-key',
        baseUrl: 'https://urlscan.io/api/v1',
        visibility: 'public',
      };

      const scanClient = new UrlScanClient(config);
      expect(scanClient.getConfig().baseUrl).toBe('https://urlscan.io/api/v1');
    });

    it('should use default base URL if not provided', () => {
      const scanClient = new UrlScanClient({ apiKey: 'test-key' });
      expect(scanClient.getConfig().baseUrl).toBe('https://urlscan.io/api/v1');
    });

    it('should support visibility settings', () => {
      const privateClient = new UrlScanClient({
        apiKey: 'test-key',
        visibility: 'private',
      });
      expect(privateClient.getConfig().visibility).toBe('private');
    });
  });

  describe('URL Submission', () => {
    it('should submit URL for scanning', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          message: 'Submission successful',
          uuid: 'scan-uuid-123',
          result: 'https://urlscan.io/result/scan-uuid-123/',
          api: 'https://urlscan.io/api/v1/result/scan-uuid-123/',
          visibility: 'public',
          url: 'https://example.com',
        }),
      });

      const result = await client.submitScan('https://example.com');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/scan'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'API-Key': 'test-api-key',
          }),
        })
      );
      expect(result.uuid).toBe('scan-uuid-123');
      expect(result.resultUrl).toContain('urlscan.io/result');
    });

    it('should submit with custom visibility', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          uuid: 'scan-uuid-123',
          visibility: 'private',
        }),
      });

      await client.submitScan('https://example.com', { visibility: 'private' });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining('"visibility":"private"'),
        })
      );
    });

    it('should submit with custom tags', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          uuid: 'scan-uuid-123',
        }),
      });

      await client.submitScan('https://example.com', {
        tags: ['phishing', 'investigation'],
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining('"tags":["phishing","investigation"]'),
        })
      );
    });
  });

  describe('Scan Results', () => {
    it('should retrieve scan results by UUID', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          task: {
            uuid: 'scan-uuid-123',
            time: '2024-01-15T10:00:00.000Z',
            url: 'https://example.com',
            visibility: 'public',
          },
          page: {
            url: 'https://example.com',
            domain: 'example.com',
            ip: '93.184.216.34',
            country: 'US',
            server: 'ECS (dcb/7EC9)',
            status: '200',
          },
          stats: {
            resourceStats: [{ type: 'Script', count: 5 }],
            protocolStats: [{ protocol: 'HTTPS', count: 10 }],
            ipStats: [{ ip: '93.184.216.34', requests: 5 }],
          },
          verdicts: {
            overall: {
              score: 0,
              categories: [],
              malicious: false,
            },
            engines: {
              score: 0,
              malicious: [],
              benign: ['google-safebrowsing'],
            },
          },
        }),
      });

      const result = await client.getResult('scan-uuid-123');

      expect(result.status).toBe(ScanStatus.COMPLETED);
      expect(result.page.domain).toBe('example.com');
      expect(result.verdict.malicious).toBe(false);
    });

    it('should handle pending scan results', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: () => Promise.resolve({
          message: 'Scan not found',
          status: 404,
        }),
      });

      const result = await client.getResult('pending-uuid');

      expect(result.status).toBe(ScanStatus.PENDING);
    });

    it('should extract page information', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          task: { uuid: 'scan-123' },
          page: {
            url: 'https://secure-login.phishing.com/login',
            domain: 'secure-login.phishing.com',
            ip: '192.168.1.1',
            country: 'RU',
            server: 'nginx',
            status: '200',
            title: 'Bank Login - Secure Access',
            mimeType: 'text/html',
          },
          verdicts: { overall: { malicious: true } },
        }),
      });

      const result = await client.getResult('scan-123');

      expect(result.page.url).toBe('https://secure-login.phishing.com/login');
      expect(result.page.country).toBe('RU');
      expect(result.page.title).toBe('Bank Login - Secure Access');
    });
  });

  describe('Scan URL (Submit and Wait)', () => {
    it('should submit and poll for results', async () => {
      // Submit response
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          uuid: 'scan-uuid-123',
        }),
      });

      // First poll - pending
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      // Second poll - completed
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          task: { uuid: 'scan-uuid-123' },
          page: { url: 'https://test.com', domain: 'test.com' },
          verdicts: { overall: { malicious: false, score: 0 } },
        }),
      });

      const scanPromise = client.scanUrl('https://test.com', { maxPolls: 5, pollInterval: 1000 });

      // Advance time for polling
      await vi.advanceTimersByTimeAsync(1000);
      await vi.advanceTimersByTimeAsync(1000);

      const result = await scanPromise;

      expect(result.status).toBe(ScanStatus.COMPLETED);
    });

    it('should timeout after max polls', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ uuid: 'scan-uuid-123' }),
      });

      // All polls return pending
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
      });

      const scanPromise = client.scanUrl('https://test.com', { maxPolls: 3, pollInterval: 500 });

      await vi.advanceTimersByTimeAsync(2000);

      const result = await scanPromise;

      expect(result.status).toBe(ScanStatus.PENDING);
    });
  });

  describe('Verdict Analysis', () => {
    it('should detect malicious verdict', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          task: { uuid: 'scan-123' },
          page: { url: 'https://phishing.com', domain: 'phishing.com' },
          verdicts: {
            overall: {
              score: 100,
              categories: ['phishing'],
              malicious: true,
            },
            engines: {
              score: 100,
              malicious: ['google-safebrowsing', 'phishtank'],
              benign: [],
            },
          },
        }),
      });

      const result = await client.getResult('scan-123');

      expect(result.verdict.malicious).toBe(true);
      expect(result.verdict.score).toBe(100);
      expect(result.verdict.categories).toContain('phishing');
    });

    it('should list malicious engine detections', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          task: { uuid: 'scan-123' },
          page: { domain: 'malware.com' },
          verdicts: {
            overall: { malicious: true, score: 80 },
            engines: {
              malicious: ['google-safebrowsing', 'phishtank', 'urlhaus'],
              benign: ['other-engine'],
            },
          },
        }),
      });

      const result = await client.getResult('scan-123');

      expect(result.verdict.maliciousEngines).toContain('google-safebrowsing');
      expect(result.verdict.maliciousEngines).toContain('phishtank');
      expect(result.verdict.maliciousEngines).toHaveLength(3);
    });
  });

  describe('Screenshot Access', () => {
    it('should return screenshot URL', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          task: { uuid: 'scan-123', screenshotURL: 'https://urlscan.io/screenshots/scan-123.png' },
          page: { domain: 'example.com' },
          verdicts: { overall: { malicious: false } },
        }),
      });

      const result = await client.getResult('scan-123');

      expect(result.screenshotUrl).toBe('https://urlscan.io/screenshots/scan-123.png');
    });

    it('should construct screenshot URL from UUID if not provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          task: { uuid: 'scan-123' },
          page: { domain: 'example.com' },
          verdicts: { overall: { malicious: false } },
        }),
      });

      const result = await client.getResult('scan-123');

      expect(result.screenshotUrl).toContain('scan-123');
    });
  });

  describe('Threat Indicators', () => {
    it('should extract suspicious indicators', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          task: { uuid: 'scan-123' },
          page: {
            domain: 'fake-bank-login.com',
            title: 'Wells Fargo - Login',
          },
          lists: {
            urls: ['https://fake-bank-login.com/steal-creds.php'],
            ips: ['192.168.1.1'],
            domains: ['fake-bank-login.com'],
          },
          verdicts: {
            overall: { malicious: true, score: 95 },
          },
        }),
      });

      const result = await client.getResult('scan-123');

      expect(result.indicators.suspiciousUrls.length).toBeGreaterThan(0);
    });

    it('should detect phishing patterns', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          task: { uuid: 'scan-123' },
          page: {
            domain: 'paypa1-secure.com',
            title: 'PayPal - Log in',
          },
          verdicts: {
            overall: {
              malicious: true,
              categories: ['phishing'],
            },
          },
        }),
      });

      const result = await client.getResult('scan-123');

      expect(result.indicators.phishingPatterns.length).toBeGreaterThan(0);
    });
  });

  describe('Rate Limiting', () => {
    it('should handle rate limit response', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          json: () => Promise.resolve({ message: 'Rate limit exceeded' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ uuid: 'scan-123' }),
        });

      const submitPromise = client.submitScan('https://test.com');

      await vi.advanceTimersByTimeAsync(60000);

      const result = await submitPromise;
      expect(result.uuid).toBe('scan-123');
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid API key', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: () => Promise.resolve({ message: 'Invalid API key' }),
      });

      await expect(client.submitScan('https://test.com'))
        .rejects.toThrow('Invalid API key');
    });

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      await expect(client.submitScan('https://test.com'))
        .rejects.toThrow('Network error');
    });

    it('should handle invalid URL submission', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ message: 'Invalid URL' }),
      });

      await expect(client.submitScan('not-a-url'))
        .rejects.toThrow('Invalid URL');
    });
  });

  describe('Search', () => {
    it('should search for existing scans', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          results: [
            {
              task: { uuid: 'scan-1', url: 'https://example.com' },
              page: { domain: 'example.com' },
            },
            {
              task: { uuid: 'scan-2', url: 'https://example.com/page' },
              page: { domain: 'example.com' },
            },
          ],
          total: 2,
        }),
      });

      const results = await client.search('domain:example.com');

      expect(results.results).toHaveLength(2);
      expect(results.total).toBe(2);
    });

    it('should search by domain', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          results: [{ task: { uuid: 'scan-1' } }],
          total: 1,
        }),
      });

      await client.searchByDomain('example.com');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('domain%3Aexample.com'),
        expect.any(Object)
      );
    });
  });

  describe('Caching', () => {
    it('should cache scan results', async () => {
      const cachingClient = new UrlScanClient({
        apiKey: 'test-key',
        cacheEnabled: true,
        cacheTtl: 3600000,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          task: { uuid: 'scan-123' },
          page: { domain: 'test.com' },
          verdicts: { overall: { malicious: false } },
        }),
      });

      await cachingClient.getResult('scan-123');
      const result2 = await cachingClient.getResult('scan-123');

      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(result2.fromCache).toBe(true);
    });
  });
});

console.log('Test suite complete.');

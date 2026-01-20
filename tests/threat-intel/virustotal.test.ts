/**
 * VirusTotal Integration Tests
 * TDD: RED phase - Write failing tests first
 *
 * Tests for VirusTotal API integration for URL/file analysis
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  VirusTotalClient,
  VirusTotalConfig,
  UrlScanResult,
  FileScanResult,
  AnalysisStatus,
  ThreatCategory,
} from '../../lib/threat-intel/virustotal';

console.log('Test suite starting...');

describe('VirusTotal Integration', () => {
  let client: VirusTotalClient;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    mockFetch = vi.fn();
    global.fetch = mockFetch;

    client = new VirusTotalClient({
      apiKey: 'test-api-key',
      baseUrl: 'https://www.virustotal.com/api/v3',
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('Configuration', () => {
    it('should accept API key configuration', () => {
      const config: VirusTotalConfig = {
        apiKey: 'my-api-key',
        baseUrl: 'https://www.virustotal.com/api/v3',
        timeout: 30000,
      };

      const vtClient = new VirusTotalClient(config);
      expect(vtClient.getConfig().baseUrl).toBe('https://www.virustotal.com/api/v3');
    });

    it('should use default base URL if not provided', () => {
      const vtClient = new VirusTotalClient({ apiKey: 'test-key' });
      expect(vtClient.getConfig().baseUrl).toBe('https://www.virustotal.com/api/v3');
    });

    it('should mask API key in config output', () => {
      const vtClient = new VirusTotalClient({ apiKey: 'secret-key-12345' });
      const config = vtClient.getConfig();
      expect(config.apiKey).not.toBe('secret-key-12345');
      expect(config.apiKey).toContain('***');
    });
  });

  describe('URL Scanning', () => {
    it('should submit URL for analysis', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            type: 'analysis',
            id: 'analysis-123',
          },
        }),
      });

      const result = await client.submitUrl('https://malicious-site.com');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/urls'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'x-apikey': 'test-api-key',
          }),
        })
      );
      expect(result.analysisId).toBe('analysis-123');
    });

    it('should get URL analysis results', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            attributes: {
              status: 'completed',
              stats: {
                malicious: 5,
                suspicious: 2,
                harmless: 50,
                undetected: 10,
              },
              results: {
                'engine-1': { category: 'malicious', result: 'phishing' },
                'engine-2': { category: 'harmless', result: 'clean' },
              },
            },
          },
        }),
      });

      const result = await client.getUrlAnalysis('analysis-123');

      expect(result.status).toBe(AnalysisStatus.COMPLETED);
      expect(result.stats.malicious).toBe(5);
      expect(result.stats.suspicious).toBe(2);
    });

    it('should scan URL and wait for results', async () => {
      // First call submits URL
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: { id: 'analysis-123' },
        }),
      });

      // Second call gets results
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            attributes: {
              status: 'completed',
              stats: { malicious: 3, suspicious: 1, harmless: 60, undetected: 5 },
              results: {},
            },
          },
        }),
      });

      const result = await client.scanUrl('https://suspicious-link.com');

      expect(result.status).toBe(AnalysisStatus.COMPLETED);
      expect(result.isMalicious).toBe(true);
    });

    it('should poll for results if analysis is queued', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { id: 'analysis-123' } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            data: { attributes: { status: 'queued' } },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            data: {
              attributes: {
                status: 'completed',
                stats: { malicious: 0, suspicious: 0, harmless: 65, undetected: 2 },
                results: {},
              },
            },
          }),
        });

      const scanPromise = client.scanUrl('https://test.com', { maxPolls: 3, pollInterval: 1000 });

      // Advance time for polling
      await vi.advanceTimersByTimeAsync(1000);
      await vi.advanceTimersByTimeAsync(1000);

      const result = await scanPromise;
      expect(result.status).toBe(AnalysisStatus.COMPLETED);
    });

    it('should calculate threat score from results', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { id: 'analysis-123' } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            data: {
              attributes: {
                status: 'completed',
                stats: { malicious: 10, suspicious: 5, harmless: 50, undetected: 5 },
                results: {},
              },
            },
          }),
        });

      const result = await client.scanUrl('https://bad-site.com');

      expect(result.threatScore).toBeGreaterThan(0);
      expect(result.threatScore).toBeLessThanOrEqual(100);
    });

    it('should extract threat categories from engine results', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { id: 'analysis-123' } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            data: {
              attributes: {
                status: 'completed',
                stats: { malicious: 3, suspicious: 0, harmless: 60, undetected: 5 },
                results: {
                  'engine-1': { category: 'malicious', result: 'phishing' },
                  'engine-2': { category: 'malicious', result: 'malware' },
                  'engine-3': { category: 'malicious', result: 'phishing' },
                },
              },
            },
          }),
        });

      const result = await client.scanUrl('https://phishing-site.com');

      expect(result.categories).toContain(ThreatCategory.PHISHING);
      expect(result.categories).toContain(ThreatCategory.MALWARE);
    });
  });

  describe('File Hash Lookup', () => {
    it('should lookup file by SHA256 hash', async () => {
      const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 0,
                suspicious: 0,
                harmless: 60,
                undetected: 10,
              },
              last_analysis_results: {},
              sha256: hash,
              type_description: 'PDF document',
            },
          },
        }),
      });

      const result = await client.getFileReport(hash);

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining(`/files/${hash}`),
        expect.any(Object)
      );
      expect(result.sha256).toBe(hash);
      expect(result.isMalicious).toBe(false);
    });

    it('should lookup file by MD5 hash', async () => {
      const md5 = 'd41d8cd98f00b204e9800998ecf8427e';

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            attributes: {
              last_analysis_stats: { malicious: 5, suspicious: 2, harmless: 50, undetected: 10 },
              last_analysis_results: {},
              md5,
            },
          },
        }),
      });

      const result = await client.getFileReport(md5);

      expect(result.stats.malicious).toBe(5);
      expect(result.isMalicious).toBe(true);
    });

    it('should return threat categories for malicious files', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            attributes: {
              last_analysis_stats: { malicious: 10, suspicious: 0, harmless: 50, undetected: 5 },
              last_analysis_results: {
                'engine-1': { category: 'malicious', result: 'Trojan.Generic' },
                'engine-2': { category: 'malicious', result: 'Ransomware.Locky' },
              },
              popular_threat_classification: {
                suggested_threat_label: 'trojan.generic/ransomware',
                popular_threat_category: [
                  { value: 'trojan', count: 8 },
                  { value: 'ransomware', count: 5 },
                ],
              },
            },
          },
        }),
      });

      const result = await client.getFileReport('abc123');

      expect(result.categories).toContain(ThreatCategory.TROJAN);
      expect(result.categories).toContain(ThreatCategory.RANSOMWARE);
    });

    it('should handle file not found', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: () => Promise.resolve({
          error: { code: 'NotFoundError' },
        }),
      });

      const result = await client.getFileReport('nonexistent-hash');

      expect(result.found).toBe(false);
      expect(result.isMalicious).toBe(false);
    });
  });

  describe('Rate Limiting', () => {
    it('should respect rate limits', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 429,
          headers: new Map([['x-ratelimit-reset', '60']]),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            data: { id: 'analysis-123' },
          }),
        });

      const submitPromise = client.submitUrl('https://test.com');

      // Advance past rate limit
      await vi.advanceTimersByTimeAsync(60000);

      const result = await submitPromise;
      expect(result.analysisId).toBe('analysis-123');
    });

    it('should track remaining quota', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Map([
          ['x-ratelimit-remaining', '100'],
          ['x-ratelimit-limit', '500'],
        ]),
        json: () => Promise.resolve({ data: { id: 'analysis-123' } }),
      });

      await client.submitUrl('https://test.com');

      const quota = client.getRateLimitStatus();
      expect(quota.remaining).toBe(100);
      expect(quota.limit).toBe(500);
    });

    it('should queue requests when near rate limit', async () => {
      const rateLimitedClient = new VirusTotalClient({
        apiKey: 'test-key',
        maxRequestsPerMinute: 4,
      });

      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ data: { id: 'analysis-123' } }),
      });

      // Make 5 requests
      const promises = Array(5).fill(null).map((_, i) =>
        rateLimitedClient.submitUrl(`https://test${i}.com`)
      );

      // First 4 should complete immediately
      await vi.advanceTimersByTimeAsync(100);
      expect(mockFetch).toHaveBeenCalledTimes(4);

      // 5th should wait for rate limit window
      await vi.advanceTimersByTimeAsync(60000);
      await Promise.all(promises);
      expect(mockFetch).toHaveBeenCalledTimes(5);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid API key', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: () => Promise.resolve({
          error: { code: 'AuthenticationRequiredError' },
        }),
      });

      await expect(client.submitUrl('https://test.com'))
        .rejects.toThrow('Invalid API key');
    });

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      await expect(client.submitUrl('https://test.com'))
        .rejects.toThrow('Network error');
    });

    it('should handle malformed response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ invalid: 'response' }),
      });

      await expect(client.submitUrl('https://test.com'))
        .rejects.toThrow('Invalid response format');
    });

    it('should handle timeout', async () => {
      // Use real timers for this test since AbortController needs them
      vi.useRealTimers();

      const slowFetch = vi.fn().mockImplementationOnce(() =>
        new Promise((resolve) => setTimeout(resolve, 500))
      );
      global.fetch = slowFetch;

      const timeoutClient = new VirusTotalClient({
        apiKey: 'test-key',
        timeout: 100, // 100ms timeout
      });

      await expect(timeoutClient.submitUrl('https://test.com')).rejects.toThrow();
    });
  });

  describe('Caching', () => {
    it('should cache URL scan results', async () => {
      const cachingClient = new VirusTotalClient({
        apiKey: 'test-key',
        cacheEnabled: true,
        cacheTtl: 3600000, // 1 hour
      });

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { id: 'analysis-123' } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            data: {
              attributes: {
                status: 'completed',
                stats: { malicious: 0, suspicious: 0, harmless: 60, undetected: 5 },
                results: {},
              },
            },
          }),
        });

      // First call
      await cachingClient.scanUrl('https://test.com');

      // Second call should use cache
      const result2 = await cachingClient.scanUrl('https://test.com');

      expect(mockFetch).toHaveBeenCalledTimes(2); // Not 4 (2 for each scan)
      expect(result2.fromCache).toBe(true);
    });

    it('should cache file hash lookups', async () => {
      const cachingClient = new VirusTotalClient({
        apiKey: 'test-key',
        cacheEnabled: true,
        cacheTtl: 3600000,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 60, undetected: 5 },
              last_analysis_results: {},
            },
          },
        }),
      });

      await cachingClient.getFileReport('abc123');
      const result2 = await cachingClient.getFileReport('abc123');

      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(result2.fromCache).toBe(true);
    });

    it('should invalidate cache after TTL', async () => {
      const cachingClient = new VirusTotalClient({
        apiKey: 'test-key',
        cacheEnabled: true,
        cacheTtl: 1000, // 1 second
      });

      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 60, undetected: 5 },
              last_analysis_results: {},
            },
          },
        }),
      });

      await cachingClient.getFileReport('abc123');

      // Advance past cache TTL
      await vi.advanceTimersByTimeAsync(2000);

      await cachingClient.getFileReport('abc123');

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('Bulk Operations', () => {
    it('should scan multiple URLs', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          data: {
            id: 'analysis-123',
            attributes: {
              status: 'completed',
              stats: { malicious: 0, suspicious: 0, harmless: 60, undetected: 5 },
              results: {},
            },
          },
        }),
      });

      const urls = [
        'https://site1.com',
        'https://site2.com',
        'https://site3.com',
      ];

      const results = await client.scanUrls(urls);

      expect(results).toHaveLength(3);
      expect(results.every(r => r.status === AnalysisStatus.COMPLETED)).toBe(true);
    });

    it('should lookup multiple file hashes', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 60, undetected: 5 },
              last_analysis_results: {},
            },
          },
        }),
      });

      const hashes = ['hash1', 'hash2', 'hash3'];
      const results = await client.getFileReports(hashes);

      expect(results).toHaveLength(3);
    });
  });
});

console.log('Test suite complete.');

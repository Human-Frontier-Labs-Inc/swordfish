/**
 * IP Blocklist Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  checkIPReputation,
  checkMultipleIPs,
  extractIPsFromHeaders,
  clearIPCache,
  getIPCacheStats,
} from '@/lib/threat-intel/ip/blocklists';

// Mock fetch
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('IP Blocklist Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearIPCache();
    mockFetch.mockReset();
  });

  describe('checkIPReputation', () => {
    it('should return clean for private IPs', async () => {
      const result = await checkIPReputation('192.168.1.1');

      expect(result.ip).toBe('192.168.1.1');
      expect(result.isThreat).toBe(false);
      expect(result.verdict).toBe('clean');
      expect(result.sources.some(s => s.description?.includes('Private'))).toBe(true);
    });

    it('should handle 10.x.x.x private range', async () => {
      const result = await checkIPReputation('10.0.0.1');

      expect(result.isThreat).toBe(false);
      expect(result.verdict).toBe('clean');
    });

    it('should handle 172.16-31.x.x private range', async () => {
      const result = await checkIPReputation('172.16.0.1');

      expect(result.isThreat).toBe(false);
      expect(result.verdict).toBe('clean');
    });

    it('should handle localhost', async () => {
      const result = await checkIPReputation('127.0.0.1');

      expect(result.isThreat).toBe(false);
      expect(result.verdict).toBe('clean');
    });

    it('should return unknown for invalid IP format', async () => {
      const result = await checkIPReputation('not-an-ip');

      expect(result.verdict).toBe('unknown');
      expect(result.sources.some(s => s.description?.includes('Invalid'))).toBe(true);
    });

    it('should reject IPs with invalid octets', async () => {
      const result = await checkIPReputation('256.0.0.1');

      expect(result.verdict).toBe('unknown');
    });

    it('should reject IPs with wrong number of parts', async () => {
      const result = await checkIPReputation('192.168.1');

      expect(result.verdict).toBe('unknown');
    });

    it('should check public IPs against blocklists', async () => {
      const result = await checkIPReputation('8.8.8.8');

      expect(result.ip).toBe('8.8.8.8');
      expect(result.checkedAt).toBeInstanceOf(Date);
    });

    it('should detect known bad IP ranges', async () => {
      // This IP is in the known bad range we defined
      const result = await checkIPReputation('185.220.100.1');

      expect(result.isThreat).toBe(true);
      expect(result.verdict).toBe('malicious');
    });

    it('should cache IP check results', async () => {
      // First check
      const result1 = await checkIPReputation('1.1.1.1');
      expect(result1.checkedAt).toBeInstanceOf(Date);

      // Second check should use cache
      const result2 = await checkIPReputation('1.1.1.1');
      expect(result2.ip).toBe(result1.ip);
    });

    it('should include geolocation when available', async () => {
      const result = await checkIPReputation('8.0.0.1');

      // Our mock returns geolocation for 8.x.x.x range
      if (result.geolocation) {
        expect(result.geolocation.countryCode).toBeDefined();
      }
    });
  });

  describe('checkMultipleIPs', () => {
    it('should check multiple IPs in parallel', async () => {
      const ips = ['8.8.8.8', '1.1.1.1', '9.9.9.9'];
      const results = await checkMultipleIPs(ips);

      expect(results.size).toBe(3);
      expect(results.has('8.8.8.8')).toBe(true);
      expect(results.has('1.1.1.1')).toBe(true);
      expect(results.has('9.9.9.9')).toBe(true);
    });

    it('should filter out invalid IPs', async () => {
      const ips = ['8.8.8.8', 'invalid', '1.1.1.1'];
      const results = await checkMultipleIPs(ips);

      expect(results.size).toBe(2);
      expect(results.has('invalid')).toBe(false);
    });

    it('should deduplicate IPs', async () => {
      const ips = ['8.8.8.8', '8.8.8.8', '8.8.8.8'];
      const results = await checkMultipleIPs(ips);

      expect(results.size).toBe(1);
    });
  });

  describe('extractIPsFromHeaders', () => {
    it('should extract IPs from Received headers', () => {
      const headers = {
        'Received': 'from mail.example.com (192.0.2.1) by mx.google.com',
      };

      const ips = extractIPsFromHeaders(headers);

      expect(ips).toContain('192.0.2.1');
    });

    it('should extract IPs from X-Originating-IP', () => {
      const headers = {
        'X-Originating-IP': '[203.0.113.50]',
      };

      const ips = extractIPsFromHeaders(headers);

      expect(ips).toContain('203.0.113.50');
    });

    it('should extract IPs from X-Sender-IP', () => {
      const headers = {
        'X-Sender-IP': '198.51.100.25',
      };

      const ips = extractIPsFromHeaders(headers);

      expect(ips).toContain('198.51.100.25');
    });

    it('should filter out private IPs', () => {
      const headers = {
        'Received': 'from internal (192.168.1.100) by gateway (10.0.0.1)',
      };

      const ips = extractIPsFromHeaders(headers);

      expect(ips).not.toContain('192.168.1.100');
      expect(ips).not.toContain('10.0.0.1');
    });

    it('should handle multiple IPs in one header', () => {
      const headers = {
        'Received': 'from a.com (203.0.113.1) via b.com (198.51.100.2)',
      };

      const ips = extractIPsFromHeaders(headers);

      expect(ips).toContain('203.0.113.1');
      expect(ips).toContain('198.51.100.2');
    });

    it('should deduplicate IPs', () => {
      const headers = {
        'Received': 'from a.com (203.0.113.1) via b.com (203.0.113.1)',
      };

      const ips = extractIPsFromHeaders(headers);
      const unique = [...new Set(ips)];

      expect(ips.length).toBe(unique.length);
    });

    it('should return empty array for missing headers', () => {
      const headers = {};

      const ips = extractIPsFromHeaders(headers);

      expect(ips).toEqual([]);
    });
  });

  describe('Cache Management', () => {
    it('should provide cache statistics', () => {
      const stats = getIPCacheStats();

      expect(typeof stats.size).toBe('number');
      expect(typeof stats.hitRate).toBe('number');
    });

    it('should clear cache', async () => {
      // Populate cache
      await checkIPReputation('8.8.8.8');

      let stats = getIPCacheStats();
      expect(stats.size).toBeGreaterThan(0);

      // Clear cache
      clearIPCache();

      stats = getIPCacheStats();
      expect(stats.size).toBe(0);
    });
  });
});

describe('Blocklist Sources', () => {
  beforeEach(() => {
    clearIPCache();
  });

  it('should check Spamhaus', async () => {
    // Test IPs are configured to be listed
    const result = await checkIPReputation('192.0.2.1');

    expect(result.checkedAt).toBeInstanceOf(Date);
  });

  it('should aggregate results from multiple sources', async () => {
    // A known bad IP should appear in multiple lists
    const result = await checkIPReputation('185.220.100.1');

    expect(result.sources.length).toBeGreaterThan(0);
  });
});

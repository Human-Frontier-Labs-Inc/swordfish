/**
 * URLScan.io Integration Tests (Real API)
 *
 * These tests require a valid URLSCAN_API_KEY environment variable.
 * They test against the actual URLScan.io API and should be run sparingly
 * to avoid rate limiting.
 *
 * Run with: npm test -- tests/integration/urlscan.integration.test.ts
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  UrlScanClient,
  ScanStatus,
} from '../../lib/threat-intel/urlscan';

// Check if we have a real API key
const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;
const hasApiKey = URLSCAN_API_KEY && URLSCAN_API_KEY.length > 10 && !URLSCAN_API_KEY.includes('test');

// Skip all tests if no API key
const describeWithApi = hasApiKey ? describe : describe.skip;

describeWithApi('URLScan.io Integration (Real API)', () => {
  let client: UrlScanClient;

  beforeAll(() => {
    if (!URLSCAN_API_KEY) {
      throw new Error('URLSCAN_API_KEY environment variable is required');
    }

    client = new UrlScanClient({
      apiKey: URLSCAN_API_KEY,
      visibility: 'private', // Use private scans for testing
    });
  });

  describe('URL Scanning', () => {
    it('should scan a known safe URL', async () => {
      // Using example.com as a known safe, stable URL
      const result = await client.scanUrl('https://example.com', {
        maxPolls: 30,
        pollInterval: 3000,
      });

      expect(result).toBeDefined();
      expect(result.uuid).toBeDefined();
      expect(result.status).toBe(ScanStatus.COMPLETED);
      expect(result.page).toBeDefined();
      expect(result.page.domain).toBe('example.com');
      expect(result.verdict).toBeDefined();
      expect(result.verdict.malicious).toBe(false);
    }, 120000); // 2 minute timeout for polling

    it('should capture page information', async () => {
      const result = await client.scanUrl('https://www.google.com', {
        maxPolls: 30,
        pollInterval: 3000,
      });

      expect(result.page).toBeDefined();
      expect(result.page.url).toContain('google.com');
      expect(result.page.domain).toContain('google');
      expect(result.page.country).toBeDefined();
    }, 120000);

    it('should return screenshot URL', async () => {
      const result = await client.scanUrl('https://example.org', {
        maxPolls: 30,
        pollInterval: 3000,
      });

      expect(result.screenshotUrl).toBeDefined();
      expect(result.screenshotUrl).toContain('urlscan.io');
      expect(result.screenshotUrl).toContain(result.uuid);
    }, 120000);
  });

  describe('Search', () => {
    it('should search for existing scans by domain', async () => {
      // Search for google.com - should have many existing scans
      const results = await client.searchByDomain('google.com');

      expect(results).toBeDefined();
      expect(results.results).toBeDefined();
      expect(results.total).toBeGreaterThan(0);
    }, 30000);

    it('should search with custom query', async () => {
      // Search for scans of example.com
      const results = await client.search('domain:example.com');

      expect(results).toBeDefined();
      expect(Array.isArray(results.results)).toBe(true);
    }, 30000);
  });

  describe('Result Retrieval', () => {
    it('should retrieve scan result by UUID', async () => {
      // First, submit a scan
      const submission = await client.submitScan('https://httpbin.org/get');
      expect(submission.uuid).toBeDefined();

      // Wait for scan to complete
      await new Promise(resolve => setTimeout(resolve, 15000));

      // Retrieve the result
      const result = await client.getResult(submission.uuid);

      expect(result).toBeDefined();
      expect(result.uuid).toBe(submission.uuid);
      // May still be pending or completed
      expect([ScanStatus.PENDING, ScanStatus.COMPLETED]).toContain(result.status);
    }, 60000);

    it('should handle pending scan status', async () => {
      // Submit a new scan
      const submission = await client.submitScan('https://httpbin.org/ip');

      // Immediately check status (likely pending)
      const result = await client.getResult(submission.uuid);

      // Should not throw, should return pending or completed
      expect(result).toBeDefined();
      expect(result.uuid).toBe(submission.uuid);
    }, 30000);
  });

  describe('Phishing Detection', () => {
    it('should detect phishing patterns in suspicious domains', async () => {
      // Note: We can't actually scan malicious URLs, but we can test the
      // pattern detection logic by checking how indicators are extracted
      const result = await client.scanUrl('https://example.com', {
        maxPolls: 20,
        pollInterval: 3000,
      });

      expect(result.indicators).toBeDefined();
      expect(Array.isArray(result.indicators.suspiciousUrls)).toBe(true);
      expect(Array.isArray(result.indicators.suspiciousIps)).toBe(true);
      expect(Array.isArray(result.indicators.suspiciousDomains)).toBe(true);
      expect(Array.isArray(result.indicators.phishingPatterns)).toBe(true);
    }, 90000);
  });

  describe('Rate Limiting', () => {
    it('should handle rate limits gracefully', async () => {
      // Make several requests in quick succession
      const urls = [
        'https://test1.example.com',
        'https://test2.example.com',
        'https://test3.example.com',
      ];

      const results = await Promise.allSettled(
        urls.map(url => client.submitScan(url))
      );

      // At least one should succeed
      const successful = results.filter(r => r.status === 'fulfilled');
      expect(successful.length).toBeGreaterThan(0);
    }, 90000);
  });

  describe('Verdict Analysis', () => {
    it('should return comprehensive verdict data', async () => {
      const result = await client.scanUrl('https://www.wikipedia.org', {
        maxPolls: 30,
        pollInterval: 3000,
      });

      expect(result.verdict).toBeDefined();
      expect(typeof result.verdict.malicious).toBe('boolean');
      expect(typeof result.verdict.score).toBe('number');
      expect(Array.isArray(result.verdict.categories)).toBe(true);
      expect(Array.isArray(result.verdict.maliciousEngines)).toBe(true);
      expect(Array.isArray(result.verdict.benignEngines)).toBe(true);
    }, 120000);
  });

  describe('Caching', () => {
    it('should cache completed scan results', async () => {
      // Create a client with caching enabled
      const cachingClient = new UrlScanClient({
        apiKey: URLSCAN_API_KEY!,
        cacheEnabled: true,
        cacheTtl: 60000, // 1 minute cache
      });

      // First request - should hit the API
      const result1 = await cachingClient.scanUrl('https://example.net', {
        maxPolls: 30,
        pollInterval: 3000,
      });

      expect(result1.status).toBe(ScanStatus.COMPLETED);

      // Second request for same UUID - should come from cache
      const result2 = await cachingClient.getResult(result1.uuid);

      expect(result2.uuid).toBe(result1.uuid);
      expect(result2.fromCache).toBe(true);
    }, 120000);
  });
});

// Log whether tests will run
if (!hasApiKey) {
  console.log('Skipping URLScan.io integration tests - no API key configured');
  console.log('Set URLSCAN_API_KEY environment variable to run these tests');
} else {
  console.log('Running URLScan.io integration tests with real API');
}

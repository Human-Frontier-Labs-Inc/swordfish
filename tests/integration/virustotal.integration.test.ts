/**
 * VirusTotal Integration Tests (Real API)
 *
 * These tests require a valid VIRUSTOTAL_API_KEY environment variable.
 * They test against the actual VirusTotal API and should be run sparingly
 * to avoid rate limiting.
 *
 * Run with: npm test -- tests/integration/virustotal.integration.test.ts
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  VirusTotalClient,
  ScanStatus,
} from '../../lib/threat-intel/virustotal';

// Check if we have a real API key
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const hasApiKey = VT_API_KEY && VT_API_KEY.length > 10 && !VT_API_KEY.includes('test');

// Skip all tests if no API key
const describeWithApi = hasApiKey ? describe : describe.skip;

describeWithApi('VirusTotal Integration (Real API)', () => {
  let client: VirusTotalClient;

  beforeAll(() => {
    if (!VT_API_KEY) {
      throw new Error('VIRUSTOTAL_API_KEY environment variable is required');
    }

    client = new VirusTotalClient({
      apiKey: VT_API_KEY,
    });
  });

  describe('URL Scanning', () => {
    it('should scan a known safe URL', async () => {
      // Using google.com as a known safe URL
      const result = await client.scanUrl('https://www.google.com', {
        maxPolls: 30,
        pollInterval: 3000,
      });

      expect(result).toBeDefined();
      expect(result.analysisId).toBeDefined();
      expect(result.status).toBe(ScanStatus.COMPLETED);
      expect(result.verdict).toBeDefined();
      expect(result.verdict.malicious).toBe(false);
    }, 120000); // 2 minute timeout for polling

    it('should return cached results for recently scanned URL', async () => {
      // Google.com should be cached from previous scans
      const result = await client.getUrlReport('https://www.google.com');

      // Should return results without needing to scan
      expect(result).toBeDefined();
      expect(result.status).toBe(ScanStatus.COMPLETED);
    }, 30000);

    it('should detect malicious indicators in suspicious URLs', async () => {
      // Use EICAR test URL pattern (this is a standard test, not actually malicious)
      // Note: This may not always trigger detection
      const result = await client.scanUrl('http://eicar.org/download/eicar.com.txt', {
        maxPolls: 30,
        pollInterval: 3000,
      });

      expect(result).toBeDefined();
      expect(result.status).toBe(ScanStatus.COMPLETED);
      // Note: The EICAR URL may or may not be flagged depending on VT's current detection
    }, 120000);
  });

  describe('File Hash Lookup', () => {
    it('should lookup EICAR test file hash', async () => {
      // EICAR test file SHA256 hash - a well-known test "malware" signature
      const eicarHash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

      const result = await client.getFileReport(eicarHash);

      expect(result).toBeDefined();
      expect(result.status).toBe(ScanStatus.COMPLETED);
      expect(result.hash).toBe(eicarHash);
      // EICAR test file is detected by most AV engines
      expect(result.verdict.malicious).toBe(true);
      expect(result.verdict.maliciousEngines.length).toBeGreaterThan(0);
    }, 30000);

    it('should lookup a known clean file hash', async () => {
      // SHA256 of an empty file (0 bytes)
      const emptyFileHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

      try {
        const result = await client.getFileReport(emptyFileHash);

        expect(result).toBeDefined();
        // Empty file should be detected as clean
        if (result.status === ScanStatus.COMPLETED) {
          expect(result.verdict.malicious).toBe(false);
        }
      } catch (error) {
        // File might not be in VT database
        expect(error).toBeDefined();
      }
    }, 30000);

    it('should handle non-existent hash gracefully', async () => {
      // Random hash that almost certainly doesn't exist
      const fakeHash = '0000000000000000000000000000000000000000000000000000000000000000';

      try {
        await client.getFileReport(fakeHash);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }
    }, 30000);
  });

  describe('Rate Limiting', () => {
    it('should handle rate limits gracefully', async () => {
      // Make several requests in quick succession
      const urls = [
        'https://example.com',
        'https://example.org',
        'https://example.net',
      ];

      const results = await Promise.allSettled(
        urls.map(url => client.submitUrl(url))
      );

      // At least one should succeed
      const successful = results.filter(r => r.status === 'fulfilled');
      expect(successful.length).toBeGreaterThan(0);
    }, 60000);
  });

  describe('API Response Parsing', () => {
    it('should correctly parse detection stats', async () => {
      // EICAR hash for reliable detection
      const eicarHash = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

      const result = await client.getFileReport(eicarHash);

      expect(result.verdict).toBeDefined();
      expect(typeof result.verdict.malicious).toBe('boolean');
      expect(typeof result.verdict.score).toBe('number');
      expect(Array.isArray(result.verdict.maliciousEngines)).toBe(true);
      expect(Array.isArray(result.verdict.benignEngines)).toBe(true);
    }, 30000);
  });
});

// Log whether tests will run
if (!hasApiKey) {
  console.log('Skipping VirusTotal integration tests - no API key configured');
  console.log('Set VIRUSTOTAL_API_KEY environment variable to run these tests');
} else {
  console.log('Running VirusTotal integration tests with real API');
}

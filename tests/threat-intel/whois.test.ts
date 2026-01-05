/**
 * WHOIS Lookup Tests
 * Separate file to avoid mock interference from domain-age tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  lookupWhois,
  clearWhoisCache,
  getWhoisCacheStats,
} from '@/lib/threat-intel/domain/whois';

describe('WHOIS Lookup', () => {
  beforeEach(() => {
    clearWhoisCache();
  });

  it('should cache WHOIS results', async () => {
    // First lookup
    const result1 = await lookupWhois('example.com');
    expect(result1.domain).toBe('example.com');

    // Second lookup should be cached
    const result2 = await lookupWhois('example.com');
    expect(result2.cached).toBe(true);
  });

  it('should provide cache statistics', () => {
    const stats = getWhoisCacheStats();

    expect(typeof stats.size).toBe('number');
    expect(stats.size).toBeGreaterThanOrEqual(0);
  });

  it('should return domain estimation for known domains', async () => {
    const result = await lookupWhois('google.com');

    expect(result.domain).toBe('google.com');
    expect(result.createdDate).toBeInstanceOf(Date);
  });

  it('should handle suspicious TLDs', async () => {
    const result = await lookupWhois('suspicious.xyz');

    expect(result.domain).toBe('suspicious.xyz');
    expect(result.registrar).toContain('Estimated');
  });

  it('should clear cache completely', () => {
    // Add some entries
    lookupWhois('test1.com');
    lookupWhois('test2.com');

    // Clear cache
    clearWhoisCache();

    const stats = getWhoisCacheStats();
    expect(stats.size).toBe(0);
  });
});

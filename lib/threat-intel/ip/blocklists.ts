/**
 * IP Blocklist Service
 * Checks IP addresses against multiple threat intelligence blocklists
 */

import type { IPCheckResult } from '../cache';

// Public IP blocklist sources
const BLOCKLIST_SOURCES = {
  // Spamhaus - Major spam/malware blocklist
  spamhaus: {
    name: 'Spamhaus',
    dnsbl: 'zen.spamhaus.org',
    categories: {
      '127.0.0.2': 'SBL (Spamhaus Block List)',
      '127.0.0.3': 'CSS (Spamhaus CSS)',
      '127.0.0.4': 'XBL (Exploits Block List)',
      '127.0.0.9': 'SBL (Spamhaus DROP)',
      '127.0.0.10': 'PBL (Policy Block List)',
      '127.0.0.11': 'PBL (Policy Block List)',
    },
  },
  // Barracuda - Email threat blocklist
  barracuda: {
    name: 'Barracuda',
    dnsbl: 'b.barracudacentral.org',
    categories: {
      '127.0.0.2': 'Listed in Barracuda',
    },
  },
  // SORBS - Spam and Open Relay Blocking System
  sorbs: {
    name: 'SORBS',
    dnsbl: 'dnsbl.sorbs.net',
    categories: {
      '127.0.0.2': 'HTTP Proxy',
      '127.0.0.3': 'SOCKS Proxy',
      '127.0.0.4': 'Misc Proxy',
      '127.0.0.5': 'SMTP Server',
      '127.0.0.6': 'Spam Source',
      '127.0.0.7': 'Web Server',
      '127.0.0.8': 'Block Zone',
      '127.0.0.9': 'Zombie/Hijacked',
      '127.0.0.10': 'Dynamic IP',
      '127.0.0.11': 'Bad Config',
      '127.0.0.12': 'No Mail Server',
    },
  },
  // SpamCop
  spamcop: {
    name: 'SpamCop',
    dnsbl: 'bl.spamcop.net',
    categories: {
      '127.0.0.2': 'Listed in SpamCop',
    },
  },
  // UCEPROTECT
  uceprotect: {
    name: 'UCEPROTECT',
    dnsbl: 'dnsbl-1.uceprotect.net',
    categories: {
      '127.0.0.2': 'Listed in UCEPROTECT Level 1',
    },
  },
};

// Cache for IP lookups
const ipCache = new Map<string, { result: IPCheckResult; expiresAt: number }>();
const CACHE_TTL = 2 * 60 * 60 * 1000; // 2 hours

// Known malicious IP ranges (sample - in production, fetch from threat feeds)
const KNOWN_BAD_RANGES = [
  // Example ranges - these would be updated from feeds
  { start: '185.220.100.0', end: '185.220.103.255', category: 'Tor Exit Nodes' },
  { start: '45.155.204.0', end: '45.155.207.255', category: 'Known Bulletproof Hosting' },
];

// Geolocation data for high-risk countries
const HIGH_RISK_COUNTRIES = new Set([
  'RU', 'CN', 'KP', 'IR', // Often sanctioned or high threat
  'NG', 'RO', 'UA', // High fraud rates
]);

/**
 * Check if IP is in a specific range
 */
function ipInRange(ip: string, start: string, end: string): boolean {
  const ipNum = ipToNumber(ip);
  const startNum = ipToNumber(start);
  const endNum = ipToNumber(end);
  return ipNum >= startNum && ipNum <= endNum;
}

/**
 * Convert IP to number for range comparison
 */
function ipToNumber(ip: string): number {
  const parts = ip.split('.').map(Number);
  return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

/**
 * Reverse IP for DNSBL lookup
 */
function reverseIP(ip: string): string {
  return ip.split('.').reverse().join('.');
}

/**
 * Check IP against DNSBL (DNS-based Blackhole List)
 * Note: In production, this would use actual DNS lookups
 */
async function checkDNSBL(
  ip: string,
  dnsbl: string,
  categories: Record<string, string>
): Promise<{ listed: boolean; category?: string }> {
  const reversedIP = reverseIP(ip);
  const query = `${reversedIP}.${dnsbl}`;

  try {
    // In production, perform actual DNS lookup
    // For now, simulate based on known patterns

    // Simulate DNS lookup result
    // In production: const result = await dns.resolve4(query);
    const simulatedResult = simulateDNSBLCheck(ip, dnsbl);

    if (simulatedResult) {
      return {
        listed: true,
        category: categories[simulatedResult] || 'Listed',
      };
    }

    return { listed: false };
  } catch {
    // DNS lookup failed or IP not listed
    return { listed: false };
  }
}

/**
 * Simulate DNSBL check for development
 * In production, this would be replaced with actual DNS lookups
 */
function simulateDNSBLCheck(ip: string, _dnsbl: string): string | null {
  // Check against known bad ranges
  for (const range of KNOWN_BAD_RANGES) {
    if (ipInRange(ip, range.start, range.end)) {
      return '127.0.0.2';
    }
  }

  // Simulate some IPs being listed for testing
  const testListedIPs = [
    '192.0.2.1',    // TEST-NET-1
    '198.51.100.1', // TEST-NET-2
    '203.0.113.1',  // TEST-NET-3
  ];

  if (testListedIPs.includes(ip)) {
    return '127.0.0.2';
  }

  return null;
}

/**
 * Get IP geolocation (simplified)
 * In production, use a real GeoIP service like MaxMind
 */
async function getIPGeolocation(ip: string): Promise<{
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  isp?: string;
  org?: string;
}> {
  // Check for private/reserved IPs
  if (isPrivateIP(ip)) {
    return { country: 'Private Network', countryCode: 'XX' };
  }

  // In production, use a GeoIP service
  // For now, return placeholder data
  const geoApiUrl = process.env.GEOIP_API_URL;
  const geoApiKey = process.env.GEOIP_API_KEY;

  if (geoApiUrl && geoApiKey) {
    try {
      const response = await fetch(`${geoApiUrl}?ip=${ip}`, {
        headers: { 'Authorization': `Bearer ${geoApiKey}` },
      });

      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
      console.error('[GeoIP] Lookup failed:', error);
    }
  }

  // Fallback: estimate based on IP patterns (for development)
  return estimateGeolocation(ip);
}

/**
 * Check if IP is private/reserved
 */
function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);

  // 10.0.0.0/8
  if (parts[0] === 10) return true;

  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;

  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;

  // 127.0.0.0/8 (localhost)
  if (parts[0] === 127) return true;

  // 169.254.0.0/16 (link-local)
  if (parts[0] === 169 && parts[1] === 254) return true;

  return false;
}

/**
 * Estimate geolocation for development
 */
function estimateGeolocation(ip: string): {
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  isp?: string;
  org?: string;
} {
  // Map some IP ranges to countries (very simplified)
  const ipNum = ipToNumber(ip);

  // This is just for development - real implementation would use GeoIP database
  if (ipNum >= ipToNumber('1.0.0.0') && ipNum <= ipToNumber('1.255.255.255')) {
    return { country: 'Australia', countryCode: 'AU' };
  }
  if (ipNum >= ipToNumber('8.0.0.0') && ipNum <= ipToNumber('8.255.255.255')) {
    return { country: 'United States', countryCode: 'US', isp: 'Level 3' };
  }

  return { country: 'Unknown', countryCode: 'XX' };
}

/**
 * Check IP reputation against all blocklists
 */
export async function checkIPReputation(ip: string): Promise<IPCheckResult> {
  // Validate IP format
  if (!isValidIPv4(ip)) {
    return {
      ip,
      isThreat: false,
      verdict: 'unknown',
      sources: [{ list: 'validation', description: 'Invalid IP format' }],
      checkedAt: new Date(),
    };
  }

  // Check cache
  const cached = ipCache.get(ip);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.result;
  }

  // Skip checks for private IPs
  if (isPrivateIP(ip)) {
    return {
      ip,
      isThreat: false,
      verdict: 'clean',
      sources: [{ list: 'internal', description: 'Private IP address' }],
      checkedAt: new Date(),
    };
  }

  const sources: IPCheckResult['sources'] = [];
  let isThreat = false;

  // Check against DNSBL sources
  const dnsblChecks = await Promise.all(
    Object.entries(BLOCKLIST_SOURCES).map(async ([key, source]) => {
      const result = await checkDNSBL(ip, source.dnsbl, source.categories);
      return { key, source, result };
    })
  );

  for (const { source, result } of dnsblChecks) {
    if (result.listed) {
      isThreat = true;
      sources.push({
        list: source.name,
        category: result.category,
        description: `Listed in ${source.name}`,
      });
    }
  }

  // Check against known bad ranges
  for (const range of KNOWN_BAD_RANGES) {
    if (ipInRange(ip, range.start, range.end)) {
      isThreat = true;
      sources.push({
        list: 'Known Bad Ranges',
        category: range.category,
        description: `IP in known malicious range: ${range.category}`,
      });
    }
  }

  // Get geolocation
  const geo = await getIPGeolocation(ip);

  // Check for high-risk country
  if (geo.countryCode && HIGH_RISK_COUNTRIES.has(geo.countryCode)) {
    sources.push({
      list: 'GeoIP Risk',
      category: 'high_risk_country',
      description: `Origin: ${geo.country} (elevated threat region)`,
    });
    // Note: High-risk country alone doesn't make it a threat, just suspicious
  }

  // Determine verdict
  let verdict: IPCheckResult['verdict'];
  if (sources.filter(s => s.list !== 'GeoIP Risk').length > 0) {
    verdict = isThreat ? 'malicious' : 'suspicious';
  } else if (sources.some(s => s.list === 'GeoIP Risk')) {
    verdict = 'suspicious';
  } else {
    verdict = 'clean';
  }

  const result: IPCheckResult = {
    ip,
    isThreat,
    verdict,
    sources,
    geolocation: geo,
    checkedAt: new Date(),
  };

  // Cache result
  ipCache.set(ip, {
    result,
    expiresAt: Date.now() + CACHE_TTL,
  });

  return result;
}

/**
 * Validate IPv4 format
 */
function isValidIPv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;

  for (const part of parts) {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255) return false;
    if (part !== num.toString()) return false; // No leading zeros
  }

  return true;
}

/**
 * Batch check multiple IPs
 */
export async function checkMultipleIPs(ips: string[]): Promise<Map<string, IPCheckResult>> {
  const results = new Map<string, IPCheckResult>();
  const uniqueIPs = [...new Set(ips.filter(ip => isValidIPv4(ip)))];

  // Process in batches to avoid overwhelming DNS servers
  const BATCH_SIZE = 10;

  for (let i = 0; i < uniqueIPs.length; i += BATCH_SIZE) {
    const batch = uniqueIPs.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(batch.map(ip => checkIPReputation(ip)));

    for (const result of batchResults) {
      results.set(result.ip, result);
    }
  }

  return results;
}

/**
 * Extract IPs from email headers
 */
export function extractIPsFromHeaders(headers: Record<string, string>): string[] {
  const ips: string[] = [];
  const ipPattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

  // Check Received headers
  const received = headers['received'] || headers['Received'];
  if (received) {
    const matches = received.match(ipPattern) || [];
    ips.push(...matches);
  }

  // Check X-Originating-IP
  const originatingIP = headers['x-originating-ip'] || headers['X-Originating-IP'];
  if (originatingIP) {
    const clean = originatingIP.replace(/[[\]]/g, '');
    if (isValidIPv4(clean)) {
      ips.push(clean);
    }
  }

  // Check X-Sender-IP
  const senderIP = headers['x-sender-ip'] || headers['X-Sender-IP'];
  if (senderIP && isValidIPv4(senderIP)) {
    ips.push(senderIP);
  }

  // Filter out private IPs and duplicates
  return [...new Set(ips.filter(ip => !isPrivateIP(ip)))];
}

/**
 * Clear IP cache
 */
export function clearIPCache(): void {
  ipCache.clear();
}

/**
 * Get cache statistics
 */
export function getIPCacheStats(): { size: number; hitRate: number } {
  return {
    size: ipCache.size,
    hitRate: 0, // Would track in production
  };
}

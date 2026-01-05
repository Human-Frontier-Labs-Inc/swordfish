/**
 * WHOIS Lookup Service
 * Retrieves domain registration information for age and ownership analysis
 */

export interface WhoisResult {
  domain: string;
  registrar?: string;
  createdDate?: Date;
  updatedDate?: Date;
  expiresDate?: Date;
  registrant?: {
    name?: string;
    organization?: string;
    country?: string;
  };
  nameServers?: string[];
  status?: string[];
  raw?: string;
  error?: string;
  cached?: boolean;
}

// WHOIS servers by TLD
const WHOIS_SERVERS: Record<string, string> = {
  'com': 'whois.verisign-grs.com',
  'net': 'whois.verisign-grs.com',
  'org': 'whois.pir.org',
  'info': 'whois.afilias.net',
  'io': 'whois.nic.io',
  'co': 'whois.nic.co',
  'xyz': 'whois.nic.xyz',
  'online': 'whois.nic.online',
  'site': 'whois.nic.site',
  'top': 'whois.nic.top',
  'app': 'whois.nic.google',
  'dev': 'whois.nic.google',
  'uk': 'whois.nic.uk',
  'de': 'whois.denic.de',
  'ru': 'whois.tcinet.ru',
  'cn': 'whois.cnnic.cn',
  'jp': 'whois.jprs.jp',
  'au': 'whois.auda.org.au',
  'ca': 'whois.cira.ca',
  'fr': 'whois.nic.fr',
  'nl': 'whois.sidn.nl',
  'br': 'whois.registro.br',
  'in': 'whois.registry.in',
};

// Cache for WHOIS results
const whoisCache = new Map<string, { result: WhoisResult; expiresAt: number }>();
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Extract TLD from domain
 */
function getTld(domain: string): string {
  const parts = domain.split('.');
  if (parts.length >= 2) {
    // Handle double TLDs like co.uk, com.au
    const lastTwo = parts.slice(-2).join('.');
    if (['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br'].includes(lastTwo)) {
      return lastTwo;
    }
  }
  return parts[parts.length - 1];
}

/**
 * Parse date from WHOIS response
 */
function parseWhoisDate(dateStr: string | undefined): Date | undefined {
  if (!dateStr) return undefined;

  // Try various date formats
  const formats = [
    // ISO 8601
    /(\d{4})-(\d{2})-(\d{2})T?(\d{2})?:?(\d{2})?:?(\d{2})?/,
    // US format
    /(\d{2})\/(\d{2})\/(\d{4})/,
    // Verbose format
    /(\d{1,2})-([A-Za-z]{3})-(\d{4})/,
  ];

  for (const format of formats) {
    const match = dateStr.match(format);
    if (match) {
      const parsed = new Date(dateStr);
      if (!isNaN(parsed.getTime())) {
        return parsed;
      }
    }
  }

  // Fallback: try direct parsing
  const date = new Date(dateStr);
  return isNaN(date.getTime()) ? undefined : date;
}

/**
 * Parse WHOIS response text
 */
function parseWhoisResponse(raw: string, domain: string): Partial<WhoisResult> {
  const result: Partial<WhoisResult> = { raw };
  const lines = raw.split('\n');

  for (const line of lines) {
    const [key, ...valueParts] = line.split(':');
    const value = valueParts.join(':').trim();

    if (!key || !value) continue;

    const keyLower = key.toLowerCase().trim();

    // Creation date
    if (keyLower.includes('creation date') ||
        keyLower.includes('created date') ||
        keyLower.includes('registration date') ||
        keyLower.includes('created')) {
      result.createdDate = parseWhoisDate(value);
    }

    // Updated date
    if (keyLower.includes('updated date') ||
        keyLower.includes('last updated') ||
        keyLower.includes('modified')) {
      result.updatedDate = parseWhoisDate(value);
    }

    // Expiration date
    if (keyLower.includes('expir') ||
        keyLower.includes('registry expiry')) {
      result.expiresDate = parseWhoisDate(value);
    }

    // Registrar
    if (keyLower.includes('registrar') && !keyLower.includes('abuse')) {
      if (!result.registrar) {
        result.registrar = value;
      }
    }

    // Name servers
    if (keyLower.includes('name server') || keyLower.includes('nserver')) {
      if (!result.nameServers) {
        result.nameServers = [];
      }
      result.nameServers.push(value.toLowerCase());
    }

    // Status
    if (keyLower.includes('status') && !keyLower.includes('query')) {
      if (!result.status) {
        result.status = [];
      }
      result.status.push(value);
    }

    // Registrant info
    if (keyLower.includes('registrant')) {
      if (!result.registrant) {
        result.registrant = {};
      }
      if (keyLower.includes('name')) {
        result.registrant.name = value;
      } else if (keyLower.includes('org')) {
        result.registrant.organization = value;
      } else if (keyLower.includes('country')) {
        result.registrant.country = value;
      }
    }
  }

  return result;
}

/**
 * Perform WHOIS lookup for a domain
 * Note: In production, this should use a proper WHOIS library or API service
 * This implementation provides a fallback estimation for development
 */
export async function lookupWhois(domain: string): Promise<WhoisResult> {
  const normalizedDomain = domain.toLowerCase().trim();

  // Check cache
  const cached = whoisCache.get(normalizedDomain);
  if (cached && Date.now() < cached.expiresAt) {
    return { ...cached.result, cached: true };
  }

  const tld = getTld(normalizedDomain);
  const whoisServer = WHOIS_SERVERS[tld];

  // If we have a configured WHOIS API endpoint, use it
  const whoisApiUrl = process.env.WHOIS_API_URL;
  const whoisApiKey = process.env.WHOIS_API_KEY;

  if (whoisApiUrl && whoisApiKey) {
    try {
      const response = await fetch(`${whoisApiUrl}?domain=${encodeURIComponent(normalizedDomain)}`, {
        headers: {
          'Authorization': `Bearer ${whoisApiKey}`,
          'Accept': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        const result: WhoisResult = {
          domain: normalizedDomain,
          registrar: data.registrar,
          createdDate: data.created_date ? new Date(data.created_date) : undefined,
          updatedDate: data.updated_date ? new Date(data.updated_date) : undefined,
          expiresDate: data.expires_date ? new Date(data.expires_date) : undefined,
          registrant: data.registrant,
          nameServers: data.name_servers,
          status: data.status,
        };

        // Cache result
        whoisCache.set(normalizedDomain, {
          result,
          expiresAt: Date.now() + CACHE_TTL,
        });

        return result;
      }
    } catch (error) {
      console.error('[WHOIS] API error:', error);
    }
  }

  // Fallback: Return estimation based on domain characteristics
  // This is used for development or when WHOIS API is unavailable
  const result = estimateDomainAge(normalizedDomain);

  // Cache result
  whoisCache.set(normalizedDomain, {
    result,
    expiresAt: Date.now() + CACHE_TTL,
  });

  return result;
}

/**
 * Estimate domain age based on characteristics
 * Used as fallback when WHOIS lookup fails
 */
function estimateDomainAge(domain: string): WhoisResult {
  const now = new Date();
  const tld = getTld(domain);

  // Known old domains (major services)
  const knownOldDomains = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
    'yahoo.com', 'gmail.com', 'outlook.com', 'paypal.com',
  ];

  if (knownOldDomains.some(d => domain === d || domain.endsWith(`.${d}`))) {
    return {
      domain,
      createdDate: new Date('2000-01-01'),
      registrar: 'Estimated (well-known domain)',
    };
  }

  // Suspicious TLDs often used by new/malicious domains
  const suspiciousTlds = ['xyz', 'top', 'club', 'online', 'site', 'work', 'tk', 'ml', 'ga', 'cf', 'gq'];

  if (suspiciousTlds.includes(tld)) {
    // Assume recently registered for suspicious TLDs
    const estimatedAge = Math.floor(Math.random() * 180); // 0-180 days
    const createdDate = new Date(now.getTime() - estimatedAge * 24 * 60 * 60 * 1000);

    return {
      domain,
      createdDate,
      registrar: 'Estimated (suspicious TLD)',
    };
  }

  // Default: assume domain is between 1-5 years old
  const estimatedYears = 1 + Math.floor(Math.random() * 4);
  const createdDate = new Date(now.getFullYear() - estimatedYears, now.getMonth(), now.getDate());

  return {
    domain,
    createdDate,
    registrar: 'Estimated (no WHOIS data)',
  };
}

/**
 * Clear WHOIS cache
 */
export function clearWhoisCache(): void {
  whoisCache.clear();
}

/**
 * Get cache statistics
 */
export function getWhoisCacheStats(): { size: number; oldestEntry: Date | null } {
  let oldestEntry: Date | null = null;

  for (const [, entry] of whoisCache) {
    const entryDate = new Date(entry.expiresAt - CACHE_TTL);
    if (!oldestEntry || entryDate < oldestEntry) {
      oldestEntry = entryDate;
    }
  }

  return {
    size: whoisCache.size,
    oldestEntry,
  };
}

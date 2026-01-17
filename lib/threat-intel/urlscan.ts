/**
 * URLScan Integration
 *
 * Provides URL scanning, analysis, and screenshot capture
 * using the URLScan.io API.
 */

export enum ScanStatus {
  PENDING = 'pending',
  COMPLETED = 'completed',
  ERROR = 'error',
}

export interface UrlScanConfig {
  apiKey: string;
  baseUrl?: string;
  visibility?: 'public' | 'private' | 'unlisted';
  timeout?: number;
  cacheEnabled?: boolean;
  cacheTtl?: number;
}

export interface ScanOptions {
  visibility?: 'public' | 'private' | 'unlisted';
  tags?: string[];
  maxPolls?: number;
  pollInterval?: number;
}

export interface ScanSubmitResult {
  uuid: string;
  resultUrl?: string;
  apiUrl?: string;
  visibility?: string;
}

export interface PageInfo {
  url: string;
  domain: string;
  ip?: string;
  country?: string;
  server?: string;
  status?: string;
  title?: string;
  mimeType?: string;
}

export interface Verdict {
  malicious: boolean;
  score: number;
  categories: string[];
  maliciousEngines: string[];
  benignEngines: string[];
}

export interface ThreatIndicator {
  suspiciousUrls: string[];
  suspiciousIps: string[];
  suspiciousDomains: string[];
  phishingPatterns: string[];
}

export interface ScanResult {
  uuid: string;
  status: ScanStatus;
  page: PageInfo;
  verdict: Verdict;
  indicators: ThreatIndicator;
  screenshotUrl: string;
  fromCache?: boolean;
}

export interface SearchResult {
  results: Array<{
    uuid: string;
    url?: string;
    domain?: string;
  }>;
  total: number;
}

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

/**
 * URLScan.io API Client
 */
export class UrlScanClient {
  private config: Required<UrlScanConfig>;
  private cache: Map<string, CacheEntry<unknown>> = new Map();

  constructor(config: UrlScanConfig) {
    this.config = {
      apiKey: config.apiKey,
      baseUrl: config.baseUrl ?? 'https://urlscan.io/api/v1',
      visibility: config.visibility ?? 'public',
      timeout: config.timeout ?? 30000,
      cacheEnabled: config.cacheEnabled ?? false,
      cacheTtl: config.cacheTtl ?? 3600000,
    };
  }

  getConfig(): { baseUrl: string; visibility: string } {
    return {
      baseUrl: this.config.baseUrl,
      visibility: this.config.visibility,
    };
  }

  async submitScan(url: string, options: ScanOptions = {}): Promise<ScanSubmitResult> {
    const body = {
      url,
      visibility: options.visibility ?? this.config.visibility,
      tags: options.tags,
    };

    const response = await this.makeRequest('/scan', {
      method: 'POST',
      body: JSON.stringify(body),
    });

    return {
      uuid: response.uuid,
      resultUrl: response.result,
      apiUrl: response.api,
      visibility: response.visibility,
    };
  }

  async getResult(uuid: string): Promise<ScanResult> {
    // Check cache first
    const cacheKey = `result:${uuid}`;
    const cached = this.getFromCache<ScanResult>(cacheKey);
    if (cached) {
      return { ...cached, fromCache: true };
    }

    try {
      const response = await this.makeRequest(`/result/${uuid}`);

      const result = this.parseResult(uuid, response);

      // Cache completed results
      if (result.status === ScanStatus.COMPLETED) {
        this.setCache(cacheKey, result);
      }

      return result;
    } catch (error) {
      if (error instanceof Error && error.message.includes('404')) {
        return this.createPendingResult(uuid);
      }
      throw error;
    }
  }

  async scanUrl(url: string, options: ScanOptions = {}): Promise<ScanResult> {
    const { maxPolls = 10, pollInterval = 5000 } = options;

    const { uuid } = await this.submitScan(url, options);

    let result = await this.getResult(uuid);
    let polls = 0;

    while (result.status === ScanStatus.PENDING && polls < maxPolls) {
      await this.sleep(pollInterval);
      result = await this.getResult(uuid);
      polls++;
    }

    return result;
  }

  async search(query: string): Promise<SearchResult> {
    const encodedQuery = encodeURIComponent(query);
    const response = await this.makeRequest(`/search/?q=${encodedQuery}`);

    return {
      results: (response.results || []).map((r: Record<string, unknown>) => ({
        uuid: (r.task as Record<string, unknown>)?.uuid as string,
        url: (r.task as Record<string, unknown>)?.url as string,
        domain: (r.page as Record<string, unknown>)?.domain as string,
      })),
      total: response.total || 0,
    };
  }

  async searchByDomain(domain: string): Promise<SearchResult> {
    return this.search(`domain:${domain}`);
  }

  private async makeRequest(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<Record<string, unknown>> {
    const url = `${this.config.baseUrl}${endpoint}`;

    const headers: Record<string, string> = {
      'API-Key': this.config.apiKey,
      'Content-Type': 'application/json',
    };

    const response = await fetch(url, {
      ...options,
      headers: {
        ...headers,
        ...(options.headers as Record<string, string>),
      },
    });

    if (response.status === 401) {
      throw new Error('Invalid API key');
    }

    if (response.status === 400) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error((errorData as { message?: string }).message || 'Invalid URL');
    }

    if (response.status === 404) {
      throw new Error('404: Not found');
    }

    if (response.status === 429) {
      // Rate limited - wait and retry
      await this.sleep(60000);
      return this.makeRequest(endpoint, options);
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    return response.json();
  }

  private parseResult(uuid: string, response: Record<string, unknown>): ScanResult {
    const task = (response.task as Record<string, unknown>) || {};
    const page = (response.page as Record<string, unknown>) || {};
    const verdicts = (response.verdicts as Record<string, unknown>) || {};
    const overall = (verdicts.overall as Record<string, unknown>) || {};
    const engines = (verdicts.engines as Record<string, unknown>) || {};
    const lists = (response.lists as Record<string, unknown>) || {};

    const pageInfo: PageInfo = {
      url: (page.url as string) || '',
      domain: (page.domain as string) || '',
      ip: page.ip as string,
      country: page.country as string,
      server: page.server as string,
      status: page.status as string,
      title: page.title as string,
      mimeType: page.mimeType as string,
    };

    const verdict: Verdict = {
      malicious: (overall.malicious as boolean) || false,
      score: (overall.score as number) || 0,
      categories: (overall.categories as string[]) || [],
      maliciousEngines: (engines.malicious as string[]) || [],
      benignEngines: (engines.benign as string[]) || [],
    };

    const indicators = this.extractIndicators(page, lists, verdict);

    const screenshotUrl = (task.screenshotURL as string) ||
      `https://urlscan.io/screenshots/${uuid}.png`;

    return {
      uuid,
      status: ScanStatus.COMPLETED,
      page: pageInfo,
      verdict,
      indicators,
      screenshotUrl,
    };
  }

  private extractIndicators(
    page: Record<string, unknown>,
    lists: Record<string, unknown>,
    verdict: Verdict
  ): ThreatIndicator {
    const indicators: ThreatIndicator = {
      suspiciousUrls: [],
      suspiciousIps: [],
      suspiciousDomains: [],
      phishingPatterns: [],
    };

    // Extract from lists
    if (Array.isArray(lists.urls)) {
      indicators.suspiciousUrls = lists.urls;
    }
    if (Array.isArray(lists.ips)) {
      indicators.suspiciousIps = lists.ips;
    }
    if (Array.isArray(lists.domains)) {
      indicators.suspiciousDomains = lists.domains;
    }

    // Detect phishing patterns
    const domain = (page.domain as string) || '';
    const title = (page.title as string) || '';

    const phishingKeywords = [
      'login', 'signin', 'verify', 'secure', 'account', 'bank',
      'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    ];

    const brandMismatches = this.detectBrandMismatch(domain, title);
    if (brandMismatches.length > 0) {
      indicators.phishingPatterns.push(...brandMismatches);
    }

    // Check for category-based phishing indicators
    if (verdict.categories.includes('phishing')) {
      indicators.phishingPatterns.push('Detected as phishing by security engines');
    }

    // Check for suspicious domain patterns
    const suspiciousPatterns = [
      /\d{1,3}-\d{1,3}-\d{1,3}/, // IP-like patterns in domain
      /[a-z]{1,3}\d{1,2}[a-z]/, // Typosquatting patterns
      /-secure|-login|-verify/i, // Security keyword suffixes
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(domain)) {
        indicators.phishingPatterns.push(`Suspicious domain pattern: ${domain}`);
        break;
      }
    }

    return indicators;
  }

  private detectBrandMismatch(domain: string, title: string): string[] {
    const patterns: string[] = [];

    const brands = [
      { name: 'PayPal', domains: ['paypal.com'], keywords: ['paypal'] },
      { name: 'Amazon', domains: ['amazon.com', 'amazon.co.uk'], keywords: ['amazon'] },
      { name: 'Apple', domains: ['apple.com', 'icloud.com'], keywords: ['apple', 'icloud'] },
      { name: 'Microsoft', domains: ['microsoft.com', 'live.com'], keywords: ['microsoft', 'outlook'] },
      { name: 'Google', domains: ['google.com', 'gmail.com'], keywords: ['google', 'gmail'] },
      { name: 'Facebook', domains: ['facebook.com', 'fb.com'], keywords: ['facebook'] },
      { name: 'Wells Fargo', domains: ['wellsfargo.com'], keywords: ['wells fargo', 'wellsfargo'] },
    ];

    const lowerTitle = title.toLowerCase();
    const lowerDomain = domain.toLowerCase();

    for (const brand of brands) {
      const titleHasBrand = brand.keywords.some(kw => lowerTitle.includes(kw));
      const domainIsBrand = brand.domains.some(d => lowerDomain.includes(d.replace('.com', '')));

      if (titleHasBrand && !domainIsBrand) {
        patterns.push(`Potential ${brand.name} impersonation: title mentions brand but domain doesn't match`);
      }
    }

    return patterns;
  }

  private createPendingResult(uuid: string): ScanResult {
    return {
      uuid,
      status: ScanStatus.PENDING,
      page: {
        url: '',
        domain: '',
      },
      verdict: {
        malicious: false,
        score: 0,
        categories: [],
        maliciousEngines: [],
        benignEngines: [],
      },
      indicators: {
        suspiciousUrls: [],
        suspiciousIps: [],
        suspiciousDomains: [],
        phishingPatterns: [],
      },
      screenshotUrl: '',
    };
  }

  private getFromCache<T>(key: string): T | null {
    if (!this.config.cacheEnabled) return null;

    const entry = this.cache.get(key) as CacheEntry<T> | undefined;
    if (!entry) return null;

    if (Date.now() - entry.timestamp > this.config.cacheTtl) {
      this.cache.delete(key);
      return null;
    }

    return entry.data;
  }

  private setCache<T>(key: string, data: T): void {
    if (!this.config.cacheEnabled) return;

    this.cache.set(key, {
      data,
      timestamp: Date.now(),
    });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

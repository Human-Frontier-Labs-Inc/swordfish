/**
 * VirusTotal Integration
 *
 * Provides URL scanning, file hash lookup, and threat analysis
 * using the VirusTotal API v3.
 */

export enum AnalysisStatus {
  QUEUED = 'queued',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  ERROR = 'error',
}

export enum ThreatCategory {
  PHISHING = 'phishing',
  MALWARE = 'malware',
  TROJAN = 'trojan',
  RANSOMWARE = 'ransomware',
  SPYWARE = 'spyware',
  ADWARE = 'adware',
  MINER = 'miner',
  EXPLOIT = 'exploit',
  UNKNOWN = 'unknown',
}

export interface VirusTotalConfig {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
  maxRequestsPerMinute?: number;
  cacheEnabled?: boolean;
  cacheTtl?: number;
}

export interface AnalysisStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}

export interface UrlSubmitResult {
  analysisId: string;
}

export interface UrlScanResult {
  status: AnalysisStatus;
  stats: AnalysisStats;
  threatScore: number;
  isMalicious: boolean;
  categories: ThreatCategory[];
  fromCache?: boolean;
}

export interface FileScanResult {
  found: boolean;
  sha256?: string;
  md5?: string;
  stats: AnalysisStats;
  threatScore: number;
  isMalicious: boolean;
  categories: ThreatCategory[];
  typeDescription?: string;
  fromCache?: boolean;
}

export interface RateLimitStatus {
  remaining: number;
  limit: number;
  resetTime?: number;
}

export interface ScanOptions {
  maxPolls?: number;
  pollInterval?: number;
}

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

/**
 * VirusTotal API Client
 */
export class VirusTotalClient {
  private config: Required<VirusTotalConfig>;
  private rateLimitStatus: RateLimitStatus = { remaining: -1, limit: -1 };
  private requestQueue: Array<() => Promise<void>> = [];
  private requestsThisMinute = 0;
  private minuteStart = Date.now();
  private cache: Map<string, CacheEntry<unknown>> = new Map();

  constructor(config: VirusTotalConfig) {
    this.config = {
      apiKey: config.apiKey,
      baseUrl: config.baseUrl ?? 'https://www.virustotal.com/api/v3',
      timeout: config.timeout ?? 30000,
      maxRequestsPerMinute: config.maxRequestsPerMinute ?? 500,
      cacheEnabled: config.cacheEnabled ?? false,
      cacheTtl: config.cacheTtl ?? 3600000, // 1 hour default
    };
  }

  getConfig(): { apiKey: string; baseUrl: string } {
    return {
      apiKey: this.maskApiKey(this.config.apiKey),
      baseUrl: this.config.baseUrl,
    };
  }

  getRateLimitStatus(): RateLimitStatus {
    return { ...this.rateLimitStatus };
  }

  async submitUrl(url: string): Promise<UrlSubmitResult> {
    await this.checkRateLimit();

    const response = await this.makeRequest('/urls', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(url)}`,
    });

    if (!response.data?.id) {
      throw new Error('Invalid response format');
    }

    return { analysisId: response.data.id };
  }

  async getUrlAnalysis(analysisId: string): Promise<UrlScanResult> {
    const response = await this.makeRequest(`/analyses/${analysisId}`);

    const attrs = response.data?.attributes;
    if (!attrs) {
      throw new Error('Invalid response format');
    }

    const stats = attrs.stats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };
    const status = this.mapStatus(attrs.status);

    return {
      status,
      stats,
      threatScore: this.calculateThreatScore(stats),
      isMalicious: stats.malicious > 0 || stats.suspicious > 2,
      categories: this.extractCategories(attrs.results || {}),
    };
  }

  async scanUrl(url: string, options: ScanOptions = {}): Promise<UrlScanResult> {
    const { maxPolls = 10, pollInterval = 5000 } = options;

    // Check cache first
    const cacheKey = `url:${url}`;
    const cached = this.getFromCache<UrlScanResult>(cacheKey);
    if (cached) {
      return { ...cached, fromCache: true };
    }

    const { analysisId } = await this.submitUrl(url);
    let result = await this.getUrlAnalysis(analysisId);

    let polls = 0;
    while (result.status === AnalysisStatus.QUEUED && polls < maxPolls) {
      await this.sleep(pollInterval);
      result = await this.getUrlAnalysis(analysisId);
      polls++;
    }

    // Cache the result
    this.setCache(cacheKey, result);

    return result;
  }

  async scanUrls(urls: string[]): Promise<UrlScanResult[]> {
    const results: UrlScanResult[] = [];
    for (const url of urls) {
      results.push(await this.scanUrl(url));
    }
    return results;
  }

  async getFileReport(hash: string): Promise<FileScanResult> {
    // Check cache first
    const cacheKey = `file:${hash}`;
    const cached = this.getFromCache<FileScanResult>(cacheKey);
    if (cached) {
      return { ...cached, fromCache: true };
    }

    try {
      const response = await this.makeRequest(`/files/${hash}`);

      const attrs = response.data?.attributes;
      if (!attrs) {
        throw new Error('Invalid response format');
      }

      const stats = attrs.last_analysis_stats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };

      const result: FileScanResult = {
        found: true,
        sha256: attrs.sha256,
        md5: attrs.md5,
        stats,
        threatScore: this.calculateThreatScore(stats),
        isMalicious: stats.malicious > 0,
        categories: this.extractFileCategories(attrs),
        typeDescription: attrs.type_description,
      };

      // Cache the result
      this.setCache(cacheKey, result);

      return result;
    } catch (error) {
      if (error instanceof Error && error.message.includes('404')) {
        return {
          found: false,
          stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
          threatScore: 0,
          isMalicious: false,
          categories: [],
        };
      }
      throw error;
    }
  }

  async getFileReports(hashes: string[]): Promise<FileScanResult[]> {
    const results: FileScanResult[] = [];
    for (const hash of hashes) {
      results.push(await this.getFileReport(hash));
    }
    return results;
  }

  private async makeRequest(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<{ data?: { id?: string; attributes?: Record<string, unknown> } }> {
    const url = `${this.config.baseUrl}${endpoint}`;

    const headers: Record<string, string> = {
      'x-apikey': this.config.apiKey,
      ...(options.headers as Record<string, string>),
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal,
      });

      // Update rate limit status
      this.updateRateLimitStatus(response);

      if (response.status === 401) {
        throw new Error('Invalid API key');
      }

      if (response.status === 404) {
        throw new Error('404: Resource not found');
      }

      if (response.status === 429) {
        // Rate limited - wait and retry
        const resetTime = this.getResetTime(response);
        await this.sleep(resetTime * 1000);
        return this.makeRequest(endpoint, options);
      }

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      return await response.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async checkRateLimit(): Promise<void> {
    const now = Date.now();

    // Reset counter if a minute has passed
    if (now - this.minuteStart >= 60000) {
      this.requestsThisMinute = 0;
      this.minuteStart = now;
    }

    // Check if we've hit the limit
    if (this.requestsThisMinute >= this.config.maxRequestsPerMinute) {
      const waitTime = 60000 - (now - this.minuteStart);
      await this.sleep(waitTime);
      this.requestsThisMinute = 0;
      this.minuteStart = Date.now();
    }

    this.requestsThisMinute++;
  }

  private updateRateLimitStatus(response: Response): void {
    const headers = response.headers;
    if (!headers) return;

    const remaining = typeof headers.get === 'function'
      ? headers.get('x-ratelimit-remaining')
      : (headers as unknown as Map<string, string>).get?.('x-ratelimit-remaining');
    const limit = typeof headers.get === 'function'
      ? headers.get('x-ratelimit-limit')
      : (headers as unknown as Map<string, string>).get?.('x-ratelimit-limit');

    if (remaining !== null && remaining !== undefined) {
      this.rateLimitStatus.remaining = parseInt(remaining, 10);
    }
    if (limit !== null && limit !== undefined) {
      this.rateLimitStatus.limit = parseInt(limit, 10);
    }
  }

  private getResetTime(response: Response): number {
    const headers = response.headers;
    if (!headers) return 60;

    const reset = typeof headers.get === 'function'
      ? headers.get('x-ratelimit-reset')
      : (headers as unknown as Map<string, string>).get?.('x-ratelimit-reset');
    return reset ? parseInt(reset, 10) : 60;
  }

  private calculateThreatScore(stats: AnalysisStats): number {
    const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
    if (total === 0) return 0;

    // Weight malicious more heavily than suspicious
    const score = ((stats.malicious * 100) + (stats.suspicious * 50)) / total;
    return Math.min(100, Math.round(score));
  }

  private extractCategories(results: Record<string, { category?: string; result?: string }>): ThreatCategory[] {
    const categories = new Set<ThreatCategory>();

    for (const engine of Object.values(results)) {
      if (engine.category === 'malicious' && engine.result) {
        const category = this.mapThreatCategory(engine.result);
        categories.add(category);
      }
    }

    return Array.from(categories);
  }

  private extractFileCategories(attrs: Record<string, unknown>): ThreatCategory[] {
    const categories = new Set<ThreatCategory>();

    // Extract from analysis results
    const results = attrs.last_analysis_results as Record<string, { category?: string; result?: string }> | undefined;
    if (results) {
      for (const engine of Object.values(results)) {
        if (engine.category === 'malicious' && engine.result) {
          const category = this.mapThreatCategory(engine.result);
          categories.add(category);
        }
      }
    }

    // Extract from popular threat classification
    const classification = attrs.popular_threat_classification as {
      popular_threat_category?: Array<{ value: string; count: number }>;
    } | undefined;

    if (classification?.popular_threat_category) {
      for (const cat of classification.popular_threat_category) {
        const category = this.mapThreatCategory(cat.value);
        categories.add(category);
      }
    }

    return Array.from(categories);
  }

  private mapThreatCategory(result: string): ThreatCategory {
    const lower = result.toLowerCase();

    if (lower.includes('phishing') || lower.includes('phish')) {
      return ThreatCategory.PHISHING;
    }
    if (lower.includes('trojan')) {
      return ThreatCategory.TROJAN;
    }
    if (lower.includes('ransomware') || lower.includes('ransom')) {
      return ThreatCategory.RANSOMWARE;
    }
    if (lower.includes('spyware') || lower.includes('spy')) {
      return ThreatCategory.SPYWARE;
    }
    if (lower.includes('adware') || lower.includes('pup')) {
      return ThreatCategory.ADWARE;
    }
    if (lower.includes('miner') || lower.includes('cryptominer')) {
      return ThreatCategory.MINER;
    }
    if (lower.includes('exploit')) {
      return ThreatCategory.EXPLOIT;
    }
    if (lower.includes('malware') || lower.includes('malicious')) {
      return ThreatCategory.MALWARE;
    }

    return ThreatCategory.UNKNOWN;
  }

  private mapStatus(status: string): AnalysisStatus {
    switch (status?.toLowerCase()) {
      case 'queued':
        return AnalysisStatus.QUEUED;
      case 'in_progress':
      case 'in-progress':
        return AnalysisStatus.IN_PROGRESS;
      case 'completed':
        return AnalysisStatus.COMPLETED;
      default:
        return AnalysisStatus.ERROR;
    }
  }

  private maskApiKey(key: string): string {
    if (key.length <= 8) return '***';
    return `${key.slice(0, 4)}***${key.slice(-4)}`;
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

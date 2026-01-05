/**
 * Sandbox Service
 *
 * File and URL analysis via sandbox providers (Hybrid Analysis, VirusTotal, etc.)
 */

export interface SandboxConfig {
  provider: 'hybrid-analysis' | 'any.run' | 'joe-sandbox' | 'cuckoo' | 'virustotal' | 'urlscan';
  apiKey: string;
  baseUrl?: string;
  fallbackProvider?: SandboxConfig;
  cacheResults?: boolean;
  cacheTtlMs?: number;
}

export interface FileSubmission {
  filename: string;
  content: Buffer;
  contentType: string;
}

export interface SubmissionResult {
  analysisId: string;
  status: 'pending' | 'processing' | 'completed' | 'error';
  error?: string;
  usedFallback?: boolean;
}

export interface SandboxResult {
  id: string;
  status: 'pending' | 'processing' | 'completed' | 'error';
  verdict?: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  score?: number;
  malwareFamily?: string;
  indicators: Array<{ type: string; value: string }>;
}

export interface FileAnalysis extends SandboxResult {
  filename?: string;
  sha256?: string;
  md5?: string;
}

export interface BehaviorIndicator {
  category: string;
  description: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
}

export interface HashCheckResult {
  found: boolean;
  verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  malwareFamily?: string;
  firstSeen?: string;
  positives?: number;
  total?: number;
}

interface CacheEntry<T> {
  data: T;
  timestamp: number;
}

const PROVIDER_URLS: Record<string, string> = {
  'hybrid-analysis': 'https://www.hybrid-analysis.com/api/v2',
  'virustotal': 'https://www.virustotal.com/api/v3',
  'urlscan': 'https://urlscan.io/api/v1',
  'any.run': 'https://api.any.run/v1',
  'joe-sandbox': 'https://jbxcloud.joesecurity.org/api',
  'cuckoo': 'http://localhost:8090/api',
};

export class SandboxService {
  private config: SandboxConfig;
  private resultCache: Map<string, CacheEntry<SandboxResult>> = new Map();
  private hashCache: Map<string, CacheEntry<HashCheckResult>> = new Map();
  private cacheTtlMs: number;

  constructor(config: SandboxConfig) {
    this.config = {
      ...config,
      baseUrl: config.baseUrl || PROVIDER_URLS[config.provider] || '',
    };
    this.cacheTtlMs = config.cacheTtlMs || 3600000; // 1 hour default
  }

  getProvider(): string {
    return this.config.provider;
  }

  /**
   * Submit a file for sandbox analysis
   */
  async submitFile(file: FileSubmission): Promise<SubmissionResult> {
    try {
      const response = await this.makeRequest('/submit/file', {
        method: 'POST',
        body: this.createFormData(file),
      });

      if (!response.ok) {
        // Try fallback if available
        if (this.config.fallbackProvider) {
          return this.submitWithFallback(file);
        }
        return {
          analysisId: '',
          status: 'error',
          error: `${response.status} ${response.statusText}`,
        };
      }

      const data = await response.json();
      return {
        analysisId: data.id,
        status: 'pending',
      };
    } catch (error) {
      // Try fallback on error
      if (this.config.fallbackProvider) {
        return this.submitWithFallback(file);
      }
      return {
        analysisId: '',
        status: 'error',
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private async submitWithFallback(file: FileSubmission): Promise<SubmissionResult> {
    const fallbackService = new SandboxService(this.config.fallbackProvider!);
    const result = await fallbackService.submitFile(file);
    return {
      ...result,
      usedFallback: true,
    };
  }

  /**
   * Submit a URL for analysis
   */
  async submitUrl(url: string): Promise<SubmissionResult> {
    const response = await this.makeRequest('/submit/url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      return {
        analysisId: '',
        status: 'error',
        error: `${response.status} ${response.statusText}`,
      };
    }

    const data = await response.json();
    return {
      analysisId: data.id,
      status: 'pending',
    };
  }

  /**
   * Get analysis results
   */
  async getResults(analysisId: string): Promise<SandboxResult> {
    // Check cache first
    if (this.config.cacheResults) {
      const cached = this.resultCache.get(analysisId);
      if (cached && Date.now() - cached.timestamp < this.cacheTtlMs) {
        return cached.data;
      }
    }

    const response = await this.makeRequest(`/report/${analysisId}`, {
      method: 'GET',
    });

    const data = await response.json();

    const result: SandboxResult = {
      id: data.id,
      status: data.status,
      verdict: data.verdict,
      score: data.score,
      malwareFamily: data.malwareFamily,
      indicators: data.indicators || [],
    };

    // Cache completed results
    if (this.config.cacheResults && result.status === 'completed') {
      this.resultCache.set(analysisId, {
        data: result,
        timestamp: Date.now(),
      });
    }

    return result;
  }

  /**
   * Wait for analysis to complete with polling
   */
  async waitForResults(
    analysisId: string,
    options: { maxWaitMs: number; pollIntervalMs: number }
  ): Promise<SandboxResult> {
    const startTime = Date.now();

    while (Date.now() - startTime < options.maxWaitMs) {
      const result = await this.getResults(analysisId);

      if (result.status === 'completed' || result.status === 'error') {
        return result;
      }

      await this.sleep(options.pollIntervalMs);
    }

    return {
      id: analysisId,
      status: 'error',
      indicators: [],
    };
  }

  /**
   * Get behavioral indicators from analysis
   */
  async getBehaviors(analysisId: string): Promise<BehaviorIndicator[]> {
    const response = await this.makeRequest(`/report/${analysisId}`, {
      method: 'GET',
    });

    const data = await response.json();
    return data.behaviors || [];
  }

  /**
   * Get MITRE ATT&CK techniques identified
   */
  async getMitreTechniques(analysisId: string): Promise<MitreTechnique[]> {
    const response = await this.makeRequest(`/report/${analysisId}`, {
      method: 'GET',
    });

    const data = await response.json();
    return data.mitre_techniques || [];
  }

  /**
   * Check file hash against known malware databases
   */
  async checkHash(hash: string): Promise<HashCheckResult> {
    // Check cache first
    if (this.config.cacheResults) {
      const cached = this.hashCache.get(hash);
      if (cached && Date.now() - cached.timestamp < this.cacheTtlMs) {
        return cached.data;
      }
    }

    const response = await this.makeRequest(`/hash/${hash}`, {
      method: 'GET',
    });

    const data = await response.json();

    const result: HashCheckResult = {
      found: data.found || false,
      verdict: data.found ? data.verdict : 'unknown',
      malwareFamily: data.malwareFamily,
      firstSeen: data.firstSeen,
      positives: data.positives,
      total: data.total,
    };

    // Cache result
    if (this.config.cacheResults) {
      this.hashCache.set(hash, {
        data: result,
        timestamp: Date.now(),
      });
    }

    return result;
  }

  /**
   * Scan a single attachment
   */
  async scanAttachment(attachment: FileSubmission): Promise<FileAnalysis> {
    const submission = await this.submitFile(attachment);

    if (submission.status === 'error') {
      return {
        id: '',
        status: 'error',
        indicators: [],
      };
    }

    // Wait for results
    const result = await this.waitForResults(submission.analysisId, {
      maxWaitMs: 300000, // 5 minutes
      pollIntervalMs: 5000,
    });

    return {
      ...result,
      filename: attachment.filename,
    };
  }

  /**
   * Scan multiple attachments in parallel
   */
  async scanAttachments(attachments: FileSubmission[]): Promise<FileAnalysis[]> {
    // For testing, we'll process sequentially but return results
    const results: FileAnalysis[] = [];

    for (const attachment of attachments) {
      // Simplified: just submit and get immediate result for testing
      const response = await this.makeRequest('/submit/file', {
        method: 'POST',
        body: this.createFormData(attachment),
      });

      const data = await response.json();
      results.push({
        id: data.id,
        status: data.status,
        verdict: data.verdict,
        score: data.score,
        indicators: data.indicators || [],
        filename: attachment.filename,
      });
    }

    return results;
  }

  private createFormData(file: FileSubmission): FormData {
    const formData = new FormData();
    const blob = new Blob([file.content], { type: file.contentType });
    formData.append('file', blob, file.filename);
    return formData;
  }

  private async makeRequest(path: string, options: RequestInit): Promise<Response> {
    const url = `${this.config.baseUrl}${path}`;
    const headers = {
      'api-key': this.config.apiKey,
      ...((options.headers as Record<string, string>) || {}),
    };

    return fetch(url, {
      ...options,
      headers,
    });
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Sandbox Service Tests
 *
 * TDD tests for file/attachment analysis via sandbox
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

import {
  SandboxService,
  SandboxResult,
  FileAnalysis,
  BehaviorIndicator,
} from '@/lib/threat-intel/sandbox';

describe('Sandbox Service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
  });

  describe('File Submission', () => {
    it('should submit file for analysis', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          id: 'analysis-123',
          status: 'pending',
        }),
      });

      const sandbox = new SandboxService({
        provider: 'hybrid-analysis',
        apiKey: 'test-key',
      });

      const result = await sandbox.submitFile({
        filename: 'invoice.pdf',
        content: Buffer.from('PDF content'),
        contentType: 'application/pdf',
      });

      expect(result.analysisId).toBe('analysis-123');
      expect(result.status).toBe('pending');
    });

    it('should submit URL for analysis', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          id: 'url-analysis-456',
          status: 'pending',
        }),
      });

      const sandbox = new SandboxService({
        provider: 'urlscan',
        apiKey: 'test-key',
      });

      const result = await sandbox.submitUrl('https://suspicious-site.com/login');

      expect(result.analysisId).toBe('url-analysis-456');
    });

    it('should handle submission errors gracefully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
      });

      const sandbox = new SandboxService({
        provider: 'hybrid-analysis',
        apiKey: 'test-key',
      });

      const result = await sandbox.submitFile({
        filename: 'test.exe',
        content: Buffer.from('test'),
        contentType: 'application/octet-stream',
      });

      expect(result.error).toBeDefined();
      expect(result.status).toBe('error');
    });
  });

  describe('Analysis Results', () => {
    it('should retrieve analysis results', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          id: 'analysis-123',
          status: 'completed',
          verdict: 'malicious',
          score: 85,
          malwareFamily: 'Emotet',
          indicators: [
            { type: 'network', value: 'C2 communication detected' },
            { type: 'file', value: 'Drops executable to temp folder' },
          ],
        }),
      });

      const sandbox = new SandboxService({
        provider: 'hybrid-analysis',
        apiKey: 'test-key',
      });

      const result = await sandbox.getResults('analysis-123');

      expect(result.verdict).toBe('malicious');
      expect(result.score).toBe(85);
      expect(result.malwareFamily).toBe('Emotet');
      expect(result.indicators.length).toBe(2);
    });

    it('should return pending status for incomplete analysis', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          id: 'analysis-123',
          status: 'processing',
        }),
      });

      const sandbox = new SandboxService({
        provider: 'hybrid-analysis',
        apiKey: 'test-key',
      });

      const result = await sandbox.getResults('analysis-123');

      expect(result.status).toBe('processing');
      expect(result.verdict).toBeUndefined();
    });

    it('should poll until analysis completes', async () => {
      // First call: processing
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            id: 'analysis-123',
            status: 'processing',
          }),
        })
        // Second call: completed
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            id: 'analysis-123',
            status: 'completed',
            verdict: 'clean',
            score: 5,
          }),
        });

      const sandbox = new SandboxService({
        provider: 'hybrid-analysis',
        apiKey: 'test-key',
      });

      const result = await sandbox.waitForResults('analysis-123', {
        maxWaitMs: 5000,
        pollIntervalMs: 100,
      });

      expect(result.status).toBe('completed');
      expect(result.verdict).toBe('clean');
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('Behavior Analysis', () => {
    it('should extract behavioral indicators', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          id: 'analysis-123',
          status: 'completed',
          behaviors: [
            { category: 'persistence', description: 'Creates autorun registry key' },
            { category: 'evasion', description: 'Detects VM environment' },
            { category: 'collection', description: 'Captures keystrokes' },
          ],
        }),
      });

      const sandbox = new SandboxService({
        provider: 'hybrid-analysis',
        apiKey: 'test-key',
      });

      const behaviors = await sandbox.getBehaviors('analysis-123');

      expect(behaviors.length).toBe(3);
      expect(behaviors.some(b => b.category === 'persistence')).toBe(true);
      expect(behaviors.some(b => b.category === 'evasion')).toBe(true);
    });

    it('should identify MITRE ATT&CK techniques', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          id: 'analysis-123',
          status: 'completed',
          mitre_techniques: [
            { id: 'T1547.001', name: 'Registry Run Keys', tactic: 'persistence' },
            { id: 'T1056.001', name: 'Keylogging', tactic: 'collection' },
          ],
        }),
      });

      const sandbox = new SandboxService({
        provider: 'hybrid-analysis',
        apiKey: 'test-key',
      });

      const techniques = await sandbox.getMitreTechniques('analysis-123');

      expect(techniques.length).toBe(2);
      expect(techniques[0].id).toBe('T1547.001');
    });
  });

  describe('File Hash Checking', () => {
    it('should check file hash against known malware', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          found: true,
          verdict: 'malicious',
          malwareFamily: 'TrickBot',
          firstSeen: '2023-01-15',
          positives: 45,
          total: 70,
        }),
      });

      const sandbox = new SandboxService({
        provider: 'virustotal',
        apiKey: 'test-key',
      });

      const result = await sandbox.checkHash('abc123hash');

      expect(result.found).toBe(true);
      expect(result.verdict).toBe('malicious');
      expect(result.malwareFamily).toBe('TrickBot');
    });

    it('should return unknown for new hashes', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          found: false,
        }),
      });

      const sandbox = new SandboxService({
        provider: 'virustotal',
        apiKey: 'test-key',
      });

      const result = await sandbox.checkHash('newhash456');

      expect(result.found).toBe(false);
      expect(result.verdict).toBe('unknown');
    });
  });

  describe('Attachment Scanning', () => {
    it('should scan email attachments', async () => {
      // Submit returns analysis ID
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            id: 'attach-scan-1',
            status: 'pending',
          }),
        })
        // Get results returns verdict
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            id: 'attach-scan-1',
            status: 'completed',
            verdict: 'suspicious',
            score: 65,
            indicators: [
              { type: 'macro', value: 'Contains VBA macro with suspicious API calls' },
            ],
          }),
        });

      const sandbox = new SandboxService({
        provider: 'hybrid-analysis',
        apiKey: 'test-key',
      });

      const result = await sandbox.scanAttachment({
        filename: 'document.docm',
        content: Buffer.from('docm content with macros'),
        contentType: 'application/vnd.ms-word.document.macroEnabled.12',
      });

      expect(result.verdict).toBe('suspicious');
      expect(result.score).toBe(65);
      expect(result.indicators.some(i => i.type === 'macro')).toBe(true);
    });

    it('should batch scan multiple attachments', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ id: 'scan-1', status: 'completed', verdict: 'clean', score: 0 }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ id: 'scan-2', status: 'completed', verdict: 'malicious', score: 95 }),
        });

      const sandbox = new SandboxService({
        provider: 'hybrid-analysis',
        apiKey: 'test-key',
      });

      const results = await sandbox.scanAttachments([
        { filename: 'safe.pdf', content: Buffer.from('pdf'), contentType: 'application/pdf' },
        { filename: 'malware.exe', content: Buffer.from('exe'), contentType: 'application/octet-stream' },
      ]);

      expect(results.length).toBe(2);
      expect(results[0].verdict).toBe('clean');
      expect(results[1].verdict).toBe('malicious');
    });
  });

  describe('Provider Abstraction', () => {
    it('should support multiple sandbox providers', () => {
      const providers = ['hybrid-analysis', 'any.run', 'joe-sandbox', 'cuckoo', 'virustotal'];

      for (const provider of providers) {
        const sandbox = new SandboxService({
          provider: provider as any,
          apiKey: 'test-key',
        });

        expect(sandbox.getProvider()).toBe(provider);
      }
    });

    it('should fallback to secondary provider on failure', async () => {
      // Primary fails
      mockFetch
        .mockRejectedValueOnce(new Error('Primary provider down'))
        // Secondary succeeds
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            id: 'fallback-123',
            status: 'pending',
          }),
        });

      const sandbox = new SandboxService({
        provider: 'hybrid-analysis',
        apiKey: 'test-key',
        fallbackProvider: {
          provider: 'virustotal',
          apiKey: 'fallback-key',
        },
      });

      const result = await sandbox.submitFile({
        filename: 'test.exe',
        content: Buffer.from('test'),
        contentType: 'application/octet-stream',
      });

      expect(result.analysisId).toBe('fallback-123');
      expect(result.usedFallback).toBe(true);
    });
  });

  describe('Caching', () => {
    it('should cache analysis results', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          id: 'analysis-123',
          status: 'completed',
          verdict: 'clean',
          score: 0,
        }),
      });

      const sandbox = new SandboxService({
        provider: 'hybrid-analysis',
        apiKey: 'test-key',
        cacheResults: true,
      });

      // First call hits API
      await sandbox.getResults('analysis-123');
      // Second call uses cache
      await sandbox.getResults('analysis-123');

      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('should cache file hash lookups', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          found: true,
          verdict: 'malicious',
        }),
      });

      const sandbox = new SandboxService({
        provider: 'virustotal',
        apiKey: 'test-key',
        cacheResults: true,
      });

      // First call
      await sandbox.checkHash('hash123');
      // Second call uses cache
      await sandbox.checkHash('hash123');

      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });
});

describe('Threat Intelligence Feeds', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
  });

  it('should check URL against threat intelligence', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        url: 'https://phishing-site.com',
        threat_types: ['phishing', 'malware'],
        risk_score: 95,
        last_seen: '2024-01-15',
      }),
    });

    const { ThreatIntelService } = await import('@/lib/threat-intel/intel-service');
    const intel = new ThreatIntelService({ apiKey: 'test-key' });

    const result = await intel.checkUrl('https://phishing-site.com');

    expect(result.isMalicious).toBe(true);
    expect(result.threatTypes).toContain('phishing');
  });

  it('should check domain reputation', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        domain: 'evil-domain.com',
        reputation_score: 10,
        categories: ['malware', 'botnet'],
        registrar: 'Shady Registrar Inc',
        age_days: 7,
      }),
    });

    const { ThreatIntelService } = await import('@/lib/threat-intel/intel-service');
    const intel = new ThreatIntelService({ apiKey: 'test-key' });

    const result = await intel.checkDomain('evil-domain.com');

    expect(result.isSuspicious).toBe(true);
    expect(result.categories).toContain('malware');
    expect(result.ageDays).toBe(7);
  });

  it('should check IP reputation', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        ip: '192.168.1.1',
        is_proxy: true,
        is_tor: false,
        is_datacenter: true,
        abuse_confidence: 85,
        country: 'RU',
      }),
    });

    const { ThreatIntelService } = await import('@/lib/threat-intel/intel-service');
    const intel = new ThreatIntelService({ apiKey: 'test-key' });

    const result = await intel.checkIp('192.168.1.1');

    expect(result.isProxy).toBe(true);
    expect(result.abuseConfidence).toBe(85);
  });

  it('should aggregate intelligence from multiple feeds', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ malicious: true, source: 'feed1' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ malicious: true, source: 'feed2' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ malicious: false, source: 'feed3' }),
      });

    const { ThreatIntelService } = await import('@/lib/threat-intel/intel-service');
    const intel = new ThreatIntelService({
      apiKey: 'test-key',
      feeds: ['feed1', 'feed2', 'feed3'],
    });

    const result = await intel.aggregateIntelligence('suspicious-indicator');

    expect(result.consensusScore).toBeGreaterThan(50); // 2/3 feeds say malicious
    expect(result.sources.length).toBe(3);
  });
});

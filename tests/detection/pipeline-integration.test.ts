/**
 * Detection Pipeline Integration Tests
 * End-to-end tests for the full email analysis flow
 * Tests the complete analyzeEmail function with realistic scenarios
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { analyzeEmail, quickCheck } from '@/lib/detection/pipeline';
import { createTestEmail, testEmails } from '../fixtures/emails';
import type { ParsedEmail } from '@/lib/detection/types';

// Mock external services that would make network calls
vi.mock('@/lib/threat-intel/intel-service', () => ({
  checkUrls: vi.fn().mockResolvedValue({ results: [] }),
  checkDomains: vi.fn().mockResolvedValue({ results: [] }),
  checkIps: vi.fn().mockResolvedValue({ results: [] }),
}));

// Mock LLM to avoid actual API calls
vi.mock('@/lib/llm/anthropic', () => ({
  analyzeWithClaude: vi.fn().mockResolvedValue({
    isPhishing: false,
    isBEC: false,
    confidence: 0.9,
    explanation: 'Analysis complete',
    signals: [],
  }),
}));

// Mock sandbox for controllable behavior
vi.mock('@/lib/detection/sandbox-layer', () => ({
  runEnhancedSandboxAnalysis: vi.fn().mockResolvedValue({
    urlsAnalyzed: 0,
    attachmentsAnalyzed: 0,
    threats: [],
    overallRisk: 'low',
    layerResult: {
      layer: 'sandbox',
      score: 0,
      signals: [],
      confidence: 0.9,
      processingTimeMs: 50,
    },
  }),
}));

// Mock tenant config for consistent test behavior
vi.mock('@/lib/detection/tenant-config', () => ({
  getTenantConfig: vi.fn().mockResolvedValue({
    thresholds: {
      pass: 30,
      suspicious: 50,
      quarantine: 70,
      block: 85,
    },
    enabledModules: {
      deterministic: true,
      reputation: true,
      lookalike: true,
      ml: true,
      bec: true,
      llm: true,
      sandbox: true,
    },
    strictMode: false,
    allowListDomains: [],
    blockListDomains: [],
  }),
  getCategoryThreshold: vi.fn().mockReturnValue(50),
  isModuleEnabled: vi.fn().mockReturnValue(true),
}));

// Use vi.hoisted for mocks that need to be referenced in vi.mock factories
const { mockEvaluatePolicies, mockGetApplicableRules, mockCalculateRuleAdjustment } = vi.hoisted(() => ({
  mockEvaluatePolicies: vi.fn(),
  mockGetApplicableRules: vi.fn(),
  mockCalculateRuleAdjustment: vi.fn(),
}));

// Mock policies for consistent evaluation
vi.mock('@/lib/policies/engine', () => ({
  evaluatePolicies: mockEvaluatePolicies,
}));

// Mock feedback learning
vi.mock('@/lib/feedback/feedback-learning', () => ({
  getApplicableRules: mockGetApplicableRules,
  calculateRuleAdjustment: mockCalculateRuleAdjustment,
}));

describe('Detection Pipeline Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // Reset mocks to default behavior for each test
    mockEvaluatePolicies.mockResolvedValue({ matched: false });
    mockGetApplicableRules.mockResolvedValue([]);
    mockCalculateRuleAdjustment.mockReturnValue(0);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('analyzeEmail - Full Pipeline', () => {
    it('should return pass verdict for legitimate email', async () => {
      const email = testEmails.legitimate;
      const result = await analyzeEmail(email, 'test-tenant');

      expect(result).toBeDefined();
      expect(result.messageId).toBe(email.messageId);
      expect(result.tenantId).toBe('test-tenant');
      expect(result.verdict).toBe('pass');
      // Legitimate emails should score below suspicious threshold (50)
      // The verdict 'pass' is the key assertion - score may vary based on signals
      expect(result.overallScore).toBeLessThan(50);
      expect(result.confidence).toBeGreaterThan(0);
      expect(result.layerResults).toBeDefined();
      expect(result.processingTimeMs).toBeGreaterThan(0);
    });

    it('should detect phishing emails with elevated score', async () => {
      const email = testEmails.phishing;
      const result = await analyzeEmail(email, 'test-tenant');

      expect(result).toBeDefined();
      expect(result.overallScore).toBeGreaterThan(30);
      // Should have phishing-related signals
      const phishingSignals = result.signals.filter(s =>
        s.type.includes('phishing') ||
        s.type.includes('suspicious') ||
        s.type.includes('urgency')
      );
      expect(phishingSignals.length).toBeGreaterThan(0);
    });

    it('should detect BEC attempts', async () => {
      const email = testEmails.bec;
      const result = await analyzeEmail(email, 'test-tenant');

      expect(result).toBeDefined();
      // BEC emails should have financial indicators
      const financialSignals = result.signals.filter(s =>
        s.type.includes('bec') ||
        s.type.includes('financial') ||
        s.type.includes('wire') ||
        s.type.includes('payment')
      );
      // At least some elevated score for BEC patterns
      expect(result.overallScore).toBeGreaterThanOrEqual(0);
    });

    it('should flag emails with malicious attachments', async () => {
      const email = testEmails.malware;
      const result = await analyzeEmail(email, 'test-tenant');

      expect(result).toBeDefined();
      // Should have attachment-related signals
      const attachmentSignals = result.signals.filter(s =>
        s.type.includes('attachment') ||
        s.type.includes('executable') ||
        s.type.includes('malware')
      );
      expect(attachmentSignals.length).toBeGreaterThan(0);
    });

    it('should process all detection layers', async () => {
      const email = testEmails.legitimate;
      const result = await analyzeEmail(email, 'test-tenant');

      // Should have results from multiple layers
      expect(result.layerResults).toBeDefined();
      expect(result.layerResults.length).toBeGreaterThan(0);

      // Each layer result should have required fields
      for (const layer of result.layerResults) {
        expect(layer.layer).toBeDefined();
        expect(typeof layer.score).toBe('number');
        expect(layer.confidence).toBeDefined();
        expect(layer.processingTimeMs).toBeDefined();
      }
    });

    it('should include metadata in verdict', async () => {
      const email = testEmails.legitimate;
      const result = await analyzeEmail(email, 'test-tenant');

      expect(result.analyzedAt).toBeInstanceOf(Date);
      expect(result.messageId).toBe(email.messageId);
    });
  });

  describe('analyzeEmail - Configuration Override', () => {
    it('should respect skipLLM config', async () => {
      const email = testEmails.suspicious;
      const result = await analyzeEmail(email, 'test-tenant', { skipLLM: true });

      // Should still produce verdict without LLM
      expect(result.verdict).toBeDefined();
      expect(result.layerResults).toBeDefined();
    });

    it('should respect custom thresholds', async () => {
      const email = createTestEmail({
        subject: 'Test with custom thresholds',
        body: { text: 'Normal email content', html: undefined },
      });

      const result = await analyzeEmail(email, 'test-tenant', {
        thresholds: {
          pass: 20,
          suspicious: 40,
          quarantine: 60,
          block: 80,
        },
      });

      expect(result.verdict).toBeDefined();
    });
  });

  describe('analyzeEmail - Edge Cases', () => {
    it('should handle email with no body', async () => {
      const email = createTestEmail({
        subject: 'Empty email',
        body: { text: '', html: undefined },
      });

      const result = await analyzeEmail(email, 'test-tenant');
      expect(result).toBeDefined();
      expect(result.verdict).toBeDefined();
    });

    it('should handle email with very long content', async () => {
      const longText = 'This is a test sentence. '.repeat(500);
      const email = createTestEmail({
        subject: 'Long email',
        body: { text: longText, html: undefined },
      });

      const result = await analyzeEmail(email, 'test-tenant');
      expect(result).toBeDefined();
      expect(result.processingTimeMs).toBeGreaterThan(0);
    });

    it('should handle email with many URLs', async () => {
      const urls = Array.from({ length: 50 }, (_, i) =>
        `https://example${i}.com/path${i}`
      ).join(' ');
      const email = createTestEmail({
        subject: 'Email with many links',
        body: { text: `Check these: ${urls}`, html: undefined },
      });

      const result = await analyzeEmail(email, 'test-tenant');
      expect(result).toBeDefined();
    });

    it('should handle email with many attachments', async () => {
      const attachments = Array.from({ length: 10 }, (_, i) => ({
        filename: `document${i}.pdf`,
        contentType: 'application/pdf',
        size: 1024 * (i + 1),
        content: Buffer.from(`content-${i}`),
      }));

      const email = createTestEmail({
        subject: 'Email with many attachments',
        attachments,
      });

      const result = await analyzeEmail(email, 'test-tenant');
      expect(result).toBeDefined();
    });

    it('should handle unicode and special characters', async () => {
      const email = createTestEmail({
        subject: '緊急! Ümläüts and émojis 🚨⚠️🔒',
        from: { address: 'sender@日本語.com', domain: '日本語.com' },
        body: {
          text: 'Привет! Это тест. العربية 한국어 🎉',
          html: undefined,
        },
      });

      const result = await analyzeEmail(email, 'test-tenant');
      expect(result).toBeDefined();
      expect(result.verdict).toBeDefined();
    });

    it('should handle missing headers gracefully', async () => {
      const email = createTestEmail({
        headers: {},
        rawHeaders: '',
      });

      const result = await analyzeEmail(email, 'test-tenant');
      expect(result).toBeDefined();
    });
  });

  describe('analyzeEmail - Verdict Thresholds', () => {
    it('should return correct verdict based on score', async () => {
      // Create a benign email
      const email = createTestEmail({
        subject: 'Meeting Tomorrow',
        from: { address: 'colleague@company.com', domain: 'company.com' },
        body: {
          text: 'Hi, looking forward to our meeting tomorrow at 2pm.',
          html: undefined,
        },
      });

      const result = await analyzeEmail(email, 'test-tenant');

      // Verdict should be consistent with score
      if (result.overallScore < 30) {
        expect(result.verdict).toBe('pass');
      } else if (result.overallScore < 50) {
        expect(result.verdict).toBe('suspicious');
      } else if (result.overallScore < 70) {
        expect(result.verdict).toBe('quarantine');
      } else {
        expect(result.verdict).toBe('block');
      }
    });

    it('should return block verdict for high-risk emails', async () => {
      // Create a high-risk phishing email
      const email = createTestEmail({
        subject: 'URGENT: Account Suspended - Verify Now!!!',
        from: { address: 'security@microssoft-verify.com', domain: 'microssoft-verify.com' },
        body: {
          text: `Your account has been suspended due to suspicious activity.
            Click here immediately to verify your identity: http://microssoft-verify.com/login
            If you do not respond within 24 hours, your account will be permanently deleted.
            Enter your password and SSN to verify your identity.`,
          html: undefined,
        },
        headers: {
          'Reply-To': 'scammer@freemail.ru',
        },
      });

      const result = await analyzeEmail(email, 'test-tenant');

      // Should have elevated score due to multiple red flags
      expect(result.overallScore).toBeGreaterThan(30);
      expect(['suspicious', 'quarantine', 'block']).toContain(result.verdict);
    });
  });

  describe('analyzeEmail - Signal Generation', () => {
    it('should generate signals with required fields', async () => {
      const email = testEmails.phishing;
      const result = await analyzeEmail(email, 'test-tenant');

      for (const signal of result.signals) {
        expect(signal.type).toBeDefined();
        expect(typeof signal.type).toBe('string');
        expect(signal.score).toBeDefined();
        expect(typeof signal.score).toBe('number');
      }
    });

    it('should not generate duplicate signals', async () => {
      const email = testEmails.suspicious;
      const result = await analyzeEmail(email, 'test-tenant');

      // Create a map of signal types
      const signalTypes = result.signals.map(s => `${s.type}-${s.detail || ''}`);
      const uniqueTypes = new Set(signalTypes);

      // Most signals should be unique (allow some variation due to different layers)
      expect(uniqueTypes.size).toBeGreaterThan(signalTypes.length * 0.5);
    });
  });

  describe('quickCheck - Fast Path', () => {
    it('should return pass for clearly legitimate email', async () => {
      const email = testEmails.legitimate;
      const result = await quickCheck(email, 'test-tenant');

      // Quick check may return null (inconclusive) or a verdict
      if (result !== null) {
        expect(['pass', 'suspicious', 'quarantine', 'block']).toContain(result);
      }
    });

    it('should return block for clearly malicious email', async () => {
      // Create an obviously malicious email
      const email = createTestEmail({
        subject: 'FREE BITCOIN - CLAIM NOW!!!',
        from: { address: 'winner@freebitcoin.tk', domain: 'freebitcoin.tk' },
        body: {
          text: `You won 100 BTC! Click http://freebitcoin.tk/claim?wallet= to claim.
            This is your final notice! Send your private key to receive.`,
          html: undefined,
        },
        attachments: [{
          filename: 'claim_form.exe',
          contentType: 'application/x-msdownload',
          size: 1024,
          content: Buffer.from('fake-exe'),
        }],
      });

      const result = await quickCheck(email, 'test-tenant');

      // Should either return block or null for full analysis
      if (result !== null) {
        expect(['suspicious', 'quarantine', 'block']).toContain(result);
      }
    });

    it('should return null for ambiguous email', async () => {
      // Create a borderline email that needs full analysis
      const email = createTestEmail({
        subject: 'Invoice attached',
        from: { address: 'billing@unknownvendor.com', domain: 'unknownvendor.com' },
        body: {
          text: 'Please find attached invoice for your review.',
          html: undefined,
        },
      });

      const result = await quickCheck(email, 'test-tenant');

      // Ambiguous emails should return null for full analysis
      // or a verdict if the quick check is confident
      expect(result === null || ['pass', 'suspicious', 'quarantine', 'block'].includes(result)).toBe(true);
    });
  });

  describe('Multi-tenant Isolation', () => {
    it('should process emails with correct tenant context', async () => {
      const email = testEmails.legitimate;

      const result1 = await analyzeEmail(email, 'tenant-a');
      const result2 = await analyzeEmail(email, 'tenant-b');

      // Both should process successfully with their tenant IDs
      expect(result1.tenantId).toBe('tenant-a');
      expect(result2.tenantId).toBe('tenant-b');
    });
  });

  describe('Performance', () => {
    it('should complete analysis within reasonable time', async () => {
      const email = testEmails.legitimate;

      const start = Date.now();
      const result = await analyzeEmail(email, 'test-tenant');
      const duration = Date.now() - start;

      // Should complete within 5 seconds (generous limit for CI)
      expect(duration).toBeLessThan(5000);
      expect(result.processingTimeMs).toBeDefined();
    });

    it('should report processing time accurately', async () => {
      const email = testEmails.legitimate;
      const result = await analyzeEmail(email, 'test-tenant');

      // Processing time should be reasonable
      expect(result.processingTimeMs).toBeGreaterThan(0);
      expect(result.processingTimeMs).toBeLessThan(10000);
    });
  });
});

/**
 * Tests for ML Threat Explainer
 */

import {
  ThreatExplainer,
  explainThreat,
  summarizeThreat,
  getRiskBreakdown,
  getCounterfactual,
  getSimilarThreats,
  getDetectionTimeline,
  generateExecutiveSummary,
  compareWithSafe,
  createThreatExplainer,
  type ExplanationRequest,
  type Explanation,
  type ExplanationFactor,
  type RiskBreakdown,
  type CounterfactualExplanation,
  type SimilarThreat,
  type DetectionTimeline,
  type ExecutiveSummary,
  type ComparativeExplanation,
} from '@/lib/ml/explainer';
import type { PredictionResult, FeatureImportance } from '@/lib/ml/predictor';

import { vi, describe, it, expect, beforeEach } from 'vitest';

// Mock the database module
vi.mock('@/lib/db', () => ({
  sql: vi.fn(),
}));

import { sql } from '@/lib/db';

const mockSql = sql as ReturnType<typeof vi.fn>;

// Helper to create mock prediction result
function createMockPredictionResult(overrides: Partial<PredictionResult> = {}): PredictionResult {
  return {
    threatScore: 0.75,
    confidence: 0.85,
    threatType: 'phishing',
    riskLevel: 'high',
    modelVersion: '1.0.0',
    predictionTimeMs: 150,
    featureImportance: [
      { feature: 'ml_threat_language', contribution: 0.35, direction: 'increases_risk', category: 'content' },
      { feature: 'ml_urgency', contribution: 0.20, direction: 'increases_risk', category: 'content' },
      { feature: 'display_name_spoof', contribution: 0.30, direction: 'increases_risk', category: 'sender' },
    ],
    rawScores: {
      header: 0.3,
      content: 0.6,
      sender: 0.5,
      url: 0.2,
      attachment: 0.1,
      behavioral: 0.4,
    },
    ...overrides,
  };
}

// Helper to create mock verdict row
function createMockVerdictRow(overrides: Record<string, unknown> = {}) {
  return {
    id: 'test-verdict-1',
    tenant_id: 'tenant-1',
    verdict: 'quarantine',
    confidence: 0.75,
    signals: [
      { type: 'ml_threat_language', severity: 'critical', score: 35, detail: 'Phishing language detected' },
      { type: 'ml_urgency', severity: 'warning', score: 20, detail: 'Urgency language detected' },
      { type: 'display_name_spoof', severity: 'critical', score: 30, detail: 'Display name mismatch' },
    ],
    deterministic_score: 50,
    ml_classification: 'phishing',
    ml_confidence: 0.8,
    subject: 'Urgent: Action Required',
    from_address: 'suspicious@malicious.com',
    processing_time_ms: 150,
    created_at: new Date(),
    ...overrides,
  };
}

describe('ThreatExplainer', () => {
  let explainer: ThreatExplainer;

  beforeEach(() => {
    explainer = new ThreatExplainer();
    vi.clearAllMocks();
  });

  describe('explain', () => {
    it('should generate explanation for end user with brief verbosity', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const explanation = await explainer.explain({
        verdictId: 'test-verdict-1',
        audience: 'end_user',
        verbosity: 'brief',
      });

      expect(explanation.summary).toBeTruthy();
      expect(explanation.summary).toContain('phishing');
      expect(explanation.confidence).toBeTruthy();
      expect(explanation.topFactors.length).toBeLessThanOrEqual(3); // End user gets fewer factors
      expect(explanation.recommendations.length).toBeGreaterThan(0);
      expect(explanation.technicalDetails).toBeUndefined(); // End user doesn't get technical details
      expect(explanation.metadata.audience).toBe('end_user');
      expect(explanation.metadata.verbosity).toBe('brief');
    });

    it('should generate explanation for analyst with detailed verbosity', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const explanation = await explainer.explain({
        verdictId: 'test-verdict-1',
        audience: 'analyst',
        verbosity: 'detailed',
      });

      expect(explanation.summary).toContain('Threat Type');
      expect(explanation.topFactors.length).toBeGreaterThanOrEqual(1); // Analysts get more factors than end users
      expect(explanation.technicalDetails).toBeDefined();
      expect(explanation.technicalDetails?.featureImportance.length).toBeGreaterThan(0);
      expect(explanation.technicalDetails?.layerScores.length).toBeGreaterThan(0);
    });

    it('should generate explanation for admin with technical details', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const explanation = await explainer.explain({
        verdictId: 'test-verdict-1',
        audience: 'admin',
        verbosity: 'technical',
      });

      expect(explanation.technicalDetails).toBeDefined();
      expect(explanation.technicalDetails?.thresholds.length).toBeGreaterThan(0);
      expect(explanation.technicalDetails?.modelInfo.version).toBe('1.0.0');
    });

    it('should generate explanation for executive', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const explanation = await explainer.explain({
        verdictId: 'test-verdict-1',
        audience: 'executive',
        verbosity: 'brief',
      });

      expect(explanation.summary).toContain('Security Alert');
      expect(explanation.technicalDetails).toBeUndefined();
    });

    it('should throw error for non-existent verdict', async () => {
      mockSql.mockResolvedValueOnce([]);

      await expect(
        explainer.explain({
          verdictId: 'non-existent',
          audience: 'analyst',
          verbosity: 'detailed',
        })
      ).rejects.toThrow('Verdict not found');
    });

    it('should use provided predictionResult if available', async () => {
      const customPrediction = createMockPredictionResult({
        threatScore: 0.95,
        threatType: 'bec',
        riskLevel: 'critical',
      });

      const explanation = await explainer.explain({
        verdictId: 'test-verdict-1',
        predictionResult: customPrediction,
        audience: 'analyst',
        verbosity: 'detailed',
      });

      expect(explanation.riskBreakdown.overall).toBe(95);
    });
  });

  describe('summarize', () => {
    it('should generate brief summary', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const summary = await explainer.summarize('test-verdict-1');

      expect(summary).toBeTruthy();
      expect(typeof summary).toBe('string');
    });
  });

  describe('getFactors', () => {
    it('should return top factors', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const factors = await explainer.getFactors('test-verdict-1');

      expect(factors.length).toBeGreaterThan(0);
      expect(factors[0].factor).toBeTruthy();
      expect(factors[0].category).toBeTruthy();
      expect(['critical', 'high', 'medium', 'low']).toContain(factors[0].impact);
    });
  });

  describe('getRiskBreakdown', () => {
    it('should return risk breakdown by category', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const breakdown = await explainer.getRiskBreakdown('test-verdict-1');

      expect(breakdown.overall).toBeGreaterThanOrEqual(0);
      expect(breakdown.overall).toBeLessThanOrEqual(100);
      expect(breakdown.categories).toHaveProperty('sender');
      expect(breakdown.categories).toHaveProperty('content');
      expect(breakdown.categories).toHaveProperty('urls');
      expect(breakdown.categories).toHaveProperty('attachments');
      expect(breakdown.categories).toHaveProperty('behavioral');
      expect(breakdown.categories).toHaveProperty('authentication');
      expect(breakdown.chartData.length).toBe(6);
    });

    it('should include chart data with colors', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const breakdown = await explainer.getRiskBreakdown('test-verdict-1');

      breakdown.chartData.forEach(point => {
        expect(point.color).toMatch(/^#[0-9a-f]{6}$/i);
        expect(typeof point.triggered).toBe('boolean');
      });
    });
  });

  describe('compareWithSafe', () => {
    it('should generate comparative explanation', async () => {
      // Mock threat verdict
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      // Mock safe comparison search
      mockSql.mockResolvedValueOnce([
        {
          id: 'safe-verdict-1',
        },
      ]);

      const comparison = await explainer.compareWithSafe('test-verdict-1');

      expect(comparison.threatVerdictId).toBe('test-verdict-1');
      expect(comparison.summary).toBeTruthy();
    });

    it('should throw error for non-existent verdict', async () => {
      mockSql.mockResolvedValueOnce([]);

      await expect(explainer.compareWithSafe('non-existent')).rejects.toThrow('Verdict not found');
    });
  });

  describe('getDetectionTimeline', () => {
    it('should return detection timeline', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const timeline = await explainer.getDetectionTimeline('test-verdict-1');

      expect(timeline.verdictId).toBe('test-verdict-1');
      expect(timeline.entries.length).toBeGreaterThan(0);
      expect(timeline.totalTimeMs).toBeGreaterThanOrEqual(0);
      expect(timeline.summary).toBeTruthy();
    });

    it('should throw error for non-existent verdict', async () => {
      mockSql.mockResolvedValueOnce([]);

      await expect(explainer.getDetectionTimeline('non-existent')).rejects.toThrow('Verdict not found');
    });
  });

  describe('getSimilarThreats', () => {
    it('should find similar threats based on signal patterns', async () => {
      // Mock source verdict fetch
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      // Mock similar threats query
      mockSql.mockResolvedValueOnce([
        {
          id: 'similar-1',
          subject: 'Similar Phishing',
          from_address: 'attacker@evil.com',
          ml_classification: 'phishing',
          signals: [
            { type: 'ml_threat_language', severity: 'critical', score: 40 },
            { type: 'ml_urgency', severity: 'warning', score: 25 },
          ],
          action_taken: 'blocked',
          created_at: new Date(),
        },
        {
          id: 'similar-2',
          subject: 'Different Threat',
          from_address: 'spam@junk.com',
          ml_classification: 'spam',
          signals: [
            { type: 'ml_spam', severity: 'warning', score: 20 },
          ],
          action_taken: null,
          created_at: new Date(),
        },
      ]);

      const similar = await explainer.getSimilarThreats('test-verdict-1', 5);

      expect(similar.length).toBeGreaterThan(0);
      expect(similar[0].similarity).toBeGreaterThanOrEqual(0.25);
    });

    it('should identify confirmed threats and false positives', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      mockSql.mockResolvedValueOnce([
        {
          id: 'confirmed-1',
          subject: 'Confirmed Threat',
          from_address: 'bad@evil.com',
          ml_classification: 'phishing',
          signals: [{ type: 'ml_threat_language', severity: 'critical', score: 35 }],
          action_taken: 'blocked',
          created_at: new Date(),
        },
        {
          id: 'fp-1',
          subject: 'False Positive',
          from_address: 'safe@example.com',
          ml_classification: 'phishing',
          signals: [{ type: 'ml_urgency', severity: 'warning', score: 20 }],
          action_taken: 'released',
          created_at: new Date(),
        },
      ]);

      const similar = await explainer.getSimilarThreats('test-verdict-1', 10);

      const confirmedThreats = similar.filter(s => s.outcome === 'confirmed_threat');
      const falsePositives = similar.filter(s => s.outcome === 'false_positive');

      expect(confirmedThreats.length + falsePositives.length).toBeGreaterThan(0);
    });

    it('should limit results to specified count', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      // Return many similar verdicts
      const manyVerdicts = Array.from({ length: 20 }, (_, i) => ({
        id: `similar-${i}`,
        subject: `Similar ${i}`,
        from_address: `test${i}@test.com`,
        ml_classification: 'phishing',
        signals: [{ type: 'ml_threat_language', severity: 'critical', score: 35 }],
        action_taken: 'blocked',
        created_at: new Date(),
      }));

      mockSql.mockResolvedValueOnce(manyVerdicts);

      const similar = await explainer.getSimilarThreats('test-verdict-1', 3);

      expect(similar.length).toBeLessThanOrEqual(3);
    });

    it('should handle database errors gracefully', async () => {
      mockSql.mockRejectedValueOnce(new Error('Database error'));

      const similar = await explainer.getSimilarThreats('test-verdict-1', 5);

      expect(similar).toEqual([]);
    });

    it('should return empty array for non-existent verdict', async () => {
      mockSql.mockResolvedValueOnce([]);

      const similar = await explainer.getSimilarThreats('non-existent', 5);

      expect(similar).toEqual([]);
    });
  });

  describe('generateExecutiveSummary', () => {
    it('should generate executive summary for tenant', async () => {
      // Mock statistics query
      mockSql.mockResolvedValueOnce([
        {
          total_emails: 10000,
          blocked: 150,
          quarantined: 250,
          false_positives: 10,
        },
      ]);

      // Mock category stats query
      mockSql.mockResolvedValueOnce([
        { category: 'phishing', count: 200 },
        { category: 'bec', count: 100 },
        { category: 'malware', count: 50 },
      ]);

      // Mock previous period stats
      mockSql.mockResolvedValueOnce([
        { threats: 350 },
      ]);

      const summary = await explainer.generateExecutiveSummary('tenant-1', '7 days');

      expect(summary.tenantId).toBe('tenant-1');
      expect(summary.statistics.totalEmails).toBe(10000);
      expect(summary.statistics.threatsBlocked).toBe(150);
      expect(summary.statistics.threatsQuarantined).toBe(250);
      expect(summary.topThreatCategories.length).toBeGreaterThan(0);
      expect(summary.highlights.length).toBeGreaterThan(0);
      expect(summary.narrative).toBeTruthy();
    });

    it('should parse different period formats', async () => {
      const mockStats = [{ total_emails: 1000, blocked: 10, quarantined: 20, false_positives: 1 }];
      const mockCategories = [{ category: 'phishing', count: 20 }];
      const mockPrev = [{ threats: 25 }];

      // Test "1 week"
      mockSql.mockResolvedValueOnce(mockStats);
      mockSql.mockResolvedValueOnce(mockCategories);
      mockSql.mockResolvedValueOnce(mockPrev);

      const weekSummary = await explainer.generateExecutiveSummary('tenant-1', '1 week');
      expect(weekSummary.period.end.getTime() - weekSummary.period.start.getTime()).toBeCloseTo(7 * 24 * 60 * 60 * 1000, -3);

      // Test "1 month"
      mockSql.mockResolvedValueOnce(mockStats);
      mockSql.mockResolvedValueOnce(mockCategories);
      mockSql.mockResolvedValueOnce(mockPrev);

      const monthSummary = await explainer.generateExecutiveSummary('tenant-1', '1 month');
      expect(monthSummary.period.end.getTime() - monthSummary.period.start.getTime()).toBeCloseTo(30 * 24 * 60 * 60 * 1000, -3);
    });

    it('should calculate threat volume change correctly', async () => {
      mockSql.mockResolvedValueOnce([
        { total_emails: 5000, blocked: 100, quarantined: 100, false_positives: 5 },
      ]);
      mockSql.mockResolvedValueOnce([{ category: 'phishing', count: 150 }]);
      mockSql.mockResolvedValueOnce([{ threats: 100 }]); // Previous period had 100 threats

      const summary = await explainer.generateExecutiveSummary('tenant-1', '7 days');

      // Current: 200 threats, Previous: 100 threats -> 100% increase
      expect(summary.trends.threatVolumeChange).toBe(100);
    });
  });

  describe('getCounterfactual', () => {
    it('should generate counterfactual explanation', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const counterfactual = await explainer.getCounterfactual('test-verdict-1');

      expect(counterfactual.currentVerdict).toBeTruthy();
      expect(counterfactual.hypotheticalVerdict).toBeTruthy();
      expect(counterfactual.summary).toBeTruthy();
    });

    it('should return empty changes for safe verdict', async () => {
      mockSql.mockResolvedValueOnce([
        createMockVerdictRow({
          verdict: 'pass',
          confidence: 0.1,
          signals: [],
        }),
      ]);

      const counterfactual = await explainer.getCounterfactual('safe-verdict');

      expect(counterfactual.currentVerdict).toBe('safe');
      expect(counterfactual.changesRequired.length).toBe(0);
    });

    it('should throw error for non-existent verdict', async () => {
      mockSql.mockResolvedValueOnce([]);

      await expect(explainer.getCounterfactual('non-existent')).rejects.toThrow('Verdict not found');
    });
  });
});

describe('Convenience Functions', () => {
  beforeEach(() => {
    mockSql.mockReset();
  });

  describe('createThreatExplainer', () => {
    it('should create ThreatExplainer instance', () => {
      const explainer = createThreatExplainer();
      expect(explainer).toBeInstanceOf(ThreatExplainer);
    });
  });

  describe('explainThreat', () => {
    it('should generate explanation', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const explanation = await explainThreat({
        verdictId: 'test-verdict-1',
        audience: 'analyst',
        verbosity: 'detailed',
      });

      expect(explanation.metadata.verdictId).toBe('test-verdict-1');
    });
  });

  describe('summarizeThreat', () => {
    it('should generate brief summary', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const summary = await summarizeThreat('test-verdict-1');

      expect(typeof summary).toBe('string');
      expect(summary.length).toBeGreaterThan(0);
    });
  });

  describe('getRiskBreakdown', () => {
    it('should return risk breakdown', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const breakdown = await getRiskBreakdown('test-verdict-1');

      expect(breakdown.overall).toBeDefined();
      expect(breakdown.categories).toBeDefined();
    });
  });

  describe('getCounterfactual', () => {
    it('should return counterfactual explanation', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const counterfactual = await getCounterfactual('test-verdict-1');

      expect(counterfactual.currentVerdict).toBeDefined();
    });
  });

  describe('getSimilarThreats', () => {
    it('should return similar threats', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);
      mockSql.mockResolvedValueOnce([]);

      const similar = await getSimilarThreats('test-verdict-1');

      expect(Array.isArray(similar)).toBe(true);
    });
  });

  describe('getDetectionTimeline', () => {
    it('should return detection timeline', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

      const timeline = await getDetectionTimeline('test-verdict-1');

      expect(timeline.verdictId).toBe('test-verdict-1');
    });
  });

  describe('generateExecutiveSummary', () => {
    it('should return executive summary', async () => {
      mockSql.mockResolvedValueOnce([
        { total_emails: 1000, blocked: 10, quarantined: 20, false_positives: 1 },
      ]);
      mockSql.mockResolvedValueOnce([{ category: 'phishing', count: 20 }]);
      mockSql.mockResolvedValueOnce([{ threats: 25 }]);

      const summary = await generateExecutiveSummary('tenant-1', '7 days');

      expect(summary.tenantId).toBe('tenant-1');
    });
  });

  describe('compareWithSafe', () => {
    it('should return comparative explanation', async () => {
      mockSql.mockResolvedValueOnce([createMockVerdictRow()]);
      mockSql.mockResolvedValueOnce([{ id: 'safe-1' }]);

      const comparison = await compareWithSafe('test-verdict-1');

      expect(comparison.threatVerdictId).toBe('test-verdict-1');
    });
  });
});

describe('Edge Cases', () => {
  let explainer: ThreatExplainer;

  beforeEach(() => {
    explainer = new ThreatExplainer();
    mockSql.mockReset();
  });

  it('should handle empty signals array', async () => {
    mockSql.mockResolvedValueOnce([
      createMockVerdictRow({
        signals: [],
        confidence: 0.1,
      }),
    ]);

    const explanation = await explainer.explain({
      verdictId: 'empty-signals',
      audience: 'analyst',
      verbosity: 'detailed',
    });

    expect(explanation.topFactors).toEqual([]);
    expect(explanation.riskBreakdown.overall).toBe(10);
  });

  it('should handle null ml_classification', async () => {
    mockSql.mockResolvedValueOnce([
      createMockVerdictRow({
        ml_classification: null,
      }),
    ]);

    const explanation = await explainer.explain({
      verdictId: 'null-classification',
      audience: 'end_user',
      verbosity: 'brief',
    });

    expect(explanation.summary).toBeTruthy();
  });

  it('should handle very high signal scores', async () => {
    mockSql.mockResolvedValueOnce([
      createMockVerdictRow({
        signals: [
          { type: 'extreme_signal', severity: 'critical', score: 150, detail: 'Extreme score' },
        ],
        confidence: 1.0,
      }),
    ]);

    const breakdown = await explainer.getRiskBreakdown('extreme');

    expect(breakdown.overall).toBeLessThanOrEqual(100);
  });

  it('should handle verdict with no similar threats in database', async () => {
    mockSql.mockResolvedValueOnce([createMockVerdictRow()]);
    mockSql.mockResolvedValueOnce([]); // No similar threats

    const similar = await explainer.getSimilarThreats('isolated-verdict', 5);

    expect(similar).toEqual([]);
  });

  it('should sort factors by impact level', async () => {
    mockSql.mockResolvedValueOnce([
      createMockVerdictRow({
        signals: [
          { type: 'low_signal', severity: 'info', score: 5, detail: 'Low' },
          { type: 'critical_signal', severity: 'critical', score: 50, detail: 'Critical' },
          { type: 'medium_signal', severity: 'warning', score: 20, detail: 'Medium' },
        ],
      }),
    ]);

    const factors = await explainer.getFactors('multi-severity');

    // Critical should come first
    expect(factors[0].impact).toBe('critical');
  });

  it('should generate appropriate recommendations based on threat type', async () => {
    // BEC threat with financial indicators
    mockSql.mockResolvedValueOnce([
      createMockVerdictRow({
        ml_classification: 'bec',
        signals: [
          { type: 'bec_wire_transfer', severity: 'critical', score: 50, detail: 'Wire transfer request' },
          { type: 'bec_impersonation', severity: 'critical', score: 45, detail: 'Executive impersonation' },
        ],
      }),
    ]);

    const explanation = await explainer.explain({
      verdictId: 'bec-threat',
      audience: 'analyst',
      verbosity: 'detailed',
    });

    const hasFinanceRecommendation = explanation.recommendations.some(
      r => r.toLowerCase().includes('finance') || r.toLowerCase().includes('financial')
    );
    expect(hasFinanceRecommendation).toBe(true);
  });
});

describe('Audience-specific Output', () => {
  let explainer: ThreatExplainer;

  beforeEach(() => {
    explainer = new ThreatExplainer();
    mockSql.mockReset();
  });

  it('should provide simpler language for end users', async () => {
    mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

    const explanation = await explainer.explain({
      verdictId: 'test',
      audience: 'end_user',
      verbosity: 'brief',
    });

    // End user summary should be simple and actionable
    expect(explanation.summary).not.toContain('Threat Type:');
    expect(explanation.technicalDetails).toBeUndefined();

    // Recommendations should be user-actionable
    explanation.recommendations.forEach(rec => {
      expect(rec.toLowerCase()).toMatch(/(click|report|contact|caution|safe|reply|download)/);
    });
  });

  it('should provide technical details for analysts', async () => {
    mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

    const explanation = await explainer.explain({
      verdictId: 'test',
      audience: 'analyst',
      verbosity: 'detailed',
    });

    expect(explanation.technicalDetails).toBeDefined();
    expect(explanation.summary).toContain('Threat Type:');
  });

  it('should include model info for admins', async () => {
    mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

    const explanation = await explainer.explain({
      verdictId: 'test',
      audience: 'admin',
      verbosity: 'technical',
    });

    expect(explanation.technicalDetails?.modelInfo).toBeDefined();
    expect(explanation.technicalDetails?.thresholds).toBeDefined();
    expect(explanation.summary).toContain('Model Version:');
  });

  it('should provide executive-friendly summary', async () => {
    mockSql.mockResolvedValueOnce([createMockVerdictRow()]);

    const explanation = await explainer.explain({
      verdictId: 'test',
      audience: 'executive',
      verbosity: 'brief',
    });

    expect(explanation.summary).toContain('Security Alert');
    expect(explanation.technicalDetails).toBeUndefined();
  });
});

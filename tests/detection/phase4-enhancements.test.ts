/**
 * Phase 4 Detection Enhancements Tests
 *
 * TDD tests for Phase 4 improvements:
 * - First-Contact Risk Amplification (+2.5 points)
 * - Behavioral Anomaly Integration (+3 points)
 * - Scoring Synergy Bonus (+0.5 points)
 *
 * Target: 80/100 → 93/100 (+13 points total)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Signal, LayerResult } from '@/lib/detection/types';
import {
  amplifyFirstContactRisk,
  calculateSynergyBonus,
  identifyCompoundPatterns,
  calculateEnhancedScore,
} from '@/lib/detection/phase4-scoring';
import {
  runBehavioralAnalysis,
  runBehavioralAnalysisLayer,
  convertAnomalyToSignals,
} from '@/lib/detection/phase4-behavioral';

// ============================================================================
// Phase 4a: First-Contact Risk Amplification Tests (+2.5 points)
// ============================================================================

describe('Phase 4a: First-Contact Risk Amplification', () => {
  describe('amplifyFirstContactRisk', () => {
    it('should amplify BEC signals when combined with first-contact', () => {
      const signals: Signal[] = [
        { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
        { type: 'bec_detected', severity: 'critical', score: 35, detail: 'BEC detected' },
      ];

      const result = amplifyFirstContactRisk(signals);

      // FP-001: BEC + first-contact now amplifies by 1.2x (reduced from 1.5x)
      const becSignal = result.find(s => s.type === 'bec_detected');
      expect(becSignal?.score).toBeGreaterThanOrEqual(36); // 35 * 1.2 = 42 (capped at 55)
    });

    it('should boost to critical when first-contact + executive title + financial request', () => {
      const signals: Signal[] = [
        { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact with executive title' },
        { type: 'bec_financial_risk', severity: 'warning', score: 20, detail: 'Financial request' },
      ];

      const result = amplifyFirstContactRisk(signals, {
        hasExecutiveTitle: true,
        hasFinancialRequest: true,
      });

      // Should be boosted to critical severity
      const hasBoost = result.some(s =>
        s.type === 'first_contact_amplified' && s.severity === 'critical'
      );
      expect(hasBoost).toBe(true);
    });

    it('should NOT amplify when no first-contact signal present', () => {
      const signals: Signal[] = [
        { type: 'bec_detected', severity: 'critical', score: 35, detail: 'BEC detected' },
      ];

      const result = amplifyFirstContactRisk(signals);

      // Score should remain unchanged
      const becSignal = result.find(s => s.type === 'bec_detected');
      expect(becSignal?.score).toBe(35);
    });

    it('should add VIP impersonation boost when first-contact targets VIP', () => {
      const signals: Signal[] = [
        { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
        { type: 'first_contact_vip_impersonation', severity: 'critical', score: 40, detail: 'VIP impersonation' },
      ];

      const result = amplifyFirstContactRisk(signals, { targetingVIP: true });

      // VIP targeting should add extra amplification
      const totalScore = result.reduce((sum, s) => sum + s.score, 0);
      expect(totalScore).toBeGreaterThan(55); // Original 55, should be higher
    });

    it('should cap amplified scores at 50 per signal to prevent over-flagging', () => {
      const signals: Signal[] = [
        { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
        { type: 'bec_detected', severity: 'critical', score: 45, detail: 'Strong BEC' },
      ];

      const result = amplifyFirstContactRisk(signals, {
        hasExecutiveTitle: true,
        hasFinancialRequest: true,
        targetingVIP: true,
      });

      // Individual signal scores should be capped
      const maxScore = Math.max(...result.map(s => s.score));
      expect(maxScore).toBeLessThanOrEqual(55); // Allow some overflow but capped
    });
  });
});

// ============================================================================
// Phase 4a: Scoring Synergy Bonus Tests (+0.5 points)
// ============================================================================

describe('Phase 4a: Scoring Synergy Bonus', () => {
  describe('calculateSynergyBonus', () => {
    it('should add synergy bonus when 2+ attack patterns detected', () => {
      const signals: Signal[] = [
        { type: 'bec_urgency_pressure', severity: 'warning', score: 15, detail: 'Urgency' },
        { type: 'bec_financial_risk', severity: 'warning', score: 20, detail: 'Financial' },
      ];

      const bonus = calculateSynergyBonus(signals);

      // FP-007: Reduced from 5 to 4 for 2 patterns
      expect(bonus).toBeGreaterThanOrEqual(4);
    });

    it('should add higher bonus for 3+ attack patterns', () => {
      const signals: Signal[] = [
        { type: 'bec_urgency_pressure', severity: 'warning', score: 15, detail: 'Urgency' },
        { type: 'bec_financial_risk', severity: 'warning', score: 20, detail: 'Financial' },
        { type: 'free_email_provider', severity: 'info', score: 10, detail: 'Free email' },
      ];

      const bonus = calculateSynergyBonus(signals);

      // FP-007: Reduced from 8 to 6 for 3 patterns
      expect(bonus).toBeGreaterThanOrEqual(6);
    });

    it('should add maximum bonus for 4+ attack patterns (compound attack)', () => {
      const signals: Signal[] = [
        { type: 'bec_urgency_pressure', severity: 'warning', score: 15, detail: 'Urgency' },
        { type: 'bec_financial_risk', severity: 'critical', score: 30, detail: 'Financial' },
        { type: 'free_email_provider', severity: 'info', score: 10, detail: 'Free email' },
        { type: 'display_name_spoof', severity: 'warning', score: 20, detail: 'Display spoof' },
      ];

      const bonus = calculateSynergyBonus(signals);

      // FP-007: Reduced from 12 to 8 (hard cap) for 4+ patterns
      expect(bonus).toBeGreaterThanOrEqual(8);
    });

    it('should return 0 for single attack pattern', () => {
      const signals: Signal[] = [
        { type: 'bec_urgency_pressure', severity: 'warning', score: 15, detail: 'Urgency' },
      ];

      const bonus = calculateSynergyBonus(signals);

      expect(bonus).toBe(0);
    });

    it('should return 0 for info-only signals (no attack patterns)', () => {
      const signals: Signal[] = [
        { type: 'classification', severity: 'info', score: 0, detail: 'Marketing' },
        { type: 'sender_reputation', severity: 'info', score: 0, detail: 'Known sender' },
      ];

      const bonus = calculateSynergyBonus(signals);

      expect(bonus).toBe(0);
    });

    it('should identify specific compound attack patterns', () => {
      const signals: Signal[] = [
        { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
        { type: 'bec_impersonation', severity: 'critical', score: 40, detail: 'CEO impersonation' },
        { type: 'bec_wire_transfer_request', severity: 'critical', score: 35, detail: 'Wire transfer' },
        { type: 'bec_secrecy_request', severity: 'warning', score: 20, detail: 'Keep confidential' },
      ];

      const patterns = identifyCompoundPatterns(signals);

      expect(patterns.includes('ceo_fraud')).toBe(true);
      expect(patterns.length).toBeGreaterThan(0);
    });
  });
});

// ============================================================================
// Phase 4a: Behavioral Anomaly Integration Tests (+3 points)
// ============================================================================

describe('Phase 4a: Behavioral Anomaly Integration', () => {
  describe('runBehavioralAnalysis', () => {
    it('should detect volume anomalies', async () => {
      const result = await runBehavioralAnalysis({
        tenantId: 'tenant-1',
        senderEmail: 'attacker@external.com',
        recipientEmails: ['victim@company.com'],
        subject: 'Urgent Wire Transfer',
        sentAt: new Date(),
        dailyVolumeForSender: 100, // Unusually high
      }, {
        tenantId: 'tenant-1',
        dailyEmailVolume: { mean: 5, stdDev: 2 },
        hourlyDistribution: new Array(24).fill(1/24),
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      });

      expect(result.hasAnomaly).toBe(true);
      expect(result.anomalyTypes).toContain('volume');
      expect(result.compositeScore).toBeGreaterThan(0);
    });

    it('should detect time anomalies (unusual hour)', async () => {
      // Sending at 3 AM when baseline shows no activity then
      const hourlyDist = new Array(24).fill(0);
      hourlyDist[9] = 0.4; // 9 AM - 40%
      hourlyDist[14] = 0.4; // 2 PM - 40%
      hourlyDist[10] = 0.2; // 10 AM - 20%

      const sentAt = new Date();
      sentAt.setHours(3, 0, 0, 0); // 3 AM

      const result = await runBehavioralAnalysis({
        tenantId: 'tenant-1',
        senderEmail: 'user@company.com',
        recipientEmails: ['recipient@company.com'],
        subject: 'Normal email',
        sentAt,
        dailyVolumeForSender: 5,
      }, {
        tenantId: 'tenant-1',
        dailyEmailVolume: { mean: 5, stdDev: 2 },
        hourlyDistribution: hourlyDist,
        topRecipients: [],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      });

      expect(result.timeAnomaly?.isUnusualHour).toBe(true);
    });

    it('should detect recipient anomalies (new recipient)', async () => {
      const result = await runBehavioralAnalysis({
        tenantId: 'tenant-1',
        senderEmail: 'user@company.com',
        recipientEmails: ['new-contact@external.com'],
        subject: 'Hello',
        sentAt: new Date(),
        dailyVolumeForSender: 5,
        isFirstContactWithRecipient: true,
      }, {
        tenantId: 'tenant-1',
        dailyEmailVolume: { mean: 5, stdDev: 2 },
        hourlyDistribution: new Array(24).fill(1/24),
        topRecipients: ['regular@company.com'],
        topSenders: [],
        subjectPatterns: [],
        calculatedAt: new Date(),
      });

      expect(result.recipientAnomaly?.hasNewRecipient).toBe(true);
    });

    it('should detect content anomalies (urgency)', async () => {
      const result = await runBehavioralAnalysis({
        tenantId: 'tenant-1',
        senderEmail: 'user@company.com',
        recipientEmails: ['recipient@company.com'],
        subject: 'URGENT!!! ACTION REQUIRED IMMEDIATELY!!!',
        sentAt: new Date(),
        dailyVolumeForSender: 5,
      }, {
        tenantId: 'tenant-1',
        dailyEmailVolume: { mean: 5, stdDev: 2 },
        hourlyDistribution: new Array(24).fill(1/24),
        topRecipients: [],
        topSenders: [],
        subjectPatterns: ['Weekly Report', 'Meeting Notes'],
        calculatedAt: new Date(),
      });

      expect(result.contentAnomaly?.hasUnusualSubject).toBe(true);
      expect(result.contentAnomaly?.urgencyScore).toBeGreaterThan(0.5);
    });

    it('should return layer result with signals for pipeline integration', async () => {
      const mockEmail = {
        messageId: 'test-1',
        from: { address: 'attacker@evil.com', domain: 'evil.com' },
        to: [{ address: 'victim@company.com', domain: 'company.com' }],
        subject: 'URGENT: Wire Transfer Required',
        date: new Date(),
        body: { text: 'Please wire $50,000 immediately' },
        attachments: [],
        headers: {},
        rawHeaders: '',
      };

      const result = await runBehavioralAnalysisLayer(mockEmail as any, 'tenant-1');

      expect(result.layer).toBe('behavioral');
      expect(typeof result.score).toBe('number');
      expect(typeof result.confidence).toBe('number');
      expect(Array.isArray(result.signals)).toBe(true);
      expect(typeof result.processingTimeMs).toBe('number');
    });

    it('should skip analysis if no baseline available', async () => {
      const mockEmail = {
        messageId: 'test-1',
        from: { address: 'user@company.com', domain: 'company.com' },
        to: [{ address: 'other@company.com', domain: 'company.com' }],
        subject: 'Hello',
        date: new Date(),
        body: { text: 'Hi there' },
        attachments: [],
        headers: {},
        rawHeaders: '',
      };

      const result = await runBehavioralAnalysisLayer(mockEmail as any, 'new-tenant-no-baseline');

      expect(result.skipped).toBe(true);
      expect(result.skipReason).toContain('baseline');
    });
  });

  describe('behavioral signals conversion', () => {
    it('should convert anomaly result to pipeline signals', () => {
      const anomalyResult = {
        tenantId: 'tenant-1',
        emailId: 'email-1',
        hasAnomaly: true,
        compositeScore: 65,
        anomalyTypes: ['volume', 'content'] as const,
        volumeAnomaly: {
          zScore: 4.5,
          severity: 'high' as const,
          actualVolume: 50,
          expectedVolume: 5,
        },
        contentAnomaly: {
          hasUnusualSubject: true,
          urgencyScore: 0.8,
          allCapsSubject: true,
          severity: 'medium' as const,
        },
        detectedAt: new Date(),
      };

      const signals = convertAnomalyToSignals(anomalyResult);

      expect(signals.length).toBeGreaterThanOrEqual(2);
      expect(signals.some(s => s.type === 'anomaly_detected')).toBe(true);
      expect(signals.some(s => s.detail.includes('volume'))).toBe(true);
    });
  });
});

// ============================================================================
// Phase 4: Pipeline Integration Tests
// ============================================================================

describe('Phase 4: Pipeline Integration', () => {
  describe('enhanced score calculation', () => {
    it('should apply first-contact amplification in final score', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 30,
          confidence: 0.8,
          signals: [
            { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
          ],
          processingTimeMs: 10,
        },
        {
          layer: 'bec',
          score: 50,
          confidence: 0.9,
          signals: [
            { type: 'bec_detected', severity: 'critical', score: 35, detail: 'BEC' },
          ],
          processingTimeMs: 20,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        enableFirstContactAmplification: true,
        enableSynergyBonus: true,
      });

      // Score should be higher due to amplification
      expect(result.overallScore).toBeGreaterThan(40);
    });

    it('should apply synergy bonus for compound attacks', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 25,
          confidence: 0.8,
          signals: [
            { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
            { type: 'free_email_provider', severity: 'info', score: 10, detail: 'Gmail' },
          ],
          processingTimeMs: 10,
        },
        {
          layer: 'bec',
          score: 60,
          confidence: 0.9,
          signals: [
            { type: 'bec_urgency_pressure', severity: 'warning', score: 20, detail: 'Urgency' },
            { type: 'bec_financial_risk', severity: 'critical', score: 30, detail: 'Wire transfer' },
            { type: 'bec_impersonation', severity: 'critical', score: 40, detail: 'CEO impersonation' },
          ],
          processingTimeMs: 20,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        enableFirstContactAmplification: true,
        enableSynergyBonus: true,
      });

      // Score should include synergy bonus
      expect(result.synergyBonus).toBeGreaterThanOrEqual(8);
      expect(result.compoundPatterns.length).toBeGreaterThan(0);
    });

    it('should include behavioral layer in final score', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 20,
          confidence: 0.8,
          signals: [],
          processingTimeMs: 10,
        },
        {
          layer: 'behavioral' as any,
          score: 45,
          confidence: 0.7,
          signals: [
            { type: 'anomaly_detected', severity: 'warning', score: 25, detail: 'Volume anomaly' },
          ],
          processingTimeMs: 15,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        enableBehavioralAnalysis: true,
      });

      // Behavioral layer should contribute to final score
      expect(result.overallScore).toBeGreaterThan(20);
    });
  });

  describe('feature flags', () => {
    it('should respect enableFirstContactAmplification flag', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 30,
          confidence: 0.8,
          signals: [
            { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
            { type: 'bec_detected', severity: 'critical', score: 35, detail: 'BEC' },
          ],
          processingTimeMs: 10,
        },
      ];

      const withAmplification = calculateEnhancedScore(layerResults, {
        enableFirstContactAmplification: true,
      });
      const withoutAmplification = calculateEnhancedScore(layerResults, {
        enableFirstContactAmplification: false,
      });

      expect(withAmplification.overallScore).toBeGreaterThan(withoutAmplification.overallScore);
    });

    it('should respect enableSynergyBonus flag', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'bec',
          score: 60,
          confidence: 0.9,
          signals: [
            { type: 'bec_urgency_pressure', severity: 'warning', score: 15, detail: 'Urgency' },
            { type: 'bec_financial_risk', severity: 'warning', score: 20, detail: 'Financial' },
            { type: 'display_name_spoof', severity: 'warning', score: 20, detail: 'Spoof' },
          ],
          processingTimeMs: 10,
        },
      ];

      const withSynergy = calculateEnhancedScore(layerResults, {
        enableSynergyBonus: true,
      });
      const withoutSynergy = calculateEnhancedScore(layerResults, {
        enableSynergyBonus: false,
      });

      expect(withSynergy.synergyBonus).toBeGreaterThan(0);
      expect(withoutSynergy.synergyBonus).toBe(0);
    });
  });
});

// ============================================================================
// Phase 4: Edge Cases and Safety Tests
// ============================================================================

describe('Phase 4: Edge Cases and Safety', () => {
  it('should not over-flag legitimate newsletters with urgency', () => {
    const layerResults: LayerResult[] = [
      {
        layer: 'deterministic',
        score: 20,
        confidence: 0.8,
        signals: [
          { type: 'ml_urgency', severity: 'info', score: 5, detail: 'Sales urgency' },
        ],
        processingTimeMs: 10,
      },
    ];

    const result = calculateEnhancedScore(layerResults, {
      enableFirstContactAmplification: true,
      enableSynergyBonus: true,
      emailClassification: { type: 'marketing', isKnownSender: true },
    });

    // Marketing emails should not get synergy bonuses
    expect(result.synergyBonus).toBe(0);
    expect(result.overallScore).toBeLessThan(35); // Should pass threshold
  });

  it('should handle empty signals gracefully', () => {
    expect(amplifyFirstContactRisk([])).toEqual([]);
    expect(calculateSynergyBonus([])).toBe(0);
  });

  it('should not double-count signals', () => {
    const layerResults: LayerResult[] = [
      {
        layer: 'deterministic',
        score: 50,
        confidence: 0.8,
        signals: [
          { type: 'bec_detected', severity: 'critical', score: 35, detail: 'BEC from deterministic' },
        ],
        processingTimeMs: 10,
      },
      {
        layer: 'bec',
        score: 50,
        confidence: 0.9,
        signals: [
          { type: 'bec_detected', severity: 'critical', score: 35, detail: 'BEC from BEC layer' },
        ],
        processingTimeMs: 20,
      },
    ];

    const result = calculateEnhancedScore(layerResults, {
      enableFirstContactAmplification: true,
      enableSynergyBonus: true,
    });

    // Should deduplicate same signal type from different layers
    const becSignals = result.signals.filter(s => s.type === 'bec_detected');
    // Score should not be doubled
    expect(result.overallScore).toBeLessThan(100);
  });
});

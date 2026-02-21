/**
 * Phase 1: False Positive Reduction Tests
 *
 * TDD tests for reducing false positive rate from ~2% to <0.1%
 *
 * FP-001: Reduce First-Contact Sender Amplification (1.5x → 1.2x)
 * FP-002: Government/Institutional Domain Whitelist
 * FP-003: Thread Context Awareness
 * FP-004: Attachment Analysis Refinement
 * FP-005: LLM Prompt Optimization (tested in llm.test.ts)
 * FP-006: ML Model Retraining Data (tested in ml.test.ts)
 * FP-007: Score Aggregation Formula
 * FP-008: Feedback Loop Integration
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Signal, LayerResult } from '@/lib/detection/types';
import {
  amplifyFirstContactRisk,
  calculateEnhancedScore,
  type AmplificationOptions,
  type EnhancedScoreOptions,
} from '@/lib/detection/phase4-scoring';

// ============================================================================
// FP-001: Reduce First-Contact Sender Amplification
// ============================================================================

describe('FP-001: First-Contact Amplification Reduction', () => {
  describe('amplifyFirstContactRisk with domain age exemption', () => {
    it('should use reduced 1.2x multiplier for base first-contact amplification', () => {
      const signals: Signal[] = [
        { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
        { type: 'bec_detected', severity: 'critical', score: 30, detail: 'BEC detected' },
      ];

      const result = amplifyFirstContactRisk(signals);

      // BEC + first-contact should amplify by 1.2x (reduced from 1.5x)
      // 30 * 1.2 = 36 (not 30 * 1.5 = 45)
      const becSignal = result.find(s => s.type === 'bec_detected');
      expect(becSignal?.score).toBe(36); // 30 * 1.2 = 36
      expect(becSignal?.metadata?.multiplier).toBe(1.2);
    });

    it('should SKIP amplification for established domains (>365 days old)', () => {
      const signals: Signal[] = [
        { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
        { type: 'bec_detected', severity: 'critical', score: 30, detail: 'BEC detected' },
      ];

      // Domain age provided as option
      const result = amplifyFirstContactRisk(signals, {
        senderDomainAgeDays: 500, // >365 days, established domain
      });

      // Should NOT amplify - score stays at 30
      const becSignal = result.find(s => s.type === 'bec_detected');
      expect(becSignal?.score).toBe(30);
      expect(becSignal?.metadata?.amplified).toBeFalsy();
    });

    it('should apply reduced amplification for domains 30-365 days old', () => {
      const signals: Signal[] = [
        { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
        { type: 'bec_detected', severity: 'critical', score: 30, detail: 'BEC detected' },
      ];

      const result = amplifyFirstContactRisk(signals, {
        senderDomainAgeDays: 180, // Between 30-365 days
      });

      // Reduced amplification of 1.1x for medium-age domains
      const becSignal = result.find(s => s.type === 'bec_detected');
      expect(becSignal?.score).toBe(33); // 30 * 1.1 = 33
      expect(becSignal?.metadata?.multiplier).toBe(1.1);
    });

    it('should apply full 1.2x amplification only for new domains (<30 days)', () => {
      const signals: Signal[] = [
        { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
        { type: 'bec_detected', severity: 'critical', score: 30, detail: 'BEC detected' },
      ];

      const result = amplifyFirstContactRisk(signals, {
        senderDomainAgeDays: 15, // <30 days, new domain
      });

      // Full (but reduced) 1.2x amplification for new domains
      const becSignal = result.find(s => s.type === 'bec_detected');
      expect(becSignal?.score).toBe(36); // 30 * 1.2 = 36
      expect(becSignal?.metadata?.multiplier).toBe(1.2);
    });

    it('should NOT add executive+financial boost for established domains', () => {
      const signals: Signal[] = [
        { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact with CEO' },
        { type: 'bec_financial_risk', severity: 'warning', score: 20, detail: 'Financial request' },
      ];

      const result = amplifyFirstContactRisk(signals, {
        hasExecutiveTitle: true,
        hasFinancialRequest: true,
        senderDomainAgeDays: 500, // Established domain
      });

      // Should NOT add the first_contact_amplified boost signal
      const hasBoost = result.some(s => s.type === 'first_contact_amplified');
      expect(hasBoost).toBe(false);
    });
  });
});

// ============================================================================
// FP-002: Government/Institutional Domain Whitelist
// ============================================================================

describe('FP-002: Government/Institutional Domain Whitelist', () => {
  describe('calculateEnhancedScore with institutional domains', () => {
    it('should apply 0.5x dampening for .gov domains', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 40,
          confidence: 0.8,
          signals: [
            { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
          ],
          processingTimeMs: 10,
        },
        {
          layer: 'bec',
          score: 45,
          confidence: 0.7,
          signals: [
            { type: 'bec_urgency_pressure', severity: 'warning', score: 20, detail: 'Urgency' },
          ],
          processingTimeMs: 20,
        },
      ];

      const resultWithGov = calculateEnhancedScore(layerResults, {
        senderDomain: 'agency.gov',
      });
      const resultWithoutGov = calculateEnhancedScore(layerResults, {
        senderDomain: 'random.com',
      });

      // .gov domain should have significantly lower score
      expect(resultWithGov.overallScore).toBeLessThan(resultWithoutGov.overallScore * 0.7);
    });

    it('should apply 0.5x dampening for .edu domains', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 40,
          confidence: 0.8,
          signals: [
            { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
          ],
          processingTimeMs: 10,
        },
      ];

      const resultWithEdu = calculateEnhancedScore(layerResults, {
        senderDomain: 'university.edu',
      });
      const resultWithoutEdu = calculateEnhancedScore(layerResults, {
        senderDomain: 'random.com',
      });

      expect(resultWithEdu.overallScore).toBeLessThan(resultWithoutEdu.overallScore * 0.7);
    });

    it('should apply 0.6x dampening for .org domains from known nonprofits', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 35,
          confidence: 0.8,
          signals: [
            { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
          ],
          processingTimeMs: 10,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        senderDomain: 'redcross.org',
      });

      // Known nonprofit should get dampening
      expect(result.institutionalDampening).toBe(true);
    });

    it('should NOT apply dampening for spoofed institutional domains', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 60,
          confidence: 0.9,
          signals: [
            { type: 'homoglyph', severity: 'critical', score: 35, detail: 'g0v domain detected' },
            { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
          ],
          processingTimeMs: 10,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        senderDomain: 'agency.g0v', // Spoofed .gov with 0 instead of o
      });

      // Spoofed domains should NOT get institutional dampening
      expect(result.institutionalDampening).toBeFalsy();
      expect(result.overallScore).toBeGreaterThan(50);
    });

    it('should NOT apply dampening when critical BEC signals present', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'bec',
          score: 70,
          confidence: 0.9,
          signals: [
            { type: 'bec_wire_transfer_request', severity: 'critical', score: 35, detail: 'Wire transfer' },
            { type: 'bec_impersonation', severity: 'critical', score: 40, detail: 'CEO impersonation' },
          ],
          processingTimeMs: 20,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        senderDomain: 'university.edu', // Legitimate .edu but with critical BEC
      });

      // Critical BEC should override institutional dampening
      expect(result.institutionalDampening).toBe(false);
      expect(result.overallScore).toBeGreaterThan(60);
    });
  });
});

// ============================================================================
// FP-003: Thread Context Awareness
// ============================================================================

describe('FP-003: Thread Context Awareness', () => {
  describe('calculateEnhancedScore with thread context', () => {
    it('should apply 0.6x dampening for replies to existing threads', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 45,
          confidence: 0.8,
          signals: [
            { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
            { type: 'urgency_language', severity: 'warning', score: 15, detail: 'Urgent' },
          ],
          processingTimeMs: 10,
        },
      ];

      const resultInThread = calculateEnhancedScore(layerResults, {
        threadContext: {
          isReply: true,
          threadDepth: 3, // Part of existing conversation
          previousSenderAddresses: ['colleague@company.com'],
        },
      });

      const resultNewEmail = calculateEnhancedScore(layerResults, {});

      // Reply in thread should have lower score
      expect(resultInThread.overallScore).toBeLessThan(resultNewEmail.overallScore * 0.8);
    });

    it('should STILL flag new senders in forwarded threads with BEC signals', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'bec',
          score: 65,
          confidence: 0.9,
          signals: [
            { type: 'bec_financial_risk', severity: 'critical', score: 30, detail: 'Wire transfer' },
            { type: 'bec_urgency_pressure', severity: 'warning', score: 20, detail: 'Urgent' },
          ],
          processingTimeMs: 20,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        threadContext: {
          isReply: true,
          threadDepth: 5,
          previousSenderAddresses: ['alice@company.com'], // Thread was with Alice
          currentSender: 'attacker@external.com', // New sender hijacking thread
        },
      });

      // Thread hijacking attempt should NOT get thread dampening
      expect(result.threadDampening).toBe(false);
      expect(result.overallScore).toBeGreaterThanOrEqual(50); // High score for BEC signals
    });

    it('should check sender consistency in thread', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 35,
          confidence: 0.8,
          signals: [
            { type: 'urgency_language', severity: 'info', score: 10, detail: 'Please respond' },
          ],
          processingTimeMs: 10,
        },
      ];

      // Same sender continuing thread
      const resultSameSender = calculateEnhancedScore(layerResults, {
        threadContext: {
          isReply: true,
          threadDepth: 2,
          previousSenderAddresses: ['bob@vendor.com'],
          currentSender: 'bob@vendor.com', // Same sender
        },
      });

      expect(resultSameSender.threadDampening).toBe(true);
    });
  });
});

// ============================================================================
// FP-004: Attachment Analysis Refinement
// ============================================================================

describe('FP-004: Attachment Analysis Refinement', () => {
  describe('calculateEnhancedScore with refined attachment signals', () => {
    it('should NOT over-penalize common business document types', () => {
      const layerResultsWithPdf: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 30,
          confidence: 0.7,
          signals: [
            {
              type: 'dangerous_attachment',
              severity: 'warning',
              score: 15,
              detail: 'PDF attachment',
              metadata: { fileType: 'application/pdf', filename: 'invoice.pdf' },
            },
          ],
          processingTimeMs: 10,
        },
      ];

      const result = calculateEnhancedScore(layerResultsWithPdf, {
        attachmentContext: {
          fileTypes: ['application/pdf'],
          hasPasswordProtected: false,
          hasMacros: false,
        },
      });

      // PDF without macros/password should have reduced signal weight
      expect(result.overallScore).toBeLessThan(35); // Should stay below suspicious threshold
    });

    it('should MAINTAIN full penalty for password-protected archives', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 60,
          confidence: 0.9,
          signals: [
            {
              type: 'password_protected_archive',
              severity: 'critical',
              score: 35,
              detail: 'Password protected ZIP',
              metadata: { filename: 'urgent.zip' },
            },
            {
              type: 'first_contact',
              severity: 'info',
              score: 15,
              detail: 'First contact',
            },
          ],
          processingTimeMs: 10,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        attachmentContext: {
          fileTypes: ['application/zip'],
          hasPasswordProtected: true,
          hasMacros: false,
        },
        senderDomainAgeDays: 10, // New domain
      });

      // Password-protected archives should keep full penalty (no dampening applies)
      // With critical signal + first-contact amplification, score should be elevated
      expect(result.overallScore).toBeGreaterThan(35);
    });

    it('should MAINTAIN full penalty for macro-enabled Office documents', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 65,
          confidence: 0.9,
          signals: [
            {
              type: 'macro_enabled',
              severity: 'critical',
              score: 30,
              detail: 'Macro-enabled document',
              metadata: { filename: 'report.xlsm' },
            },
            {
              type: 'first_contact',
              severity: 'info',
              score: 15,
              detail: 'First contact',
            },
          ],
          processingTimeMs: 10,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        attachmentContext: {
          fileTypes: ['application/vnd.ms-excel.sheet.macroEnabled.12'],
          hasPasswordProtected: false,
          hasMacros: true,
        },
        senderDomainAgeDays: 10, // New domain
      });

      // Macro-enabled should keep full penalty (no known sender dampening)
      // With critical signal + first-contact, score should be elevated
      expect(result.overallScore).toBeGreaterThan(35);
    });

    it('should recognize safe attachment patterns from known senders', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 25,
          confidence: 0.7,
          signals: [
            {
              type: 'dangerous_attachment',
              severity: 'info',
              score: 10,
              detail: 'DOCX attachment',
            },
          ],
          processingTimeMs: 10,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        emailClassification: { type: 'transactional', isKnownSender: true },
        attachmentContext: {
          fileTypes: ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
          hasPasswordProtected: false,
          hasMacros: false,
        },
      });

      // Known sender with safe document should pass
      expect(result.overallScore).toBeLessThan(35);
    });
  });
});

// ============================================================================
// FP-007: Score Aggregation Formula
// ============================================================================

describe('FP-007: Score Aggregation Formula Improvements', () => {
  describe('calculateEnhancedScore with improved aggregation', () => {
    it('should use geometric mean for layer scores to prevent outlier inflation', () => {
      // One high layer + several low layers
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 80, // High score
          confidence: 0.9,
          signals: [],
          processingTimeMs: 10,
        },
        {
          layer: 'reputation',
          score: 10, // Low score
          confidence: 0.8,
          signals: [],
          processingTimeMs: 10,
        },
        {
          layer: 'ml',
          score: 15, // Low score
          confidence: 0.85,
          signals: [],
          processingTimeMs: 10,
        },
        {
          layer: 'bec',
          score: 10, // Low score
          confidence: 0.7,
          signals: [],
          processingTimeMs: 10,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        enableImprovedAggregation: true,
      });

      // Geometric mean should dampen the effect of the single high-scoring layer
      // Old arithmetic weighted average might give ~30-40
      // Geometric mean approach should give <30
      expect(result.overallScore).toBeLessThan(35);
    });

    it('should cap synergy bonus at 8 points to prevent stacking', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 40,
          confidence: 0.8,
          signals: [
            { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
            { type: 'free_email_provider', severity: 'info', score: 10, detail: 'Gmail' },
            { type: 'display_name_spoof', severity: 'warning', score: 15, detail: 'Spoof' },
          ],
          processingTimeMs: 10,
        },
        {
          layer: 'bec',
          score: 50,
          confidence: 0.9,
          signals: [
            { type: 'bec_urgency_pressure', severity: 'warning', score: 15, detail: 'Urgency' },
            { type: 'bec_financial_risk', severity: 'warning', score: 20, detail: 'Financial' },
          ],
          processingTimeMs: 20,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        enableSynergyBonus: true,
      });

      // Synergy bonus should be capped at 8 (reduced from 12)
      expect(result.synergyBonus).toBeLessThanOrEqual(8);
    });

    it('should reduce critical signal boost to +5 per signal (from +7)', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'bec',
          score: 60,
          confidence: 0.9,
          signals: [
            { type: 'bec_impersonation', severity: 'critical', score: 30, detail: 'BEC' },
            { type: 'bec_wire_transfer_request', severity: 'critical', score: 35, detail: 'Wire' },
          ],
          processingTimeMs: 20,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        enableReducedCriticalBoost: true,
      });

      // 2 critical signals should add +10 (2 * 5), not +14 (2 * 7)
      // This should result in a lower overall score
      expect(result.criticalBoost).toBe(10);
    });
  });
});

// ============================================================================
// FP-008: Feedback Loop Integration
// ============================================================================

describe('FP-008: Feedback Loop Integration', () => {
  describe('calculateEnhancedScore with user feedback', () => {
    it('should apply 0.7x dampening for senders marked as safe by user', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 45,
          confidence: 0.8,
          signals: [
            { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
            { type: 'free_email_provider', severity: 'info', score: 10, detail: 'Gmail' },
          ],
          processingTimeMs: 10,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        feedbackContext: {
          senderMarkedSafe: true,
          feedbackCount: 3, // User has marked as safe 3 times
          lastFeedbackAt: new Date(Date.now() - 24 * 60 * 60 * 1000), // 1 day ago
        },
      });

      // Sender marked safe should get dampening
      expect(result.feedbackDampening).toBe(true);
      expect(result.overallScore).toBeLessThan(35); // Should pass
    });

    it('should IGNORE safe feedback for senders with critical BEC signals', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'bec',
          score: 75,
          confidence: 0.95,
          signals: [
            { type: 'bec_wire_transfer_request', severity: 'critical', score: 35, detail: 'Wire transfer' },
            { type: 'bec_impersonation', severity: 'critical', score: 40, detail: 'CEO impersonation' },
          ],
          processingTimeMs: 20,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        feedbackContext: {
          senderMarkedSafe: true, // User previously marked as safe
          feedbackCount: 5,
          lastFeedbackAt: new Date(),
        },
      });

      // Critical BEC should override feedback dampening
      expect(result.feedbackDampening).toBe(false);
      expect(result.overallScore).toBeGreaterThan(60);
    });

    it('should expire feedback dampening after 90 days', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 40,
          confidence: 0.8,
          signals: [
            { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
          ],
          processingTimeMs: 10,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        feedbackContext: {
          senderMarkedSafe: true,
          feedbackCount: 2,
          lastFeedbackAt: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000), // 100 days ago
        },
      });

      // Expired feedback should not apply dampening
      expect(result.feedbackDampening).toBe(false);
    });

    it('should learn from FP reports and reduce score for similar patterns', () => {
      const layerResults: LayerResult[] = [
        {
          layer: 'deterministic',
          score: 42,
          confidence: 0.75,
          signals: [
            { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
            { type: 'urgency_language', severity: 'info', score: 10, detail: 'ASAP' },
          ],
          processingTimeMs: 10,
        },
      ];

      const result = calculateEnhancedScore(layerResults, {
        feedbackContext: {
          similarPatternFpRate: 0.15, // 15% of similar patterns were FP
          similarPatternCount: 50, // Significant sample size
        },
      });

      // High FP rate for similar patterns should apply dampening
      expect(result.patternFpDampening).toBe(true);
    });
  });
});

// ============================================================================
// Integration Tests: Combined FP Reduction
// ============================================================================

describe('Phase 1: Combined FP Reduction', () => {
  it('should significantly reduce FP rate for legitimate first-contact from established domains', () => {
    const layerResults: LayerResult[] = [
      {
        layer: 'deterministic',
        score: 35,
        confidence: 0.7,
        signals: [
          { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
        ],
        processingTimeMs: 10,
      },
      {
        layer: 'bec',
        score: 25,
        confidence: 0.6,
        signals: [
          { type: 'bec_urgency_pressure', severity: 'info', score: 10, detail: 'Time sensitive' },
        ],
        processingTimeMs: 20,
      },
    ];

    const result = calculateEnhancedScore(layerResults, {
      senderDomain: 'microsoft.com',
      senderDomainAgeDays: 9000, // Very established domain
      threadContext: {
        isReply: false,
        threadDepth: 0,
      },
    });

    // Established sender with low-level signals should PASS
    expect(result.overallScore).toBeLessThan(35); // Below pass threshold
  });

  it('should STILL catch obvious BEC attacks even with mitigations', () => {
    const layerResults: LayerResult[] = [
      {
        layer: 'deterministic',
        score: 50,
        confidence: 0.9,
        signals: [
          { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
          { type: 'display_name_spoof', severity: 'critical', score: 25, detail: 'CEO Display Name' },
        ],
        processingTimeMs: 10,
      },
      {
        layer: 'bec',
        score: 80,
        confidence: 0.95,
        signals: [
          { type: 'bec_impersonation', severity: 'critical', score: 40, detail: 'CEO impersonation' },
          { type: 'bec_wire_transfer_request', severity: 'critical', score: 35, detail: 'Wire $50,000' },
          { type: 'bec_secrecy_request', severity: 'warning', score: 20, detail: 'Keep confidential' },
        ],
        processingTimeMs: 20,
      },
    ];

    const result = calculateEnhancedScore(layerResults, {
      senderDomain: 'gmail.com', // Free email
      senderDomainAgeDays: 7000, // Old domain but free email
      feedbackContext: {
        senderMarkedSafe: false,
      },
    });

    // Obvious BEC should STILL be caught
    expect(result.overallScore).toBeGreaterThan(70); // Should trigger quarantine/block
  });

  it('should reduce FP for legitimate .gov first-contact emails', () => {
    const layerResults: LayerResult[] = [
      {
        layer: 'deterministic',
        score: 40,
        confidence: 0.7,
        signals: [
          { type: 'first_contact', severity: 'info', score: 15, detail: 'First contact' },
        ],
        processingTimeMs: 10,
      },
      {
        layer: 'bec',
        score: 30,
        confidence: 0.5,
        signals: [
          { type: 'bec_urgency_pressure', severity: 'info', score: 10, detail: 'Response needed' },
        ],
        processingTimeMs: 20,
      },
    ];

    const result = calculateEnhancedScore(layerResults, {
      senderDomain: 'irs.gov',
      senderDomainAgeDays: 10000, // Very established
    });

    // Government email with minor signals should PASS
    expect(result.overallScore).toBeLessThan(35);
    expect(result.institutionalDampening).toBe(true);
  });
});

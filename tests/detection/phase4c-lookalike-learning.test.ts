/**
 * Phase 4c: Lookalike Domain Learning Tests
 *
 * Tests for adaptive lookalike domain detection:
 * - Tenant-specific brand protection
 * - Learning from confirmed threats
 * - Pattern generalization from attacks
 * - Adaptive confidence scoring
 *
 * Expected Impact: +1 detection point
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  LookalikeLearningService,
  addTenantBrand,
  getTenantBrands,
  recordLookalikeDetection,
  recordFeedback,
  getLearnedPatterns,
  calculateAdaptiveConfidence,
  detectWithLearning,
  type TenantBrand,
  type LookalikeDetection,
  type DetectionFeedback,
  type LearnedPattern,
} from '../../lib/detection/phase4c-lookalike-learning';

describe('Phase 4c: Lookalike Domain Learning', () => {
  let service: LookalikeLearningService;

  beforeEach(() => {
    service = new LookalikeLearningService();
  });

  describe('Tenant-Specific Brand Protection', () => {
    it('should allow tenants to register custom brands', () => {
      const tenantId = 'tenant-123';
      const brand: TenantBrand = {
        domain: 'acmecorp.com',
        brandName: 'ACME Corporation',
        aliases: ['acme', 'acmeco'],
        priority: 'high',
      };

      addTenantBrand(service, tenantId, brand);
      const brands = getTenantBrands(service, tenantId);

      expect(brands).toHaveLength(1);
      expect(brands[0].domain).toBe('acmecorp.com');
      expect(brands[0].brandName).toBe('ACME Corporation');
    });

    it('should detect lookalikes for tenant-specific brands', () => {
      const tenantId = 'tenant-456';
      addTenantBrand(service, tenantId, {
        domain: 'mycompany.com',
        brandName: 'My Company',
        aliases: ['myco'],
        priority: 'critical',
      });

      const result = detectWithLearning(service, tenantId, 'mycompanny.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetBrand).toBe('My Company');
      expect(result.attackType).toBe('typosquat');
    });

    it('should support multiple brands per tenant', () => {
      const tenantId = 'tenant-789';
      addTenantBrand(service, tenantId, {
        domain: 'brand1.com',
        brandName: 'Brand One',
        priority: 'high',
      });
      addTenantBrand(service, tenantId, {
        domain: 'brand2.com',
        brandName: 'Brand Two',
        priority: 'medium',
      });
      addTenantBrand(service, tenantId, {
        domain: 'brand3.com',
        brandName: 'Brand Three',
        priority: 'low',
      });

      const brands = getTenantBrands(service, tenantId);
      expect(brands).toHaveLength(3);
    });

    it('should not cross-contaminate brands between tenants', () => {
      addTenantBrand(service, 'tenant-A', {
        domain: 'tenantA.com',
        brandName: 'Tenant A Corp',
        priority: 'high',
      });
      addTenantBrand(service, 'tenant-B', {
        domain: 'tenantB.com',
        brandName: 'Tenant B Corp',
        priority: 'high',
      });

      const brandsA = getTenantBrands(service, 'tenant-A');
      const brandsB = getTenantBrands(service, 'tenant-B');

      expect(brandsA).toHaveLength(1);
      expect(brandsA[0].domain).toBe('tenantA.com');
      expect(brandsB).toHaveLength(1);
      expect(brandsB[0].domain).toBe('tenantB.com');
    });
  });

  describe('Learning from Confirmed Threats', () => {
    it('should record lookalike detections', () => {
      const detection: LookalikeDetection = {
        attackerDomain: 'g00gle.com',
        targetBrand: 'Google',
        targetDomain: 'google.com',
        attackType: 'homoglyph',
        confidence: 0.95,
        timestamp: new Date(),
      };

      recordLookalikeDetection(service, detection);
      const patterns = getLearnedPatterns(service);

      expect(patterns.length).toBeGreaterThan(0);
    });

    it('should learn patterns from multiple similar detections', () => {
      // Record multiple homoglyph attacks on same brand
      recordLookalikeDetection(service, {
        attackerDomain: 'g00gle.com',
        targetBrand: 'Google',
        targetDomain: 'google.com',
        attackType: 'homoglyph',
        confidence: 0.9,
        timestamp: new Date(),
      });
      recordLookalikeDetection(service, {
        attackerDomain: 'goog1e.com',
        targetBrand: 'Google',
        targetDomain: 'google.com',
        attackType: 'homoglyph',
        confidence: 0.92,
        timestamp: new Date(),
      });
      recordLookalikeDetection(service, {
        attackerDomain: 'googIe.com',
        targetBrand: 'Google',
        targetDomain: 'google.com',
        attackType: 'homoglyph',
        confidence: 0.88,
        timestamp: new Date(),
      });

      const patterns = getLearnedPatterns(service);
      const googlePattern = patterns.find(p => p.targetBrand === 'Google');

      expect(googlePattern).toBeDefined();
      expect(googlePattern!.occurrences).toBe(3);
      expect(googlePattern!.averageConfidence).toBeGreaterThan(0.85);
    });

    it('should increase pattern confidence with positive feedback', () => {
      recordLookalikeDetection(service, {
        attackerDomain: 'paypa1.com',
        targetBrand: 'PayPal',
        targetDomain: 'paypal.com',
        attackType: 'homoglyph',
        confidence: 0.85,
        timestamp: new Date(),
      });

      const initialPatterns = getLearnedPatterns(service);
      const initialConfidence = initialPatterns.find(p => p.targetBrand === 'PayPal')?.averageConfidence ?? 0;

      recordFeedback(service, {
        attackerDomain: 'paypa1.com',
        wasCorrect: true,
        confirmedThreat: true,
        feedbackSource: 'analyst',
      });

      const updatedPatterns = getLearnedPatterns(service);
      const updatedConfidence = updatedPatterns.find(p => p.targetBrand === 'PayPal')?.averageConfidence ?? 0;

      expect(updatedConfidence).toBeGreaterThanOrEqual(initialConfidence);
    });

    it('should decrease pattern confidence with negative feedback', () => {
      recordLookalikeDetection(service, {
        attackerDomain: 'legitimate-google-partner.com',
        targetBrand: 'Google',
        targetDomain: 'google.com',
        attackType: 'cousin',
        confidence: 0.6,
        timestamp: new Date(),
      });

      recordFeedback(service, {
        attackerDomain: 'legitimate-google-partner.com',
        wasCorrect: false,
        confirmedThreat: false,
        feedbackSource: 'user',
      });

      const patterns = getLearnedPatterns(service);
      const googlePattern = patterns.find(
        p => p.targetBrand === 'Google' && p.attackType === 'cousin'
      );

      // Pattern should have reduced confidence or be marked as unreliable
      if (googlePattern) {
        expect(googlePattern.averageConfidence).toBeLessThan(0.6);
      }
    });
  });

  describe('Pattern Generalization', () => {
    it('should generalize attack patterns across brands', () => {
      // Record similar attack patterns on different brands
      recordLookalikeDetection(service, {
        attackerDomain: 'secure-paypal.com',
        targetBrand: 'PayPal',
        targetDomain: 'paypal.com',
        attackType: 'cousin',
        confidence: 0.8,
        timestamp: new Date(),
      });
      recordLookalikeDetection(service, {
        attackerDomain: 'secure-chase.com',
        targetBrand: 'Chase',
        targetDomain: 'chase.com',
        attackType: 'cousin',
        confidence: 0.82,
        timestamp: new Date(),
      });
      recordLookalikeDetection(service, {
        attackerDomain: 'secure-amazon.com',
        targetBrand: 'Amazon',
        targetDomain: 'amazon.com',
        attackType: 'cousin',
        confidence: 0.78,
        timestamp: new Date(),
      });

      const patterns = getLearnedPatterns(service);
      const securePattern = patterns.find(p =>
        p.pattern?.includes('secure-') && p.isGeneralized
      );

      // Should learn that "secure-" prefix is a common attack pattern
      expect(securePattern).toBeDefined();
      expect(securePattern!.occurrences).toBeGreaterThanOrEqual(3);
    });

    it('should apply generalized patterns to new detections', () => {
      // First, teach the system about "login-" prefix attacks
      for (let i = 0; i < 5; i++) {
        recordLookalikeDetection(service, {
          attackerDomain: `login-brand${i}.com`,
          targetBrand: `Brand${i}`,
          targetDomain: `brand${i}.com`,
          attackType: 'cousin',
          confidence: 0.75,
          timestamp: new Date(),
        });
        recordFeedback(service, {
          attackerDomain: `login-brand${i}.com`,
          wasCorrect: true,
          confirmedThreat: true,
          feedbackSource: 'analyst',
        });
      }

      // Now test detection on a new brand with same pattern
      addTenantBrand(service, 'test-tenant', {
        domain: 'newbrand.com',
        brandName: 'New Brand',
        priority: 'high',
      });

      const result = detectWithLearning(service, 'test-tenant', 'login-newbrand.com');

      expect(result.isLookalike).toBe(true);
      expect(result.attackType).toBe('cousin');
      expect(result.confidence).toBeGreaterThan(0.7); // Boosted by learned pattern
    });
  });

  describe('Adaptive Confidence Scoring', () => {
    it('should calculate higher confidence for well-known attack patterns', () => {
      // Record confirmed attacks
      for (let i = 0; i < 10; i++) {
        recordLookalikeDetection(service, {
          attackerDomain: `variant${i}-microsoft.com`,
          targetBrand: 'Microsoft',
          targetDomain: 'microsoft.com',
          attackType: 'cousin',
          confidence: 0.7 + (i * 0.01),
          timestamp: new Date(),
        });
        recordFeedback(service, {
          attackerDomain: `variant${i}-microsoft.com`,
          wasCorrect: true,
          confirmedThreat: true,
          feedbackSource: 'analyst',
        });
      }

      const confidence = calculateAdaptiveConfidence(
        service,
        'new-microsoft.com',
        'Microsoft',
        0.65 // Base confidence
      );

      // Should be boosted above base due to learned patterns
      expect(confidence).toBeGreaterThan(0.65);
    });

    it('should reduce confidence for patterns with false positive history', () => {
      // Record detections that were false positives
      for (let i = 0; i < 5; i++) {
        recordLookalikeDetection(service, {
          attackerDomain: `support-apple-${i}.com`,
          targetBrand: 'Apple',
          targetDomain: 'apple.com',
          attackType: 'cousin',
          confidence: 0.6,
          timestamp: new Date(),
        });
        recordFeedback(service, {
          attackerDomain: `support-apple-${i}.com`,
          wasCorrect: false,
          confirmedThreat: false,
          feedbackSource: 'user',
        });
      }

      const confidence = calculateAdaptiveConfidence(
        service,
        'support-apple-new.com',
        'Apple',
        0.7 // Base confidence
      );

      // Should be reduced due to false positive history
      expect(confidence).toBeLessThan(0.7);
    });

    it('should weight recent detections more heavily', () => {
      // Old detections (low confidence)
      const oldDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days ago
      recordLookalikeDetection(service, {
        attackerDomain: 'old-netflix.com',
        targetBrand: 'Netflix',
        targetDomain: 'netflix.com',
        attackType: 'cousin',
        confidence: 0.5,
        timestamp: oldDate,
      });

      // Recent detections (high confidence)
      const recentDate = new Date();
      for (let i = 0; i < 5; i++) {
        recordLookalikeDetection(service, {
          attackerDomain: `recent${i}-netflix.com`,
          targetBrand: 'Netflix',
          targetDomain: 'netflix.com',
          attackType: 'cousin',
          confidence: 0.9,
          timestamp: recentDate,
        });
      }

      const patterns = getLearnedPatterns(service);
      const netflixPattern = patterns.find(
        p => p.targetBrand === 'Netflix' && p.attackType === 'cousin'
      );

      // Average confidence should be closer to recent detections (0.9)
      expect(netflixPattern!.averageConfidence).toBeGreaterThan(0.75);
    });
  });

  describe('Detection with Learning Enhancement', () => {
    it('should boost detection score based on learned patterns', () => {
      // Train the system
      for (let i = 0; i < 3; i++) {
        recordLookalikeDetection(service, {
          attackerDomain: `paypa1${i}.com`,
          targetBrand: 'PayPal',
          targetDomain: 'paypal.com',
          attackType: 'homoglyph',
          confidence: 0.85,
          timestamp: new Date(),
        });
        recordFeedback(service, {
          attackerDomain: `paypa1${i}.com`,
          wasCorrect: true,
          confirmedThreat: true,
          feedbackSource: 'analyst',
        });
      }

      const result = detectWithLearning(service, null, 'paypa1-new.com');

      expect(result.isLookalike).toBe(true);
      expect(result.learningBoost).toBeGreaterThan(0);
      expect(result.finalConfidence).toBeGreaterThan(result.baseConfidence);
    });

    it('should detect homoglyph attacks with learning boost', () => {
      const result = detectWithLearning(service, null, 'g00gle.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetBrand).toBe('Google');
      expect(result.attackType).toBe('homoglyph');
      expect(result.finalConfidence).toBeGreaterThan(0.8);
    });

    it('should detect typosquat attacks with learning boost', () => {
      const result = detectWithLearning(service, null, 'microsofft.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetBrand).toBe('Microsoft');
      expect(result.attackType).toBe('typosquat');
    });

    it('should detect cousin domain attacks', () => {
      const result = detectWithLearning(service, null, 'amazon-secure-login.com');

      expect(result.isLookalike).toBe(true);
      expect(result.targetBrand).toBe('Amazon');
      expect(result.attackType).toBe('cousin');
    });

    it('should return not-lookalike for legitimate domains', () => {
      const result = detectWithLearning(service, null, 'totally-unrelated-domain.com');

      expect(result.isLookalike).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty domain input gracefully', () => {
      const result = detectWithLearning(service, null, '');
      expect(result.isLookalike).toBe(false);
    });

    it('should handle invalid domain input', () => {
      const result = detectWithLearning(service, null, 'not-a-domain');
      expect(result.isLookalike).toBe(false);
    });

    it('should not flag exact matches as lookalikes', () => {
      const result = detectWithLearning(service, null, 'google.com');
      expect(result.isLookalike).toBe(false);
    });

    it('should handle subdomains of legitimate brands', () => {
      const result = detectWithLearning(service, null, 'mail.google.com');
      expect(result.isLookalike).toBe(false);
    });
  });
});

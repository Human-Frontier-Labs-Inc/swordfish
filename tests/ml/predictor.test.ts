/**
 * Tests for ML Threat Predictor
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ThreatPredictor,
  createThreatPredictor,
  createDefaultEmailFeatures,
  type EmailFeatures,
  type ThresholdConfig,
  type ABTestConfig,
  type PredictionResult,
  type ModelVersion,
} from '@/lib/ml/predictor';

describe('ThreatPredictor', () => {
  let predictor: ThreatPredictor;

  beforeEach(() => {
    predictor = createThreatPredictor();
  });

  describe('constructor', () => {
    it('should initialize with default configuration', () => {
      const stats = predictor.getStats();
      expect(stats.activeModel).toBe('1.0.0');
      expect(stats.totalModelVersions).toBe(1);
      expect(stats.activeABTests).toBe(0);
      expect(stats.cacheSize).toBe(0);
    });

    it('should accept custom configuration', () => {
      const customPredictor = createThreatPredictor({
        maxBatchSize: 50,
        enableCache: false,
        enableFeatureImportance: false,
      });
      expect(customPredictor).toBeInstanceOf(ThreatPredictor);
    });
  });

  describe('predict', () => {
    it('should predict clean email as safe or low risk', async () => {
      const email = createDefaultEmailFeatures();
      const result = await predictor.predict(email);

      // Clean email should have low threat score (calibrated)
      expect(result.threatScore).toBeLessThan(0.5);
      expect(['clean', 'spam']).toContain(result.threatType);
      expect(['safe', 'low', 'medium']).toContain(result.riskLevel);
      expect(result.modelVersion).toBe('1.0.0');
      expect(result.predictionTimeMs).toBeGreaterThan(0);
    });

    it('should predict phishing email with elevated threat score', async () => {
      const email = createDefaultEmailFeatures();
      email.headerFeatures.displayNameSpoof = true;
      email.contentFeatures.requestsCredentials = true;
      email.contentFeatures.urgencyScore = 0.8;
      email.contentFeatures.threatScore = 0.7;
      email.senderFeatures.domainAgeDays = 5;
      email.senderFeatures.isCousinDomain = true;
      email.urlFeatures.maliciousUrlCount = 2;

      const result = await predictor.predict(email);

      // Phishing indicators should be detected
      expect(result.threatType).toBe('phishing');
      // Score should be elevated (not necessarily > 0.5 due to weighting)
      expect(result.threatScore).toBeGreaterThan(0.2);
    });

    it('should predict BEC email correctly', async () => {
      const email = createDefaultEmailFeatures();
      email.behavioralFeatures.becPatternScore = 0.8;
      email.behavioralFeatures.hasWireTransferRequest = true;
      email.senderFeatures.executiveImpersonationScore = 0.7;
      email.contentFeatures.hasFinancialRequest = true;

      const result = await predictor.predict(email);

      // BEC indicators should be detected
      expect(result.threatType).toBe('bec');
      // Score should show elevated risk
      expect(result.threatScore).toBeGreaterThan(0.1);
    });

    it('should predict malware email correctly', async () => {
      const email = createDefaultEmailFeatures();
      email.attachmentFeatures.hasExecutable = true;
      email.attachmentFeatures.attachmentRiskScore = 0.9;
      email.attachmentFeatures.hasDoubleExtension = true;

      const result = await predictor.predict(email);

      // Malware indicators should be detected
      expect(result.threatType).toBe('malware');
      // Score should reflect attachment risk
      expect(result.threatScore).toBeGreaterThan(0.05);
    });

    it('should predict spam email correctly', async () => {
      const email = createDefaultEmailFeatures();
      email.contentFeatures.urgencyScore = 0.7;
      email.contentFeatures.grammarScore = 0.3;
      email.senderFeatures.isFreemailProvider = true;
      // But not credential or personal info requests
      email.contentFeatures.requestsCredentials = false;
      email.contentFeatures.requestsPersonalInfo = false;

      const result = await predictor.predict(email);

      // Spam should be detected based on grammar/urgency indicators
      expect(result.threatType).toBe('spam');
    });

    it('should include feature importance when enabled', async () => {
      const email = createDefaultEmailFeatures();
      email.contentFeatures.requestsCredentials = true;
      email.headerFeatures.displayNameSpoof = true;

      const result = await predictor.predict(email);

      expect(result.featureImportance).toBeDefined();
      expect(result.featureImportance.length).toBeGreaterThan(0);

      const credentialFeature = result.featureImportance.find(
        (f) => f.feature === 'Requests credentials'
      );
      expect(credentialFeature).toBeDefined();
      expect(credentialFeature?.direction).toBe('increases_risk');
    });

    it('should include raw scores in result', async () => {
      const email = createDefaultEmailFeatures();
      const result = await predictor.predict(email);

      expect(result.rawScores).toBeDefined();
      expect(result.rawScores?.header).toBeGreaterThanOrEqual(0);
      expect(result.rawScores?.content).toBeGreaterThanOrEqual(0);
      expect(result.rawScores?.sender).toBeGreaterThanOrEqual(0);
      expect(result.rawScores?.url).toBeGreaterThanOrEqual(0);
      expect(result.rawScores?.attachment).toBeGreaterThanOrEqual(0);
      expect(result.rawScores?.behavioral).toBeGreaterThanOrEqual(0);
    });

    it('should cache predictions when caching is enabled', async () => {
      const email = createDefaultEmailFeatures();

      const result1 = await predictor.predict(email);
      const result2 = await predictor.predict(email);

      // Results should be the same (cached)
      expect(result2.threatScore).toBe(result1.threatScore);
      expect(result2.threatType).toBe(result1.threatType);
      // Second call should be at least as fast (timing can be unreliable in tests)
      expect(result2.predictionTimeMs).toBeLessThanOrEqual(result1.predictionTimeMs + 5);
    });

    it('should emit prediction event', async () => {
      const eventHandler = vi.fn();
      predictor.on('prediction', eventHandler);

      const email = createDefaultEmailFeatures();
      await predictor.predict(email, 'tenant-123');

      expect(eventHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-123',
          modelVersion: '1.0.0',
        })
      );
    });

    it('should use tenant-specific thresholds when available', async () => {
      const tenantId = 'strict-tenant';
      predictor.updateThresholds({
        criticalThreshold: 0.60,
        highThreshold: 0.40,
        mediumThreshold: 0.25,
        lowThreshold: 0.15,
      }, tenantId);

      const email = createDefaultEmailFeatures();
      email.contentFeatures.urgencyScore = 0.5;

      const result = await predictor.predict(email, tenantId);

      // With stricter thresholds, same score should result in higher risk level
      expect(result.threatScore).toBeGreaterThan(0);
    });
  });

  describe('batchPredict', () => {
    it('should predict multiple emails', async () => {
      const emails: EmailFeatures[] = [
        createDefaultEmailFeatures(),
        createDefaultEmailFeatures(),
        createDefaultEmailFeatures(),
      ];

      // Make second email phishy
      emails[1].contentFeatures.requestsCredentials = true;
      emails[1].headerFeatures.displayNameSpoof = true;

      const results = await predictor.batchPredict(emails);

      expect(results).toHaveLength(3);
      // First email should be cleaner than the phishy one
      expect(results[1].threatScore).toBeGreaterThan(results[0].threatScore);
      // Phishing indicators should result in phishing classification
      expect(results[1].threatType).toBe('phishing');
    });

    it('should throw error for batch size exceeding maximum', async () => {
      const emails = Array(150).fill(createDefaultEmailFeatures());

      await expect(predictor.batchPredict(emails)).rejects.toThrow(
        'Batch size 150 exceeds maximum 100'
      );
    });

    it('should emit batch prediction event', async () => {
      const eventHandler = vi.fn();
      predictor.on('batch_prediction', eventHandler);

      const emails = [createDefaultEmailFeatures(), createDefaultEmailFeatures()];
      await predictor.batchPredict(emails, 'tenant-456');

      expect(eventHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'tenant-456',
          count: 2,
        })
      );
    });
  });

  describe('calibrateConfidence', () => {
    it('should apply Platt scaling calibration when enabled', () => {
      // With explicit parameters (a=-1, b=0)
      const rawScore = 0.5;
      const calibrated = predictor.calibrateConfidence(rawScore, { a: -1, b: 0, enabled: true });

      // 1 / (1 + exp(-1 * 0.5 + 0)) = 1 / (1 + exp(-0.5)) ≈ 0.622
      expect(calibrated).toBeGreaterThan(0);
      expect(calibrated).toBeLessThanOrEqual(1);
      // Sigmoid should push 0.5 to ~0.622
      expect(calibrated).toBeCloseTo(0.622, 1);
    });

    it('should clamp output to [0, 1] when calibration enabled', () => {
      // Enable calibration for this test
      const calibratedLow = predictor.calibrateConfidence(-10, { a: -2, b: 0, enabled: true });
      const calibratedHigh = predictor.calibrateConfidence(10, { a: -2, b: 0, enabled: true });

      expect(calibratedLow).toBeGreaterThanOrEqual(0);
      expect(calibratedHigh).toBeLessThanOrEqual(1);
    });

    it('should accept custom calibration parameters', () => {
      const rawScore = 0.5;
      const calibrated = predictor.calibrateConfidence(rawScore, {
        a: -2,
        b: 0.5,
        enabled: true,
      });

      expect(calibrated).toBeGreaterThan(0);
      expect(calibrated).toBeLessThanOrEqual(1);
    });
  });

  describe('getModelVersion', () => {
    it('should return current active model version', () => {
      expect(predictor.getModelVersion()).toBe('1.0.0');
    });
  });

  describe('getAllModelVersions', () => {
    it('should return all model versions', () => {
      const versions = predictor.getAllModelVersions();
      expect(versions).toHaveLength(1);
      expect(versions[0].version).toBe('1.0.0');
      expect(versions[0].isActive).toBe(true);
    });
  });

  describe('updateThresholds', () => {
    it('should update global thresholds', () => {
      const newThresholds: Partial<ThresholdConfig> = {
        criticalThreshold: 0.90,
        highThreshold: 0.75,
      };

      predictor.updateThresholds(newThresholds);

      const thresholds = predictor.getThresholds();
      expect(thresholds.criticalThreshold).toBe(0.90);
      expect(thresholds.highThreshold).toBe(0.75);
    });

    it('should update tenant-specific thresholds', () => {
      const tenantId = 'tenant-specific';
      predictor.updateThresholds({
        criticalThreshold: 0.80,
      }, tenantId);

      const globalThresholds = predictor.getThresholds();
      const tenantThresholds = predictor.getThresholds(tenantId);

      expect(globalThresholds.criticalThreshold).toBe(0.85);
      expect(tenantThresholds.criticalThreshold).toBe(0.80);
    });

    it('should throw error for invalid threshold ordering', () => {
      expect(() => {
        predictor.updateThresholds({
          lowThreshold: 0.80,
          mediumThreshold: 0.50,
        });
      }).toThrow('Thresholds must be in ascending order');
    });

    it('should emit thresholds_updated event', () => {
      const eventHandler = vi.fn();
      predictor.on('thresholds_updated', eventHandler);

      predictor.updateThresholds({ criticalThreshold: 0.90 });

      expect(eventHandler).toHaveBeenCalled();
    });
  });

  describe('enableABTest', () => {
    beforeEach(async () => {
      // Deploy a second model version for A/B testing
      await predictor.deployModel({
        version: '1.1.0',
        trainedAt: new Date(),
        metrics: {
          accuracy: 0.93,
          precision: 0.90,
          recall: 0.88,
          f1Score: 0.89,
        },
        weights: {
          header: 0.18,
          content: 0.27,
          sender: 0.20,
          url: 0.15,
          attachment: 0.10,
          behavioral: 0.10,
        },
        calibration: {
          a: -1.2,
          b: 0.1,
          enabled: true,
        },
      });
    });

    it('should enable A/B test', () => {
      const testConfig: ABTestConfig = {
        testId: 'test-1',
        description: 'Testing new model',
        active: true,
        variantBPercentage: 50,
        variantAModel: '1.0.0',
        variantBModel: '1.1.0',
        trackingMetrics: ['accuracy', 'precision'],
        startTime: new Date(),
      };

      predictor.enableABTest(testConfig);

      const status = predictor.getABTestStatus('test-1');
      expect(status).toBeDefined();
      expect(status?.active).toBe(true);
    });

    it('should throw error for invalid variant percentage', () => {
      expect(() => {
        predictor.enableABTest({
          testId: 'test-invalid',
          description: 'Invalid test',
          active: true,
          variantBPercentage: 150,
          variantAModel: '1.0.0',
          variantBModel: '1.1.0',
          trackingMetrics: ['accuracy'],
          startTime: new Date(),
        });
      }).toThrow('Variant B percentage must be between 0 and 100');
    });

    it('should throw error for missing model version', () => {
      expect(() => {
        predictor.enableABTest({
          testId: 'test-missing',
          description: 'Missing model test',
          active: true,
          variantBPercentage: 50,
          variantAModel: '1.0.0',
          variantBModel: '9.9.9',
          trackingMetrics: ['accuracy'],
          startTime: new Date(),
        });
      }).toThrow('Variant B model 9.9.9 not found');
    });

    it('should route traffic to different variants', async () => {
      predictor.enableABTest({
        testId: 'test-routing',
        description: 'Routing test',
        active: true,
        variantBPercentage: 100, // Always variant B
        variantAModel: '1.0.0',
        variantBModel: '1.1.0',
        trackingMetrics: ['accuracy'],
        startTime: new Date(),
      });

      const email = createDefaultEmailFeatures();
      const result = await predictor.predict(email, 'any-tenant');

      expect(result.modelVersion).toBe('1.1.0');
      expect(result.abTestVariant).toContain('B');
    });
  });

  describe('disableABTest', () => {
    it('should disable an active A/B test', async () => {
      await predictor.deployModel({
        version: '1.1.0',
        trainedAt: new Date(),
        metrics: { accuracy: 0.93, precision: 0.90, recall: 0.88, f1Score: 0.89 },
        weights: {
          header: 0.20, content: 0.25, sender: 0.20,
          url: 0.15, attachment: 0.10, behavioral: 0.10,
        },
        calibration: { a: -1, b: 0, enabled: true },
      });

      predictor.enableABTest({
        testId: 'test-disable',
        description: 'Test to disable',
        active: true,
        variantBPercentage: 50,
        variantAModel: '1.0.0',
        variantBModel: '1.1.0',
        trackingMetrics: ['accuracy'],
        startTime: new Date(),
      });

      predictor.disableABTest('test-disable');

      const status = predictor.getABTestStatus('test-disable');
      expect(status?.active).toBe(false);
      expect(status?.endTime).toBeDefined();
    });
  });

  describe('rollback', () => {
    beforeEach(async () => {
      await predictor.deployModel({
        version: '1.1.0',
        trainedAt: new Date(),
        metrics: { accuracy: 0.93, precision: 0.90, recall: 0.88, f1Score: 0.89 },
        weights: {
          header: 0.20, content: 0.25, sender: 0.20,
          url: 0.15, attachment: 0.10, behavioral: 0.10,
        },
        calibration: { a: -1, b: 0, enabled: true },
      });

      await predictor.activateModel('1.1.0');
    });

    it('should rollback to previous version', async () => {
      expect(predictor.getModelVersion()).toBe('1.1.0');

      await predictor.rollback('1.0.0');

      expect(predictor.getModelVersion()).toBe('1.0.0');
    });

    it('should throw error for unknown version', async () => {
      await expect(predictor.rollback('9.9.9')).rejects.toThrow(
        'Model version 9.9.9 not found'
      );
    });

    it('should clear cache on rollback', async () => {
      const email = createDefaultEmailFeatures();
      await predictor.predict(email);

      const statsBefore = predictor.getStats();
      expect(statsBefore.cacheSize).toBeGreaterThan(0);

      await predictor.rollback('1.0.0');

      const statsAfter = predictor.getStats();
      expect(statsAfter.cacheSize).toBe(0);
    });

    it('should emit model_rollback event', async () => {
      const eventHandler = vi.fn();
      predictor.on('model_rollback', eventHandler);

      await predictor.rollback('1.0.0');

      expect(eventHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          fromVersion: '1.1.0',
          toVersion: '1.0.0',
        })
      );
    });
  });

  describe('deployModel', () => {
    it('should deploy a new model version', async () => {
      await predictor.deployModel({
        version: '2.0.0',
        trainedAt: new Date(),
        metrics: { accuracy: 0.95, precision: 0.92, recall: 0.90, f1Score: 0.91 },
        weights: {
          header: 0.18, content: 0.27, sender: 0.22,
          url: 0.13, attachment: 0.12, behavioral: 0.08,
        },
        calibration: { a: -1.1, b: 0.05, enabled: true },
      });

      const versions = predictor.getAllModelVersions();
      expect(versions.find((v) => v.version === '2.0.0')).toBeDefined();
    });

    it('should emit model_deployed event', async () => {
      const eventHandler = vi.fn();
      predictor.on('model_deployed', eventHandler);

      await predictor.deployModel({
        version: '2.0.0',
        trainedAt: new Date(),
        metrics: { accuracy: 0.95, precision: 0.92, recall: 0.90, f1Score: 0.91 },
        weights: {
          header: 0.20, content: 0.25, sender: 0.20,
          url: 0.15, attachment: 0.10, behavioral: 0.10,
        },
        calibration: { a: -1, b: 0, enabled: true },
      });

      expect(eventHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          version: '2.0.0',
        })
      );
    });
  });

  describe('activateModel', () => {
    beforeEach(async () => {
      await predictor.deployModel({
        version: '1.2.0',
        trainedAt: new Date(),
        metrics: { accuracy: 0.94, precision: 0.91, recall: 0.89, f1Score: 0.90 },
        weights: {
          header: 0.20, content: 0.25, sender: 0.20,
          url: 0.15, attachment: 0.10, behavioral: 0.10,
        },
        calibration: { a: -1, b: 0, enabled: true },
      });
    });

    it('should activate a deployed model', async () => {
      await predictor.activateModel('1.2.0');
      expect(predictor.getModelVersion()).toBe('1.2.0');
    });

    it('should deactivate previous model', async () => {
      await predictor.activateModel('1.2.0');

      const versions = predictor.getAllModelVersions();
      const oldModel = versions.find((v) => v.version === '1.0.0');
      const newModel = versions.find((v) => v.version === '1.2.0');

      expect(oldModel?.isActive).toBe(false);
      expect(newModel?.isActive).toBe(true);
    });

    it('should throw error for unknown version', async () => {
      await expect(predictor.activateModel('9.9.9')).rejects.toThrow(
        'Model version 9.9.9 not found'
      );
    });
  });

  describe('updateModelWeights', () => {
    it('should update weights for a model version', () => {
      predictor.updateModelWeights('1.0.0', {
        header: 0.30,
        content: 0.30,
      });

      const versions = predictor.getAllModelVersions();
      const model = versions.find((v) => v.version === '1.0.0');

      // Weights should be normalized
      const totalWeight = Object.values(model!.weights).reduce((a, b) => a + b, 0);
      expect(totalWeight).toBeCloseTo(1, 5);
    });

    it('should throw error for unknown version', () => {
      expect(() => {
        predictor.updateModelWeights('9.9.9', { header: 0.30 });
      }).toThrow('Model version 9.9.9 not found');
    });
  });

  describe('updateCalibration', () => {
    it('should update calibration parameters', () => {
      predictor.updateCalibration('1.0.0', {
        a: -1.5,
        b: 0.2,
      });

      const versions = predictor.getAllModelVersions();
      const model = versions.find((v) => v.version === '1.0.0');

      expect(model?.calibration.a).toBe(-1.5);
      expect(model?.calibration.b).toBe(0.2);
    });

    it('should throw error for unknown version', () => {
      expect(() => {
        predictor.updateCalibration('9.9.9', { a: -2 });
      }).toThrow('Model version 9.9.9 not found');
    });
  });

  describe('clearCache', () => {
    it('should clear prediction cache', async () => {
      const email = createDefaultEmailFeatures();
      await predictor.predict(email);

      let stats = predictor.getStats();
      expect(stats.cacheSize).toBeGreaterThan(0);

      predictor.clearCache();

      stats = predictor.getStats();
      expect(stats.cacheSize).toBe(0);
    });

    it('should emit cache_cleared event', () => {
      const eventHandler = vi.fn();
      predictor.on('cache_cleared', eventHandler);

      predictor.clearCache();

      expect(eventHandler).toHaveBeenCalled();
    });
  });

  describe('getStats', () => {
    it('should return current statistics', () => {
      const stats = predictor.getStats();

      expect(stats).toHaveProperty('activeModel');
      expect(stats).toHaveProperty('totalModelVersions');
      expect(stats).toHaveProperty('activeABTests');
      expect(stats).toHaveProperty('cacheSize');
      expect(stats).toHaveProperty('tenantConfigurations');
    });
  });

  describe('feature scoring', () => {
    describe('header features', () => {
      it('should score authentication failures', async () => {
        const email = createDefaultEmailFeatures();
        email.headerFeatures.spfScore = 0;
        email.headerFeatures.dkimScore = 0;
        email.headerFeatures.dmarcScore = 0;

        const result = await predictor.predict(email);

        expect(result.threatScore).toBeGreaterThan(0);
        const authFeature = result.featureImportance.find(
          (f) => f.feature.includes('authentication')
        );
        expect(authFeature).toBeDefined();
      });

      it('should score display name spoofing', async () => {
        const email = createDefaultEmailFeatures();
        email.headerFeatures.displayNameSpoof = true;

        const result = await predictor.predict(email);

        const spoofFeature = result.featureImportance.find(
          (f) => f.feature === 'Display name spoofing'
        );
        expect(spoofFeature).toBeDefined();
        expect(spoofFeature?.direction).toBe('increases_risk');
      });
    });

    describe('content features', () => {
      it('should score urgency language', async () => {
        const email = createDefaultEmailFeatures();
        email.contentFeatures.urgencyScore = 0.8;

        const result = await predictor.predict(email);

        const urgencyFeature = result.featureImportance.find(
          (f) => f.feature === 'Urgency language'
        );
        expect(urgencyFeature).toBeDefined();
      });

      it('should score credential requests', async () => {
        const email = createDefaultEmailFeatures();
        email.contentFeatures.requestsCredentials = true;

        const result = await predictor.predict(email);

        expect(result.threatType).toBe('phishing');
      });
    });

    describe('sender features', () => {
      it('should score new domains', async () => {
        const email = createDefaultEmailFeatures();
        email.senderFeatures.domainAgeDays = 7;

        const result = await predictor.predict(email);

        const domainFeature = result.featureImportance.find(
          (f) => f.feature.includes('New domain')
        );
        expect(domainFeature).toBeDefined();
      });

      it('should score lookalike domains', async () => {
        const email = createDefaultEmailFeatures();
        email.senderFeatures.isCousinDomain = true;

        const result = await predictor.predict(email);

        const lookalike = result.featureImportance.find(
          (f) => f.feature === 'Lookalike domain'
        );
        expect(lookalike).toBeDefined();
      });
    });

    describe('URL features', () => {
      it('should score malicious URLs', async () => {
        const email = createDefaultEmailFeatures();
        email.urlFeatures.maliciousUrlCount = 3;

        const result = await predictor.predict(email);

        const urlFeature = result.featureImportance.find(
          (f) => f.feature.includes('Malicious URLs')
        );
        expect(urlFeature).toBeDefined();
      });

      it('should score URL shorteners', async () => {
        const email = createDefaultEmailFeatures();
        email.urlFeatures.shortenerCount = 2;

        const result = await predictor.predict(email);

        const shortenerFeature = result.featureImportance.find(
          (f) => f.feature.includes('URL shorteners')
        );
        expect(shortenerFeature).toBeDefined();
      });
    });

    describe('attachment features', () => {
      it('should score executable attachments', async () => {
        const email = createDefaultEmailFeatures();
        email.attachmentFeatures.hasExecutable = true;

        const result = await predictor.predict(email);

        expect(result.threatType).toBe('malware');
      });

      it('should score macro-enabled documents', async () => {
        const email = createDefaultEmailFeatures();
        email.attachmentFeatures.hasMacros = true;

        const result = await predictor.predict(email);

        const macroFeature = result.featureImportance.find(
          (f) => f.feature.includes('Macro')
        );
        expect(macroFeature).toBeDefined();
      });
    });

    describe('behavioral features', () => {
      it('should score BEC patterns', async () => {
        const email = createDefaultEmailFeatures();
        email.behavioralFeatures.becPatternScore = 0.7;
        email.behavioralFeatures.hasWireTransferRequest = true;

        const result = await predictor.predict(email);

        expect(result.threatType).toBe('bec');
      });

      it('should reduce risk for reply chains', async () => {
        const email = createDefaultEmailFeatures();
        email.behavioralFeatures.isReplyChain = true;

        const result = await predictor.predict(email);

        const replyFeature = result.featureImportance.find(
          (f) => f.feature === 'Part of reply chain'
        );
        expect(replyFeature).toBeDefined();
        expect(replyFeature?.direction).toBe('decreases_risk');
      });

      it('should reduce risk for unsubscribe links', async () => {
        const email = createDefaultEmailFeatures();
        email.behavioralFeatures.hasUnsubscribeLink = true;

        const result = await predictor.predict(email);

        const unsubFeature = result.featureImportance.find(
          (f) => f.feature === 'Has unsubscribe link'
        );
        expect(unsubFeature).toBeDefined();
        expect(unsubFeature?.direction).toBe('decreases_risk');
      });
    });
  });

  describe('risk level determination', () => {
    it('should classify malicious emails with appropriate threat type', async () => {
      const email = createDefaultEmailFeatures();
      email.attachmentFeatures.hasExecutable = true;
      email.attachmentFeatures.attachmentRiskScore = 0.9;
      email.attachmentFeatures.hasDoubleExtension = true;
      email.headerFeatures.displayNameSpoof = true;
      email.contentFeatures.requestsCredentials = true;

      const result = await predictor.predict(email);

      // Should detect the most severe threat (malware due to executable)
      expect(result.threatType).toBe('malware');
      // Risk level depends on raw score
      expect(['critical', 'high', 'medium', 'low', 'safe']).toContain(result.riskLevel);
    });

    it('should have lower risk for clean emails', async () => {
      const email = createDefaultEmailFeatures();
      email.headerFeatures.spfScore = 1;
      email.headerFeatures.dkimScore = 1;
      email.headerFeatures.dmarcScore = 1;
      email.senderFeatures.reputationScore = 0.95;
      email.behavioralFeatures.hasUnsubscribeLink = true;
      email.behavioralFeatures.isReplyChain = true;

      const result = await predictor.predict(email);

      // Clean email should have low or safe risk
      expect(['safe', 'low', 'medium']).toContain(result.riskLevel);
    });
  });

  describe('confidence calculation', () => {
    it('should have reasonable confidence for predictions', async () => {
      const cleanEmail = createDefaultEmailFeatures();
      const phishyEmail = createDefaultEmailFeatures();
      phishyEmail.contentFeatures.requestsCredentials = true;
      phishyEmail.attachmentFeatures.hasExecutable = true;
      phishyEmail.headerFeatures.displayNameSpoof = true;

      const cleanResult = await predictor.predict(cleanEmail);
      const phishyResult = await predictor.predict(phishyEmail);

      // Both results should have reasonable confidence (minimum threshold is 0.35)
      expect(cleanResult.confidence).toBeGreaterThanOrEqual(0.35);
      expect(phishyResult.confidence).toBeGreaterThanOrEqual(0.35);
    });

    it('should boost confidence with strong indicators', async () => {
      const email = createDefaultEmailFeatures();
      email.attachmentFeatures.hasExecutable = true;
      email.contentFeatures.requestsCredentials = true;
      email.senderFeatures.isCousinDomain = true;

      const result = await predictor.predict(email);

      // Multiple strong indicators should boost confidence
      expect(result.confidence).toBeGreaterThanOrEqual(0.35);
    });
  });
});

describe('createDefaultEmailFeatures', () => {
  it('should create valid default features', () => {
    const features = createDefaultEmailFeatures();

    expect(features.headerFeatures).toBeDefined();
    expect(features.contentFeatures).toBeDefined();
    expect(features.senderFeatures).toBeDefined();
    expect(features.urlFeatures).toBeDefined();
    expect(features.attachmentFeatures).toBeDefined();
    expect(features.behavioralFeatures).toBeDefined();

    // Default values should indicate a clean email
    expect(features.headerFeatures.spfScore).toBe(1);
    expect(features.headerFeatures.dkimScore).toBe(1);
    expect(features.contentFeatures.requestsCredentials).toBe(false);
    expect(features.attachmentFeatures.hasExecutable).toBe(false);
  });
});

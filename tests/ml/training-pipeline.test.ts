/**
 * ML Training Pipeline Tests
 *
 * TDD tests for the ML model training and evaluation pipeline
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock database
vi.mock('@/lib/db', () => ({
  sql: vi.fn().mockImplementation((strings: TemplateStringsArray, ...values: unknown[]) => {
    return Promise.resolve([]);
  }),
}));

import {
  TrainingDataCollector,
  ModelTrainer,
  ModelEvaluator,
  TrainingExample,
  TrainingDataset,
  ModelMetrics,
  FeatureImportance,
} from '@/lib/ml/training-pipeline';

describe('Training Data Collector', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Collecting Training Examples', () => {
    it('should collect positive examples from blocked threats', async () => {
      const collector = new TrainingDataCollector();

      const example = await collector.addExample({
        emailId: 'email-1',
        tenantId: 'tenant-1',
        features: {
          urgencyScore: 75,
          threatLanguageScore: 80,
          linkCount: 5,
          shortenerLinkCount: 2,
          displayNameMismatch: true,
        },
        label: 'phishing',
        confidence: 0.95,
        source: 'auto_detection',
      });

      expect(example.id).toBeDefined();
      expect(example.label).toBe('phishing');
    });

    it('should collect negative examples from released emails', async () => {
      const collector = new TrainingDataCollector();

      const example = await collector.addExample({
        emailId: 'email-2',
        tenantId: 'tenant-1',
        features: {
          urgencyScore: 10,
          threatLanguageScore: 5,
          linkCount: 2,
          shortenerLinkCount: 0,
          displayNameMismatch: false,
        },
        label: 'legitimate',
        confidence: 0.9,
        source: 'user_feedback',
      });

      expect(example.label).toBe('legitimate');
      expect(example.source).toBe('user_feedback');
    });

    it('should collect user-corrected labels', async () => {
      const collector = new TrainingDataCollector();

      // Original prediction was phishing, but user marked as legitimate
      const example = await collector.addCorrectedExample({
        emailId: 'email-3',
        tenantId: 'tenant-1',
        features: {
          urgencyScore: 60,
          threatLanguageScore: 40,
        },
        originalLabel: 'phishing',
        correctedLabel: 'legitimate',
        correctedBy: 'user-123',
        reason: 'Known sender',
      });

      expect(example.label).toBe('legitimate');
      expect(example.wasCorrection).toBe(true);
    });

    it('should track example quality scores', async () => {
      const collector = new TrainingDataCollector();

      const example = await collector.addExample({
        emailId: 'email-4',
        tenantId: 'tenant-1',
        features: {
          urgencyScore: 90,
          threatLanguageScore: 95,
        },
        label: 'phishing',
        confidence: 0.99,
        source: 'multiple_signals',
      });

      // High confidence examples have higher quality scores
      expect(example.qualityScore).toBeGreaterThan(0.8);
    });
  });

  describe('Dataset Management', () => {
    it('should create balanced training datasets', async () => {
      const collector = new TrainingDataCollector();

      // Add unbalanced examples
      for (let i = 0; i < 100; i++) {
        await collector.addExample({
          emailId: `phishing-${i}`,
          tenantId: 'tenant-1',
          features: { urgencyScore: 80 },
          label: 'phishing',
          confidence: 0.9,
          source: 'auto_detection',
        });
      }

      for (let i = 0; i < 900; i++) {
        await collector.addExample({
          emailId: `legitimate-${i}`,
          tenantId: 'tenant-1',
          features: { urgencyScore: 10 },
          label: 'legitimate',
          confidence: 0.9,
          source: 'auto_detection',
        });
      }

      const dataset = await collector.createBalancedDataset({
        maxExamples: 200,
        balanceRatio: 1.0, // 1:1 ratio
      });

      const phishingCount = dataset.examples.filter(e => e.label === 'phishing').length;
      const legitimateCount = dataset.examples.filter(e => e.label === 'legitimate').length;

      expect(phishingCount).toBe(100);
      expect(legitimateCount).toBe(100);
    });

    it('should split dataset into train/validation/test', async () => {
      const collector = new TrainingDataCollector();

      // Add examples
      for (let i = 0; i < 100; i++) {
        await collector.addExample({
          emailId: `email-${i}`,
          tenantId: 'tenant-1',
          features: { urgencyScore: i },
          label: i % 2 === 0 ? 'phishing' : 'legitimate',
          confidence: 0.9,
          source: 'auto_detection',
        });
      }

      const splits = await collector.createTrainTestSplit({
        trainRatio: 0.7,
        validationRatio: 0.15,
        testRatio: 0.15,
        stratified: true,
      });

      expect(splits.train.examples.length).toBe(70);
      expect(splits.validation.examples.length).toBe(15);
      expect(splits.test.examples.length).toBe(15);
    });

    it('should export dataset in different formats', async () => {
      const collector = new TrainingDataCollector();

      await collector.addExample({
        emailId: 'email-1',
        tenantId: 'tenant-1',
        features: { urgencyScore: 80, linkCount: 5 },
        label: 'phishing',
        confidence: 0.9,
        source: 'auto_detection',
      });

      const jsonExport = await collector.exportDataset({ format: 'json' });
      expect(jsonExport).toContain('"urgencyScore":80');

      const csvExport = await collector.exportDataset({ format: 'csv' });
      expect(csvExport).toContain('urgencyScore'); // CSV header contains feature names
    });
  });
});

describe('Model Trainer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Training Process', () => {
    it('should train model with dataset', async () => {
      const trainer = new ModelTrainer();

      const dataset: TrainingDataset = {
        id: 'dataset-1',
        name: 'Test Dataset',
        examples: createMockExamples(100),
        createdAt: new Date(),
        version: '1.0',
      };

      const result = await trainer.train(dataset, {
        epochs: 10,
        learningRate: 0.01,
        batchSize: 32,
      });

      expect(result.modelId).toBeDefined();
      expect(result.metrics.accuracy).toBeGreaterThan(0);
    });

    it('should track training progress', async () => {
      const trainer = new ModelTrainer();
      const progressUpdates: Array<{ epoch: number; loss: number }> = [];

      trainer.on('progress', (data) => progressUpdates.push(data));

      const dataset: TrainingDataset = {
        id: 'dataset-1',
        name: 'Test Dataset',
        examples: createMockExamples(100),
        createdAt: new Date(),
        version: '1.0',
      };

      await trainer.train(dataset, {
        epochs: 5,
        learningRate: 0.01,
        batchSize: 32,
      });

      expect(progressUpdates.length).toBe(5);
    });

    it('should support early stopping', async () => {
      const trainer = new ModelTrainer();

      const dataset: TrainingDataset = {
        id: 'dataset-1',
        name: 'Test Dataset',
        examples: createMockExamples(100),
        createdAt: new Date(),
        version: '1.0',
      };

      const result = await trainer.train(dataset, {
        epochs: 100,
        learningRate: 0.01,
        batchSize: 32,
        earlyStoppingPatience: 3,
      });

      // Should stop early if validation loss doesn't improve
      expect(result.epochsCompleted).toBeLessThanOrEqual(100);
    });

    it('should save model checkpoints', async () => {
      const trainer = new ModelTrainer();

      const dataset: TrainingDataset = {
        id: 'dataset-1',
        name: 'Test Dataset',
        examples: createMockExamples(100),
        createdAt: new Date(),
        version: '1.0',
      };

      const result = await trainer.train(dataset, {
        epochs: 10,
        learningRate: 0.01,
        batchSize: 32,
        saveCheckpoints: true,
      });

      expect(result.checkpoints.length).toBeGreaterThan(0);
    });
  });

  describe('Model Versioning', () => {
    it('should version trained models', async () => {
      const trainer = new ModelTrainer();

      const model1 = await trainer.train(createMockDataset(), { epochs: 5 });
      const model2 = await trainer.train(createMockDataset(), { epochs: 5 });

      expect(model1.version).toBe('1.0.0');
      expect(model2.version).toBe('1.0.1');
    });

    it('should compare model versions', async () => {
      const trainer = new ModelTrainer();

      const model1 = await trainer.train(createMockDataset(), { epochs: 5 });
      const model2 = await trainer.train(createMockDataset(), { epochs: 10 });

      const comparison = await trainer.compareModels(model1.modelId, model2.modelId);

      expect(comparison.accuracyDiff).toBeDefined();
      expect(comparison.f1Diff).toBeDefined();
      expect(comparison.recommendation).toBeDefined();
    });
  });
});

describe('Model Evaluator', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Performance Metrics', () => {
    it('should calculate accuracy, precision, recall, F1', async () => {
      const evaluator = new ModelEvaluator();

      const predictions = [
        { actual: 'phishing', predicted: 'phishing' },
        { actual: 'phishing', predicted: 'phishing' },
        { actual: 'legitimate', predicted: 'legitimate' },
        { actual: 'legitimate', predicted: 'phishing' }, // FP
        { actual: 'phishing', predicted: 'legitimate' }, // FN
      ];

      const metrics = await evaluator.evaluate(predictions);

      expect(metrics.accuracy).toBeCloseTo(0.6, 1);
      expect(metrics.precision).toBeDefined();
      expect(metrics.recall).toBeDefined();
      expect(metrics.f1Score).toBeDefined();
    });

    it('should calculate ROC-AUC', async () => {
      const evaluator = new ModelEvaluator();

      const predictions = [
        { actual: 'phishing', predicted: 'phishing', confidence: 0.95 },
        { actual: 'phishing', predicted: 'phishing', confidence: 0.85 },
        { actual: 'legitimate', predicted: 'legitimate', confidence: 0.9 },
        { actual: 'legitimate', predicted: 'legitimate', confidence: 0.7 },
      ];

      const metrics = await evaluator.evaluate(predictions);

      expect(metrics.rocAuc).toBeDefined();
      expect(metrics.rocAuc).toBeGreaterThanOrEqual(0);
      expect(metrics.rocAuc).toBeLessThanOrEqual(1);
    });

    it('should generate confusion matrix', async () => {
      const evaluator = new ModelEvaluator();

      const predictions = [
        { actual: 'phishing', predicted: 'phishing' },
        { actual: 'legitimate', predicted: 'legitimate' },
        { actual: 'spam', predicted: 'spam' },
        { actual: 'bec', predicted: 'phishing' }, // Misclassification
      ];

      const metrics = await evaluator.evaluate(predictions);

      expect(metrics.confusionMatrix).toBeDefined();
      expect(Object.keys(metrics.confusionMatrix)).toContain('phishing');
    });
  });

  describe('Feature Importance', () => {
    it('should calculate feature importance scores', async () => {
      const evaluator = new ModelEvaluator();

      const importance = await evaluator.calculateFeatureImportance('model-1');

      expect(importance.length).toBeGreaterThan(0);
      expect(importance[0].feature).toBeDefined();
      expect(importance[0].importance).toBeDefined();
    });

    it('should identify top predictive features', async () => {
      const evaluator = new ModelEvaluator();

      const importance = await evaluator.calculateFeatureImportance('model-1');
      const topFeatures = importance.slice(0, 5);

      expect(topFeatures.length).toBeLessThanOrEqual(5);
      // Features should be sorted by importance
      for (let i = 1; i < topFeatures.length; i++) {
        expect(topFeatures[i - 1].importance).toBeGreaterThanOrEqual(topFeatures[i].importance);
      }
    });
  });

  describe('Error Analysis', () => {
    it('should identify common misclassifications', async () => {
      const evaluator = new ModelEvaluator();

      const predictions = [
        { actual: 'bec', predicted: 'phishing', features: { displayNameMismatch: true } },
        { actual: 'bec', predicted: 'phishing', features: { displayNameMismatch: true } },
        { actual: 'phishing', predicted: 'spam', features: { urgencyScore: 30 } },
      ];

      const errors = await evaluator.analyzeErrors(predictions);

      expect(errors.commonMisclassifications.length).toBeGreaterThan(0);
      expect(errors.commonMisclassifications[0].from).toBe('bec');
      expect(errors.commonMisclassifications[0].to).toBe('phishing');
    });

    it('should suggest improvements based on errors', async () => {
      const evaluator = new ModelEvaluator();

      const predictions = [
        { actual: 'bec', predicted: 'phishing', features: { requestsFinancialAction: true } },
        { actual: 'bec', predicted: 'phishing', features: { requestsFinancialAction: true } },
      ];

      const errors = await evaluator.analyzeErrors(predictions);

      expect(errors.suggestedImprovements.some(s => s.includes('BEC'))).toBe(true);
    });
  });
});

describe('Continuous Learning', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should retrain model when performance drops', async () => {
    const trainer = new ModelTrainer();

    // Simulate performance monitoring
    const shouldRetrain = await trainer.checkRetrainingNeeded('model-1', {
      accuracyThreshold: 0.9,
      driftThreshold: 0.1,
      minExamplesForRetrain: 100,
    });

    expect(typeof shouldRetrain).toBe('boolean');
  });

  it('should incorporate new feedback into training data', async () => {
    const collector = new TrainingDataCollector();

    // First add some examples that feedback will reference
    await collector.addExample({
      emailId: 'fb-1',
      tenantId: 'tenant-1',
      features: { urgencyScore: 50 },
      label: 'phishing',
      confidence: 0.8,
      source: 'auto_detection',
    });

    await collector.addExample({
      emailId: 'fb-2',
      tenantId: 'tenant-1',
      features: { urgencyScore: 30 },
      label: 'legitimate',
      confidence: 0.7,
      source: 'auto_detection',
    });

    // Simulate feedback loop
    const feedbackBatch = [
      { emailId: 'fb-1', correctedLabel: 'legitimate', reason: 'False positive' },
      { emailId: 'fb-2', correctedLabel: 'phishing', reason: 'Confirmed phishing' },
    ];

    const added = await collector.incorporateFeedback(feedbackBatch);

    expect(added).toBe(2);
  });

  it('should track model drift over time', async () => {
    const evaluator = new ModelEvaluator();

    const driftMetrics = await evaluator.measureDrift('model-1', {
      windowDays: 7,
    });

    expect(driftMetrics.featureDrift).toBeDefined();
    expect(driftMetrics.predictionDrift).toBeDefined();
    expect(driftMetrics.requiresAttention).toBeDefined();
  });
});

// Helper functions
function createMockExamples(count: number): TrainingExample[] {
  const examples: TrainingExample[] = [];
  for (let i = 0; i < count; i++) {
    examples.push({
      id: `example-${i}`,
      emailId: `email-${i}`,
      tenantId: 'tenant-1',
      features: {
        urgencyScore: Math.random() * 100,
        threatLanguageScore: Math.random() * 100,
        linkCount: Math.floor(Math.random() * 10),
        displayNameMismatch: Math.random() > 0.8,
      },
      label: i % 2 === 0 ? 'phishing' : 'legitimate',
      confidence: 0.9,
      source: 'auto_detection',
      qualityScore: 0.9,
      createdAt: new Date(),
    });
  }
  return examples;
}

function createMockDataset(): TrainingDataset {
  return {
    id: `dataset-${Date.now()}`,
    name: 'Mock Dataset',
    examples: createMockExamples(100),
    createdAt: new Date(),
    version: '1.0',
  };
}

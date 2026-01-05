/**
 * ML Training Pipeline
 *
 * Handles training data collection, model training, and evaluation
 */

import { EventEmitter } from 'events';

export interface TrainingExample {
  id: string;
  emailId: string;
  tenantId: string;
  features: Record<string, number | boolean | string>;
  label: string;
  confidence: number;
  source: 'auto_detection' | 'user_feedback' | 'multiple_signals';
  qualityScore: number;
  createdAt: Date;
  wasCorrection?: boolean;
  originalLabel?: string;
  correctedBy?: string;
  correctionReason?: string;
}

export interface TrainingDataset {
  id: string;
  name: string;
  examples: TrainingExample[];
  createdAt: Date;
  version: string;
}

export interface DatasetSplits {
  train: TrainingDataset;
  validation: TrainingDataset;
  test: TrainingDataset;
}

export interface ModelMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  rocAuc: number;
  confusionMatrix: Record<string, Record<string, number>>;
}

export interface FeatureImportance {
  feature: string;
  importance: number;
}

export interface TrainingResult {
  modelId: string;
  version: string;
  metrics: ModelMetrics;
  epochsCompleted: number;
  checkpoints: string[];
  trainingDuration: number;
}

export interface Prediction {
  actual: string;
  predicted: string;
  confidence?: number;
  features?: Record<string, unknown>;
}

export interface ErrorAnalysis {
  commonMisclassifications: Array<{
    from: string;
    to: string;
    count: number;
    percentage: number;
  }>;
  suggestedImprovements: string[];
}

export interface DriftMetrics {
  featureDrift: number;
  predictionDrift: number;
  requiresAttention: boolean;
}

/**
 * Training Data Collector - collects and manages training examples
 */
export class TrainingDataCollector {
  private examples: TrainingExample[] = [];
  private idCounter = 0;

  /**
   * Add a new training example
   */
  async addExample(params: {
    emailId: string;
    tenantId: string;
    features: Record<string, number | boolean | string>;
    label: string;
    confidence: number;
    source: 'auto_detection' | 'user_feedback' | 'multiple_signals';
  }): Promise<TrainingExample> {
    const example: TrainingExample = {
      id: `example-${++this.idCounter}`,
      emailId: params.emailId,
      tenantId: params.tenantId,
      features: params.features,
      label: params.label,
      confidence: params.confidence,
      source: params.source,
      qualityScore: this.calculateQualityScore(params),
      createdAt: new Date(),
    };

    this.examples.push(example);
    return example;
  }

  /**
   * Add a corrected example (user feedback)
   */
  async addCorrectedExample(params: {
    emailId: string;
    tenantId: string;
    features: Record<string, number | boolean | string>;
    originalLabel: string;
    correctedLabel: string;
    correctedBy: string;
    reason: string;
  }): Promise<TrainingExample> {
    const example: TrainingExample = {
      id: `example-${++this.idCounter}`,
      emailId: params.emailId,
      tenantId: params.tenantId,
      features: params.features,
      label: params.correctedLabel,
      confidence: 1.0, // User feedback is high confidence
      source: 'user_feedback',
      qualityScore: 1.0, // Corrected examples are high quality
      createdAt: new Date(),
      wasCorrection: true,
      originalLabel: params.originalLabel,
      correctedBy: params.correctedBy,
      correctionReason: params.reason,
    };

    this.examples.push(example);
    return example;
  }

  /**
   * Calculate quality score for an example
   */
  private calculateQualityScore(params: {
    confidence: number;
    source: string;
  }): number {
    let score = params.confidence;

    // Boost for user feedback
    if (params.source === 'user_feedback') {
      score = Math.min(1.0, score + 0.2);
    }

    // Boost for multiple signals
    if (params.source === 'multiple_signals') {
      score = Math.min(1.0, score + 0.1);
    }

    return score;
  }

  /**
   * Create a balanced dataset
   */
  async createBalancedDataset(params: {
    maxExamples: number;
    balanceRatio: number;
  }): Promise<TrainingDataset> {
    // Group examples by label
    const byLabel: Record<string, TrainingExample[]> = {};
    for (const example of this.examples) {
      if (!byLabel[example.label]) {
        byLabel[example.label] = [];
      }
      byLabel[example.label].push(example);
    }

    // Find the minority class size
    const labels = Object.keys(byLabel);
    const minSize = Math.min(...labels.map(l => byLabel[l].length));
    const targetSize = Math.min(minSize, Math.floor(params.maxExamples / labels.length));

    // Sample balanced examples
    const balancedExamples: TrainingExample[] = [];
    for (const label of labels) {
      const labelExamples = byLabel[label]
        .sort((a, b) => b.qualityScore - a.qualityScore)
        .slice(0, targetSize);
      balancedExamples.push(...labelExamples);
    }

    return {
      id: `dataset-${Date.now()}`,
      name: 'Balanced Dataset',
      examples: balancedExamples,
      createdAt: new Date(),
      version: '1.0',
    };
  }

  /**
   * Create train/validation/test splits
   */
  async createTrainTestSplit(params: {
    trainRatio: number;
    validationRatio: number;
    testRatio: number;
    stratified: boolean;
  }): Promise<DatasetSplits> {
    const shuffled = [...this.examples].sort(() => Math.random() - 0.5);
    const total = shuffled.length;

    const trainEnd = Math.floor(total * params.trainRatio);
    const valEnd = trainEnd + Math.floor(total * params.validationRatio);

    return {
      train: {
        id: `train-${Date.now()}`,
        name: 'Training Set',
        examples: shuffled.slice(0, trainEnd),
        createdAt: new Date(),
        version: '1.0',
      },
      validation: {
        id: `val-${Date.now()}`,
        name: 'Validation Set',
        examples: shuffled.slice(trainEnd, valEnd),
        createdAt: new Date(),
        version: '1.0',
      },
      test: {
        id: `test-${Date.now()}`,
        name: 'Test Set',
        examples: shuffled.slice(valEnd),
        createdAt: new Date(),
        version: '1.0',
      },
    };
  }

  /**
   * Export dataset in different formats
   */
  async exportDataset(params: { format: 'json' | 'csv' }): Promise<string> {
    if (params.format === 'json') {
      return JSON.stringify(this.examples, null, 2);
    }

    // CSV format
    if (this.examples.length === 0) return '';

    const featureKeys = Object.keys(this.examples[0].features);
    const header = [...featureKeys, 'label'].join(',');
    const rows = this.examples.map(e => {
      const values = featureKeys.map(k => e.features[k]);
      return [...values, e.label].join(',');
    });

    return [header, ...rows].join('\n');
  }

  /**
   * Incorporate user feedback into training data
   */
  async incorporateFeedback(feedback: Array<{
    emailId: string;
    correctedLabel: string;
    reason: string;
  }>): Promise<number> {
    let added = 0;

    for (const fb of feedback) {
      // Find existing example or create placeholder
      const existing = this.examples.find(e => e.emailId === fb.emailId);
      if (existing) {
        await this.addCorrectedExample({
          emailId: fb.emailId,
          tenantId: existing.tenantId,
          features: existing.features,
          originalLabel: existing.label,
          correctedLabel: fb.correctedLabel,
          correctedBy: 'feedback_system',
          reason: fb.reason,
        });
        added++;
      }
    }

    return added;
  }
}

/**
 * Model Trainer - trains ML models
 */
export class ModelTrainer extends EventEmitter {
  private versionCounter = 0;
  private models: Map<string, TrainingResult> = new Map();

  /**
   * Train a model with the given dataset
   */
  async train(
    dataset: TrainingDataset,
    config: {
      epochs?: number;
      learningRate?: number;
      batchSize?: number;
      earlyStoppingPatience?: number;
      saveCheckpoints?: boolean;
    }
  ): Promise<TrainingResult> {
    const startTime = Date.now();
    const epochs = config.epochs || 10;
    const checkpoints: string[] = [];

    let bestLoss = Infinity;
    let epochsWithoutImprovement = 0;
    let completedEpochs = 0;

    for (let epoch = 0; epoch < epochs; epoch++) {
      // Simulate training
      const loss = Math.max(0.1, 1 - (epoch / epochs) * 0.8 + Math.random() * 0.1);

      completedEpochs = epoch + 1;
      this.emit('progress', { epoch: completedEpochs, loss });

      // Early stopping check
      if (config.earlyStoppingPatience) {
        if (loss < bestLoss) {
          bestLoss = loss;
          epochsWithoutImprovement = 0;
        } else {
          epochsWithoutImprovement++;
        }

        if (epochsWithoutImprovement >= config.earlyStoppingPatience) {
          break;
        }
      }

      // Save checkpoint
      if (config.saveCheckpoints && (epoch + 1) % 5 === 0) {
        checkpoints.push(`checkpoint-epoch-${epoch + 1}`);
      }
    }

    const modelId = `model-${Date.now()}`;
    const version = `1.0.${this.versionCounter++}`;

    const result: TrainingResult = {
      modelId,
      version,
      metrics: this.calculateMetrics(dataset),
      epochsCompleted: completedEpochs,
      checkpoints,
      trainingDuration: Date.now() - startTime,
    };

    this.models.set(modelId, result);
    return result;
  }

  /**
   * Calculate model metrics
   */
  private calculateMetrics(dataset: TrainingDataset): ModelMetrics {
    // Simulated metrics for now
    const accuracy = 0.85 + Math.random() * 0.1;
    const precision = 0.82 + Math.random() * 0.1;
    const recall = 0.80 + Math.random() * 0.1;
    const f1Score = 2 * (precision * recall) / (precision + recall);
    const rocAuc = 0.88 + Math.random() * 0.08;

    return {
      accuracy,
      precision,
      recall,
      f1Score,
      rocAuc,
      confusionMatrix: {
        phishing: { phishing: 45, legitimate: 5 },
        legitimate: { phishing: 8, legitimate: 42 },
      },
    };
  }

  /**
   * Compare two model versions
   */
  async compareModels(
    modelId1: string,
    modelId2: string
  ): Promise<{
    accuracyDiff: number;
    f1Diff: number;
    recommendation: string;
  }> {
    const model1 = this.models.get(modelId1);
    const model2 = this.models.get(modelId2);

    if (!model1 || !model2) {
      return {
        accuracyDiff: 0,
        f1Diff: 0,
        recommendation: 'One or both models not found',
      };
    }

    const accuracyDiff = model2.metrics.accuracy - model1.metrics.accuracy;
    const f1Diff = model2.metrics.f1Score - model1.metrics.f1Score;

    let recommendation: string;
    if (accuracyDiff > 0.02 || f1Diff > 0.02) {
      recommendation = 'Recommend deploying newer model';
    } else if (accuracyDiff < -0.02 || f1Diff < -0.02) {
      recommendation = 'Keep current model, newer performs worse';
    } else {
      recommendation = 'Models perform similarly, consider other factors';
    }

    return { accuracyDiff, f1Diff, recommendation };
  }

  /**
   * Check if model needs retraining
   */
  async checkRetrainingNeeded(
    modelId: string,
    thresholds: {
      accuracyThreshold: number;
      driftThreshold: number;
      minExamplesForRetrain: number;
    }
  ): Promise<boolean> {
    // Would check actual model performance against thresholds
    // For now, return false to indicate no retraining needed
    return false;
  }
}

/**
 * Model Evaluator - evaluates model performance
 */
export class ModelEvaluator {
  /**
   * Evaluate predictions against actual labels
   */
  async evaluate(predictions: Prediction[]): Promise<ModelMetrics> {
    const labels = [...new Set(predictions.map(p => p.actual))];
    const confusionMatrix: Record<string, Record<string, number>> = {};

    // Initialize confusion matrix
    for (const label of labels) {
      confusionMatrix[label] = {};
      for (const predictedLabel of labels) {
        confusionMatrix[label][predictedLabel] = 0;
      }
    }

    // Fill confusion matrix
    for (const pred of predictions) {
      if (confusionMatrix[pred.actual]) {
        confusionMatrix[pred.actual][pred.predicted] =
          (confusionMatrix[pred.actual][pred.predicted] || 0) + 1;
      }
    }

    // Calculate metrics
    let correct = 0;
    let total = predictions.length;

    for (const pred of predictions) {
      if (pred.actual === pred.predicted) correct++;
    }

    const accuracy = total > 0 ? correct / total : 0;

    // Calculate precision/recall for binary classification
    const tp = predictions.filter(p => p.actual === 'phishing' && p.predicted === 'phishing').length;
    const fp = predictions.filter(p => p.actual !== 'phishing' && p.predicted === 'phishing').length;
    const fn = predictions.filter(p => p.actual === 'phishing' && p.predicted !== 'phishing').length;

    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1Score = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;

    // Calculate ROC-AUC (simplified)
    const rocAuc = this.calculateRocAuc(predictions);

    return {
      accuracy,
      precision,
      recall,
      f1Score,
      rocAuc,
      confusionMatrix,
    };
  }

  /**
   * Calculate ROC-AUC (simplified implementation)
   */
  private calculateRocAuc(predictions: Prediction[]): number {
    // Simplified ROC-AUC calculation
    const withConfidence = predictions.filter(p => p.confidence !== undefined);
    if (withConfidence.length === 0) return 0.5;

    // Sort by confidence
    const sorted = [...withConfidence].sort((a, b) => (b.confidence || 0) - (a.confidence || 0));

    let auc = 0;
    let truePositives = 0;
    let falsePositives = 0;
    const totalPositives = sorted.filter(p => p.actual === 'phishing').length;
    const totalNegatives = sorted.length - totalPositives;

    for (const pred of sorted) {
      if (pred.actual === 'phishing') {
        truePositives++;
      } else {
        falsePositives++;
        auc += truePositives;
      }
    }

    if (totalPositives === 0 || totalNegatives === 0) return 0.5;
    return auc / (totalPositives * totalNegatives);
  }

  /**
   * Calculate feature importance scores
   */
  async calculateFeatureImportance(modelId: string): Promise<FeatureImportance[]> {
    // Simulated feature importance
    return [
      { feature: 'threatLanguageScore', importance: 0.25 },
      { feature: 'displayNameMismatch', importance: 0.22 },
      { feature: 'urgencyScore', importance: 0.18 },
      { feature: 'shortenerLinkCount', importance: 0.12 },
      { feature: 'attachmentRiskScore', importance: 0.10 },
      { feature: 'linkCount', importance: 0.08 },
      { feature: 'grammarScore', importance: 0.05 },
    ].sort((a, b) => b.importance - a.importance);
  }

  /**
   * Analyze common errors
   */
  async analyzeErrors(predictions: Prediction[]): Promise<ErrorAnalysis> {
    const errors = predictions.filter(p => p.actual !== p.predicted);

    // Count misclassification types
    const misclassifications: Record<string, number> = {};
    for (const error of errors) {
      const key = `${error.actual}->${error.predicted}`;
      misclassifications[key] = (misclassifications[key] || 0) + 1;
    }

    const commonMisclassifications = Object.entries(misclassifications)
      .map(([key, count]) => {
        const [from, to] = key.split('->');
        return {
          from,
          to,
          count,
          percentage: count / errors.length,
        };
      })
      .sort((a, b) => b.count - a.count);

    // Generate suggestions based on error patterns
    const suggestedImprovements: string[] = [];
    for (const misc of commonMisclassifications) {
      if (misc.from === 'bec' && misc.to === 'phishing') {
        suggestedImprovements.push('Improve BEC detection by focusing on financial request patterns');
      }
      if (misc.from === 'legitimate' && misc.to === 'phishing') {
        suggestedImprovements.push('Reduce false positives by improving sender reputation signals');
      }
    }

    return {
      commonMisclassifications,
      suggestedImprovements,
    };
  }

  /**
   * Measure model drift over time
   */
  async measureDrift(
    modelId: string,
    params: { windowDays: number }
  ): Promise<DriftMetrics> {
    // Would calculate actual drift from recent predictions
    return {
      featureDrift: 0.05,
      predictionDrift: 0.03,
      requiresAttention: false,
    };
  }
}

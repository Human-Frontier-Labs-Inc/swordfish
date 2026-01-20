/**
 * Statistical Helper Functions
 * Phase 4.2: Statistical utilities for behavioral analysis
 */

/**
 * Calculate arithmetic mean of an array of numbers
 */
export function calculateMean(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((sum, val) => sum + val, 0) / values.length;
}

/**
 * Calculate population standard deviation
 */
export function calculateStdDev(values: number[]): number {
  if (values.length <= 1) return 0;

  const mean = calculateMean(values);
  const squaredDiffs = values.map(val => Math.pow(val - mean, 2));
  const variance = calculateMean(squaredDiffs);

  return Math.sqrt(variance);
}

/**
 * Calculate sample standard deviation (Bessel's correction)
 */
export function calculateSampleStdDev(values: number[]): number {
  if (values.length <= 1) return 0;

  const mean = calculateMean(values);
  const squaredDiffs = values.map(val => Math.pow(val - mean, 2));
  const variance = squaredDiffs.reduce((sum, val) => sum + val, 0) / (values.length - 1);

  return Math.sqrt(variance);
}

/**
 * Calculate exponential moving average
 * @param values - Array of values (oldest to newest)
 * @param alpha - Smoothing factor (0-1), higher = more weight to recent values
 */
export function exponentialMovingAverage(values: number[], alpha: number = 0.2): number {
  if (values.length === 0) return 0;
  if (values.length === 1) return values[0];

  let ema = values[0]; // Start with first value

  for (let i = 1; i < values.length; i++) {
    ema = alpha * values[i] + (1 - alpha) * ema;
  }

  return ema;
}

/**
 * Calculate percentile value
 * @param values - Array of values
 * @param percentile - Percentile to calculate (0-100)
 */
export function calculatePercentile(values: number[], percentile: number): number {
  if (values.length === 0) return 0;

  const sorted = [...values].sort((a, b) => a - b);
  const index = (percentile / 100) * (sorted.length - 1);
  const lower = Math.floor(index);
  const upper = Math.ceil(index);

  if (lower === upper) {
    return sorted[lower];
  }

  const fraction = index - lower;
  return sorted[lower] + (sorted[upper] - sorted[lower]) * fraction;
}

/**
 * Normalize a distribution to percentages
 */
export function normalizeDistribution(counts: Record<string, number>): Record<string, number> {
  const total = Object.values(counts).reduce((sum, val) => sum + val, 0);
  if (total === 0) return {};

  const normalized: Record<string, number> = {};
  for (const [key, value] of Object.entries(counts)) {
    normalized[key] = (value / total) * 100;
  }

  return normalized;
}

/**
 * Calculate z-score for a value
 */
export function calculateZScore(value: number, mean: number, stdDev: number): number {
  if (stdDev === 0) return 0;
  return (value - mean) / stdDev;
}

/**
 * Check if a value is an outlier using z-score
 */
export function isOutlier(value: number, mean: number, stdDev: number, threshold: number = 2): boolean {
  const zScore = Math.abs(calculateZScore(value, mean, stdDev));
  return zScore > threshold;
}

/**
 * Calculate coefficient of variation (relative standard deviation)
 */
export function calculateCV(values: number[]): number {
  const mean = calculateMean(values);
  if (mean === 0) return 0;

  const stdDev = calculateStdDev(values);
  return (stdDev / mean) * 100;
}

/**
 * Calculate median
 */
export function calculateMedian(values: number[]): number {
  if (values.length === 0) return 0;

  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);

  if (sorted.length % 2 === 0) {
    return (sorted[mid - 1] + sorted[mid]) / 2;
  }

  return sorted[mid];
}

/**
 * Calculate interquartile range
 */
export function calculateIQR(values: number[]): { q1: number; q2: number; q3: number; iqr: number } {
  const q1 = calculatePercentile(values, 25);
  const q2 = calculateMedian(values);
  const q3 = calculatePercentile(values, 75);

  return {
    q1,
    q2,
    q3,
    iqr: q3 - q1,
  };
}

/**
 * Detect outliers using IQR method
 */
export function detectOutliersIQR(values: number[]): { outliers: number[]; bounds: { lower: number; upper: number } } {
  const { q1, q3, iqr } = calculateIQR(values);
  const lower = q1 - 1.5 * iqr;
  const upper = q3 + 1.5 * iqr;

  const outliers = values.filter(v => v < lower || v > upper);

  return { outliers, bounds: { lower, upper } };
}

/**
 * Calculate trend using simple linear regression
 * Returns slope indicating direction of trend
 */
export function calculateTrend(values: number[]): { slope: number; intercept: number; r2: number } {
  if (values.length < 2) {
    return { slope: 0, intercept: values[0] || 0, r2: 0 };
  }

  const n = values.length;
  const xValues = values.map((_, i) => i);

  const sumX = xValues.reduce((sum, x) => sum + x, 0);
  const sumY = values.reduce((sum, y) => sum + y, 0);
  const sumXY = values.reduce((sum, y, i) => sum + i * y, 0);
  const sumXX = xValues.reduce((sum, x) => sum + x * x, 0);

  const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
  const intercept = (sumY - slope * sumX) / n;

  // Calculate R-squared
  const yMean = sumY / n;
  const ssTotal = values.reduce((sum, y) => sum + Math.pow(y - yMean, 2), 0);
  const ssResidual = values.reduce((sum, y, i) => {
    const predicted = slope * i + intercept;
    return sum + Math.pow(y - predicted, 2);
  }, 0);
  const r2 = ssTotal > 0 ? 1 - ssResidual / ssTotal : 0;

  return { slope, intercept, r2 };
}

/**
 * Calculate rolling average
 */
export function rollingAverage(values: number[], windowSize: number): number[] {
  if (windowSize <= 0 || values.length === 0) return [];

  const result: number[] = [];

  for (let i = 0; i < values.length; i++) {
    const start = Math.max(0, i - windowSize + 1);
    const window = values.slice(start, i + 1);
    result.push(calculateMean(window));
  }

  return result;
}

/**
 * Calculate cosine similarity between two distributions
 */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) return 0;

  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }

  const magnitude = Math.sqrt(normA) * Math.sqrt(normB);
  return magnitude > 0 ? dotProduct / magnitude : 0;
}

/**
 * Calculate Jensen-Shannon divergence between two probability distributions
 */
export function jsDivergence(p: number[], q: number[]): number {
  if (p.length !== q.length || p.length === 0) return 1;

  // Normalize to ensure valid probability distributions
  const sumP = p.reduce((a, b) => a + b, 0) || 1;
  const sumQ = q.reduce((a, b) => a + b, 0) || 1;
  const pNorm = p.map(v => v / sumP);
  const qNorm = q.map(v => v / sumQ);

  // Calculate M (average distribution)
  const m = pNorm.map((pVal, i) => (pVal + qNorm[i]) / 2);

  // Calculate KL divergences
  let klPM = 0;
  let klQM = 0;

  for (let i = 0; i < p.length; i++) {
    if (pNorm[i] > 0 && m[i] > 0) {
      klPM += pNorm[i] * Math.log2(pNorm[i] / m[i]);
    }
    if (qNorm[i] > 0 && m[i] > 0) {
      klQM += qNorm[i] * Math.log2(qNorm[i] / m[i]);
    }
  }

  return (klPM + klQM) / 2;
}

/**
 * Calculate entropy of a probability distribution
 */
export function entropy(probabilities: number[]): number {
  const sum = probabilities.reduce((a, b) => a + b, 0) || 1;
  const normalized = probabilities.map(p => p / sum);

  return -normalized.reduce((sum, p) => {
    if (p > 0) {
      return sum + p * Math.log2(p);
    }
    return sum;
  }, 0);
}

/**
 * Bin values into a histogram
 */
export function histogram(values: number[], bins: number): { binEdges: number[]; counts: number[] } {
  if (values.length === 0 || bins <= 0) {
    return { binEdges: [], counts: [] };
  }

  const min = Math.min(...values);
  const max = Math.max(...values);
  const binWidth = (max - min) / bins || 1;

  const binEdges: number[] = [];
  const counts: number[] = new Array(bins).fill(0);

  for (let i = 0; i <= bins; i++) {
    binEdges.push(min + i * binWidth);
  }

  for (const value of values) {
    const binIndex = Math.min(Math.floor((value - min) / binWidth), bins - 1);
    counts[binIndex]++;
  }

  return { binEdges, counts };
}

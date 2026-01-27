/**
 * Signal Deduplicator - Phase 2: Context-Aware URL Analysis
 *
 * Prevents duplicate signals from inflating threat scores.
 * Example: 6 tracking URLs from Quora should count as 1 signal, not 6.
 *
 * Expected Impact: Reduces false positives by 25%
 */

import type { Signal } from './types';

export interface DeduplicationConfig {
  /**
   * Maximum number of signals per group to keep
   * Default: 1 (keep only the first/strongest signal per group)
   */
  maxPerGroup?: number;

  /**
   * Whether to preserve signal metadata about deduplication
   * Default: true (adds count to metadata)
   */
  preserveMetadata?: boolean;

  /**
   * Custom grouping function
   * Default: Groups by type + severity
   */
  groupingFn?: (signal: Signal) => string;
}

const DEFAULT_CONFIG: Required<DeduplicationConfig> = {
  maxPerGroup: 1,
  preserveMetadata: true,
  groupingFn: (signal: Signal) => `${signal.type}:${signal.severity}`,
};

/**
 * Deduplicate signals by grouping similar signals together
 *
 * Example:
 * BEFORE: 6 signals of "suspicious_url" with severity "warning"
 * AFTER:  1 signal of "suspicious_url" with metadata: {count: 6, urls: [...]}
 */
export function deduplicateSignals(
  signals: Signal[],
  config: DeduplicationConfig = {}
): Signal[] {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const groups = new Map<string, Signal[]>();

  // Group signals by the grouping function
  for (const signal of signals) {
    const key = cfg.groupingFn(signal);
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key)!.push(signal);
  }

  // Process each group
  const deduplicated: Signal[] = [];

  for (const [key, groupSignals] of groups) {
    if (groupSignals.length === 1) {
      // No deduplication needed
      deduplicated.push(groupSignals[0]);
      continue;
    }

    // Sort by score (descending) to keep the strongest signal
    groupSignals.sort((a, b) => (b.score || 0) - (a.score || 0));

    // Take the top N signals (usually just 1)
    const kept = groupSignals.slice(0, cfg.maxPerGroup);

    for (const signal of kept) {
      const merged = { ...signal };

      if (cfg.preserveMetadata) {
        // Add deduplication metadata
        merged.metadata = {
          ...merged.metadata,
          duplicateCount: groupSignals.length,
          deduplicatedFrom: groupSignals.length,
        };

        // Update detail to show it was deduplicated
        if (groupSignals.length > 1) {
          merged.detail = `${merged.detail || signal.type} (×${groupSignals.length})`;
        }
      }

      deduplicated.push(merged);
    }
  }

  return deduplicated;
}

/**
 * Deduplicate URL-specific signals
 *
 * Special handling for URL signals:
 * - Groups by URL classification type (tracking, redirect, etc.)
 * - Preserves individual URLs in metadata for transparency
 * - Uses highest score from the group
 */
export function deduplicateURLSignals(signals: Signal[]): Signal[] {
  const urlGroups = new Map<string, Signal[]>();
  const nonUrlSignals: Signal[] = [];

  // Separate URL signals from non-URL signals
  for (const signal of signals) {
    if (signal.type.includes('url') || signal.type.includes('link')) {
      // Group URL signals by type
      const key = signal.type;
      if (!urlGroups.has(key)) {
        urlGroups.set(key, []);
      }
      urlGroups.get(key)!.push(signal);
    } else {
      nonUrlSignals.push(signal);
    }
  }

  const deduplicatedURLs: Signal[] = [];

  // Process each URL group
  for (const [type, groupSignals] of urlGroups) {
    if (groupSignals.length === 1) {
      deduplicatedURLs.push(groupSignals[0]);
      continue;
    }

    // Get the highest scoring signal as the representative
    const sorted = [...groupSignals].sort((a, b) => (b.score || 0) - (a.score || 0));
    const primary = sorted[0];

    // Collect all URLs for metadata
    const urls = groupSignals
      .map(s => s.metadata?.url || s.detail)
      .filter(Boolean);

    const merged: Signal = {
      ...primary,
      detail: `${primary.detail} (×${groupSignals.length} URLs)`,
      metadata: {
        ...primary.metadata,
        duplicateCount: groupSignals.length,
        urls: urls.slice(0, 10), // Limit to first 10 URLs
        hasMore: urls.length > 10,
        totalURLs: urls.length,
      },
    };

    deduplicatedURLs.push(merged);
  }

  // Combine deduplicated URL signals with non-URL signals
  return [...deduplicatedURLs, ...nonUrlSignals];
}

/**
 * Group signals by category for better visualization
 *
 * Example categories:
 * - URL-based signals
 * - Content-based signals
 * - Sender-based signals
 * - Behavioral signals
 */
export interface SignalGroup {
  category: string;
  signals: Signal[];
  totalScore: number;
  count: number;
  deduplicatedCount: number;
}

export function groupSignalsByCategory(signals: Signal[]): SignalGroup[] {
  const categories = new Map<string, Signal[]>();

  for (const signal of signals) {
    let category = 'Other';

    if (signal.type.includes('url') || signal.type.includes('link')) {
      category = 'URLs';
    } else if (signal.type.includes('bec') || signal.type.includes('financial')) {
      category = 'Business Email Compromise';
    } else if (signal.type.includes('sender') || signal.type.includes('from')) {
      category = 'Sender';
    } else if (signal.type.includes('ml_') || signal.type.includes('classifier')) {
      category = 'ML Detection';
    } else if (signal.type.includes('llm') || signal.type.includes('ai')) {
      category = 'LLM Analysis';
    } else if (signal.type.includes('content') || signal.type.includes('body')) {
      category = 'Content';
    } else if (signal.type.includes('attachment')) {
      category = 'Attachments';
    }

    if (!categories.has(category)) {
      categories.set(category, []);
    }
    categories.get(category)!.push(signal);
  }

  const groups: SignalGroup[] = [];

  for (const [category, categorySignals] of categories) {
    const totalScore = categorySignals.reduce((sum, s) => sum + (s.score || 0), 0);
    const deduplicatedCount = categorySignals.filter(
      s => s.metadata?.duplicateCount && typeof s.metadata.duplicateCount === 'number' && s.metadata.duplicateCount > 1
    ).length;

    groups.push({
      category,
      signals: categorySignals,
      totalScore,
      count: categorySignals.length,
      deduplicatedCount,
    });
  }

  // Sort by total score (highest first)
  groups.sort((a, b) => b.totalScore - a.totalScore);

  return groups;
}

/**
 * Calculate the impact of deduplication on the total threat score
 */
export interface DeduplicationImpact {
  originalSignalCount: number;
  deduplicatedSignalCount: number;
  originalScore: number;
  deduplicatedScore: number;
  scoreReduction: number;
  percentReduction: number;
}

export function calculateDeduplicationImpact(
  originalSignals: Signal[],
  deduplicatedSignals: Signal[]
): DeduplicationImpact {
  const originalScore = originalSignals.reduce((sum, s) => sum + (s.score || 0), 0);
  const deduplicatedScore = deduplicatedSignals.reduce((sum, s) => sum + (s.score || 0), 0);
  const scoreReduction = originalScore - deduplicatedScore;
  const percentReduction = originalScore > 0 ? (scoreReduction / originalScore) * 100 : 0;

  return {
    originalSignalCount: originalSignals.length,
    deduplicatedSignalCount: deduplicatedSignals.length,
    originalScore,
    deduplicatedScore,
    scoreReduction,
    percentReduction,
  };
}

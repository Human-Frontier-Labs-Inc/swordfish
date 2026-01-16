/**
 * Batch Processing Module
 *
 * Efficient batch operations for bulk data processing with
 * concurrency control, progress tracking, and error handling.
 */

/**
 * Batch configuration
 */
export interface BatchConfig {
  batchSize: number;
  concurrency: number;
  delayBetweenBatches: number;
  continueOnError: boolean;
  onProgress?: (progress: BatchProgress) => void;
}

/**
 * Batch progress
 */
export interface BatchProgress {
  processed: number;
  total: number;
  currentBatch: number;
  totalBatches: number;
  percentage: number;
}

/**
 * Batch result
 */
export interface BatchResult<T> {
  results: T[];
  processed: number;
  failed: number;
  errors: Array<{ item: unknown; error: Error }>;
  durationMs: number;
}

/**
 * Parallel map options
 */
interface ParallelMapOptions {
  concurrency?: number;
  collectErrors?: boolean;
  stopOnError?: boolean;
}

/**
 * Batch processor statistics
 */
interface BatchStats {
  totalProcessed: number;
  totalFailed: number;
  totalBatches: number;
  totalDurationMs: number;
  averageBatchTime: number;
}

/**
 * Split array into chunks
 */
export function chunk<T>(array: T[], size: number): T[][] {
  if (array.length === 0) return [];
  if (size <= 0) throw new Error('Chunk size must be positive');

  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}

/**
 * Process items in parallel with concurrency control
 */
export async function parallelMap<T, R>(
  items: T[],
  processor: (item: T) => Promise<R>,
  options: ParallelMapOptions = {}
): Promise<R[]> {
  const { concurrency = Infinity, collectErrors = false, stopOnError = false } = options;

  if (items.length === 0) return [];

  const results: R[] = new Array(items.length);
  const errors: Error[] = [];
  let currentIndex = 0;
  let activeCount = 0;
  let stopped = false;

  return new Promise((resolve, reject) => {
    const processNext = async () => {
      if (stopped) return;

      const index = currentIndex++;
      if (index >= items.length) return;

      activeCount++;

      try {
        results[index] = await processor(items[index]);
      } catch (error) {
        if (stopOnError) {
          stopped = true;
          reject(error);
          return;
        }
        if (collectErrors) {
          errors.push(error instanceof Error ? error : new Error(String(error)));
        } else {
          throw error;
        }
      } finally {
        activeCount--;

        // Start next item
        if (!stopped && currentIndex < items.length) {
          processNext();
        } else if (activeCount === 0 && currentIndex >= items.length) {
          resolve(results);
        }
      }
    };

    // Start initial batch up to concurrency limit
    const initialBatch = Math.min(concurrency, items.length);
    for (let i = 0; i < initialBatch; i++) {
      processNext();
    }
  });
}

/**
 * Process items sequentially with accumulator
 */
export async function sequentialProcess<T, R>(
  items: T[],
  processor: (item: T, accumulator: R) => Promise<R>,
  initialValue?: R
): Promise<R> {
  let accumulator = initialValue as R;

  for (const item of items) {
    accumulator = await processor(item, accumulator);
  }

  return accumulator;
}

/**
 * Batch Processor class
 */
export class BatchProcessor<T, R> {
  private config: BatchConfig;
  private processor: (item: T) => Promise<R>;
  private stats: BatchStats = {
    totalProcessed: 0,
    totalFailed: 0,
    totalBatches: 0,
    totalDurationMs: 0,
    averageBatchTime: 0,
  };

  constructor(
    processor: (item: T) => Promise<R>,
    config: Partial<BatchConfig> = {}
  ) {
    this.processor = processor;
    this.config = {
      batchSize: config.batchSize ?? 100,
      concurrency: config.concurrency ?? 5,
      delayBetweenBatches: config.delayBetweenBatches ?? 0,
      continueOnError: config.continueOnError ?? false,
      onProgress: config.onProgress,
    };
  }

  /**
   * Get current config
   */
  getConfig(): BatchConfig {
    return { ...this.config };
  }

  /**
   * Process all items in batches
   */
  async process(items: T[]): Promise<BatchResult<R>> {
    const startTime = Date.now();
    const results: R[] = [];
    const errors: Array<{ item: unknown; error: Error }> = [];
    let processed = 0;
    let failed = 0;

    const batches = chunk(items, this.config.batchSize);
    const totalBatches = batches.length;

    for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
      const batch = batches[batchIndex];
      const batchStart = Date.now();

      // Process batch with concurrency
      const batchResults = await parallelMap(
        batch,
        async (item) => {
          try {
            const result = await this.processor(item);
            processed++;
            return { success: true as const, result };
          } catch (error) {
            failed++;
            const err = error instanceof Error ? error : new Error(String(error));
            errors.push({ item, error: err });

            if (!this.config.continueOnError) {
              throw error;
            }

            return { success: false as const, error: err };
          }
        },
        { concurrency: this.config.concurrency, collectErrors: this.config.continueOnError }
      );

      // Collect successful results
      for (const result of batchResults) {
        if (result && result.success) {
          results.push(result.result);
        }
      }

      // Update stats
      const batchDuration = Date.now() - batchStart;
      this.stats.totalBatches++;
      this.stats.totalDurationMs += batchDuration;
      this.stats.averageBatchTime = this.stats.totalDurationMs / this.stats.totalBatches;

      // Call progress callback
      if (this.config.onProgress) {
        this.config.onProgress({
          processed,
          total: items.length,
          currentBatch: batchIndex + 1,
          totalBatches,
          percentage: (processed / items.length) * 100,
        });
      }

      // Delay between batches
      if (this.config.delayBetweenBatches > 0 && batchIndex < batches.length - 1) {
        await new Promise((r) => setTimeout(r, this.config.delayBetweenBatches));
      }
    }

    const durationMs = Date.now() - startTime;

    // Update cumulative stats
    this.stats.totalProcessed += processed;
    this.stats.totalFailed += failed;

    return {
      results,
      processed,
      failed,
      errors,
      durationMs,
    };
  }

  /**
   * Get processing statistics
   */
  getStats(): BatchStats {
    return { ...this.stats };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.stats = {
      totalProcessed: 0,
      totalFailed: 0,
      totalBatches: 0,
      totalDurationMs: 0,
      averageBatchTime: 0,
    };
  }
}

/**
 * Create a batch processor
 */
export function createBatchProcessor<T, R>(
  processor: (item: T) => Promise<R>,
  config?: Partial<BatchConfig>
): BatchProcessor<T, R> {
  return new BatchProcessor(processor, config);
}

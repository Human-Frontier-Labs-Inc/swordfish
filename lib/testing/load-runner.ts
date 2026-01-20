/**
 * Load Testing Infrastructure
 *
 * Provides tools for load testing with configurable concurrency,
 * latency tracking, and comprehensive metrics collection.
 */

export interface LoadTestConfig {
  concurrency: number;
  duration: number; // milliseconds
  rampUpTime?: number; // milliseconds
  targetRps?: number; // requests per second
}

export interface LoadTestResult {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  duration: number;
  requestsPerSecond: number;
  avgLatency: number;
  p50Latency: number;
  p95Latency: number;
  p99Latency: number;
  maxLatency: number;
  minLatency: number;
  aborted?: boolean;
  errorBreakdown?: Record<string, number>;
}

export interface RunOptions {
  signal?: AbortSignal;
}

export interface MetricsSnapshot {
  count: number;
  successCount: number;
  failureCount: number;
  avgLatency: number;
  p50Latency: number;
  p95Latency: number;
  p99Latency: number;
  maxLatency: number;
  minLatency: number;
  errorBreakdown: Record<string, number>;
}

/**
 * Collects and calculates metrics during load tests
 */
export class MetricsCollector {
  private latencies: number[] = [];
  private successCount = 0;
  private failureCount = 0;
  private errorBreakdown: Record<string, number> = {};

  recordLatency(latencyMs: number): void {
    this.latencies.push(latencyMs);
  }

  recordSuccess(): void {
    this.successCount++;
  }

  recordFailure(error: Error): void {
    this.failureCount++;
    const errorMessage = error.message || 'Unknown error';
    this.errorBreakdown[errorMessage] = (this.errorBreakdown[errorMessage] || 0) + 1;
  }

  reset(): void {
    this.latencies = [];
    this.successCount = 0;
    this.failureCount = 0;
    this.errorBreakdown = {};
  }

  getMetrics(): MetricsSnapshot {
    const sorted = [...this.latencies].sort((a, b) => a - b);
    const count = sorted.length;

    if (count === 0) {
      return {
        count: 0,
        successCount: this.successCount,
        failureCount: this.failureCount,
        avgLatency: 0,
        p50Latency: 0,
        p95Latency: 0,
        p99Latency: 0,
        maxLatency: 0,
        minLatency: 0,
        errorBreakdown: this.errorBreakdown,
      };
    }

    const sum = sorted.reduce((a, b) => a + b, 0);

    return {
      count,
      successCount: this.successCount,
      failureCount: this.failureCount,
      avgLatency: sum / count,
      p50Latency: this.percentile(sorted, 50),
      p95Latency: this.percentile(sorted, 95),
      p99Latency: this.percentile(sorted, 99),
      maxLatency: sorted[count - 1],
      minLatency: sorted[0],
      errorBreakdown: this.errorBreakdown,
    };
  }

  private percentile(sortedArr: number[], p: number): number {
    const index = Math.ceil((p / 100) * sortedArr.length) - 1;
    return sortedArr[Math.max(0, index)];
  }
}

/**
 * Manages concurrent task execution with a configurable limit
 */
export class ConcurrencyManager {
  private maxConcurrency: number;
  private currentConcurrency = 0;
  private queue: Array<{
    task: () => Promise<unknown>;
    resolve: (value: unknown) => void;
    reject: (error: unknown) => void;
  }> = [];

  constructor(maxConcurrency: number) {
    this.maxConcurrency = maxConcurrency;
  }

  setMaxConcurrency(max: number): void {
    this.maxConcurrency = max;
    this.processQueue();
  }

  getCurrentConcurrency(): number {
    return this.currentConcurrency;
  }

  async run<T>(task: () => Promise<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      this.queue.push({
        task: task as () => Promise<unknown>,
        resolve: resolve as (value: unknown) => void,
        reject,
      });
      this.processQueue();
    });
  }

  private processQueue(): void {
    while (
      this.queue.length > 0 &&
      this.currentConcurrency < this.maxConcurrency
    ) {
      const item = this.queue.shift();
      if (!item) break;

      this.currentConcurrency++;
      item
        .task()
        .then((result) => {
          this.currentConcurrency--;
          this.processQueue();
          item.resolve(result);
        })
        .catch((error) => {
          this.currentConcurrency--;
          this.processQueue();
          item.reject(error);
        });
    }
  }
}

/**
 * Main load test runner
 */
export class LoadRunner {
  private config: LoadTestConfig = {
    concurrency: 10,
    duration: 10000,
    rampUpTime: 0,
  };

  configure(config: LoadTestConfig): void {
    if (
      config.concurrency <= 0 ||
      config.duration <= 0 ||
      (config.rampUpTime !== undefined && config.rampUpTime < 0)
    ) {
      throw new Error('Invalid configuration');
    }

    this.config = {
      ...config,
      rampUpTime: config.rampUpTime ?? 0,
    };
  }

  getConfig(): LoadTestConfig {
    return { ...this.config };
  }

  async run<T>(
    taskFn: () => Promise<T>,
    options: RunOptions = {}
  ): Promise<LoadTestResult> {
    const metrics = new MetricsCollector();
    const startTime = Date.now();
    const endTime = startTime + this.config.duration;

    let running = true;
    let aborted = false;

    // Handle abort signal
    if (options.signal) {
      options.signal.addEventListener('abort', () => {
        running = false;
        aborted = true;
      });
    }

    const manager = new ConcurrencyManager(1); // Start with 1 for ramp-up

    // Ramp-up scheduler
    const rampUpInterval = this.config.rampUpTime
      ? setInterval(() => {
          const elapsed = Date.now() - startTime;
          const progress = Math.min(elapsed / this.config.rampUpTime!, 1);
          const targetConcurrency = Math.ceil(progress * this.config.concurrency);
          manager.setMaxConcurrency(targetConcurrency);
        }, 50)
      : null;

    // If no ramp-up, set full concurrency immediately
    if (!this.config.rampUpTime) {
      manager.setMaxConcurrency(this.config.concurrency);
    }

    // Worker function
    const executeTask = async (): Promise<void> => {
      while (running && Date.now() < endTime) {
        const taskStart = Date.now();
        try {
          await manager.run(async () => {
            const innerStart = Date.now();
            try {
              await taskFn();
              metrics.recordSuccess();
            } catch (error) {
              metrics.recordFailure(error instanceof Error ? error : new Error(String(error)));
            }
            metrics.recordLatency(Date.now() - innerStart);
          });
        } catch {
          // Queue rejected, continue
        }

        // Small delay to prevent tight loop
        if (Date.now() - taskStart < 1) {
          await new Promise((resolve) => setTimeout(resolve, 1));
        }
      }
    };

    // Start workers
    const workers = Array(this.config.concurrency)
      .fill(null)
      .map(() => executeTask());

    await Promise.all(workers);

    if (rampUpInterval) {
      clearInterval(rampUpInterval);
    }

    const actualDuration = Date.now() - startTime;
    const metricsSnapshot = metrics.getMetrics();

    return {
      totalRequests: metricsSnapshot.count,
      successfulRequests: metricsSnapshot.successCount,
      failedRequests: metricsSnapshot.failureCount,
      duration: actualDuration,
      requestsPerSecond: metricsSnapshot.count / (actualDuration / 1000),
      avgLatency: metricsSnapshot.avgLatency,
      p50Latency: metricsSnapshot.p50Latency,
      p95Latency: metricsSnapshot.p95Latency,
      p99Latency: metricsSnapshot.p99Latency,
      maxLatency: metricsSnapshot.maxLatency,
      minLatency: metricsSnapshot.minLatency,
      aborted,
      errorBreakdown: metricsSnapshot.errorBreakdown,
    };
  }
}

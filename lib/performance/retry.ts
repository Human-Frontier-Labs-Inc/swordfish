/**
 * Retry Utility Module
 *
 * Exponential backoff retry logic for handling transient failures
 * in network requests, database operations, and external APIs.
 */

/**
 * Retry configuration
 */
export interface RetryConfig {
  maxAttempts: number;
  delay?: number;
  baseDelay?: number;
  maxDelay?: number;
  jitter?: boolean;
  shouldRetry?: (error: unknown) => boolean;
  onRetry?: (error: Error, attempt: number) => void;
  onSuccess?: (result: unknown, attempt: number) => void;
  onFailure?: (error: Error, attempts: number) => void;
  signal?: AbortSignal;
}

/**
 * Retry error with attempt information
 */
export class RetryError extends Error {
  constructor(
    message: string,
    public readonly attempts: number,
    public readonly lastError: Error
  ) {
    super(message);
    this.name = 'RetryError';
  }
}

/**
 * Retry policy statistics
 */
interface RetryStats {
  totalExecutions: number;
  totalRetries: number;
  successfulExecutions: number;
  failedExecutions: number;
}

/**
 * Sleep for a specified duration
 */
function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error('Retry aborted'));
      return;
    }

    const timeoutId = setTimeout(resolve, ms);

    if (signal) {
      signal.addEventListener('abort', () => {
        clearTimeout(timeoutId);
        reject(new Error('Retry aborted'));
      });
    }
  });
}

/**
 * Calculate delay with optional jitter
 */
function calculateDelay(
  baseDelay: number,
  attempt: number,
  maxDelay: number,
  jitter: boolean
): number {
  // Exponential backoff: baseDelay * 2^(attempt-1)
  let delay = baseDelay * Math.pow(2, attempt - 1);

  // Cap at maxDelay
  delay = Math.min(delay, maxDelay);

  // Add jitter (0-50% of delay)
  if (jitter) {
    delay = delay + Math.random() * delay * 0.5;
  }

  return Math.floor(delay);
}

/**
 * Check if an error is retryable (default implementation)
 */
export function isRetryable(error: unknown): boolean {
  if (!error) return false;

  // Check for HTTP status codes
  if (typeof error === 'object' && error !== null && 'status' in error) {
    const status = (error as { status: number }).status;
    // Retry on rate limit (429) and server errors (5xx)
    if (status === 429 || (status >= 500 && status < 600)) {
      return true;
    }
    // Don't retry client errors (4xx except 429)
    if (status >= 400 && status < 500) {
      return false;
    }
  }

  // Check error message for common transient patterns
  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    const name = error.name.toLowerCase();

    const transientPatterns = [
      'econnrefused',
      'econnreset',
      'etimedout',
      'enotfound',
      'socket hang up',
      'network',
      'timeout',
      'temporarily unavailable',
      'service unavailable',
      'too many requests',
      'rate limit',
    ];

    if (transientPatterns.some((p) => message.includes(p) || name.includes(p))) {
      return true;
    }

    // Check error name
    if (name === 'timeouterror' || name === 'networkerror') {
      return true;
    }
  }

  return false;
}

/**
 * Basic retry with fixed delay
 */
export async function retry<T>(
  fn: () => Promise<T>,
  config: RetryConfig
): Promise<T> {
  const {
    maxAttempts,
    delay = 1000,
    shouldRetry = isRetryable,
    onRetry,
    onSuccess,
    onFailure,
    signal,
  } = config;

  let lastError: Error = new Error('Unknown error');

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    // Check abort signal
    if (signal?.aborted) {
      throw new Error('Retry aborted');
    }

    try {
      const result = await fn();
      onSuccess?.(result, attempt);
      return result;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      // Check if we should retry
      if (attempt < maxAttempts && shouldRetry(error)) {
        onRetry?.(lastError, attempt);
        await sleep(delay, signal);
      } else if (attempt >= maxAttempts) {
        onFailure?.(lastError, attempt);
        throw new RetryError(
          `Failed after ${attempt} attempts: ${lastError.message}`,
          attempt,
          lastError
        );
      } else {
        // Not retryable
        onFailure?.(lastError, attempt);
        throw lastError;
      }
    }
  }

  throw new RetryError(`Failed after ${maxAttempts} attempts`, maxAttempts, lastError);
}

/**
 * Retry with exponential backoff
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  config: RetryConfig
): Promise<T> {
  const {
    maxAttempts,
    baseDelay = 1000,
    maxDelay = 30000,
    jitter = false,
    shouldRetry = isRetryable,
    onRetry,
    onSuccess,
    onFailure,
    signal,
  } = config;

  let lastError: Error = new Error('Unknown error');

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    // Check abort signal
    if (signal?.aborted) {
      throw new Error('Retry aborted');
    }

    try {
      const result = await fn();
      onSuccess?.(result, attempt);
      return result;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      // Check if we should retry
      if (attempt < maxAttempts && shouldRetry(error)) {
        const delay = calculateDelay(baseDelay, attempt, maxDelay, jitter);
        onRetry?.(lastError, attempt);
        await sleep(delay, signal);
      } else if (attempt >= maxAttempts) {
        onFailure?.(lastError, attempt);
        throw new RetryError(
          `Failed after ${attempt} attempts: ${lastError.message}`,
          attempt,
          lastError
        );
      } else {
        // Not retryable
        onFailure?.(lastError, attempt);
        throw lastError;
      }
    }
  }

  throw new RetryError(`Failed after ${maxAttempts} attempts`, maxAttempts, lastError);
}

/**
 * Retry policy - reusable retry configuration with statistics
 */
export class RetryPolicy {
  private config: RetryConfig;
  private stats: RetryStats = {
    totalExecutions: 0,
    totalRetries: 0,
    successfulExecutions: 0,
    failedExecutions: 0,
  };

  constructor(config: Omit<RetryConfig, 'onRetry' | 'onSuccess' | 'onFailure'>) {
    this.config = config;
  }

  /**
   * Execute a function with retry policy
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    this.stats.totalExecutions++;
    let retries = 0;

    try {
      const result = await retryWithBackoff(fn, {
        ...this.config,
        onRetry: () => {
          retries++;
          this.stats.totalRetries++;
        },
      });

      this.stats.successfulExecutions++;
      return result;
    } catch (error) {
      this.stats.failedExecutions++;
      throw error;
    }
  }

  /**
   * Get retry statistics
   */
  getStats(): RetryStats {
    return { ...this.stats };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.stats = {
      totalExecutions: 0,
      totalRetries: 0,
      successfulExecutions: 0,
      failedExecutions: 0,
    };
  }
}

/**
 * Create a retry policy
 */
export function createRetryPolicy(
  config: Omit<RetryConfig, 'onRetry' | 'onSuccess' | 'onFailure'>
): RetryPolicy {
  return new RetryPolicy(config);
}

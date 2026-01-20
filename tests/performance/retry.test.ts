/**
 * Retry Utility Tests
 * TDD: Exponential backoff retry for transient failures
 */

import { describe, it, expect, vi } from 'vitest';

import {
  retry,
  retryWithBackoff,
  RetryError,
  isRetryable,
  createRetryPolicy,
} from '@/lib/performance/retry';

describe('Retry Utility', () => {
  describe('Basic retry', () => {
    it('should succeed on first try', async () => {
      const fn = vi.fn().mockResolvedValue('success');

      const result = await retry(fn, { maxAttempts: 3 });

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('should retry on failure', async () => {
      const fn = vi
        .fn()
        .mockRejectedValueOnce(new Error('Fail 1'))
        .mockRejectedValueOnce(new Error('Fail 2'))
        .mockResolvedValue('success');

      const result = await retry(fn, { maxAttempts: 3, delay: 5, shouldRetry: () => true });

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(3);
    });

    it('should throw after max attempts', async () => {
      const fn = vi.fn().mockRejectedValue(new Error('Always fails'));

      await expect(
        retry(fn, { maxAttempts: 3, delay: 5, shouldRetry: () => true })
      ).rejects.toThrow(RetryError);
      expect(fn).toHaveBeenCalledTimes(3);
    });

    it('should include attempt count in error', async () => {
      const fn = vi.fn().mockRejectedValue(new Error('Fail'));

      try {
        await retry(fn, { maxAttempts: 2, delay: 5, shouldRetry: () => true });
      } catch (error) {
        expect(error).toBeInstanceOf(RetryError);
        expect((error as RetryError).attempts).toBe(2);
      }
    });
  });

  describe('Exponential backoff', () => {
    it('should increase delays exponentially', async () => {
      const fn = vi
        .fn()
        .mockRejectedValueOnce(new Error('Fail'))
        .mockRejectedValueOnce(new Error('Fail'))
        .mockResolvedValue('success');

      await retryWithBackoff(fn, {
        maxAttempts: 3,
        baseDelay: 10,
        maxDelay: 10000,
        shouldRetry: () => true,
      });

      expect(fn).toHaveBeenCalledTimes(3);
    });

    it('should succeed after retries with backoff', async () => {
      const fn = vi
        .fn()
        .mockRejectedValueOnce(new Error('Fail'))
        .mockResolvedValue('success');

      const result = await retryWithBackoff(fn, {
        maxAttempts: 3,
        baseDelay: 5,
        maxDelay: 100,
        shouldRetry: () => true,
      });

      expect(result).toBe('success');
      expect(fn).toHaveBeenCalledTimes(2);
    });

    it('should respect maxDelay', async () => {
      const fn = vi
        .fn()
        .mockRejectedValueOnce(new Error('Fail'))
        .mockRejectedValueOnce(new Error('Fail'))
        .mockResolvedValue('success');

      const start = Date.now();
      await retryWithBackoff(fn, {
        maxAttempts: 3,
        baseDelay: 5,
        maxDelay: 10,
        shouldRetry: () => true,
      });
      const duration = Date.now() - start;

      // With maxDelay of 10, total delay should be < 100ms
      expect(duration).toBeLessThan(100);
    });

    it('should support jitter', async () => {
      const fn = vi
        .fn()
        .mockRejectedValueOnce(new Error('Fail'))
        .mockResolvedValue('success');

      const result = await retryWithBackoff(fn, {
        maxAttempts: 2,
        baseDelay: 5,
        jitter: true,
        shouldRetry: () => true,
      });

      expect(result).toBe('success');
    });
  });

  describe('Retry conditions', () => {
    it('should not retry non-retryable errors', async () => {
      const error = new Error('Not retryable');
      const fn = vi.fn().mockRejectedValue(error);

      await expect(
        retry(fn, {
          maxAttempts: 3,
          delay: 5,
          shouldRetry: () => false,
        })
      ).rejects.toThrow();

      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('should retry only specific error types', async () => {
      class TransientError extends Error {}
      class PermanentError extends Error {}

      const fn = vi
        .fn()
        .mockRejectedValueOnce(new TransientError('Transient'))
        .mockRejectedValueOnce(new PermanentError('Permanent'));

      await expect(
        retry(fn, {
          maxAttempts: 3,
          delay: 5,
          shouldRetry: (err) => err instanceof TransientError,
        })
      ).rejects.toBeInstanceOf(PermanentError);

      expect(fn).toHaveBeenCalledTimes(2);
    });
  });

  describe('isRetryable helper', () => {
    it('should identify network errors as retryable', () => {
      const error = new Error('ECONNREFUSED');
      expect(isRetryable(error)).toBe(true);
    });

    it('should identify timeout errors as retryable', () => {
      const error = new Error('Request timeout');
      error.name = 'TimeoutError';
      expect(isRetryable(error)).toBe(true);
    });

    it('should identify rate limit errors as retryable', () => {
      const error = { status: 429, message: 'Too many requests' };
      expect(isRetryable(error)).toBe(true);
    });

    it('should identify server errors as retryable', () => {
      const error = { status: 503, message: 'Service unavailable' };
      expect(isRetryable(error)).toBe(true);
    });

    it('should not retry client errors', () => {
      const error = { status: 400, message: 'Bad request' };
      expect(isRetryable(error)).toBe(false);
    });

    it('should not retry auth errors', () => {
      const error = { status: 401, message: 'Unauthorized' };
      expect(isRetryable(error)).toBe(false);
    });
  });

  describe('Retry policy', () => {
    it('should create reusable policy', async () => {
      const policy = createRetryPolicy({
        maxAttempts: 3,
        baseDelay: 5,
        shouldRetry: () => true,
      });

      const fn = vi
        .fn()
        .mockRejectedValueOnce(new Error('Fail'))
        .mockResolvedValue('success');

      const result = await policy.execute(fn);

      expect(result).toBe('success');
    });

    it('should track retry statistics', async () => {
      const policy = createRetryPolicy({
        maxAttempts: 3,
        baseDelay: 5,
        shouldRetry: () => true,
      });

      // Successful on first try
      await policy.execute(() => Promise.resolve('ok'));

      // Needs retries
      const fn = vi
        .fn()
        .mockRejectedValueOnce(new Error('Fail'))
        .mockResolvedValue('ok');

      await policy.execute(fn);

      const stats = policy.getStats();
      expect(stats.totalExecutions).toBe(2);
      expect(stats.totalRetries).toBeGreaterThan(0);
    });

    it('should reset statistics', async () => {
      const policy = createRetryPolicy({
        maxAttempts: 3,
        baseDelay: 5,
      });

      await policy.execute(() => Promise.resolve('ok'));
      policy.resetStats();

      const stats = policy.getStats();
      expect(stats.totalExecutions).toBe(0);
    });
  });

  describe('Callbacks', () => {
    it('should call onRetry callback', async () => {
      const onRetry = vi.fn();
      const fn = vi
        .fn()
        .mockRejectedValueOnce(new Error('Fail'))
        .mockResolvedValue('success');

      await retry(fn, {
        maxAttempts: 2,
        delay: 5,
        shouldRetry: () => true,
        onRetry,
      });

      expect(onRetry).toHaveBeenCalledTimes(1);
      expect(onRetry).toHaveBeenCalledWith(expect.any(Error), 1);
    });

    it('should call onSuccess callback', async () => {
      const onSuccess = vi.fn();
      const fn = vi.fn().mockResolvedValue('success');

      await retry(fn, {
        maxAttempts: 2,
        delay: 5,
        onSuccess,
      });

      expect(onSuccess).toHaveBeenCalledWith('success', 1);
    });

    it('should call onFailure callback after all retries', async () => {
      const onFailure = vi.fn();
      const fn = vi.fn().mockRejectedValue(new Error('Always fails'));

      try {
        await retry(fn, {
          maxAttempts: 2,
          delay: 5,
          shouldRetry: () => true,
          onFailure,
        });
      } catch {
        // Expected
      }

      expect(onFailure).toHaveBeenCalledWith(expect.any(Error), 2);
    });
  });

  describe('Abort support', () => {
    it('should abort on signal', async () => {
      const controller = new AbortController();
      const fn = vi.fn().mockImplementation(async () => {
        await new Promise((r) => setTimeout(r, 50));
        throw new Error('Fail');
      });

      // Abort immediately
      controller.abort();

      await expect(
        retry(fn, {
          maxAttempts: 10,
          delay: 100,
          signal: controller.signal,
        })
      ).rejects.toThrow('Retry aborted');
    });
  });
});

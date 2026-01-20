/**
 * Batch Processing Tests
 * TDD: Efficient batch operations for bulk data processing
 */

import { describe, it, expect, vi } from 'vitest';

import {
  BatchProcessor,
  createBatchProcessor,
  BatchConfig,
  BatchResult,
  chunk,
  parallelMap,
  sequentialProcess,
} from '@/lib/performance/batch';

describe('Batch Processing', () => {
  describe('chunk utility', () => {
    it('should split array into chunks', () => {
      const items = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      const chunks = chunk(items, 3);

      expect(chunks).toHaveLength(4);
      expect(chunks[0]).toEqual([1, 2, 3]);
      expect(chunks[1]).toEqual([4, 5, 6]);
      expect(chunks[2]).toEqual([7, 8, 9]);
      expect(chunks[3]).toEqual([10]);
    });

    it('should handle empty array', () => {
      const chunks = chunk([], 3);

      expect(chunks).toHaveLength(0);
    });

    it('should handle chunk size larger than array', () => {
      const items = [1, 2, 3];
      const chunks = chunk(items, 10);

      expect(chunks).toHaveLength(1);
      expect(chunks[0]).toEqual([1, 2, 3]);
    });

    it('should handle chunk size of 1', () => {
      const items = [1, 2, 3];
      const chunks = chunk(items, 1);

      expect(chunks).toHaveLength(3);
    });
  });

  describe('parallelMap', () => {
    it('should process items in parallel', async () => {
      const items = [1, 2, 3, 4, 5];
      const processor = vi.fn().mockImplementation(async (n: number) => n * 2);

      const results = await parallelMap(items, processor);

      expect(results).toEqual([2, 4, 6, 8, 10]);
      expect(processor).toHaveBeenCalledTimes(5);
    });

    it('should respect concurrency limit', async () => {
      const items = [1, 2, 3, 4, 5, 6];
      let concurrent = 0;
      let maxConcurrent = 0;

      const processor = vi.fn().mockImplementation(async (n: number) => {
        concurrent++;
        maxConcurrent = Math.max(maxConcurrent, concurrent);
        await new Promise((r) => setTimeout(r, 10));
        concurrent--;
        return n * 2;
      });

      await parallelMap(items, processor, { concurrency: 2 });

      expect(maxConcurrent).toBeLessThanOrEqual(2);
    });

    it('should collect errors', async () => {
      const items = [1, 2, 3];
      const processor = vi.fn().mockImplementation(async (n: number) => {
        if (n === 2) throw new Error('Failed on 2');
        return n * 2;
      });

      const results = await parallelMap(items, processor, { collectErrors: true });

      expect(results.filter((r) => r !== undefined)).toHaveLength(2);
    });

    it('should stop on first error when not collecting', async () => {
      const items = [1, 2, 3];
      const processor = vi.fn().mockImplementation(async (n: number) => {
        if (n === 2) throw new Error('Failed on 2');
        return n * 2;
      });

      await expect(
        parallelMap(items, processor, { stopOnError: true })
      ).rejects.toThrow('Failed on 2');
    });
  });

  describe('sequentialProcess', () => {
    it('should process items sequentially', async () => {
      const order: number[] = [];
      const items = [1, 2, 3];

      await sequentialProcess(items, async (n) => {
        order.push(n);
        await new Promise((r) => setTimeout(r, 5));
      });

      expect(order).toEqual([1, 2, 3]);
    });

    it('should pass accumulator through items', async () => {
      const items = [1, 2, 3, 4, 5];

      const result = await sequentialProcess(
        items,
        async (n, acc) => acc + n,
        0
      );

      expect(result).toBe(15);
    });
  });

  describe('BatchProcessor', () => {
    it('should create processor with default config', () => {
      const processor = createBatchProcessor<number, number>(async (n) => n * 2);

      const config = processor.getConfig();
      expect(config.batchSize).toBe(100);
      expect(config.concurrency).toBe(5);
    });

    it('should create processor with custom config', () => {
      const processor = createBatchProcessor<number, number>(
        async (n) => n * 2,
        {
          batchSize: 50,
          concurrency: 10,
          delayBetweenBatches: 100,
        }
      );

      const config = processor.getConfig();
      expect(config.batchSize).toBe(50);
      expect(config.concurrency).toBe(10);
    });

    it('should process all items', async () => {
      const processor = createBatchProcessor<number, number>(
        async (n) => n * 2,
        { batchSize: 3 }
      );

      const items = [1, 2, 3, 4, 5, 6, 7];
      const result = await processor.process(items);

      expect(result.results).toEqual([2, 4, 6, 8, 10, 12, 14]);
      expect(result.processed).toBe(7);
      expect(result.failed).toBe(0);
    });

    it('should handle failures gracefully', async () => {
      const processor = createBatchProcessor<number, number>(
        async (n) => {
          if (n === 3) throw new Error('Failed on 3');
          return n * 2;
        },
        { batchSize: 2, continueOnError: true }
      );

      const items = [1, 2, 3, 4, 5];
      const result = await processor.process(items);

      expect(result.processed).toBe(4);
      expect(result.failed).toBe(1);
      expect(result.errors).toHaveLength(1);
    });

    it('should call progress callback', async () => {
      const onProgress = vi.fn();
      const processor = createBatchProcessor<number, number>(
        async (n) => n * 2,
        { batchSize: 2, onProgress }
      );

      await processor.process([1, 2, 3, 4, 5]);

      expect(onProgress).toHaveBeenCalled();
    });

    it('should track processing time', async () => {
      const processor = createBatchProcessor<number, number>(
        async (n) => {
          await new Promise((r) => setTimeout(r, 5));
          return n * 2;
        },
        { batchSize: 2 }
      );

      const result = await processor.process([1, 2, 3]);

      expect(result.durationMs).toBeGreaterThan(0);
    });

    it('should add delay between batches', async () => {
      const processor = createBatchProcessor<number, number>(
        async (n) => n * 2,
        { batchSize: 2, delayBetweenBatches: 20 }
      );

      const start = Date.now();
      await processor.process([1, 2, 3, 4]);
      const duration = Date.now() - start;

      // Should have at least one delay between batches
      expect(duration).toBeGreaterThanOrEqual(15);
    });
  });

  describe('BatchProcessor statistics', () => {
    it('should provide comprehensive statistics', async () => {
      const processor = createBatchProcessor<number, number>(
        async (n) => n * 2,
        { batchSize: 5 }
      );

      await processor.process([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

      const stats = processor.getStats();
      expect(stats.totalProcessed).toBe(10);
      expect(stats.totalBatches).toBe(2);
      expect(stats.averageBatchTime).toBeGreaterThanOrEqual(0);
    });

    it('should accumulate stats across multiple calls', async () => {
      const processor = createBatchProcessor<number, number>(
        async (n) => n * 2,
        { batchSize: 5 }
      );

      await processor.process([1, 2, 3, 4, 5]);
      await processor.process([6, 7, 8, 9, 10]);

      const stats = processor.getStats();
      expect(stats.totalProcessed).toBe(10);
    });

    it('should reset stats', async () => {
      const processor = createBatchProcessor<number, number>(
        async (n) => n * 2,
        { batchSize: 5 }
      );

      await processor.process([1, 2, 3, 4, 5]);
      processor.resetStats();

      const stats = processor.getStats();
      expect(stats.totalProcessed).toBe(0);
    });
  });

  describe('Type preservation', () => {
    it('should preserve complex types', async () => {
      interface User {
        id: number;
        name: string;
      }

      interface UserWithRole extends User {
        role: string;
      }

      const processor = createBatchProcessor<User, UserWithRole>(
        async (user) => ({
          ...user,
          role: 'admin',
        }),
        { batchSize: 2 }
      );

      const users = [
        { id: 1, name: 'Alice' },
        { id: 2, name: 'Bob' },
      ];

      const result = await processor.process(users);

      expect(result.results[0]).toEqual({ id: 1, name: 'Alice', role: 'admin' });
      expect(result.results[1]).toEqual({ id: 2, name: 'Bob', role: 'admin' });
    });
  });
});

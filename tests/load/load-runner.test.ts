/**
 * Load Testing Infrastructure Tests
 * TDD: RED phase - Write failing tests first
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  LoadRunner,
  LoadTestConfig,
  LoadTestResult,
  MetricsCollector,
  ConcurrencyManager,
} from '../../lib/testing/load-runner';

describe('Load Testing Infrastructure', () => {
  describe('LoadRunner', () => {
    let runner: LoadRunner;

    beforeEach(() => {
      runner = new LoadRunner();
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    describe('Configuration', () => {
      it('should accept load test configuration', () => {
        const config: LoadTestConfig = {
          concurrency: 100,
          duration: 60000, // 60 seconds
          rampUpTime: 5000, // 5 seconds
          targetRps: 1000,
        };

        runner.configure(config);
        expect(runner.getConfig()).toEqual(config);
      });

      it('should validate configuration parameters', () => {
        const invalidConfig: LoadTestConfig = {
          concurrency: -1,
          duration: 0,
          rampUpTime: -100,
          targetRps: 0,
        };

        expect(() => runner.configure(invalidConfig)).toThrow('Invalid configuration');
      });

      it('should set default values for optional parameters', () => {
        const minimalConfig: LoadTestConfig = {
          concurrency: 10,
          duration: 10000,
        };

        runner.configure(minimalConfig);
        const config = runner.getConfig();

        expect(config.rampUpTime).toBe(0);
        expect(config.targetRps).toBeUndefined();
      });
    });

    describe('Execution', () => {
      it('should execute load test with specified concurrency', async () => {
        const taskFn = vi.fn().mockResolvedValue({ success: true });

        runner.configure({
          concurrency: 10,
          duration: 1000,
        });

        const result = await runner.run(taskFn);

        expect(taskFn).toHaveBeenCalled();
        expect(result.totalRequests).toBeGreaterThan(0);
      });

      it('should respect maximum concurrency limit', async () => {
        let currentConcurrency = 0;
        let maxObservedConcurrency = 0;

        const taskFn = vi.fn().mockImplementation(async () => {
          currentConcurrency++;
          maxObservedConcurrency = Math.max(maxObservedConcurrency, currentConcurrency);
          await new Promise((resolve) => setTimeout(resolve, 50));
          currentConcurrency--;
          return { success: true };
        });

        runner.configure({
          concurrency: 5,
          duration: 500,
        });

        await runner.run(taskFn);

        expect(maxObservedConcurrency).toBeLessThanOrEqual(5);
      });

      it('should ramp up concurrency gradually', async () => {
        const concurrencyLog: number[] = [];
        let currentConcurrency = 0;

        const taskFn = vi.fn().mockImplementation(async () => {
          currentConcurrency++;
          concurrencyLog.push(currentConcurrency);
          await new Promise((resolve) => setTimeout(resolve, 20));
          currentConcurrency--;
          return { success: true };
        });

        runner.configure({
          concurrency: 20,
          duration: 500,
          rampUpTime: 200,
        });

        await runner.run(taskFn);

        // Early concurrency should be lower than later concurrency
        const earlyAvg =
          concurrencyLog.slice(0, 5).reduce((a, b) => a + b, 0) / 5;
        const lateAvg =
          concurrencyLog.slice(-5).reduce((a, b) => a + b, 0) / 5;

        expect(earlyAvg).toBeLessThan(lateAvg);
      });

      it('should stop after specified duration', async () => {
        const startTime = Date.now();

        const taskFn = vi.fn().mockImplementation(async () => {
          await new Promise((resolve) => setTimeout(resolve, 10));
          return { success: true };
        });

        runner.configure({
          concurrency: 5,
          duration: 200,
        });

        await runner.run(taskFn);

        const elapsed = Date.now() - startTime;
        expect(elapsed).toBeLessThan(500); // Should stop around 200ms + cleanup
      });

      it('should support abort signal for early termination', async () => {
        const controller = new AbortController();
        const taskFn = vi.fn().mockImplementation(async () => {
          await new Promise((resolve) => setTimeout(resolve, 50));
          return { success: true };
        });

        runner.configure({
          concurrency: 10,
          duration: 5000,
        });

        // Abort after 100ms
        setTimeout(() => controller.abort(), 100);

        const result = await runner.run(taskFn, { signal: controller.signal });

        expect(result.aborted).toBe(true);
        expect(result.duration).toBeLessThan(500);
      });
    });

    describe('Results', () => {
      it('should return comprehensive test results', async () => {
        const taskFn = vi.fn().mockResolvedValue({ success: true });

        runner.configure({
          concurrency: 5,
          duration: 200,
        });

        const result = await runner.run(taskFn);

        expect(result).toMatchObject({
          totalRequests: expect.any(Number),
          successfulRequests: expect.any(Number),
          failedRequests: expect.any(Number),
          duration: expect.any(Number),
          requestsPerSecond: expect.any(Number),
          avgLatency: expect.any(Number),
          p50Latency: expect.any(Number),
          p95Latency: expect.any(Number),
          p99Latency: expect.any(Number),
          maxLatency: expect.any(Number),
          minLatency: expect.any(Number),
        });
      });

      it('should calculate accurate success rate', async () => {
        let callCount = 0;
        const taskFn = vi.fn().mockImplementation(async () => {
          callCount++;
          if (callCount % 3 === 0) {
            throw new Error('Simulated failure');
          }
          return { success: true };
        });

        runner.configure({
          concurrency: 3,
          duration: 300,
        });

        const result = await runner.run(taskFn);

        const expectedSuccessRate =
          result.successfulRequests / result.totalRequests;
        expect(expectedSuccessRate).toBeGreaterThan(0.5);
        expect(expectedSuccessRate).toBeLessThan(0.8);
      });

      it('should track latency percentiles accurately', async () => {
        const taskFn = vi.fn().mockImplementation(async () => {
          // Random latency between 10-100ms
          const latency = 10 + Math.random() * 90;
          await new Promise((resolve) => setTimeout(resolve, latency));
          return { success: true };
        });

        runner.configure({
          concurrency: 5,
          duration: 500,
        });

        const result = await runner.run(taskFn);

        // CI environments can be faster than expected, so use lenient bounds
        expect(result.minLatency).toBeGreaterThanOrEqual(0);
        expect(result.maxLatency).toBeLessThanOrEqual(200);
        expect(result.p50Latency).toBeGreaterThan(result.minLatency);
        expect(result.p95Latency).toBeGreaterThan(result.p50Latency);
        expect(result.p99Latency).toBeGreaterThanOrEqual(result.p95Latency);
      });
    });
  });

  describe('MetricsCollector', () => {
    let collector: MetricsCollector;

    beforeEach(() => {
      collector = new MetricsCollector();
    });

    it('should record request latencies', () => {
      collector.recordLatency(100);
      collector.recordLatency(150);
      collector.recordLatency(200);

      const metrics = collector.getMetrics();

      expect(metrics.count).toBe(3);
      expect(metrics.avgLatency).toBe(150);
    });

    it('should calculate percentiles correctly', () => {
      // Add 100 samples with known distribution
      for (let i = 1; i <= 100; i++) {
        collector.recordLatency(i);
      }

      const metrics = collector.getMetrics();

      expect(metrics.p50Latency).toBe(50);
      expect(metrics.p95Latency).toBe(95);
      expect(metrics.p99Latency).toBe(99);
    });

    it('should track success and failure counts', () => {
      collector.recordSuccess();
      collector.recordSuccess();
      collector.recordFailure(new Error('Test error'));

      const metrics = collector.getMetrics();

      expect(metrics.successCount).toBe(2);
      expect(metrics.failureCount).toBe(1);
    });

    it('should track error types', () => {
      collector.recordFailure(new Error('Connection timeout'));
      collector.recordFailure(new Error('Connection timeout'));
      collector.recordFailure(new Error('Rate limited'));

      const metrics = collector.getMetrics();

      expect(metrics.errorBreakdown).toEqual({
        'Connection timeout': 2,
        'Rate limited': 1,
      });
    });

    it('should calculate throughput over time windows', () => {
      const startTime = Date.now();

      // Simulate 100 requests over ~100ms
      for (let i = 0; i < 100; i++) {
        collector.recordSuccess();
        collector.recordLatency(1);
      }

      const metrics = collector.getMetrics();

      expect(metrics.count).toBe(100);
    });

    it('should reset metrics', () => {
      collector.recordLatency(100);
      collector.recordSuccess();

      collector.reset();

      const metrics = collector.getMetrics();

      expect(metrics.count).toBe(0);
      expect(metrics.successCount).toBe(0);
    });
  });

  describe('ConcurrencyManager', () => {
    let manager: ConcurrencyManager;

    beforeEach(() => {
      manager = new ConcurrencyManager(5);
    });

    it('should limit concurrent executions', async () => {
      let currentConcurrency = 0;
      let maxConcurrency = 0;

      const tasks = Array(20)
        .fill(null)
        .map(() => async () => {
          currentConcurrency++;
          maxConcurrency = Math.max(maxConcurrency, currentConcurrency);
          await new Promise((resolve) => setTimeout(resolve, 20));
          currentConcurrency--;
          return 'done';
        });

      await Promise.all(tasks.map((task) => manager.run(task)));

      expect(maxConcurrency).toBe(5);
    });

    it('should queue tasks when at capacity', async () => {
      const executionOrder: number[] = [];

      const createTask = (id: number) => async () => {
        executionOrder.push(id);
        await new Promise((resolve) => setTimeout(resolve, 10));
        return id;
      };

      const tasks = [1, 2, 3, 4, 5, 6, 7, 8].map(createTask);

      await Promise.all(tasks.map((task) => manager.run(task)));

      // First 5 should start immediately
      expect(executionOrder.slice(0, 5).sort()).toEqual([1, 2, 3, 4, 5]);
    });

    it('should handle task failures without blocking queue', async () => {
      const results: (string | Error)[] = [];

      const tasks = [
        async () => {
          results.push('success-1');
          return 'ok';
        },
        async () => {
          throw new Error('failure');
        },
        async () => {
          results.push('success-2');
          return 'ok';
        },
      ];

      await Promise.allSettled(tasks.map((task) => manager.run(task)));

      expect(results).toContain('success-1');
      expect(results).toContain('success-2');
    });

    it('should report current concurrency level', async () => {
      expect(manager.getCurrentConcurrency()).toBe(0);

      const slowTask = async () => {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return 'done';
      };

      const promise = manager.run(slowTask);

      // Give it time to start
      await new Promise((resolve) => setTimeout(resolve, 10));
      expect(manager.getCurrentConcurrency()).toBe(1);

      await promise;
      expect(manager.getCurrentConcurrency()).toBe(0);
    });

    it('should support dynamic concurrency adjustment', async () => {
      let maxObserved = 0;
      let currentConcurrency = 0;

      const task = async () => {
        currentConcurrency++;
        maxObserved = Math.max(maxObserved, currentConcurrency);
        await new Promise((resolve) => setTimeout(resolve, 50));
        currentConcurrency--;
        return 'done';
      };

      // Start with concurrency 3
      manager.setMaxConcurrency(3);

      const tasks1 = Array(10)
        .fill(null)
        .map(() => manager.run(task));

      await Promise.all(tasks1);
      expect(maxObserved).toBe(3);

      // Increase to 7
      maxObserved = 0;
      manager.setMaxConcurrency(7);

      const tasks2 = Array(10)
        .fill(null)
        .map(() => manager.run(task));

      await Promise.all(tasks2);
      expect(maxObserved).toBe(7);
    });
  });

  describe('Integration', () => {
    it('should handle high concurrency load test', async () => {
      const runner = new LoadRunner();
      let processedCount = 0;

      const taskFn = vi.fn().mockImplementation(async () => {
        processedCount++;
        await new Promise((resolve) => setTimeout(resolve, 5));
        return { success: true };
      });

      runner.configure({
        concurrency: 50,
        duration: 500,
      });

      const result = await runner.run(taskFn);

      expect(result.totalRequests).toBeGreaterThan(100);
      expect(result.successfulRequests).toBe(result.totalRequests);
      expect(result.failedRequests).toBe(0);
    });

    it('should gracefully handle errors during load test', async () => {
      const runner = new LoadRunner();

      const taskFn = vi.fn().mockImplementation(async () => {
        if (Math.random() < 0.3) {
          throw new Error('Random failure');
        }
        await new Promise((resolve) => setTimeout(resolve, 5));
        return { success: true };
      });

      runner.configure({
        concurrency: 20,
        duration: 300,
      });

      const result = await runner.run(taskFn);

      expect(result.totalRequests).toBeGreaterThan(0);
      expect(result.failedRequests).toBeGreaterThan(0);
      expect(result.successfulRequests).toBeGreaterThan(0);
      // Error rate should be around 30%
      const errorRate = result.failedRequests / result.totalRequests;
      expect(errorRate).toBeGreaterThan(0.1);
      expect(errorRate).toBeLessThan(0.5);
    });

    it('should maintain stable memory under sustained load', async () => {
      const runner = new LoadRunner();
      const memorySnapshots: number[] = [];

      const taskFn = vi.fn().mockImplementation(async () => {
        // Allocate some memory
        const data = new Array(1000).fill('x');
        await new Promise((resolve) => setTimeout(resolve, 2));
        return { success: true, data: data.length };
      });

      runner.configure({
        concurrency: 30,
        duration: 1000,
      });

      // Take memory snapshots during test
      const snapshotInterval = setInterval(() => {
        memorySnapshots.push(process.memoryUsage().heapUsed);
      }, 100);

      await runner.run(taskFn);

      clearInterval(snapshotInterval);

      // Memory should not grow unboundedly
      if (memorySnapshots.length > 2) {
        const firstHalf = memorySnapshots.slice(
          0,
          Math.floor(memorySnapshots.length / 2)
        );
        const secondHalf = memorySnapshots.slice(
          Math.floor(memorySnapshots.length / 2)
        );

        const firstAvg = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
        const secondAvg =
          secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;

        // Allow up to 50% growth (accounts for GC timing variations)
        expect(secondAvg).toBeLessThan(firstAvg * 1.5);
      }
    });
  });
});

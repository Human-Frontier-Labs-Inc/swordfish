/**
 * Circuit Breaker Tests
 * TDD: RED phase - Write failing tests first
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  CircuitBreaker,
  CircuitBreakerConfig,
  CircuitState,
  CircuitBreakerRegistry,
  CircuitBreakerStats,
} from '../../lib/resilience/circuit-breaker';

describe('Circuit Breaker', () => {
  let breaker: CircuitBreaker;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('Configuration', () => {
    it('should accept circuit breaker configuration', () => {
      const config: CircuitBreakerConfig = {
        failureThreshold: 5,
        successThreshold: 3,
        timeout: 30000,
        resetTimeout: 60000,
      };

      breaker = new CircuitBreaker('test-service', config);
      expect(breaker.getConfig()).toEqual(config);
    });

    it('should use default values for optional parameters', () => {
      breaker = new CircuitBreaker('test-service');
      const config = breaker.getConfig();

      expect(config.failureThreshold).toBe(5);
      expect(config.successThreshold).toBe(2);
      expect(config.timeout).toBe(30000);
      expect(config.resetTimeout).toBe(60000);
    });

    it('should validate configuration parameters', () => {
      expect(() => new CircuitBreaker('test-service', {
        failureThreshold: -1,
        successThreshold: 0,
        timeout: 0,
        resetTimeout: 0,
      })).toThrow('Invalid configuration');
    });

    it('should require a name for the circuit', () => {
      expect(() => new CircuitBreaker('')).toThrow('Circuit name is required');
    });
  });

  describe('State Management', () => {
    beforeEach(() => {
      breaker = new CircuitBreaker('test-service', {
        failureThreshold: 3,
        successThreshold: 2,
        timeout: 1000,
        resetTimeout: 5000,
      });
    });

    it('should start in CLOSED state', () => {
      expect(breaker.getState()).toBe(CircuitState.CLOSED);
    });

    it('should transition to OPEN after reaching failure threshold', async () => {
      const failingFn = vi.fn().mockRejectedValue(new Error('Service unavailable'));

      // Trigger failures up to threshold
      for (let i = 0; i < 3; i++) {
        await breaker.execute(failingFn).catch(() => {});
      }

      expect(breaker.getState()).toBe(CircuitState.OPEN);
    });

    it('should transition to HALF_OPEN after reset timeout', async () => {
      const failingFn = vi.fn().mockRejectedValue(new Error('Service unavailable'));

      // Open the circuit
      for (let i = 0; i < 3; i++) {
        await breaker.execute(failingFn).catch(() => {});
      }
      expect(breaker.getState()).toBe(CircuitState.OPEN);

      // Wait for reset timeout
      vi.advanceTimersByTime(5000);

      expect(breaker.getState()).toBe(CircuitState.HALF_OPEN);
    });

    it('should transition from HALF_OPEN to CLOSED after success threshold', async () => {
      const failingFn = vi.fn().mockRejectedValue(new Error('Service unavailable'));
      const succeedingFn = vi.fn().mockResolvedValue('success');

      // Open the circuit
      for (let i = 0; i < 3; i++) {
        await breaker.execute(failingFn).catch(() => {});
      }

      // Wait for reset timeout
      vi.advanceTimersByTime(5000);
      expect(breaker.getState()).toBe(CircuitState.HALF_OPEN);

      // Successful calls in half-open state
      await breaker.execute(succeedingFn);
      await breaker.execute(succeedingFn);

      expect(breaker.getState()).toBe(CircuitState.CLOSED);
    });

    it('should transition from HALF_OPEN to OPEN on failure', async () => {
      const failingFn = vi.fn().mockRejectedValue(new Error('Service unavailable'));

      // Open the circuit
      for (let i = 0; i < 3; i++) {
        await breaker.execute(failingFn).catch(() => {});
      }

      // Wait for reset timeout
      vi.advanceTimersByTime(5000);
      expect(breaker.getState()).toBe(CircuitState.HALF_OPEN);

      // Failure in half-open state
      await breaker.execute(failingFn).catch(() => {});

      expect(breaker.getState()).toBe(CircuitState.OPEN);
    });

    it('should reset failure count on successful call in CLOSED state', async () => {
      const failingFn = vi.fn().mockRejectedValue(new Error('Service unavailable'));
      const succeedingFn = vi.fn().mockResolvedValue('success');

      // Accumulate some failures (but not enough to open)
      await breaker.execute(failingFn).catch(() => {});
      await breaker.execute(failingFn).catch(() => {});

      // Successful call should reset failure count
      await breaker.execute(succeedingFn);

      // These failures should now start from 0
      await breaker.execute(failingFn).catch(() => {});
      await breaker.execute(failingFn).catch(() => {});

      // Circuit should still be closed (only 2 failures since reset)
      expect(breaker.getState()).toBe(CircuitState.CLOSED);
    });
  });

  describe('Execution', () => {
    beforeEach(() => {
      breaker = new CircuitBreaker('test-service', {
        failureThreshold: 3,
        successThreshold: 2,
        timeout: 1000,
        resetTimeout: 5000,
      });
    });

    it('should execute function when circuit is closed', async () => {
      const fn = vi.fn().mockResolvedValue('result');

      const result = await breaker.execute(fn);

      expect(result).toBe('result');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('should reject immediately when circuit is open', async () => {
      const failingFn = vi.fn().mockRejectedValue(new Error('Service unavailable'));
      const fn = vi.fn().mockResolvedValue('result');

      // Open the circuit
      for (let i = 0; i < 3; i++) {
        await breaker.execute(failingFn).catch(() => {});
      }

      // Try to execute while open
      await expect(breaker.execute(fn)).rejects.toThrow('Circuit is open');
      expect(fn).not.toHaveBeenCalled();
    });

    it('should handle timeout during execution', async () => {
      const slowFn = vi.fn().mockImplementation(() =>
        new Promise((resolve) => setTimeout(() => resolve('slow'), 2000))
      );

      const executePromise = breaker.execute(slowFn);

      // Advance time past timeout
      vi.advanceTimersByTime(1001);

      await expect(executePromise).rejects.toThrow('Operation timed out');
    });

    it('should pass arguments to the wrapped function', async () => {
      const fn = vi.fn().mockImplementation((a: number, b: string) =>
        Promise.resolve(`${a}-${b}`)
      );

      const result = await breaker.execute(() => fn(42, 'test'));

      expect(result).toBe('42-test');
      expect(fn).toHaveBeenCalledWith(42, 'test');
    });

    it('should propagate errors from the wrapped function', async () => {
      const error = new Error('Custom error');
      const fn = vi.fn().mockRejectedValue(error);

      await expect(breaker.execute(fn)).rejects.toThrow('Custom error');
    });
  });

  describe('Events', () => {
    it('should emit event when circuit opens', async () => {
      const onOpen = vi.fn();
      breaker = new CircuitBreaker('test-service', {
        failureThreshold: 3,
        successThreshold: 2,
        timeout: 1000,
        resetTimeout: 5000,
        onOpen,
      });

      const failingFn = vi.fn().mockRejectedValue(new Error('fail'));

      for (let i = 0; i < 3; i++) {
        await breaker.execute(failingFn).catch(() => {});
      }

      expect(onOpen).toHaveBeenCalledTimes(1);
      expect(onOpen).toHaveBeenCalledWith(expect.objectContaining({
        name: 'test-service',
        state: CircuitState.OPEN,
      }));
    });

    it('should emit event when circuit closes', async () => {
      const onClose = vi.fn();
      breaker = new CircuitBreaker('test-service', {
        failureThreshold: 3,
        successThreshold: 2,
        timeout: 1000,
        resetTimeout: 5000,
        onClose,
      });

      const failingFn = vi.fn().mockRejectedValue(new Error('fail'));
      const succeedingFn = vi.fn().mockResolvedValue('success');

      // Open circuit
      for (let i = 0; i < 3; i++) {
        await breaker.execute(failingFn).catch(() => {});
      }

      // Wait for half-open
      vi.advanceTimersByTime(5000);

      // Close circuit with successful calls
      await breaker.execute(succeedingFn);
      await breaker.execute(succeedingFn);

      expect(onClose).toHaveBeenCalledTimes(1);
      expect(onClose).toHaveBeenCalledWith(expect.objectContaining({
        name: 'test-service',
        state: CircuitState.CLOSED,
      }));
    });

    it('should emit event when circuit enters half-open', async () => {
      const onHalfOpen = vi.fn();
      breaker = new CircuitBreaker('test-service', {
        failureThreshold: 3,
        successThreshold: 2,
        timeout: 1000,
        resetTimeout: 5000,
        onHalfOpen,
      });

      const failingFn = vi.fn().mockRejectedValue(new Error('fail'));

      // Open circuit
      for (let i = 0; i < 3; i++) {
        await breaker.execute(failingFn).catch(() => {});
      }

      // Wait for half-open
      vi.advanceTimersByTime(5000);

      // Trigger state check
      breaker.getState();

      expect(onHalfOpen).toHaveBeenCalledTimes(1);
    });
  });

  describe('Statistics', () => {
    beforeEach(() => {
      breaker = new CircuitBreaker('test-service', {
        failureThreshold: 5,
        successThreshold: 2,
        timeout: 1000,
        resetTimeout: 5000,
      });
    });

    it('should track success count', async () => {
      const fn = vi.fn().mockResolvedValue('result');

      await breaker.execute(fn);
      await breaker.execute(fn);
      await breaker.execute(fn);

      const stats = breaker.getStats();
      expect(stats.successCount).toBe(3);
    });

    it('should track failure count', async () => {
      const fn = vi.fn().mockRejectedValue(new Error('fail'));

      await breaker.execute(fn).catch(() => {});
      await breaker.execute(fn).catch(() => {});

      const stats = breaker.getStats();
      expect(stats.failureCount).toBe(2);
    });

    it('should track rejected count (when circuit is open)', async () => {
      const failingFn = vi.fn().mockRejectedValue(new Error('fail'));
      const fn = vi.fn().mockResolvedValue('result');

      // Open circuit
      for (let i = 0; i < 5; i++) {
        await breaker.execute(failingFn).catch(() => {});
      }

      // Try while open
      await breaker.execute(fn).catch(() => {});
      await breaker.execute(fn).catch(() => {});

      const stats = breaker.getStats();
      expect(stats.rejectedCount).toBe(2);
    });

    it('should track timeout count', async () => {
      const slowFn = vi.fn().mockImplementation(() =>
        new Promise((resolve) => setTimeout(() => resolve('slow'), 2000))
      );

      const promise1 = breaker.execute(slowFn).catch(() => {});
      vi.advanceTimersByTime(1001);
      await promise1;

      const promise2 = breaker.execute(slowFn).catch(() => {});
      vi.advanceTimersByTime(1001);
      await promise2;

      const stats = breaker.getStats();
      expect(stats.timeoutCount).toBe(2);
    });

    it('should calculate success rate', async () => {
      const succeedingFn = vi.fn().mockResolvedValue('result');
      const failingFn = vi.fn().mockRejectedValue(new Error('fail'));

      await breaker.execute(succeedingFn);
      await breaker.execute(succeedingFn);
      await breaker.execute(succeedingFn);
      await breaker.execute(failingFn).catch(() => {});

      const stats = breaker.getStats();
      expect(stats.successRate).toBe(0.75);
    });

    it('should reset statistics', async () => {
      const fn = vi.fn().mockResolvedValue('result');

      await breaker.execute(fn);
      await breaker.execute(fn);

      breaker.resetStats();

      const stats = breaker.getStats();
      expect(stats.successCount).toBe(0);
      expect(stats.failureCount).toBe(0);
    });

    it('should track state transitions', async () => {
      const failingFn = vi.fn().mockRejectedValue(new Error('fail'));
      const succeedingFn = vi.fn().mockResolvedValue('success');

      // Open circuit
      for (let i = 0; i < 5; i++) {
        await breaker.execute(failingFn).catch(() => {});
      }

      // Wait for half-open
      vi.advanceTimersByTime(5000);
      breaker.getState(); // Trigger transition

      // Close circuit
      await breaker.execute(succeedingFn);
      await breaker.execute(succeedingFn);

      const stats = breaker.getStats();
      expect(stats.stateTransitions).toBeGreaterThanOrEqual(2);
    });
  });

  describe('CircuitBreakerRegistry', () => {
    let registry: CircuitBreakerRegistry;

    beforeEach(() => {
      registry = new CircuitBreakerRegistry();
    });

    it('should register and retrieve circuit breakers', () => {
      const config: CircuitBreakerConfig = {
        failureThreshold: 5,
        successThreshold: 2,
        timeout: 1000,
        resetTimeout: 5000,
      };

      const breaker = registry.getOrCreate('service-a', config);
      const retrieved = registry.get('service-a');

      expect(retrieved).toBe(breaker);
    });

    it('should return existing circuit breaker if already registered', () => {
      const breaker1 = registry.getOrCreate('service-a');
      const breaker2 = registry.getOrCreate('service-a');

      expect(breaker1).toBe(breaker2);
    });

    it('should list all registered circuit breakers', () => {
      registry.getOrCreate('service-a');
      registry.getOrCreate('service-b');
      registry.getOrCreate('service-c');

      const all = registry.listAll();

      expect(all).toHaveLength(3);
      expect(all.map(b => b.getName())).toEqual(['service-a', 'service-b', 'service-c']);
    });

    it('should return aggregated statistics', async () => {
      const breakerA = registry.getOrCreate('service-a');
      const breakerB = registry.getOrCreate('service-b');

      const fn = vi.fn().mockResolvedValue('result');
      await breakerA.execute(fn);
      await breakerB.execute(fn);

      const stats = registry.getAggregatedStats();

      expect(stats.totalCircuits).toBe(2);
      expect(stats.totalSuccesses).toBe(2);
    });

    it('should remove circuit breaker from registry', () => {
      registry.getOrCreate('service-a');
      registry.remove('service-a');

      expect(registry.get('service-a')).toBeUndefined();
    });

    it('should reset all circuit breakers', async () => {
      const breakerA = registry.getOrCreate('service-a', { failureThreshold: 2 });
      const failingFn = vi.fn().mockRejectedValue(new Error('fail'));

      // Open circuit A
      await breakerA.execute(failingFn).catch(() => {});
      await breakerA.execute(failingFn).catch(() => {});

      expect(breakerA.getState()).toBe(CircuitState.OPEN);

      registry.resetAll();

      expect(breakerA.getState()).toBe(CircuitState.CLOSED);
    });
  });

  describe('Integration', () => {
    it('should protect against cascading failures', async () => {
      const registry = new CircuitBreakerRegistry();
      const serviceA = registry.getOrCreate('service-a', { failureThreshold: 3 });
      const serviceB = registry.getOrCreate('service-b', { failureThreshold: 3 });

      const failingService = vi.fn().mockRejectedValue(new Error('Service down'));
      const callOrder: string[] = [];

      // Service A fails
      for (let i = 0; i < 3; i++) {
        await serviceA.execute(() => {
          callOrder.push('A');
          return failingService();
        }).catch(() => {});
      }

      // Service A is now open, should not call failing service
      await serviceA.execute(failingService).catch(() => {});

      // Service B should still be available
      const fnB = vi.fn().mockResolvedValue('B works');
      const result = await serviceB.execute(fnB);

      expect(result).toBe('B works');
      expect(serviceA.getState()).toBe(CircuitState.OPEN);
      expect(serviceB.getState()).toBe(CircuitState.CLOSED);
    });

    it('should handle concurrent requests correctly', async () => {
      breaker = new CircuitBreaker('test-service', {
        failureThreshold: 5,
        successThreshold: 2,
        timeout: 5000,
        resetTimeout: 5000,
      });

      const fn = vi.fn().mockImplementation(async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
        return 'result';
      });

      // Execute many concurrent requests
      const promises = Array(20).fill(null).map(() => breaker.execute(fn));

      vi.advanceTimersByTime(20);
      const results = await Promise.all(promises);

      expect(results).toHaveLength(20);
      expect(results.every(r => r === 'result')).toBe(true);
    });

    it('should gracefully degrade under load', async () => {
      // Use real timers for this integration test
      vi.useRealTimers();

      breaker = new CircuitBreaker('degraded-service', {
        failureThreshold: 5,
        successThreshold: 2,
        timeout: 50,
        resetTimeout: 200,
      });

      let callCount = 0;
      const degradingFn = vi.fn().mockImplementation(async () => {
        callCount++;
        // Simulate increasing latency - after 8 calls, latency exceeds timeout
        const latency = callCount > 8 ? 100 : 10;
        await new Promise(resolve => setTimeout(resolve, latency));
        return 'result';
      });

      const results: Array<{ success: boolean; error?: string }> = [];

      for (let i = 0; i < 20; i++) {
        try {
          await breaker.execute(degradingFn);
          results.push({ success: true });
        } catch (error) {
          results.push({ success: false, error: (error as Error).message });
        }
      }

      // Some should succeed (first ~8), some should fail due to timeout or open circuit
      const successes = results.filter(r => r.success).length;
      const failures = results.filter(r => !r.success).length;

      expect(successes).toBeGreaterThan(0);
      expect(failures).toBeGreaterThan(0);
    });
  });

  describe('Manual Controls', () => {
    beforeEach(() => {
      breaker = new CircuitBreaker('test-service', {
        failureThreshold: 5,
        successThreshold: 2,
        timeout: 1000,
        resetTimeout: 5000,
      });
    });

    it('should allow manual circuit open', () => {
      breaker.forceOpen();
      expect(breaker.getState()).toBe(CircuitState.OPEN);
    });

    it('should allow manual circuit close', async () => {
      const failingFn = vi.fn().mockRejectedValue(new Error('fail'));

      // Open circuit
      for (let i = 0; i < 5; i++) {
        await breaker.execute(failingFn).catch(() => {});
      }
      expect(breaker.getState()).toBe(CircuitState.OPEN);

      breaker.forceClose();
      expect(breaker.getState()).toBe(CircuitState.CLOSED);
    });

    it('should allow manual reset', async () => {
      const failingFn = vi.fn().mockRejectedValue(new Error('fail'));

      // Accumulate failures
      await breaker.execute(failingFn).catch(() => {});
      await breaker.execute(failingFn).catch(() => {});

      breaker.reset();

      // Check that failure count is reset
      const stats = breaker.getStats();
      expect(stats.consecutiveFailures).toBe(0);
    });
  });
});

/**
 * Deep Health Check Tests
 * TDD: RED phase - Write failing tests first
 *
 * Comprehensive health checking system that validates all system
 * dependencies and provides detailed diagnostics.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  HealthChecker,
  HealthCheckConfig,
  HealthStatus,
  ComponentHealth,
  HealthCheckResult,
  HealthCheckRegistry,
  DatabaseHealthCheck,
  RedisHealthCheck,
  ExternalServiceHealthCheck,
  DiskSpaceHealthCheck,
  MemoryHealthCheck,
} from '../../lib/api/deep-health-checks';

describe('Deep Health Checks', () => {
  let checker: HealthChecker;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('HealthChecker Configuration', () => {
    it('should accept health checker configuration', () => {
      const config: HealthCheckConfig = {
        timeout: 5000,
        cacheTtl: 30000,
        parallel: true,
      };

      checker = new HealthChecker(config);
      expect(checker.getConfig()).toEqual(config);
    });

    it('should use default values for optional parameters', () => {
      checker = new HealthChecker();
      const config = checker.getConfig();

      expect(config.timeout).toBe(10000);
      expect(config.cacheTtl).toBe(60000);
      expect(config.parallel).toBe(true);
    });

    it('should validate configuration parameters', () => {
      expect(() => new HealthChecker({
        timeout: -1,
      })).toThrow('Invalid configuration');
    });
  });

  describe('Component Registration', () => {
    beforeEach(() => {
      checker = new HealthChecker();
    });

    it('should register health check components', () => {
      const mockCheck = {
        name: 'database',
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      };

      checker.register(mockCheck);

      const components = checker.getComponents();
      expect(components).toContain('database');
    });

    it('should prevent duplicate component names', () => {
      const mockCheck = {
        name: 'database',
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      };

      checker.register(mockCheck);

      expect(() => checker.register(mockCheck)).toThrow('Component already registered');
    });

    it('should unregister components', () => {
      const mockCheck = {
        name: 'database',
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      };

      checker.register(mockCheck);
      checker.unregister('database');

      const components = checker.getComponents();
      expect(components).not.toContain('database');
    });

    it('should categorize components by criticality', () => {
      const criticalCheck = {
        name: 'database',
        critical: true,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      };

      const nonCriticalCheck = {
        name: 'cache',
        critical: false,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      };

      checker.register(criticalCheck);
      checker.register(nonCriticalCheck);

      const critical = checker.getCriticalComponents();
      expect(critical).toContain('database');
      expect(critical).not.toContain('cache');
    });
  });

  describe('Health Check Execution', () => {
    beforeEach(() => {
      checker = new HealthChecker({ timeout: 1000 });
    });

    it('should execute all registered health checks', async () => {
      const check1 = vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY });
      const check2 = vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY });

      checker.register({ name: 'service1', check: check1 });
      checker.register({ name: 'service2', check: check2 });

      await checker.checkAll();

      expect(check1).toHaveBeenCalled();
      expect(check2).toHaveBeenCalled();
    });

    it('should execute checks in parallel by default', async () => {
      vi.useRealTimers();

      const startTimes: number[] = [];
      const check1 = vi.fn().mockImplementation(async () => {
        startTimes.push(Date.now());
        await new Promise(resolve => setTimeout(resolve, 50));
        return { status: HealthStatus.HEALTHY };
      });
      const check2 = vi.fn().mockImplementation(async () => {
        startTimes.push(Date.now());
        await new Promise(resolve => setTimeout(resolve, 50));
        return { status: HealthStatus.HEALTHY };
      });

      checker.register({ name: 'service1', check: check1 });
      checker.register({ name: 'service2', check: check2 });

      await checker.checkAll();

      // Start times should be very close (within 10ms) if running in parallel
      expect(Math.abs(startTimes[0] - startTimes[1])).toBeLessThan(20);
    });

    it('should handle check timeout', async () => {
      const slowCheck = vi.fn().mockImplementation(async () => {
        await new Promise(resolve => setTimeout(resolve, 5000));
        return { status: HealthStatus.HEALTHY };
      });

      checker.register({ name: 'slow-service', check: slowCheck });

      const resultPromise = checker.checkAll();
      vi.advanceTimersByTime(1001);
      const result = await resultPromise;

      expect(result.components['slow-service'].status).toBe(HealthStatus.UNHEALTHY);
      expect(result.components['slow-service'].error).toContain('timeout');
    });

    it('should check specific component', async () => {
      const check1 = vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY });
      const check2 = vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY });

      checker.register({ name: 'service1', check: check1 });
      checker.register({ name: 'service2', check: check2 });

      await checker.check('service1');

      expect(check1).toHaveBeenCalled();
      expect(check2).not.toHaveBeenCalled();
    });

    it('should cache health check results', async () => {
      const check = vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY });
      checker = new HealthChecker({ cacheTtl: 5000 });
      checker.register({ name: 'service', check });

      await checker.checkAll();
      await checker.checkAll();
      await checker.checkAll();

      expect(check).toHaveBeenCalledTimes(1);

      // Advance time past cache TTL
      vi.advanceTimersByTime(5001);

      await checker.checkAll();
      expect(check).toHaveBeenCalledTimes(2);
    });

    it('should bypass cache when forced', async () => {
      const check = vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY });
      checker = new HealthChecker({ cacheTtl: 5000 });
      checker.register({ name: 'service', check });

      await checker.checkAll();
      await checker.checkAll({ force: true });

      expect(check).toHaveBeenCalledTimes(2);
    });
  });

  describe('Health Status Aggregation', () => {
    beforeEach(() => {
      checker = new HealthChecker();
    });

    it('should return HEALTHY when all components are healthy', async () => {
      checker.register({
        name: 'db',
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      });
      checker.register({
        name: 'cache',
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      });

      const result = await checker.checkAll();

      expect(result.status).toBe(HealthStatus.HEALTHY);
    });

    it('should return DEGRADED when non-critical component is unhealthy', async () => {
      checker.register({
        name: 'db',
        critical: true,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      });
      checker.register({
        name: 'cache',
        critical: false,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.UNHEALTHY }),
      });

      const result = await checker.checkAll();

      expect(result.status).toBe(HealthStatus.DEGRADED);
    });

    it('should return UNHEALTHY when critical component is unhealthy', async () => {
      checker.register({
        name: 'db',
        critical: true,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.UNHEALTHY }),
      });
      checker.register({
        name: 'cache',
        critical: false,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      });

      const result = await checker.checkAll();

      expect(result.status).toBe(HealthStatus.UNHEALTHY);
    });

    it('should include component-level details', async () => {
      checker.register({
        name: 'db',
        check: vi.fn().mockResolvedValue({
          status: HealthStatus.HEALTHY,
          details: { latency: 5, connections: 10 },
        }),
      });

      const result = await checker.checkAll();

      expect(result.components['db'].details?.latency).toBe(5);
      expect(result.components['db'].details?.connections).toBe(10);
    });

    it('should include timing information', async () => {
      vi.useRealTimers();

      checker.register({
        name: 'service',
        check: vi.fn().mockImplementation(async () => {
          await new Promise(resolve => setTimeout(resolve, 10));
          return { status: HealthStatus.HEALTHY };
        }),
      });

      const result = await checker.checkAll();

      expect(result.components['service'].duration).toBeGreaterThanOrEqual(10);
      expect(result.totalDuration).toBeGreaterThanOrEqual(10);
    });
  });

  describe('Built-in Health Checks', () => {
    describe('DatabaseHealthCheck', () => {
      it('should check database connectivity', async () => {
        const mockQuery = vi.fn().mockResolvedValue({ rows: [{ result: 1 }] });
        const dbCheck = new DatabaseHealthCheck({
          name: 'postgres',
          query: mockQuery,
        });

        const result = await dbCheck.check();

        expect(result.status).toBe(HealthStatus.HEALTHY);
        expect(mockQuery).toHaveBeenCalled();
      });

      it('should report unhealthy on query failure', async () => {
        const mockQuery = vi.fn().mockRejectedValue(new Error('Connection refused'));
        const dbCheck = new DatabaseHealthCheck({
          name: 'postgres',
          query: mockQuery,
        });

        const result = await dbCheck.check();

        expect(result.status).toBe(HealthStatus.UNHEALTHY);
        expect(result.error).toContain('Connection refused');
      });

      it('should include connection pool stats', async () => {
        const mockQuery = vi.fn().mockResolvedValue({ rows: [{ result: 1 }] });
        const mockPoolStats = vi.fn().mockReturnValue({
          total: 10,
          idle: 5,
          waiting: 0,
        });

        const dbCheck = new DatabaseHealthCheck({
          name: 'postgres',
          query: mockQuery,
          getPoolStats: mockPoolStats,
        });

        const result = await dbCheck.check();

        expect(result.details?.pool).toEqual({
          total: 10,
          idle: 5,
          waiting: 0,
        });
      });
    });

    describe('RedisHealthCheck', () => {
      it('should check Redis connectivity with PING', async () => {
        const mockPing = vi.fn().mockResolvedValue('PONG');
        const redisCheck = new RedisHealthCheck({
          name: 'redis',
          ping: mockPing,
        });

        const result = await redisCheck.check();

        expect(result.status).toBe(HealthStatus.HEALTHY);
      });

      it('should report unhealthy on PING failure', async () => {
        const mockPing = vi.fn().mockRejectedValue(new Error('Connection lost'));
        const redisCheck = new RedisHealthCheck({
          name: 'redis',
          ping: mockPing,
        });

        const result = await redisCheck.check();

        expect(result.status).toBe(HealthStatus.UNHEALTHY);
      });

      it('should include Redis info metrics', async () => {
        const mockPing = vi.fn().mockResolvedValue('PONG');
        const mockInfo = vi.fn().mockResolvedValue({
          connected_clients: 5,
          used_memory: 1024000,
          uptime_in_seconds: 86400,
        });

        const redisCheck = new RedisHealthCheck({
          name: 'redis',
          ping: mockPing,
          getInfo: mockInfo,
        });

        const result = await redisCheck.check();

        expect(result.details?.connectedClients).toBe(5);
        expect(result.details?.usedMemory).toBe(1024000);
      });
    });

    describe('ExternalServiceHealthCheck', () => {
      it('should check external service with HTTP request', async () => {
        const mockFetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
        global.fetch = mockFetch;

        const serviceCheck = new ExternalServiceHealthCheck({
          name: 'api-gateway',
          url: 'https://api.example.com/health',
        });

        const result = await serviceCheck.check();

        expect(result.status).toBe(HealthStatus.HEALTHY);
      });

      it('should report unhealthy on non-200 response', async () => {
        const mockFetch = vi.fn().mockResolvedValue({ ok: false, status: 503 });
        global.fetch = mockFetch;

        const serviceCheck = new ExternalServiceHealthCheck({
          name: 'api-gateway',
          url: 'https://api.example.com/health',
        });

        const result = await serviceCheck.check();

        expect(result.status).toBe(HealthStatus.UNHEALTHY);
        expect(result.details?.statusCode).toBe(503);
      });

      it('should report degraded on slow response', async () => {
        vi.useRealTimers();
        const mockFetch = vi.fn().mockImplementation(async () => {
          await new Promise(resolve => setTimeout(resolve, 100));
          return { ok: true, status: 200 };
        });
        global.fetch = mockFetch;

        const serviceCheck = new ExternalServiceHealthCheck({
          name: 'api-gateway',
          url: 'https://api.example.com/health',
          degradedThreshold: 50, // 50ms
        });

        const result = await serviceCheck.check();

        expect(result.status).toBe(HealthStatus.DEGRADED);
      });
    });

    describe('DiskSpaceHealthCheck', () => {
      it('should check disk space usage', async () => {
        const mockGetDiskUsage = vi.fn().mockResolvedValue({
          total: 1000000000,
          used: 500000000,
          free: 500000000,
          usedPercent: 50,
        });

        const diskCheck = new DiskSpaceHealthCheck({
          name: 'disk',
          getDiskUsage: mockGetDiskUsage,
          path: '/',
        });

        const result = await diskCheck.check();

        expect(result.status).toBe(HealthStatus.HEALTHY);
        expect(result.details?.usedPercent).toBe(50);
      });

      it('should report degraded when usage exceeds warning threshold', async () => {
        const mockGetDiskUsage = vi.fn().mockResolvedValue({
          total: 1000000000,
          used: 800000000,
          free: 200000000,
          usedPercent: 80,
        });

        const diskCheck = new DiskSpaceHealthCheck({
          name: 'disk',
          getDiskUsage: mockGetDiskUsage,
          path: '/',
          warningThreshold: 75,
          criticalThreshold: 90,
        });

        const result = await diskCheck.check();

        expect(result.status).toBe(HealthStatus.DEGRADED);
      });

      it('should report unhealthy when usage exceeds critical threshold', async () => {
        const mockGetDiskUsage = vi.fn().mockResolvedValue({
          total: 1000000000,
          used: 950000000,
          free: 50000000,
          usedPercent: 95,
        });

        const diskCheck = new DiskSpaceHealthCheck({
          name: 'disk',
          getDiskUsage: mockGetDiskUsage,
          path: '/',
          warningThreshold: 75,
          criticalThreshold: 90,
        });

        const result = await diskCheck.check();

        expect(result.status).toBe(HealthStatus.UNHEALTHY);
      });
    });

    describe('MemoryHealthCheck', () => {
      it('should check memory usage', async () => {
        const mockGetMemoryUsage = vi.fn().mockReturnValue({
          heapUsed: 50000000,
          heapTotal: 100000000,
          rss: 120000000,
          external: 5000000,
        });

        const memoryCheck = new MemoryHealthCheck({
          name: 'memory',
          getMemoryUsage: mockGetMemoryUsage,
        });

        const result = await memoryCheck.check();

        expect(result.status).toBe(HealthStatus.HEALTHY);
        expect(result.details?.heapUsedPercent).toBe(50);
      });

      it('should report degraded on high memory usage', async () => {
        const mockGetMemoryUsage = vi.fn().mockReturnValue({
          heapUsed: 85000000,
          heapTotal: 100000000,
          rss: 120000000,
          external: 5000000,
        });

        const memoryCheck = new MemoryHealthCheck({
          name: 'memory',
          getMemoryUsage: mockGetMemoryUsage,
          warningThreshold: 80,
          criticalThreshold: 95,
        });

        const result = await memoryCheck.check();

        expect(result.status).toBe(HealthStatus.DEGRADED);
      });
    });
  });

  describe('HealthCheckRegistry', () => {
    let registry: HealthCheckRegistry;

    beforeEach(() => {
      registry = new HealthCheckRegistry();
    });

    it('should create pre-configured health checker', () => {
      registry.registerDefaults();

      const checker = registry.createChecker();
      const components = checker.getComponents();

      expect(components.length).toBeGreaterThan(0);
    });

    it('should support custom health check factories', () => {
      const customFactory = vi.fn().mockReturnValue({
        name: 'custom',
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      });

      registry.registerFactory('custom', customFactory);
      registry.create('custom', { option: 'value' });

      expect(customFactory).toHaveBeenCalledWith({ option: 'value' });
    });
  });

  describe('Liveness vs Readiness', () => {
    beforeEach(() => {
      checker = new HealthChecker();
    });

    it('should support liveness check (basic alive check)', async () => {
      checker.register({
        name: 'critical-db',
        critical: true,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      });
      checker.register({
        name: 'non-critical-cache',
        critical: false,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.UNHEALTHY }),
      });

      const result = await checker.liveness();

      // Liveness only checks if the app is running, not all dependencies
      expect(result.status).toBe(HealthStatus.HEALTHY);
    });

    it('should support readiness check (full dependency check)', async () => {
      checker.register({
        name: 'db',
        critical: true,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      });
      checker.register({
        name: 'cache',
        critical: false,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.UNHEALTHY }),
      });

      const result = await checker.readiness();

      // Readiness checks all dependencies
      expect(result.status).toBe(HealthStatus.DEGRADED);
    });
  });

  describe('Integration', () => {
    it('should provide HTTP-compatible response format', async () => {
      checker = new HealthChecker();
      checker.register({
        name: 'db',
        critical: true,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      });

      const result = await checker.checkAll();
      const httpResponse = checker.toHttpResponse(result);

      expect(httpResponse.statusCode).toBe(200);
      expect(httpResponse.body.status).toBe('healthy');
      expect(httpResponse.body.checks).toBeDefined();
    });

    it('should return 503 for unhealthy status', async () => {
      checker = new HealthChecker();
      checker.register({
        name: 'db',
        critical: true,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.UNHEALTHY }),
      });

      const result = await checker.checkAll();
      const httpResponse = checker.toHttpResponse(result);

      expect(httpResponse.statusCode).toBe(503);
      expect(httpResponse.body.status).toBe('unhealthy');
    });

    it('should return 200 for degraded status', async () => {
      checker = new HealthChecker();
      checker.register({
        name: 'db',
        critical: true,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.HEALTHY }),
      });
      checker.register({
        name: 'cache',
        critical: false,
        check: vi.fn().mockResolvedValue({ status: HealthStatus.UNHEALTHY }),
      });

      const result = await checker.checkAll();
      const httpResponse = checker.toHttpResponse(result);

      expect(httpResponse.statusCode).toBe(200);
      expect(httpResponse.body.status).toBe('degraded');
    });
  });
});

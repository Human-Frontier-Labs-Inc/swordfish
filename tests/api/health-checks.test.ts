/**
 * Health Check Endpoints Tests
 * TDD: Kubernetes-compatible health probes
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import {
  HealthChecker,
  HealthStatus,
  HealthCheckResult,
  ComponentHealth,
  createHealthChecker,
  checkDatabase,
  checkExternalService,
} from '@/lib/api/health';

// Mock database
vi.mock('@/lib/db', () => ({
  sql: vi.fn(),
}));

describe('Health Check Endpoints', () => {
  let checker: HealthChecker;

  beforeEach(() => {
    vi.clearAllMocks();
    checker = createHealthChecker();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('HealthStatus', () => {
    it('should have standard status values', () => {
      expect(HealthStatus.HEALTHY).toBe('healthy');
      expect(HealthStatus.UNHEALTHY).toBe('unhealthy');
      expect(HealthStatus.DEGRADED).toBe('degraded');
    });
  });

  describe('HealthChecker', () => {
    describe('liveness', () => {
      it('should return healthy when app is running', async () => {
        const result = await checker.liveness();

        expect(result.status).toBe(HealthStatus.HEALTHY);
      });

      it('should include timestamp', async () => {
        const result = await checker.liveness();

        expect(result.timestamp).toBeDefined();
        expect(new Date(result.timestamp).getTime()).toBeGreaterThan(0);
      });

      it('should be fast (no external checks)', async () => {
        const start = Date.now();
        await checker.liveness();
        const duration = Date.now() - start;

        expect(duration).toBeLessThan(10); // Should be nearly instant
      });
    });

    describe('readiness', () => {
      it('should return healthy when all dependencies are available', async () => {
        const { sql } = await import('@/lib/db');
        vi.mocked(sql).mockResolvedValue([{ ok: 1 }] as any);

        checker.registerCheck('database', async () => ({
          status: HealthStatus.HEALTHY,
          message: 'Connected',
        }));

        const result = await checker.readiness();

        expect(result.status).toBe(HealthStatus.HEALTHY);
      });

      it('should return unhealthy when critical dependency fails', async () => {
        checker.registerCheck('database', async () => ({
          status: HealthStatus.UNHEALTHY,
          message: 'Connection failed',
        }));

        const result = await checker.readiness();

        expect(result.status).toBe(HealthStatus.UNHEALTHY);
      });

      it('should return degraded when non-critical dependency fails', async () => {
        checker.registerCheck(
          'cache',
          async () => ({
            status: HealthStatus.UNHEALTHY,
            message: 'Redis unavailable',
          }),
          { critical: false }
        );

        const result = await checker.readiness();

        expect(result.status).toBe(HealthStatus.DEGRADED);
      });

      it('should include component health details', async () => {
        checker.registerCheck('database', async () => ({
          status: HealthStatus.HEALTHY,
          message: 'Connected',
          latencyMs: 5,
        }));

        const result = await checker.readiness();

        expect(result.components).toBeDefined();
        expect(result.components?.database).toBeDefined();
        expect(result.components?.database.status).toBe(HealthStatus.HEALTHY);
      });

      it('should timeout slow health checks', async () => {
        checker.registerCheck(
          'slow-service',
          async () => {
            await new Promise((r) => setTimeout(r, 10000)); // 10 seconds
            return { status: HealthStatus.HEALTHY, message: 'OK' };
          },
          { timeoutMs: 100 }
        );

        const result = await checker.readiness();

        expect(result.components?.['slow-service'].status).toBe(HealthStatus.UNHEALTHY);
        expect(result.components?.['slow-service'].message).toContain('timeout');
      });
    });

    describe('registerCheck', () => {
      it('should register a health check', () => {
        const checkFn = async () => ({ status: HealthStatus.HEALTHY, message: 'OK' });

        checker.registerCheck('test-service', checkFn);

        expect(checker.getRegisteredChecks()).toContain('test-service');
      });

      it('should support critical flag', () => {
        checker.registerCheck(
          'critical-db',
          async () => ({ status: HealthStatus.HEALTHY, message: 'OK' }),
          { critical: true }
        );

        checker.registerCheck(
          'optional-cache',
          async () => ({ status: HealthStatus.HEALTHY, message: 'OK' }),
          { critical: false }
        );

        const checks = checker.getCheckOptions();
        expect(checks['critical-db']?.critical).toBe(true);
        expect(checks['optional-cache']?.critical).toBe(false);
      });
    });

    describe('full health check', () => {
      it('should include version info', async () => {
        const result = await checker.full();

        expect(result.version).toBeDefined();
      });

      it('should include uptime', async () => {
        const result = await checker.full();

        expect(result.uptime).toBeDefined();
        expect(typeof result.uptime).toBe('number');
      });

      it('should include all component details', async () => {
        checker.registerCheck('db', async () => ({
          status: HealthStatus.HEALTHY,
          message: 'Connected',
        }));
        checker.registerCheck('cache', async () => ({
          status: HealthStatus.HEALTHY,
          message: 'Available',
        }));

        const result = await checker.full();

        expect(result.components).toBeDefined();
        expect(Object.keys(result.components || {})).toHaveLength(2);
      });
    });
  });

  describe('checkDatabase', () => {
    it('should return healthy when query succeeds', async () => {
      const { sql } = await import('@/lib/db');
      vi.mocked(sql).mockResolvedValue([{ ok: 1 }] as any);

      const result = await checkDatabase();

      expect(result.status).toBe(HealthStatus.HEALTHY);
    });

    it('should return unhealthy when query fails', async () => {
      const { sql } = await import('@/lib/db');
      vi.mocked(sql).mockRejectedValue(new Error('Connection refused'));

      const result = await checkDatabase();

      expect(result.status).toBe(HealthStatus.UNHEALTHY);
      expect(result.message).toContain('Connection refused');
    });

    it('should include latency measurement', async () => {
      const { sql } = await import('@/lib/db');
      vi.mocked(sql).mockResolvedValue([{ ok: 1 }] as any);

      const result = await checkDatabase();

      expect(result.latencyMs).toBeDefined();
      expect(typeof result.latencyMs).toBe('number');
    });
  });

  describe('checkExternalService', () => {
    it('should return healthy when service responds', async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });

      const result = await checkExternalService('https://api.example.com/health');

      expect(result.status).toBe(HealthStatus.HEALTHY);
    });

    it('should return unhealthy when service fails', async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 503 });

      const result = await checkExternalService('https://api.example.com/health');

      expect(result.status).toBe(HealthStatus.UNHEALTHY);
    });

    it('should return unhealthy on network error', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

      const result = await checkExternalService('https://api.example.com/health');

      expect(result.status).toBe(HealthStatus.UNHEALTHY);
      expect(result.message).toContain('Network error');
    });

    it('should include latency measurement', async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });

      const result = await checkExternalService('https://api.example.com/health');

      expect(result.latencyMs).toBeDefined();
    });

    it('should timeout slow services', async () => {
      global.fetch = vi.fn().mockImplementation(
        (_url: string, options?: { signal?: AbortSignal }) =>
          new Promise((resolve, reject) => {
            const timeout = setTimeout(() => resolve({ ok: true, status: 200 }), 10000);
            // Listen for abort signal
            if (options?.signal) {
              options.signal.addEventListener('abort', () => {
                clearTimeout(timeout);
                const error = new Error('The operation was aborted');
                error.name = 'AbortError';
                reject(error);
              });
            }
          })
      );

      const result = await checkExternalService('https://api.example.com/health', 100);

      expect(result.status).toBe(HealthStatus.UNHEALTHY);
      expect(result.message).toContain('timeout');
    });
  });

  describe('HTTP Response formatting', () => {
    it('should return 200 for healthy status', async () => {
      const result = await checker.liveness();

      expect(result.httpStatus).toBe(200);
    });

    it('should return 503 for unhealthy status', async () => {
      checker.registerCheck('failing', async () => ({
        status: HealthStatus.UNHEALTHY,
        message: 'Failed',
      }));

      const result = await checker.readiness();

      expect(result.httpStatus).toBe(503);
    });

    it('should return 200 for degraded status (still serving)', async () => {
      checker.registerCheck(
        'optional',
        async () => ({
          status: HealthStatus.UNHEALTHY,
          message: 'Down',
        }),
        { critical: false }
      );

      const result = await checker.readiness();

      expect(result.httpStatus).toBe(200);
    });
  });

  describe('Kubernetes probe compatibility', () => {
    it('should support /healthz (liveness) pattern', async () => {
      const result = await checker.liveness();

      // Kubernetes expects simple 200 OK for liveness
      expect(result.httpStatus).toBe(200);
      expect(result.status).toBe(HealthStatus.HEALTHY);
    });

    it('should support /readyz (readiness) pattern', async () => {
      const result = await checker.readiness();

      // Should include check results
      expect(result.status).toBeDefined();
    });

    it('should support startup probe (same as liveness)', async () => {
      const startup = await checker.liveness();
      const liveness = await checker.liveness();

      expect(startup.status).toBe(liveness.status);
    });
  });
});

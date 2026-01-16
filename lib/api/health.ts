/**
 * Health Check Module
 *
 * Provides Kubernetes-compatible health probes for liveness, readiness, and startup checks.
 * Supports dependency health monitoring and graceful degradation.
 */

import { sql } from '@/lib/db';

/**
 * Health status values
 */
export const HealthStatus = {
  HEALTHY: 'healthy',
  UNHEALTHY: 'unhealthy',
  DEGRADED: 'degraded',
} as const;

export type HealthStatusType = (typeof HealthStatus)[keyof typeof HealthStatus];

/**
 * Component health result
 */
export interface ComponentHealth {
  status: HealthStatusType;
  message: string;
  latencyMs?: number;
}

/**
 * Health check options
 */
export interface CheckOptions {
  /** Whether this check is critical for readiness (default: true) */
  critical?: boolean;
  /** Timeout for this check in milliseconds (default: 5000) */
  timeoutMs?: number;
}

/**
 * Full health check result
 */
export interface HealthCheckResult {
  status: HealthStatusType;
  timestamp: string;
  httpStatus: number;
  components?: Record<string, ComponentHealth>;
  version?: string;
  uptime?: number;
}

/**
 * Health check function type
 */
type HealthCheckFn = () => Promise<ComponentHealth>;

/**
 * Registered check with options
 */
interface RegisteredCheck {
  fn: HealthCheckFn;
  options: Required<CheckOptions>;
}

/**
 * Start time for uptime calculation
 */
const startTime = Date.now();

/**
 * Health checker class
 */
export class HealthChecker {
  private checks: Map<string, RegisteredCheck> = new Map();

  /**
   * Register a health check
   */
  registerCheck(name: string, fn: HealthCheckFn, options: CheckOptions = {}): void {
    this.checks.set(name, {
      fn,
      options: {
        critical: options.critical ?? true,
        timeoutMs: options.timeoutMs ?? 5000,
      },
    });
  }

  /**
   * Get list of registered check names
   */
  getRegisteredChecks(): string[] {
    return Array.from(this.checks.keys());
  }

  /**
   * Get check options
   */
  getCheckOptions(): Record<string, CheckOptions> {
    const result: Record<string, CheckOptions> = {};
    for (const [name, check] of this.checks) {
      result[name] = check.options;
    }
    return result;
  }

  /**
   * Run a single health check with timeout
   */
  private async runCheck(name: string, check: RegisteredCheck): Promise<ComponentHealth> {
    try {
      const result = await Promise.race([
        check.fn(),
        new Promise<ComponentHealth>((_, reject) =>
          setTimeout(() => reject(new Error('Health check timeout')), check.options.timeoutMs)
        ),
      ]);
      return result;
    } catch (error) {
      return {
        status: HealthStatus.UNHEALTHY,
        message: error instanceof Error ? `Check timeout: ${error.message}` : 'Check timeout',
      };
    }
  }

  /**
   * Liveness probe - is the app running?
   *
   * Used by Kubernetes to determine if the container should be restarted.
   * Should be fast and not check external dependencies.
   */
  async liveness(): Promise<HealthCheckResult> {
    return {
      status: HealthStatus.HEALTHY,
      timestamp: new Date().toISOString(),
      httpStatus: 200,
    };
  }

  /**
   * Readiness probe - is the app ready to receive traffic?
   *
   * Checks all registered dependencies and returns overall status.
   */
  async readiness(): Promise<HealthCheckResult> {
    const components: Record<string, ComponentHealth> = {};
    let hasUnhealthyCritical = false;
    let hasUnhealthyNonCritical = false;

    // Run all checks in parallel
    const checkPromises = Array.from(this.checks.entries()).map(async ([name, check]) => {
      const result = await this.runCheck(name, check);
      components[name] = result;

      if (result.status === HealthStatus.UNHEALTHY) {
        if (check.options.critical) {
          hasUnhealthyCritical = true;
        } else {
          hasUnhealthyNonCritical = true;
        }
      }
    });

    await Promise.all(checkPromises);

    let status: HealthStatusType;
    let httpStatus: number;

    if (hasUnhealthyCritical) {
      status = HealthStatus.UNHEALTHY;
      httpStatus = 503;
    } else if (hasUnhealthyNonCritical) {
      status = HealthStatus.DEGRADED;
      httpStatus = 200; // Still serving traffic
    } else {
      status = HealthStatus.HEALTHY;
      httpStatus = 200;
    }

    return {
      status,
      timestamp: new Date().toISOString(),
      httpStatus,
      components,
    };
  }

  /**
   * Full health check with all details
   *
   * Includes version, uptime, and all component details.
   */
  async full(): Promise<HealthCheckResult> {
    const readiness = await this.readiness();

    return {
      ...readiness,
      version: process.env.npm_package_version || '0.0.0',
      uptime: Math.floor((Date.now() - startTime) / 1000),
    };
  }
}

/**
 * Create a health checker instance
 */
export function createHealthChecker(): HealthChecker {
  return new HealthChecker();
}

/**
 * Check database connectivity
 */
export async function checkDatabase(): Promise<ComponentHealth> {
  const start = Date.now();

  try {
    await sql`SELECT 1 as ok`;

    return {
      status: HealthStatus.HEALTHY,
      message: 'Connected',
      latencyMs: Date.now() - start,
    };
  } catch (error) {
    return {
      status: HealthStatus.UNHEALTHY,
      message: error instanceof Error ? error.message : 'Database connection failed',
      latencyMs: Date.now() - start,
    };
  }
}

/**
 * Check external service health
 */
export async function checkExternalService(
  url: string,
  timeoutMs = 5000
): Promise<ComponentHealth> {
  const start = Date.now();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (response.ok) {
      return {
        status: HealthStatus.HEALTHY,
        message: `Status: ${response.status}`,
        latencyMs: Date.now() - start,
      };
    }

    return {
      status: HealthStatus.UNHEALTHY,
      message: `Unhealthy status: ${response.status}`,
      latencyMs: Date.now() - start,
    };
  } catch (error) {
    clearTimeout(timeoutId);

    const message =
      error instanceof Error
        ? error.name === 'AbortError'
          ? 'Request timeout'
          : error.message
        : 'Unknown error';

    return {
      status: HealthStatus.UNHEALTHY,
      message,
      latencyMs: Date.now() - start,
    };
  }
}

/**
 * Default health checker with common checks
 */
export const defaultHealthChecker = createHealthChecker();

// Register default checks
defaultHealthChecker.registerCheck('database', checkDatabase, { critical: true });

/**
 * Deep Health Check System
 *
 * Provides comprehensive health checking with support for multiple
 * components, caching, timeouts, and detailed diagnostics.
 */

export enum HealthStatus {
  HEALTHY = 'healthy',
  DEGRADED = 'degraded',
  UNHEALTHY = 'unhealthy',
}

export interface ComponentHealth {
  status: HealthStatus;
  duration?: number;
  error?: string;
  details?: Record<string, unknown>;
}

export interface HealthCheckResult {
  status: HealthStatus;
  timestamp: Date;
  totalDuration: number;
  components: Record<string, ComponentHealth>;
}

export interface HealthCheckConfig {
  timeout?: number;
  cacheTtl?: number;
  parallel?: boolean;
}

export interface HealthCheck {
  name: string;
  critical?: boolean;
  check(): Promise<ComponentHealth>;
}

export interface HttpHealthResponse {
  statusCode: number;
  body: {
    status: string;
    timestamp: string;
    duration: number;
    checks: Record<string, unknown>;
  };
}

/**
 * Main health checker class
 */
export class HealthChecker {
  private config: Required<HealthCheckConfig>;
  private components: Map<string, HealthCheck> = new Map();
  private cache: Map<string, { result: ComponentHealth; timestamp: number }> = new Map();

  constructor(config: HealthCheckConfig = {}) {
    if (config.timeout !== undefined && config.timeout <= 0) {
      throw new Error('Invalid configuration');
    }

    this.config = {
      timeout: config.timeout ?? 10000,
      cacheTtl: config.cacheTtl ?? 60000,
      parallel: config.parallel ?? true,
    };
  }

  getConfig(): HealthCheckConfig {
    return { ...this.config };
  }

  register(check: HealthCheck): void {
    if (this.components.has(check.name)) {
      throw new Error('Component already registered');
    }
    this.components.set(check.name, check);
  }

  unregister(name: string): void {
    this.components.delete(name);
    this.cache.delete(name);
  }

  getComponents(): string[] {
    return Array.from(this.components.keys());
  }

  getCriticalComponents(): string[] {
    return Array.from(this.components.entries())
      .filter(([_, check]) => check.critical)
      .map(([name]) => name);
  }

  async check(name: string, options: { force?: boolean } = {}): Promise<ComponentHealth> {
    const check = this.components.get(name);
    if (!check) {
      return { status: HealthStatus.UNHEALTHY, error: 'Component not found' };
    }

    // Check cache
    if (!options.force) {
      const cached = this.cache.get(name);
      if (cached && Date.now() - cached.timestamp < this.config.cacheTtl) {
        return cached.result;
      }
    }

    const result = await this.executeCheck(check);

    // Update cache
    this.cache.set(name, { result, timestamp: Date.now() });

    return result;
  }

  async checkAll(options: { force?: boolean } = {}): Promise<HealthCheckResult> {
    const startTime = Date.now();
    const components: Record<string, ComponentHealth> = {};

    const checks = Array.from(this.components.entries());

    if (this.config.parallel) {
      const results = await Promise.all(
        checks.map(async ([name, check]) => {
          const result = await this.check(name, options);
          return { name, result };
        })
      );

      for (const { name, result } of results) {
        components[name] = result;
      }
    } else {
      for (const [name] of checks) {
        components[name] = await this.check(name, options);
      }
    }

    const totalDuration = Date.now() - startTime;
    const status = this.aggregateStatus(components);

    return {
      status,
      timestamp: new Date(),
      totalDuration,
      components,
    };
  }

  async liveness(): Promise<HealthCheckResult> {
    // Liveness just checks if the app is running
    return {
      status: HealthStatus.HEALTHY,
      timestamp: new Date(),
      totalDuration: 0,
      components: {},
    };
  }

  async readiness(): Promise<HealthCheckResult> {
    // Readiness checks all dependencies
    return this.checkAll();
  }

  toHttpResponse(result: HealthCheckResult): HttpHealthResponse {
    const statusCode = result.status === HealthStatus.UNHEALTHY ? 503 : 200;

    const checks: Record<string, unknown> = {};
    for (const [name, health] of Object.entries(result.components)) {
      checks[name] = {
        status: health.status,
        duration: health.duration,
        error: health.error,
        details: health.details,
      };
    }

    return {
      statusCode,
      body: {
        status: result.status,
        timestamp: result.timestamp.toISOString(),
        duration: result.totalDuration,
        checks,
      },
    };
  }

  private async executeCheck(check: HealthCheck): Promise<ComponentHealth> {
    const startTime = Date.now();

    try {
      const result = await Promise.race([
        check.check(),
        new Promise<ComponentHealth>((_, reject) =>
          setTimeout(() => reject(new Error('Health check timeout')), this.config.timeout)
        ),
      ]);

      return {
        ...result,
        duration: Date.now() - startTime,
      };
    } catch (error) {
      return {
        status: HealthStatus.UNHEALTHY,
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  private aggregateStatus(components: Record<string, ComponentHealth>): HealthStatus {
    let hasDegraded = false;
    let hasUnhealthyCritical = false;
    let hasUnhealthyNonCritical = false;

    for (const [name, health] of Object.entries(components)) {
      const check = this.components.get(name);
      const isCritical = check?.critical ?? true;

      if (health.status === HealthStatus.UNHEALTHY) {
        if (isCritical) {
          hasUnhealthyCritical = true;
        } else {
          hasUnhealthyNonCritical = true;
        }
      } else if (health.status === HealthStatus.DEGRADED) {
        hasDegraded = true;
      }
    }

    if (hasUnhealthyCritical) {
      return HealthStatus.UNHEALTHY;
    }

    if (hasUnhealthyNonCritical || hasDegraded) {
      return HealthStatus.DEGRADED;
    }

    return HealthStatus.HEALTHY;
  }
}

/**
 * Database health check
 */
export interface DatabaseHealthCheckConfig {
  name: string;
  query: () => Promise<unknown>;
  getPoolStats?: () => { total: number; idle: number; waiting: number };
}

export class DatabaseHealthCheck implements HealthCheck {
  name: string;
  critical = true;
  private config: DatabaseHealthCheckConfig;

  constructor(config: DatabaseHealthCheckConfig) {
    this.name = config.name;
    this.config = config;
  }

  async check(): Promise<ComponentHealth> {
    try {
      await this.config.query();

      const details: Record<string, unknown> = {};
      if (this.config.getPoolStats) {
        details.pool = this.config.getPoolStats();
      }

      return {
        status: HealthStatus.HEALTHY,
        details,
      };
    } catch (error) {
      return {
        status: HealthStatus.UNHEALTHY,
        error: error instanceof Error ? error.message : 'Database check failed',
      };
    }
  }
}

/**
 * Redis health check
 */
export interface RedisHealthCheckConfig {
  name: string;
  ping: () => Promise<string>;
  getInfo?: () => Promise<{
    connected_clients: number;
    used_memory: number;
    uptime_in_seconds: number;
  }>;
}

export class RedisHealthCheck implements HealthCheck {
  name: string;
  critical = false;
  private config: RedisHealthCheckConfig;

  constructor(config: RedisHealthCheckConfig) {
    this.name = config.name;
    this.config = config;
  }

  async check(): Promise<ComponentHealth> {
    try {
      const response = await this.config.ping();
      if (response !== 'PONG') {
        return {
          status: HealthStatus.UNHEALTHY,
          error: `Unexpected PING response: ${response}`,
        };
      }

      const details: Record<string, unknown> = {};
      if (this.config.getInfo) {
        const info = await this.config.getInfo();
        details.connectedClients = info.connected_clients;
        details.usedMemory = info.used_memory;
        details.uptimeSeconds = info.uptime_in_seconds;
      }

      return {
        status: HealthStatus.HEALTHY,
        details,
      };
    } catch (error) {
      return {
        status: HealthStatus.UNHEALTHY,
        error: error instanceof Error ? error.message : 'Redis check failed',
      };
    }
  }
}

/**
 * External service health check
 */
export interface ExternalServiceHealthCheckConfig {
  name: string;
  url: string;
  method?: string;
  headers?: Record<string, string>;
  degradedThreshold?: number;
}

export class ExternalServiceHealthCheck implements HealthCheck {
  name: string;
  critical = false;
  private config: ExternalServiceHealthCheckConfig;

  constructor(config: ExternalServiceHealthCheckConfig) {
    this.name = config.name;
    this.config = config;
  }

  async check(): Promise<ComponentHealth> {
    const startTime = Date.now();

    try {
      const response = await fetch(this.config.url, {
        method: this.config.method ?? 'GET',
        headers: this.config.headers,
      });

      const duration = Date.now() - startTime;
      const details: Record<string, unknown> = {
        statusCode: response.status,
        duration,
      };

      if (!response.ok) {
        return {
          status: HealthStatus.UNHEALTHY,
          details,
          error: `HTTP ${response.status}`,
        };
      }

      // Check if response is slow (degraded)
      if (this.config.degradedThreshold && duration > this.config.degradedThreshold) {
        return {
          status: HealthStatus.DEGRADED,
          details,
        };
      }

      return {
        status: HealthStatus.HEALTHY,
        details,
      };
    } catch (error) {
      return {
        status: HealthStatus.UNHEALTHY,
        error: error instanceof Error ? error.message : 'Service check failed',
      };
    }
  }
}

/**
 * Disk space health check
 */
export interface DiskSpaceHealthCheckConfig {
  name: string;
  path: string;
  getDiskUsage: () => Promise<{
    total: number;
    used: number;
    free: number;
    usedPercent: number;
  }>;
  warningThreshold?: number;
  criticalThreshold?: number;
}

export class DiskSpaceHealthCheck implements HealthCheck {
  name: string;
  critical = false;
  private config: DiskSpaceHealthCheckConfig;

  constructor(config: DiskSpaceHealthCheckConfig) {
    this.name = config.name;
    this.config = {
      ...config,
      warningThreshold: config.warningThreshold ?? 80,
      criticalThreshold: config.criticalThreshold ?? 90,
    };
  }

  async check(): Promise<ComponentHealth> {
    try {
      const usage = await this.config.getDiskUsage();

      const details: Record<string, unknown> = {
        path: this.config.path,
        total: usage.total,
        used: usage.used,
        free: usage.free,
        usedPercent: usage.usedPercent,
      };

      if (usage.usedPercent >= this.config.criticalThreshold!) {
        return {
          status: HealthStatus.UNHEALTHY,
          details,
          error: `Disk usage ${usage.usedPercent}% exceeds critical threshold ${this.config.criticalThreshold}%`,
        };
      }

      if (usage.usedPercent >= this.config.warningThreshold!) {
        return {
          status: HealthStatus.DEGRADED,
          details,
        };
      }

      return {
        status: HealthStatus.HEALTHY,
        details,
      };
    } catch (error) {
      return {
        status: HealthStatus.UNHEALTHY,
        error: error instanceof Error ? error.message : 'Disk check failed',
      };
    }
  }
}

/**
 * Memory health check
 */
export interface MemoryHealthCheckConfig {
  name: string;
  getMemoryUsage: () => {
    heapUsed: number;
    heapTotal: number;
    rss: number;
    external: number;
  };
  warningThreshold?: number;
  criticalThreshold?: number;
}

export class MemoryHealthCheck implements HealthCheck {
  name: string;
  critical = false;
  private config: MemoryHealthCheckConfig;

  constructor(config: MemoryHealthCheckConfig) {
    this.name = config.name;
    this.config = {
      ...config,
      warningThreshold: config.warningThreshold ?? 85,
      criticalThreshold: config.criticalThreshold ?? 95,
    };
  }

  async check(): Promise<ComponentHealth> {
    try {
      const usage = this.config.getMemoryUsage();
      const heapUsedPercent = (usage.heapUsed / usage.heapTotal) * 100;

      const details: Record<string, unknown> = {
        heapUsed: usage.heapUsed,
        heapTotal: usage.heapTotal,
        heapUsedPercent,
        rss: usage.rss,
        external: usage.external,
      };

      if (heapUsedPercent >= this.config.criticalThreshold!) {
        return {
          status: HealthStatus.UNHEALTHY,
          details,
          error: `Memory usage ${heapUsedPercent.toFixed(1)}% exceeds critical threshold`,
        };
      }

      if (heapUsedPercent >= this.config.warningThreshold!) {
        return {
          status: HealthStatus.DEGRADED,
          details,
        };
      }

      return {
        status: HealthStatus.HEALTHY,
        details,
      };
    } catch (error) {
      return {
        status: HealthStatus.UNHEALTHY,
        error: error instanceof Error ? error.message : 'Memory check failed',
      };
    }
  }
}

/**
 * Health check registry for managing and creating health checks
 */
export class HealthCheckRegistry {
  private factories: Map<string, (config: unknown) => HealthCheck> = new Map();
  private checks: HealthCheck[] = [];

  registerFactory(name: string, factory: (config: unknown) => HealthCheck): void {
    this.factories.set(name, factory);
  }

  create(name: string, config: unknown): HealthCheck {
    const factory = this.factories.get(name);
    if (!factory) {
      throw new Error(`Unknown health check type: ${name}`);
    }
    const check = factory(config);
    this.checks.push(check);
    return check;
  }

  registerDefaults(): void {
    // Register memory check by default
    this.checks.push(
      new MemoryHealthCheck({
        name: 'memory',
        getMemoryUsage: () => process.memoryUsage(),
      })
    );
  }

  createChecker(config?: HealthCheckConfig): HealthChecker {
    const checker = new HealthChecker(config);
    for (const check of this.checks) {
      checker.register(check);
    }
    return checker;
  }
}

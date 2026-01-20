/**
 * Connection Pool Module
 *
 * High-performance database connection pooling with health checks,
 * idle timeout management, and comprehensive statistics.
 */

import { nanoid } from 'nanoid';

/**
 * Pool configuration
 */
export interface PoolConfig {
  minConnections: number;
  maxConnections: number;
  acquireTimeout: number;
  idleTimeout: number;
  healthCheckInterval: number;
}

/**
 * Pool statistics
 */
export interface PoolStats {
  minConnections: number;
  maxConnections: number;
  totalConnections: number;
  activeConnections: number;
  idleConnections: number;
  totalAcquisitions: number;
  totalWaitTime: number;
  avgIdleTime: number;
  utilization: number;
  acquisitionsPerSecond: number;
  removedConnections: number;
  isDraining: boolean;
}

/**
 * Pooled connection interface
 */
export interface PooledConnection {
  id: string;
  isActive: boolean;
  createdAt: number;
  lastUsedAt: number;
  lastHealthCheck: number;
  queryCount: number;
  age: number;
  query: (sql: string, params?: unknown[]) => Promise<unknown>;
  execute: (sql: string, params?: unknown[]) => Promise<unknown>;
}

/**
 * Internal connection state
 */
interface InternalConnection {
  id: string;
  isActive: boolean;
  createdAt: number;
  lastUsedAt: number;
  lastHealthCheck: number;
  queryCount: number;
  isHealthy: boolean;
}

/**
 * Pool exhausted error
 */
export class PoolExhaustedError extends Error {
  constructor(
    message: string,
    public poolStats: PoolStats,
    public waitTime: number
  ) {
    super(message);
    this.name = 'PoolExhaustedError';
  }
}

/**
 * Connection timeout error
 */
export class ConnectionTimeoutError extends PoolExhaustedError {
  constructor(poolStats: PoolStats, waitTime: number) {
    super(`Connection acquisition timed out after ${waitTime}ms`, poolStats, waitTime);
    this.name = 'ConnectionTimeoutError';
  }
}

/**
 * Waiting request
 */
interface WaitingRequest {
  resolve: (conn: PooledConnection) => void;
  reject: (error: Error) => void;
  startTime: number;
  timeoutId: ReturnType<typeof setTimeout>;
}

/**
 * Connection Pool class
 */
export class ConnectionPool {
  private config: PoolConfig;
  private connections: Map<string, InternalConnection> = new Map();
  private idleConnections: string[] = [];
  private waitingRequests: WaitingRequest[] = [];
  private totalAcquisitions: number = 0;
  private totalWaitTime: number = 0;
  private removedConnections: number = 0;
  private isDraining: boolean = false;
  private startTime: number = Date.now();
  private drainResolve?: () => void;

  constructor(config: Partial<PoolConfig> = {}) {
    // Validate config
    const minConn = config.minConnections ?? 2;
    const maxConn = config.maxConnections ?? 10;

    if (minConn < 0 || maxConn < 0) {
      throw new Error('Connection counts must be positive');
    }

    if (minConn > maxConn) {
      throw new Error('minConnections cannot exceed maxConnections');
    }

    this.config = {
      minConnections: minConn,
      maxConnections: maxConn,
      acquireTimeout: config.acquireTimeout ?? 5000,
      idleTimeout: config.idleTimeout ?? 30000,
      healthCheckInterval: config.healthCheckInterval ?? 30000,
    };
  }

  /**
   * Acquire a connection from the pool
   */
  async acquire(): Promise<PooledConnection> {
    if (this.isDraining) {
      throw new Error('Pool is draining');
    }

    this.totalAcquisitions++;
    const startTime = Date.now();

    // Try to get an idle connection
    while (this.idleConnections.length > 0) {
      const connId = this.idleConnections.shift()!;
      const conn = this.connections.get(connId);

      if (conn && conn.isHealthy) {
        conn.isActive = true;
        conn.lastUsedAt = Date.now();
        conn.lastHealthCheck = Date.now();
        return this.wrapConnection(conn);
      }
    }

    // Create new connection if under max
    if (this.connections.size < this.config.maxConnections) {
      const conn = this.createConnection();
      conn.isActive = true;
      return this.wrapConnection(conn);
    }

    // Wait for available connection
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        const index = this.waitingRequests.findIndex(
          (r) => r.resolve === resolve
        );
        if (index !== -1) {
          this.waitingRequests.splice(index, 1);
        }

        const waitTime = Date.now() - startTime;
        this.totalWaitTime += waitTime;
        reject(new ConnectionTimeoutError(this.getStats(), waitTime));
      }, this.config.acquireTimeout);

      this.waitingRequests.push({
        resolve,
        reject,
        startTime,
        timeoutId,
      });
    });
  }

  /**
   * Release a connection back to the pool
   */
  release(conn: PooledConnection): void {
    const internal = this.connections.get(conn.id);

    if (!internal) {
      // Connection not in pool, ignore
      return;
    }

    internal.isActive = false;
    internal.lastUsedAt = Date.now();

    // Mark wrapped connection as inactive
    (conn as any).isActive = false;

    // Check if there are waiting requests
    if (this.waitingRequests.length > 0) {
      const request = this.waitingRequests.shift()!;
      clearTimeout(request.timeoutId);

      const waitTime = Date.now() - request.startTime;
      this.totalWaitTime += waitTime;

      internal.isActive = true;
      internal.lastHealthCheck = Date.now();
      request.resolve(this.wrapConnection(internal));
      return;
    }

    // Add to idle pool
    this.idleConnections.push(conn.id);

    // Check if draining
    if (this.isDraining && this.getActiveCount() === 0 && this.drainResolve) {
      this.drainResolve();
    }
  }

  /**
   * Mark a connection as unhealthy
   */
  markUnhealthy(connId: string): void {
    const conn = this.connections.get(connId);
    if (conn) {
      conn.isHealthy = false;
      this.connections.delete(connId);
      this.idleConnections = this.idleConnections.filter((id) => id !== connId);
      this.removedConnections++;
    }
  }

  /**
   * Prune idle connections that have exceeded timeout
   */
  pruneIdleConnections(): void {
    const now = Date.now();
    const toRemove: string[] = [];

    for (const connId of this.idleConnections) {
      const conn = this.connections.get(connId);
      if (!conn) continue;

      const idleTime = now - conn.lastUsedAt;
      if (idleTime > this.config.idleTimeout) {
        // Keep minimum connections
        if (this.connections.size - toRemove.length > this.config.minConnections) {
          toRemove.push(connId);
        }
      }
    }

    for (const connId of toRemove) {
      this.connections.delete(connId);
      this.idleConnections = this.idleConnections.filter((id) => id !== connId);
      this.removedConnections++;
    }
  }

  /**
   * Drain the pool (close all connections)
   */
  async drain(timeout: number = 5000): Promise<void> {
    this.isDraining = true;

    // Reject all waiting requests
    for (const request of this.waitingRequests) {
      clearTimeout(request.timeoutId);
      request.reject(new Error('Pool is draining'));
    }
    this.waitingRequests = [];

    // Wait for active connections to be released (with timeout)
    if (this.getActiveCount() > 0) {
      await Promise.race([
        new Promise<void>((resolve) => {
          this.drainResolve = resolve;
        }),
        new Promise<void>((resolve) => setTimeout(resolve, timeout)),
      ]);
    }

    // Clear all connections (force cleanup)
    this.connections.clear();
    this.idleConnections = [];
  }

  /**
   * Get pool statistics
   */
  getStats(): PoolStats {
    const now = Date.now();
    const runtime = (now - this.startTime) / 1000;

    const idleConnections = this.idleConnections.length;
    const totalConnections = this.connections.size;
    const activeConnections = this.getActiveCount();

    // Calculate average idle time
    let totalIdleTime = 0;
    let idleCount = 0;
    for (const connId of this.idleConnections) {
      const conn = this.connections.get(connId);
      if (conn) {
        totalIdleTime += now - conn.lastUsedAt;
        idleCount++;
      }
    }
    const avgIdleTime = idleCount > 0 ? totalIdleTime / idleCount : 0;

    return {
      minConnections: this.config.minConnections,
      maxConnections: this.config.maxConnections,
      totalConnections,
      activeConnections,
      idleConnections,
      totalAcquisitions: this.totalAcquisitions,
      totalWaitTime: this.totalWaitTime,
      avgIdleTime,
      utilization: activeConnections / this.config.maxConnections,
      acquisitionsPerSecond: runtime > 0 ? this.totalAcquisitions / runtime : 0,
      removedConnections: this.removedConnections,
      isDraining: this.isDraining,
    };
  }

  /**
   * Execute a function with a connection that is automatically released
   */
  async withConnection<T>(fn: (conn: PooledConnection) => Promise<T>): Promise<T> {
    const conn = await this.acquire();
    try {
      return await fn(conn);
    } finally {
      this.release(conn);
    }
  }

  private createConnection(): InternalConnection {
    const now = Date.now();
    const conn: InternalConnection = {
      id: 'conn_' + nanoid(12),
      isActive: false,
      createdAt: now,
      lastUsedAt: now,
      lastHealthCheck: now,
      queryCount: 0,
      isHealthy: true,
    };

    this.connections.set(conn.id, conn);
    return conn;
  }

  private wrapConnection(internal: InternalConnection): PooledConnection {
    return {
      get id() {
        return internal.id;
      },
      get isActive() {
        return internal.isActive;
      },
      set isActive(value: boolean) {
        internal.isActive = value;
      },
      get createdAt() {
        return internal.createdAt;
      },
      get lastUsedAt() {
        return internal.lastUsedAt;
      },
      get lastHealthCheck() {
        return internal.lastHealthCheck;
      },
      get queryCount() {
        return internal.queryCount;
      },
      get age() {
        return Date.now() - internal.createdAt;
      },
      async query(sql: string, _params?: unknown[]): Promise<unknown> {
        internal.queryCount++;
        internal.lastUsedAt = Date.now();
        // Simulated query - in real implementation, this would use actual DB driver
        return { rows: [], sql };
      },
      async execute(sql: string, _params?: unknown[]): Promise<unknown> {
        internal.queryCount++;
        internal.lastUsedAt = Date.now();
        // Simulated execute - in real implementation, this would use actual DB driver
        return { affectedRows: 0, sql };
      },
    };
  }

  private getActiveCount(): number {
    let count = 0;
    Array.from(this.connections.values()).forEach((conn) => {
      if (conn.isActive) count++;
    });
    return count;
  }
}

/**
 * Create a connection pool with the given configuration
 */
export function createConnectionPool(config?: Partial<PoolConfig>): ConnectionPool {
  return new ConnectionPool(config);
}

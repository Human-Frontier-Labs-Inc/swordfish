/**
 * Connection Pool Tests
 * TDD: Database connection pooling for performance
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import {
  ConnectionPool,
  createConnectionPool,
  PooledConnection,
  PoolExhaustedError,
  ConnectionTimeoutError,
} from '@/lib/performance/connection-pool';

describe('Connection Pool', () => {
  let pool: ConnectionPool;

  afterEach(async () => {
    if (pool) {
      await pool.drain(100); // Short timeout for tests
    }
  });

  describe('Pool creation', () => {
    it('should create pool with default config', () => {
      pool = createConnectionPool();

      const stats = pool.getStats();
      expect(stats.minConnections).toBe(2);
      expect(stats.maxConnections).toBe(10);
    });

    it('should create pool with custom config', () => {
      pool = createConnectionPool({
        minConnections: 5,
        maxConnections: 20,
        acquireTimeout: 10000,
        idleTimeout: 60000,
      });

      const stats = pool.getStats();
      expect(stats.minConnections).toBe(5);
      expect(stats.maxConnections).toBe(20);
    });

    it('should validate config constraints', () => {
      expect(() =>
        createConnectionPool({
          minConnections: 10,
          maxConnections: 5, // Invalid: min > max
        })
      ).toThrow('minConnections cannot exceed maxConnections');
    });

    it('should require positive values', () => {
      expect(() =>
        createConnectionPool({
          minConnections: -1,
        })
      ).toThrow('Connection counts must be positive');
    });
  });

  describe('Connection acquisition', () => {
    beforeEach(() => {
      pool = createConnectionPool({
        minConnections: 1,
        maxConnections: 3,
        acquireTimeout: 100, // Short timeout for tests
      });
    });

    it('should acquire a connection', async () => {
      const conn = await pool.acquire();

      expect(conn).toBeDefined();
      expect(conn.id).toBeDefined();
      expect(conn.isActive).toBe(true);
    });

    it('should track active connections', async () => {
      await pool.acquire();
      await pool.acquire();

      const stats = pool.getStats();
      expect(stats.activeConnections).toBe(2);
    });

    it('should create new connections up to max', async () => {
      await pool.acquire();
      await pool.acquire();
      await pool.acquire();

      const stats = pool.getStats();
      expect(stats.totalConnections).toBe(3);
    });

    it('should throw when pool exhausted', async () => {
      await pool.acquire();
      await pool.acquire();
      await pool.acquire();

      // Pool is at max, should timeout
      await expect(pool.acquire()).rejects.toThrow(PoolExhaustedError);
    });

    it('should wait for available connection', async () => {
      const conn1 = await pool.acquire();
      await pool.acquire();
      await pool.acquire();

      // Start acquiring (will wait)
      const acquirePromise = pool.acquire();

      // Release a connection shortly
      setTimeout(() => pool.release(conn1), 10);

      // Should now succeed
      const conn4 = await acquirePromise;
      expect(conn4).toBeDefined();
    });

    it('should track acquisition wait time', async () => {
      pool = createConnectionPool({
        minConnections: 1,
        maxConnections: 1,
        acquireTimeout: 500,
      });

      const conn1 = await pool.acquire();

      const acquirePromise = pool.acquire();

      // Release after delay
      setTimeout(() => pool.release(conn1), 50);

      await acquirePromise;

      const stats = pool.getStats();
      expect(stats.totalWaitTime).toBeGreaterThanOrEqual(40);
    });
  });

  describe('Connection release', () => {
    beforeEach(() => {
      pool = createConnectionPool({
        minConnections: 1,
        maxConnections: 5,
      });
    });

    it('should release connection back to pool', async () => {
      const conn = await pool.acquire();
      pool.release(conn);

      const stats = pool.getStats();
      expect(stats.activeConnections).toBe(0);
      expect(stats.idleConnections).toBe(1);
    });

    it('should reuse released connections', async () => {
      const conn1 = await pool.acquire();
      pool.release(conn1);

      const conn2 = await pool.acquire();
      expect(conn2.id).toBe(conn1.id);
    });

    it('should handle releasing invalid connection', () => {
      const fakeConn = { id: 'fake', isActive: true } as PooledConnection;

      // Should not throw, just log warning
      expect(() => pool.release(fakeConn)).not.toThrow();
    });

    it('should mark connection as inactive on release', async () => {
      const conn = await pool.acquire();
      pool.release(conn);

      expect(conn.isActive).toBe(false);
    });
  });

  describe('Connection health', () => {
    beforeEach(() => {
      pool = createConnectionPool({
        minConnections: 1,
        maxConnections: 5,
        healthCheckInterval: 5000,
      });
    });

    it('should validate connection health on acquire', async () => {
      const conn = await pool.acquire();

      expect(conn.lastHealthCheck).toBeDefined();
    });

    it('should remove unhealthy connections', async () => {
      const conn = await pool.acquire();
      pool.release(conn);

      // Mark as unhealthy
      pool.markUnhealthy(conn.id);

      // Acquire should get a new connection
      const conn2 = await pool.acquire();
      expect(conn2.id).not.toBe(conn.id);
    });

    it('should track removed connections', async () => {
      const conn = await pool.acquire();
      pool.release(conn);
      pool.markUnhealthy(conn.id);

      const stats = pool.getStats();
      expect(stats.removedConnections).toBe(1);
    });
  });

  describe('Idle connection management', () => {
    beforeEach(() => {
      pool = createConnectionPool({
        minConnections: 1,
        maxConnections: 5,
        idleTimeout: 50, // Short timeout for tests
      });
    });

    it('should close idle connections after timeout', async () => {
      const conn1 = await pool.acquire();
      const conn2 = await pool.acquire();
      pool.release(conn1);
      pool.release(conn2);

      // Wait past idle timeout
      await new Promise((resolve) => setTimeout(resolve, 60));
      pool.pruneIdleConnections();

      const stats = pool.getStats();
      // Should keep minConnections
      expect(stats.totalConnections).toBe(1);
    });

    it('should keep minimum connections even when idle', async () => {
      const conn = await pool.acquire();
      pool.release(conn);

      await new Promise((resolve) => setTimeout(resolve, 60));
      pool.pruneIdleConnections();

      const stats = pool.getStats();
      expect(stats.totalConnections).toBeGreaterThanOrEqual(1);
    });

    it('should track connection idle time', async () => {
      const conn = await pool.acquire();
      pool.release(conn);

      await new Promise((resolve) => setTimeout(resolve, 50));

      const stats = pool.getStats();
      expect(stats.avgIdleTime).toBeGreaterThanOrEqual(40);
    });
  });

  describe('Pool statistics', () => {
    beforeEach(() => {
      pool = createConnectionPool({
        minConnections: 2,
        maxConnections: 10,
      });
    });

    it('should track total acquisitions', async () => {
      await pool.acquire();
      await pool.acquire();
      await pool.acquire();

      const stats = pool.getStats();
      expect(stats.totalAcquisitions).toBe(3);
    });

    it('should track acquisition rate', async () => {
      await pool.acquire();
      await pool.acquire();
      await pool.acquire();

      // Add a small delay to ensure non-zero runtime
      await new Promise((resolve) => setTimeout(resolve, 10));

      const stats = pool.getStats();
      expect(stats.acquisitionsPerSecond).toBeGreaterThanOrEqual(0);
      expect(typeof stats.acquisitionsPerSecond).toBe('number');
    });

    it('should calculate pool utilization', async () => {
      await pool.acquire();
      await pool.acquire();
      await pool.acquire();

      const stats = pool.getStats();
      expect(stats.utilization).toBe(0.3); // 3/10 max connections
    });

    it('should provide comprehensive stats', () => {
      const stats = pool.getStats();

      expect(stats).toHaveProperty('minConnections');
      expect(stats).toHaveProperty('maxConnections');
      expect(stats).toHaveProperty('totalConnections');
      expect(stats).toHaveProperty('activeConnections');
      expect(stats).toHaveProperty('idleConnections');
      expect(stats).toHaveProperty('totalAcquisitions');
      expect(stats).toHaveProperty('totalWaitTime');
      expect(stats).toHaveProperty('utilization');
    });
  });

  describe('Pool draining', () => {
    beforeEach(() => {
      pool = createConnectionPool({
        minConnections: 1,
        maxConnections: 5,
      });
    });

    it('should drain all connections', async () => {
      await pool.acquire();
      await pool.acquire();

      await pool.drain();

      const stats = pool.getStats();
      expect(stats.totalConnections).toBe(0);
      expect(stats.isDraining).toBe(true);
    });

    it('should reject new acquisitions when draining', async () => {
      await pool.drain();

      await expect(pool.acquire()).rejects.toThrow('Pool is draining');
    });

    it('should wait for active connections to be released', async () => {
      const conn = await pool.acquire();

      const drainPromise = pool.drain();

      // Release after delay
      setTimeout(() => pool.release(conn), 10);

      await drainPromise;

      const stats = pool.getStats();
      expect(stats.isDraining).toBe(true);
    });
  });

  describe('Connection wrapper', () => {
    beforeEach(() => {
      pool = createConnectionPool({
        minConnections: 1,
        maxConnections: 5,
      });
    });

    it('should provide query method', async () => {
      const conn = await pool.acquire();

      expect(conn.query).toBeDefined();
      expect(typeof conn.query).toBe('function');
    });

    it('should provide execute method', async () => {
      const conn = await pool.acquire();

      expect(conn.execute).toBeDefined();
      expect(typeof conn.execute).toBe('function');
    });

    it('should track query count', async () => {
      const conn = await pool.acquire();

      await conn.query('SELECT 1');
      await conn.query('SELECT 2');

      expect(conn.queryCount).toBe(2);
    });

    it('should track connection age', async () => {
      const conn = await pool.acquire();

      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(conn.age).toBeGreaterThanOrEqual(40);
    });
  });

  describe('Error handling', () => {
    beforeEach(() => {
      pool = createConnectionPool({
        minConnections: 1,
        maxConnections: 3,
        acquireTimeout: 50,
      });
    });

    it('should provide PoolExhaustedError with details', async () => {
      await pool.acquire();
      await pool.acquire();
      await pool.acquire();

      try {
        await pool.acquire();
      } catch (error) {
        expect(error).toBeInstanceOf(PoolExhaustedError);
        expect((error as PoolExhaustedError).poolStats).toBeDefined();
        expect((error as PoolExhaustedError).waitTime).toBeGreaterThan(0);
      }
    });

    it('should provide ConnectionTimeoutError for acquire timeout', async () => {
      await pool.acquire();
      await pool.acquire();
      await pool.acquire();

      await expect(pool.acquire()).rejects.toBeInstanceOf(ConnectionTimeoutError);
    });
  });

  describe('withConnection helper', () => {
    beforeEach(() => {
      pool = createConnectionPool({
        minConnections: 1,
        maxConnections: 5,
      });
    });

    it('should automatically acquire and release', async () => {
      const result = await pool.withConnection(async (conn) => {
        expect(conn.isActive).toBe(true);
        return 'success';
      });

      expect(result).toBe('success');

      const stats = pool.getStats();
      expect(stats.activeConnections).toBe(0);
    });

    it('should release on error', async () => {
      await expect(
        pool.withConnection(async () => {
          throw new Error('Test error');
        })
      ).rejects.toThrow('Test error');

      const stats = pool.getStats();
      expect(stats.activeConnections).toBe(0);
    });

    it('should support nested withConnection', async () => {
      await pool.withConnection(async (conn1) => {
        await pool.withConnection(async (conn2) => {
          expect(conn1.id).not.toBe(conn2.id);
        });
      });

      const stats = pool.getStats();
      expect(stats.activeConnections).toBe(0);
    });
  });
});

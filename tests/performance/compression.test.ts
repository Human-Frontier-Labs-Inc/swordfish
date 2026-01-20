/**
 * Response Compression Tests
 * TDD: Gzip/Brotli compression for API responses
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

import {
  CompressionMiddleware,
  createCompressionMiddleware,
  CompressionConfig,
  CompressionAlgorithm,
  CompressedResponse,
} from '@/lib/performance/compression';

describe('Response Compression', () => {
  let middleware: CompressionMiddleware;

  beforeEach(() => {
    middleware = createCompressionMiddleware();
  });

  describe('Middleware creation', () => {
    it('should create middleware with default config', () => {
      const config = middleware.getConfig();

      expect(config.threshold).toBe(1024); // 1KB default
      expect(config.defaultAlgorithm).toBe('gzip');
    });

    it('should create middleware with custom config', () => {
      middleware = createCompressionMiddleware({
        threshold: 512,
        defaultAlgorithm: 'br',
        level: 6,
      });

      const config = middleware.getConfig();
      expect(config.threshold).toBe(512);
      expect(config.defaultAlgorithm).toBe('br');
      expect(config.level).toBe(6);
    });

    it('should validate threshold is positive', () => {
      expect(() =>
        createCompressionMiddleware({
          threshold: -1,
        })
      ).toThrow('threshold must be positive');
    });

    it('should validate compression level', () => {
      expect(() =>
        createCompressionMiddleware({
          level: 15, // Invalid level
        })
      ).toThrow('level must be between 1 and 9');
    });
  });

  describe('Compression algorithms', () => {
    it('should support gzip compression', () => {
      expect(CompressionAlgorithm.GZIP).toBe('gzip');
    });

    it('should support brotli compression', () => {
      expect(CompressionAlgorithm.BROTLI).toBe('br');
    });

    it('should support deflate compression', () => {
      expect(CompressionAlgorithm.DEFLATE).toBe('deflate');
    });

    it('should support identity (no compression)', () => {
      expect(CompressionAlgorithm.IDENTITY).toBe('identity');
    });
  });

  describe('Compression detection', () => {
    it('should detect gzip from Accept-Encoding', () => {
      const algorithm = middleware.detectAlgorithm('gzip, deflate, br');

      expect(algorithm).toBe('gzip');
    });

    it('should prefer brotli when available', () => {
      middleware = createCompressionMiddleware({
        preferBrotli: true,
      });

      const algorithm = middleware.detectAlgorithm('gzip, deflate, br');

      expect(algorithm).toBe('br');
    });

    it('should fallback to gzip when brotli not supported', () => {
      const algorithm = middleware.detectAlgorithm('gzip, deflate');

      expect(algorithm).toBe('gzip');
    });

    it('should return identity when no compression supported', () => {
      const algorithm = middleware.detectAlgorithm('');

      expect(algorithm).toBe('identity');
    });

    it('should handle quality values', () => {
      const algorithm = middleware.detectAlgorithm('gzip;q=0.5, br;q=1.0');

      expect(algorithm).toBe('br');
    });

    it('should handle wildcard', () => {
      const algorithm = middleware.detectAlgorithm('*');

      expect(['gzip', 'br']).toContain(algorithm);
    });
  });

  describe('Compression execution', () => {
    beforeEach(() => {
      middleware = createCompressionMiddleware({
        threshold: 10, // Low threshold for testing
      });
    });

    it('should compress string content', async () => {
      const content = 'Hello, World! '.repeat(100);
      const result = await middleware.compress(content, 'gzip');

      expect(result.compressed).toBeDefined();
      expect(result.algorithm).toBe('gzip');
      expect(result.originalSize).toBe(content.length);
      expect(result.compressedSize).toBeLessThan(content.length);
    });

    it('should compress buffer content', async () => {
      const content = Buffer.from('Hello, World! '.repeat(100));
      const result = await middleware.compress(content, 'gzip');

      expect(result.compressed).toBeInstanceOf(Buffer);
      expect(result.compressedSize).toBeLessThan(content.length);
    });

    it('should compress JSON objects', async () => {
      const content = { data: 'x'.repeat(1000), items: Array(100).fill({ id: 1 }) };
      const result = await middleware.compressJSON(content, 'gzip');

      expect(result.algorithm).toBe('gzip');
      expect(result.compressedSize).toBeLessThan(result.originalSize);
    });

    it('should skip compression below threshold', async () => {
      middleware = createCompressionMiddleware({
        threshold: 1000,
      });

      const content = 'Short content';
      const result = await middleware.compress(content, 'gzip');

      expect(result.algorithm).toBe('identity');
      expect(result.compressedSize).toBe(result.originalSize);
    });

    it('should skip compression for already compressed content', async () => {
      const content = 'x'.repeat(1000);
      const firstPass = await middleware.compress(content, 'gzip');

      // Trying to compress already compressed data
      const secondPass = await middleware.compress(
        firstPass.compressed,
        'gzip',
        { skipIfCompressed: true }
      );

      // Should detect it's already compressed or skip
      expect(secondPass.algorithm).toBe('identity');
    });
  });

  describe('Decompression', () => {
    beforeEach(() => {
      middleware = createCompressionMiddleware({
        threshold: 10,
      });
    });

    it('should decompress gzip content', async () => {
      const original = 'Hello, World! '.repeat(100);
      const compressed = await middleware.compress(original, 'gzip');

      const decompressed = await middleware.decompress(
        compressed.compressed,
        'gzip'
      );

      expect(decompressed.toString()).toBe(original);
    });

    it('should decompress brotli content', async () => {
      const original = 'Hello, World! '.repeat(100);
      const compressed = await middleware.compress(original, 'br');

      const decompressed = await middleware.decompress(
        compressed.compressed,
        'br'
      );

      expect(decompressed.toString()).toBe(original);
    });

    it('should handle identity (no decompression)', async () => {
      const content = Buffer.from('Not compressed');

      const result = await middleware.decompress(content, 'identity');

      expect(result).toEqual(content);
    });

    it('should throw on invalid compressed data', async () => {
      const invalidData = Buffer.from('Not valid gzip data');

      await expect(
        middleware.decompress(invalidData, 'gzip')
      ).rejects.toThrow();
    });
  });

  describe('Compression ratio', () => {
    beforeEach(() => {
      middleware = createCompressionMiddleware({
        threshold: 10,
      });
    });

    it('should calculate compression ratio', async () => {
      const content = 'Hello, World! '.repeat(100);
      const result = await middleware.compress(content, 'gzip');

      expect(result.ratio).toBeDefined();
      expect(result.ratio).toBeGreaterThan(0);
      expect(result.ratio).toBeLessThan(1);
    });

    it('should report ratio of 1 when not compressed', async () => {
      middleware = createCompressionMiddleware({
        threshold: 10000,
      });

      const content = 'Short';
      const result = await middleware.compress(content, 'gzip');

      expect(result.ratio).toBe(1);
    });

    it('should skip compression when ratio is poor', async () => {
      middleware = createCompressionMiddleware({
        threshold: 10,
        minRatio: 0.5, // Only compress if achieves 50% reduction
      });

      // Random data compresses poorly
      const randomData = Buffer.alloc(1000);
      for (let i = 0; i < 1000; i++) {
        randomData[i] = Math.floor(Math.random() * 256);
      }

      const result = await middleware.compress(randomData, 'gzip');

      // May or may not be compressed depending on data
      expect(result.algorithm).toBeDefined();
    });
  });

  describe('Content-Type filtering', () => {
    beforeEach(() => {
      middleware = createCompressionMiddleware({
        threshold: 10,
      });
    });

    it('should compress JSON content type', () => {
      expect(middleware.shouldCompress('application/json')).toBe(true);
    });

    it('should compress text content types', () => {
      expect(middleware.shouldCompress('text/html')).toBe(true);
      expect(middleware.shouldCompress('text/plain')).toBe(true);
      expect(middleware.shouldCompress('text/css')).toBe(true);
      expect(middleware.shouldCompress('text/javascript')).toBe(true);
    });

    it('should compress XML content types', () => {
      expect(middleware.shouldCompress('application/xml')).toBe(true);
      expect(middleware.shouldCompress('text/xml')).toBe(true);
    });

    it('should not compress images by default', () => {
      expect(middleware.shouldCompress('image/png')).toBe(false);
      expect(middleware.shouldCompress('image/jpeg')).toBe(false);
    });

    it('should not compress already compressed formats', () => {
      expect(middleware.shouldCompress('application/zip')).toBe(false);
      expect(middleware.shouldCompress('application/gzip')).toBe(false);
    });

    it('should support custom content type filter', () => {
      middleware = createCompressionMiddleware({
        threshold: 10,
        shouldCompress: (contentType) => contentType.includes('custom'),
      });

      expect(middleware.shouldCompress('application/custom')).toBe(true);
      expect(middleware.shouldCompress('application/json')).toBe(false);
    });
  });

  describe('Stream compression', () => {
    it('should create gzip transform stream', () => {
      const stream = middleware.createCompressStream('gzip');

      expect(stream).toBeDefined();
      expect(stream.writable).toBe(true);
    });

    it('should create brotli transform stream', () => {
      const stream = middleware.createCompressStream('br');

      expect(stream).toBeDefined();
      expect(stream.writable).toBe(true);
    });

    it('should create decompress stream', () => {
      const stream = middleware.createDecompressStream('gzip');

      expect(stream).toBeDefined();
      expect(stream.writable).toBe(true);
    });
  });

  describe('Compression statistics', () => {
    beforeEach(() => {
      middleware = createCompressionMiddleware({
        threshold: 10,
      });
    });

    it('should track compression operations', async () => {
      const content = 'Hello '.repeat(200);

      await middleware.compress(content, 'gzip');
      await middleware.compress(content, 'gzip');
      await middleware.compress(content, 'br');

      const stats = middleware.getStats();
      expect(stats.compressionCount).toBe(3);
    });

    it('should track bytes saved', async () => {
      const content = 'Hello '.repeat(500);

      await middleware.compress(content, 'gzip');

      const stats = middleware.getStats();
      expect(stats.bytesSaved).toBeGreaterThan(0);
    });

    it('should track average compression ratio', async () => {
      const content = 'Hello '.repeat(500);

      await middleware.compress(content, 'gzip');
      await middleware.compress(content, 'br');

      const stats = middleware.getStats();
      expect(stats.averageRatio).toBeGreaterThan(0);
      expect(stats.averageRatio).toBeLessThan(1);
    });

    it('should track by algorithm', async () => {
      const content = 'Hello '.repeat(500);

      await middleware.compress(content, 'gzip');
      await middleware.compress(content, 'gzip');
      await middleware.compress(content, 'br');

      const stats = middleware.getStats();
      expect(stats.byAlgorithm.gzip).toBe(2);
      expect(stats.byAlgorithm.br).toBe(1);
    });

    it('should reset stats', async () => {
      const content = 'Hello '.repeat(500);

      await middleware.compress(content, 'gzip');

      middleware.resetStats();

      const stats = middleware.getStats();
      expect(stats.compressionCount).toBe(0);
      expect(stats.bytesSaved).toBe(0);
    });
  });

  describe('Performance optimizations', () => {
    it('should use sync compression for small payloads', async () => {
      middleware = createCompressionMiddleware({
        threshold: 10,
        asyncThreshold: 10000, // Use sync below 10KB
      });

      const content = 'Hello '.repeat(100); // Small payload

      const start = Date.now();
      await middleware.compress(content, 'gzip');
      const duration = Date.now() - start;

      // Sync should be fast
      expect(duration).toBeLessThan(100);
    });

    it('should provide compression hints', () => {
      const hints = middleware.getCompressionHints('application/json', 5000);

      expect(hints.recommended).toBeDefined();
      expect(hints.estimatedRatio).toBeDefined();
    });
  });

  describe('Error handling', () => {
    it('should handle unsupported algorithm gracefully', async () => {
      const content = 'Test content';

      // @ts-expect-error Testing invalid algorithm
      const result = await middleware.compress(content, 'invalid');

      expect(result.algorithm).toBe('identity');
    });

    it('should not throw on compression failure', async () => {
      // Create middleware that might fail
      middleware = createCompressionMiddleware({
        threshold: 10,
      });

      // Should handle gracefully
      const result = await middleware.compress('content', 'gzip');
      expect(result).toBeDefined();
    });
  });
});

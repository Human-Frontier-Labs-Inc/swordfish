/**
 * Response Compression Module
 *
 * Gzip/Brotli compression middleware for API responses with
 * content-type filtering, streaming support, and statistics.
 */

import { gzipSync, gunzipSync, deflateSync, inflateSync } from 'zlib';
import {
  brotliCompressSync,
  brotliDecompressSync,
  constants as zlibConstants,
} from 'zlib';
import { Transform, TransformCallback } from 'stream';
import { createGzip, createGunzip, createDeflate, createInflate, createBrotliCompress, createBrotliDecompress } from 'zlib';

/**
 * Compression algorithms
 */
export const CompressionAlgorithm = {
  GZIP: 'gzip',
  BROTLI: 'br',
  DEFLATE: 'deflate',
  IDENTITY: 'identity',
} as const;

export type CompressionAlgorithmType = (typeof CompressionAlgorithm)[keyof typeof CompressionAlgorithm];

/**
 * Compression configuration
 */
export interface CompressionConfig {
  threshold: number;
  defaultAlgorithm: CompressionAlgorithmType;
  level: number;
  preferBrotli: boolean;
  minRatio: number;
  asyncThreshold: number;
  shouldCompress?: (contentType: string) => boolean;
}

/**
 * Compressed response
 */
export interface CompressedResponse {
  compressed: Buffer;
  algorithm: CompressionAlgorithmType;
  originalSize: number;
  compressedSize: number;
  ratio: number;
}

/**
 * Compression statistics
 */
interface CompressionStats {
  compressionCount: number;
  bytesSaved: number;
  averageRatio: number;
  byAlgorithm: Record<string, number>;
}

/**
 * Compression hints
 */
interface CompressionHints {
  recommended: CompressionAlgorithmType;
  estimatedRatio: number;
}

/**
 * Compress options
 */
interface CompressOptions {
  skipIfCompressed?: boolean;
}

/**
 * Default compressible content types
 */
const COMPRESSIBLE_TYPES = [
  'application/json',
  'application/javascript',
  'application/xml',
  'application/xhtml+xml',
  'text/html',
  'text/plain',
  'text/css',
  'text/javascript',
  'text/xml',
  'image/svg+xml',
];

/**
 * Content types that are already compressed
 */
const ALREADY_COMPRESSED = [
  'application/zip',
  'application/gzip',
  'application/x-gzip',
  'application/x-compress',
  'application/x-bzip2',
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'video/',
  'audio/',
];

/**
 * Check if content looks like it's already compressed
 */
function looksCompressed(data: Buffer): boolean {
  if (data.length < 2) return false;

  // Check for gzip magic bytes
  if (data[0] === 0x1f && data[1] === 0x8b) return true;

  // Check for brotli (harder to detect, but common patterns)
  // Brotli streams typically don't have easily identifiable magic bytes

  return false;
}

/**
 * Compression Middleware class
 */
export class CompressionMiddleware {
  private config: CompressionConfig;
  private stats: CompressionStats = {
    compressionCount: 0,
    bytesSaved: 0,
    averageRatio: 0,
    byAlgorithm: {},
  };
  private totalRatios: number = 0;

  constructor(config: Partial<CompressionConfig> = {}) {
    // Validate config
    const threshold = config.threshold ?? 1024;
    const level = config.level ?? 6;

    if (threshold < 0) {
      throw new Error('threshold must be positive');
    }

    if (level < 1 || level > 9) {
      throw new Error('level must be between 1 and 9');
    }

    this.config = {
      threshold,
      defaultAlgorithm: config.defaultAlgorithm ?? 'gzip',
      level,
      preferBrotli: config.preferBrotli ?? false,
      minRatio: config.minRatio ?? 0.9,
      asyncThreshold: config.asyncThreshold ?? 65536,
      shouldCompress: config.shouldCompress,
    };
  }

  /**
   * Get current config
   */
  getConfig(): CompressionConfig {
    return { ...this.config };
  }

  /**
   * Detect best compression algorithm from Accept-Encoding header
   */
  detectAlgorithm(acceptEncoding: string): CompressionAlgorithmType {
    if (!acceptEncoding) {
      return 'identity';
    }

    // Parse Accept-Encoding with quality values
    const encodings = acceptEncoding.split(',').map((e) => {
      const parts = e.trim().split(';');
      const encoding = parts[0].trim().toLowerCase();
      let quality = 1;

      if (parts[1]) {
        const qMatch = parts[1].match(/q=(\d+\.?\d*)/);
        if (qMatch) {
          quality = parseFloat(qMatch[1]);
        }
      }

      return { encoding, quality };
    });

    // Sort by quality (highest first)
    encodings.sort((a, b) => b.quality - a.quality);

    // Check for wildcard
    if (encodings.some((e) => e.encoding === '*')) {
      return this.config.preferBrotli ? 'br' : 'gzip';
    }

    // If preferBrotli is set and br is supported, return br
    if (this.config.preferBrotli && encodings.some((e) => e.encoding === 'br')) {
      return 'br';
    }

    // Find best supported encoding by quality
    for (const { encoding } of encodings) {
      if (encoding === 'br') {
        return 'br';
      }
      if (encoding === 'gzip') {
        return 'gzip';
      }
      if (encoding === 'deflate') {
        return 'deflate';
      }
    }

    return 'identity';
  }

  /**
   * Check if content type should be compressed
   */
  shouldCompress(contentType: string): boolean {
    if (this.config.shouldCompress) {
      return this.config.shouldCompress(contentType);
    }

    const lowerType = contentType.toLowerCase();

    // Check if already compressed
    for (const type of ALREADY_COMPRESSED) {
      if (lowerType.startsWith(type)) {
        return false;
      }
    }

    // Check if compressible
    for (const type of COMPRESSIBLE_TYPES) {
      if (lowerType.startsWith(type)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Compress content
   */
  async compress(
    content: string | Buffer,
    algorithm: CompressionAlgorithmType,
    options: CompressOptions = {}
  ): Promise<CompressedResponse> {
    const inputBuffer = typeof content === 'string' ? Buffer.from(content) : content;
    const originalSize = inputBuffer.length;

    // Check threshold
    if (originalSize < this.config.threshold) {
      return {
        compressed: inputBuffer,
        algorithm: 'identity',
        originalSize,
        compressedSize: originalSize,
        ratio: 1,
      };
    }

    // Check if already compressed
    if (options.skipIfCompressed && looksCompressed(inputBuffer)) {
      return {
        compressed: inputBuffer,
        algorithm: 'identity',
        originalSize,
        compressedSize: originalSize,
        ratio: 1,
      };
    }

    try {
      let compressed: Buffer;

      switch (algorithm) {
        case 'gzip':
          compressed = gzipSync(inputBuffer, { level: this.config.level });
          break;
        case 'br':
          compressed = brotliCompressSync(inputBuffer, {
            params: {
              [zlibConstants.BROTLI_PARAM_QUALITY]: this.config.level,
            },
          });
          break;
        case 'deflate':
          compressed = deflateSync(inputBuffer, { level: this.config.level });
          break;
        default:
          return {
            compressed: inputBuffer,
            algorithm: 'identity',
            originalSize,
            compressedSize: originalSize,
            ratio: 1,
          };
      }

      const compressedSize = compressed.length;
      const ratio = compressedSize / originalSize;

      // Check if compression was effective
      if (ratio >= this.config.minRatio) {
        return {
          compressed: inputBuffer,
          algorithm: 'identity',
          originalSize,
          compressedSize: originalSize,
          ratio: 1,
        };
      }

      // Update stats
      this.stats.compressionCount++;
      this.stats.bytesSaved += originalSize - compressedSize;
      this.totalRatios += ratio;
      this.stats.averageRatio = this.totalRatios / this.stats.compressionCount;
      this.stats.byAlgorithm[algorithm] = (this.stats.byAlgorithm[algorithm] || 0) + 1;

      return {
        compressed,
        algorithm,
        originalSize,
        compressedSize,
        ratio,
      };
    } catch {
      return {
        compressed: inputBuffer,
        algorithm: 'identity',
        originalSize,
        compressedSize: originalSize,
        ratio: 1,
      };
    }
  }

  /**
   * Compress JSON content
   */
  async compressJSON(
    content: object,
    algorithm: CompressionAlgorithmType
  ): Promise<CompressedResponse> {
    const json = JSON.stringify(content);
    return this.compress(json, algorithm);
  }

  /**
   * Decompress content
   */
  async decompress(
    content: Buffer,
    algorithm: CompressionAlgorithmType
  ): Promise<Buffer> {
    switch (algorithm) {
      case 'gzip':
        return gunzipSync(content);
      case 'br':
        return brotliDecompressSync(content);
      case 'deflate':
        return inflateSync(content);
      case 'identity':
        return content;
      default:
        return content;
    }
  }

  /**
   * Create a compression transform stream
   */
  createCompressStream(algorithm: CompressionAlgorithmType): Transform {
    switch (algorithm) {
      case 'gzip':
        return createGzip({ level: this.config.level });
      case 'br':
        return createBrotliCompress({
          params: {
            [zlibConstants.BROTLI_PARAM_QUALITY]: this.config.level,
          },
        });
      case 'deflate':
        return createDeflate({ level: this.config.level });
      default:
        // Pass-through transform
        return new Transform({
          transform(chunk: Buffer, _encoding: string, callback: TransformCallback) {
            callback(null, chunk);
          },
        });
    }
  }

  /**
   * Create a decompression transform stream
   */
  createDecompressStream(algorithm: CompressionAlgorithmType): Transform {
    switch (algorithm) {
      case 'gzip':
        return createGunzip();
      case 'br':
        return createBrotliDecompress();
      case 'deflate':
        return createInflate();
      default:
        // Pass-through transform
        return new Transform({
          transform(chunk: Buffer, _encoding: string, callback: TransformCallback) {
            callback(null, chunk);
          },
        });
    }
  }

  /**
   * Get compression hints for content
   */
  getCompressionHints(contentType: string, size: number): CompressionHints {
    let recommended: CompressionAlgorithmType = 'identity';
    let estimatedRatio = 1;

    if (this.shouldCompress(contentType) && size >= this.config.threshold) {
      // Text-based content typically compresses well
      if (contentType.includes('json') || contentType.includes('text')) {
        estimatedRatio = 0.3; // ~70% reduction
        recommended = this.config.preferBrotli ? 'br' : 'gzip';
      } else if (contentType.includes('html') || contentType.includes('xml')) {
        estimatedRatio = 0.25; // ~75% reduction
        recommended = this.config.preferBrotli ? 'br' : 'gzip';
      } else {
        estimatedRatio = 0.5;
        recommended = 'gzip';
      }
    }

    return { recommended, estimatedRatio };
  }

  /**
   * Get compression statistics
   */
  getStats(): CompressionStats {
    return { ...this.stats };
  }

  /**
   * Reset statistics
   */
  resetStats(): void {
    this.stats = {
      compressionCount: 0,
      bytesSaved: 0,
      averageRatio: 0,
      byAlgorithm: {},
    };
    this.totalRatios = 0;
  }
}

/**
 * Create compression middleware instance
 */
export function createCompressionMiddleware(
  config?: Partial<CompressionConfig>
): CompressionMiddleware {
  return new CompressionMiddleware(config);
}

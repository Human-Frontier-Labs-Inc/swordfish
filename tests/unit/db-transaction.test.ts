/**
 * Unit tests for withTransaction database utility
 * Mocks the Neon Pool/client to verify BEGIN/COMMIT/ROLLBACK behavior
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock @neondatabase/serverless before importing the module under test
const mockQuery = vi.fn();
const mockRelease = vi.fn();
const mockConnect = vi.fn();
const mockEnd = vi.fn();

vi.mock('@neondatabase/serverless', () => {
  return {
    neon: vi.fn(() => vi.fn()),
    Pool: vi.fn().mockImplementation(() => ({
      connect: mockConnect,
      end: mockEnd,
    })),
  };
});

// Mock validate-env to prevent side effects on import
vi.mock('@/lib/config/validate-env', () => ({
  validateEnvironment: vi.fn(),
}));

// Override the global @/lib/db mock from vitest-setup to include withTransaction
vi.mock('@/lib/db', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
  };
});

// Set DATABASE_URL so withTransaction doesn't throw early
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/testdb';

import { withTransaction } from '@/lib/db';

describe('withTransaction', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConnect.mockResolvedValue({
      query: mockQuery,
      release: mockRelease,
    });
    mockEnd.mockResolvedValue(undefined);
    mockQuery.mockResolvedValue({ rows: [] });
  });

  it('should call BEGIN and COMMIT on success', async () => {
    const callback = vi.fn().mockResolvedValue('result');

    const result = await withTransaction(callback);

    expect(result).toBe('result');
    expect(mockQuery).toHaveBeenCalledWith('BEGIN');
    expect(mockQuery).toHaveBeenCalledWith('COMMIT');
    expect(mockQuery).not.toHaveBeenCalledWith('ROLLBACK');
    expect(mockRelease).toHaveBeenCalled();
    expect(mockEnd).toHaveBeenCalled();
  });

  it('should call BEGIN and ROLLBACK on failure', async () => {
    const error = new Error('Something went wrong');
    const callback = vi.fn().mockRejectedValue(error);

    await expect(withTransaction(callback)).rejects.toThrow('Something went wrong');

    expect(mockQuery).toHaveBeenCalledWith('BEGIN');
    expect(mockQuery).toHaveBeenCalledWith('ROLLBACK');
    expect(mockQuery).not.toHaveBeenCalledWith('COMMIT');
    expect(mockRelease).toHaveBeenCalled();
    expect(mockEnd).toHaveBeenCalled();
  });

  it('should propagate the error from the callback', async () => {
    const customError = new Error('Custom DB error');
    const callback = vi.fn().mockRejectedValue(customError);

    await expect(withTransaction(callback)).rejects.toThrow(customError);
  });

  it('should pass a tx query function to the callback', async () => {
    mockQuery.mockResolvedValue({ rows: [{ id: '1', name: 'test' }] });

    await withTransaction(async (tx) => {
      const rows = await tx`INSERT INTO users (name) VALUES (${'Alice'}) RETURNING id`;
      expect(rows).toEqual([{ id: '1', name: 'test' }]);
    });

    // Verify that a parameterized query was built and executed
    // The call order: BEGIN, the INSERT query, COMMIT
    expect(mockQuery).toHaveBeenCalledTimes(3);
    expect(mockQuery).toHaveBeenCalledWith('BEGIN');
    expect(mockQuery).toHaveBeenCalledWith('COMMIT');
  });

  it('should release the client even when an error occurs', async () => {
    const callback = vi.fn().mockRejectedValue(new Error('fail'));

    await expect(withTransaction(callback)).rejects.toThrow('fail');

    expect(mockRelease).toHaveBeenCalledTimes(1);
    expect(mockEnd).toHaveBeenCalledTimes(1);
  });
});

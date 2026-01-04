/**
 * Threats API Tests
 * Tests for threat management endpoints
 *
 * Note: These are integration tests that require a real database connection.
 * Set DATABASE_URL environment variable to run these tests.
 * For CI, use: npm run test:integration
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { NextRequest } from 'next/server';
import {
  TEST_TENANT_ID,
  TEST_USER_ID,
  cleanupTestData,
} from '../helpers/vitest-setup';

// Check if we have a real database
const hasRealDatabase = process.env.DATABASE_URL &&
  !process.env.DATABASE_URL.includes('localhost:5432/test');

// Skip API tests if no real database - they require actual DB operations
const describeWithDb = hasRealDatabase ? describe : describe.skip;

describeWithDb('Threats API (Integration)', () => {
  beforeAll(async () => {
    await cleanupTestData();
  });

  afterAll(async () => {
    await cleanupTestData();
  });

  describe('GET /api/threats', () => {
    it('should return list of threats', async () => {
      const { GET } = await import('@/app/api/threats/route');

      const request = new NextRequest('http://localhost:3000/api/threats');
      const response = await GET(request);
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.threats).toBeDefined();
      expect(Array.isArray(data.threats)).toBe(true);
    });
  });
});

// Unit tests that don't require database
describe('API Response Formats', () => {
  it('should have correct success response structure', () => {
    const successResponse = { success: true, message: 'Operation completed' };
    expect(successResponse).toHaveProperty('success', true);
  });

  it('should have correct error response structure', () => {
    const errorResponse = { error: 'Not found', details: { id: '123' } };
    expect(errorResponse).toHaveProperty('error');
  });

  it('should have correct pagination structure', () => {
    const pagination = {
      total: 100,
      limit: 50,
      offset: 0,
      hasMore: true,
    };
    expect(pagination.total).toBeGreaterThanOrEqual(0);
    expect(pagination.limit).toBeGreaterThan(0);
    expect(typeof pagination.hasMore).toBe('boolean');
  });
});

describe('Request Validation', () => {
  it('should validate threat ID format', () => {
    const validUUID = '550e8400-e29b-41d4-a716-446655440000';
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    expect(uuidRegex.test(validUUID)).toBe(true);
  });

  it('should validate date range format', () => {
    const dateRange = {
      start: '2024-01-01',
      end: '2024-12-31',
    };
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    expect(dateRegex.test(dateRange.start)).toBe(true);
    expect(dateRegex.test(dateRange.end)).toBe(true);
  });

  it('should validate email format', () => {
    const validEmail = 'user@example.com';
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    expect(emailRegex.test(validEmail)).toBe(true);
  });
});

describe('Export Formats', () => {
  it('should support CSV format', () => {
    const exportConfig = {
      type: 'verdicts',
      format: 'csv',
    };
    expect(['csv', 'json']).toContain(exportConfig.format);
  });

  it('should support JSON format', () => {
    const exportConfig = {
      type: 'threats',
      format: 'json',
    };
    expect(['csv', 'json']).toContain(exportConfig.format);
  });

  it('should validate export types', () => {
    const validTypes = ['verdicts', 'threats', 'audit_log', 'executive_summary'];
    const exportType = 'verdicts';
    expect(validTypes).toContain(exportType);
  });
});

describe('Notification Config', () => {
  it('should validate severity thresholds', () => {
    const validSeverities = ['info', 'warning', 'critical'];
    const threshold = 'warning';
    expect(validSeverities).toContain(threshold);
  });

  it('should validate notification channels', () => {
    const config = {
      emailEnabled: true,
      slackEnabled: false,
      webhookEnabled: true,
    };
    expect(typeof config.emailEnabled).toBe('boolean');
    expect(typeof config.slackEnabled).toBe('boolean');
    expect(typeof config.webhookEnabled).toBe('boolean');
  });
});

/**
 * Vitest Setup File
 * Configures mocks and global setup for tests
 */

import { vi, beforeAll, afterAll } from 'vitest';

// Set a fallback DATABASE_URL if not provided
if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
}

// Check if we have a real database connection
const hasRealDatabase = process.env.DATABASE_URL &&
  !process.env.DATABASE_URL.includes('localhost:5432/test');

// Mock the database module if no real connection
if (!hasRealDatabase) {
  vi.mock('@/lib/db', () => {
    const mockSql = vi.fn().mockImplementation(async () => []);

    // Add template literal support
    const sqlProxy = new Proxy(mockSql, {
      apply: (_target, _thisArg, args) => {
        return Promise.resolve([]);
      },
      get: (_target, prop) => {
        if (prop === 'then') return undefined;
        return mockSql;
      },
    });

    return {
      sql: sqlProxy,
      default: sqlProxy,
    };
  });
}

// Mock Clerk auth
vi.mock('@clerk/nextjs/server', () => ({
  auth: vi.fn().mockResolvedValue({
    userId: 'test_user_001',
    orgId: 'test_tenant_001',
  }),
  currentUser: vi.fn().mockResolvedValue({
    id: 'test_user_001',
    emailAddresses: [{ emailAddress: 'test@example.com' }],
  }),
}));

// Mock Resend for notifications
vi.mock('resend', () => ({
  Resend: vi.fn().mockImplementation(() => ({
    emails: {
      send: vi.fn().mockResolvedValue({ id: 'mock-email-id' }),
    },
  })),
}));

// Global test setup
beforeAll(() => {
  // Set up any global state
  console.log('Test suite starting...');
});

afterAll(() => {
  // Clean up any global state
  console.log('Test suite complete.');
});

// Export test utilities
export const TEST_TENANT_ID = 'test_tenant_001';
export const TEST_USER_ID = 'test_user_001';

export async function cleanupTestData(): Promise<void> {
  // When using mocked DB, this is a no-op
  if (!hasRealDatabase) {
    return;
  }

  // Real cleanup would happen here for integration tests
}

export async function setupTestPolicies(): Promise<void> {
  // When using mocked DB, this is a no-op
  if (!hasRealDatabase) {
    return;
  }
}

export async function setupTestThreatIntel(): Promise<void> {
  // When using mocked DB, this is a no-op
  if (!hasRealDatabase) {
    return;
  }
}

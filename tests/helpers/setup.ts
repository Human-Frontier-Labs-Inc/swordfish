/**
 * Test Setup and Helpers
 * Common utilities for testing
 */

import { sql } from '@/lib/db';

// Test tenant ID
export const TEST_TENANT_ID = 'test_tenant_001';
export const TEST_USER_ID = 'test_user_001';

/**
 * Clean up test data before/after tests
 */
export async function cleanupTestData(): Promise<void> {
  try {
    // Clean up in order to respect foreign key constraints
    await sql`DELETE FROM ml_predictions WHERE tenant_id = ${TEST_TENANT_ID}`;
    await sql`DELETE FROM feedback WHERE tenant_id = ${TEST_TENANT_ID}`;
    await sql`DELETE FROM notifications WHERE tenant_id = ${TEST_TENANT_ID}`;
    await sql`DELETE FROM notification_configs WHERE tenant_id = ${TEST_TENANT_ID}`;
    await sql`DELETE FROM scheduled_reports WHERE tenant_id = ${TEST_TENANT_ID}`;
    await sql`DELETE FROM threat_intelligence WHERE tenant_id = ${TEST_TENANT_ID}`;
    await sql`DELETE FROM allowlist WHERE tenant_id = ${TEST_TENANT_ID}`;
    await sql`DELETE FROM blocklist WHERE tenant_id = ${TEST_TENANT_ID}`;
    await sql`DELETE FROM policy_rules WHERE tenant_id = ${TEST_TENANT_ID}`;
    await sql`DELETE FROM verdicts WHERE tenant_id = ${TEST_TENANT_ID}`;
    await sql`DELETE FROM audit_log WHERE tenant_id = ${TEST_TENANT_ID}`;
  } catch (error) {
    // Ignore errors if tables don't exist
    console.warn('Cleanup warning:', error);
  }
}

/**
 * Setup test policies
 */
export async function setupTestPolicies(): Promise<void> {
  // Add test allowlist entry
  await sql`
    INSERT INTO allowlist (tenant_id, pattern, pattern_type, name, created_by, created_at)
    VALUES (${TEST_TENANT_ID}, 'google.com', 'domain', 'Google', ${TEST_USER_ID}, NOW())
    ON CONFLICT DO NOTHING
  `;

  // Add test blocklist entry
  await sql`
    INSERT INTO blocklist (tenant_id, pattern, pattern_type, name, created_by, created_at)
    VALUES (${TEST_TENANT_ID}, 'malicious.tk', 'domain', 'Test Block', ${TEST_USER_ID}, NOW())
    ON CONFLICT DO NOTHING
  `;
}

/**
 * Setup test threat intelligence
 */
export async function setupTestThreatIntel(): Promise<void> {
  await sql`
    INSERT INTO threat_intelligence (tenant_id, entity, entity_type, verdict, source, details, created_at)
    VALUES
      (${TEST_TENANT_ID}, 'known-bad.com', 'domain', 'malicious', 'test', 'Test malicious domain', NOW()),
      (${TEST_TENANT_ID}, 'suspicious-sender@phishing.net', 'email', 'malicious', 'test', 'Test malicious sender', NOW())
    ON CONFLICT DO NOTHING
  `;
}

/**
 * Create a mock request object
 */
export function createMockRequest(
  method: string,
  body?: Record<string, unknown>,
  headers?: Record<string, string>
): Request {
  const init: RequestInit = {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  };

  if (body && method !== 'GET') {
    init.body = JSON.stringify(body);
  }

  return new Request('http://localhost:3000/api/test', init);
}

/**
 * Wait for a condition to be true
 */
export async function waitFor(
  condition: () => boolean | Promise<boolean>,
  timeout = 5000,
  interval = 100
): Promise<void> {
  const start = Date.now();

  while (Date.now() - start < timeout) {
    if (await condition()) {
      return;
    }
    await new Promise(resolve => setTimeout(resolve, interval));
  }

  throw new Error('Timeout waiting for condition');
}

/**
 * Assert that a value matches expected structure
 */
export function assertShape<T>(
  value: unknown,
  shape: Record<string, 'string' | 'number' | 'boolean' | 'object' | 'array'>
): asserts value is T {
  if (typeof value !== 'object' || value === null) {
    throw new Error('Expected an object');
  }

  for (const [key, expectedType] of Object.entries(shape)) {
    const actual = (value as Record<string, unknown>)[key];

    if (expectedType === 'array') {
      if (!Array.isArray(actual)) {
        throw new Error(`Expected ${key} to be an array`);
      }
    } else if (typeof actual !== expectedType) {
      throw new Error(`Expected ${key} to be ${expectedType}, got ${typeof actual}`);
    }
  }
}

/**
 * Generate a random string for unique IDs
 */
export function randomId(prefix = 'test'): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).substring(7)}`;
}

/**
 * Mock console.error to suppress expected errors during tests
 */
export function suppressErrors(): () => void {
  const originalError = console.error;
  console.error = () => {};
  return () => {
    console.error = originalError;
  };
}

/**
 * Assert response is JSON and has expected status
 */
export async function assertJsonResponse(
  response: Response,
  expectedStatus: number
): Promise<Record<string, unknown>> {
  if (response.status !== expectedStatus) {
    const text = await response.text();
    throw new Error(
      `Expected status ${expectedStatus}, got ${response.status}: ${text}`
    );
  }

  const data = await response.json();
  return data as Record<string, unknown>;
}

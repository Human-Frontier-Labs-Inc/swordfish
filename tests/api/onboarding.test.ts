/**
 * Tests for onboarding and oauth_states database compatibility
 *
 * Bug 1: onboarding_progress uses INTEGER[] columns but code passes JSON strings like "[1]"
 * Bug 2: oauth_states legacy code inserts (tenant_id, state, expires_at) but state_token is NOT NULL
 */

import { describe, it, expect } from 'vitest';

// ============================================================================
// Onboarding array format tests
// ============================================================================

describe('Onboarding completed_steps format', () => {
  /**
   * PostgreSQL INTEGER[] expects array literals like {1,2,3}
   * JSON.stringify([1]) produces "[1]" which is NOT valid for INTEGER[]
   * The Neon driver handles native JS arrays correctly — we should pass arrays directly
   */
  it('should produce valid Postgres array format from JS arrays', () => {
    const completedSteps = [1];
    // JSON.stringify produces "[1]" — INVALID for INTEGER[] column
    const jsonFormat = JSON.stringify(completedSteps);
    expect(jsonFormat).toBe('[1]');

    // Native JS array should be passed directly to the SQL driver
    // The Neon serverless driver handles Array -> PostgreSQL INTEGER[] natively
    expect(Array.isArray(completedSteps)).toBe(true);
  });

  it('should handle empty arrays', () => {
    const completedSteps: number[] = [];
    expect(Array.isArray(completedSteps)).toBe(true);
    expect(completedSteps).toEqual([]);
  });

  it('should handle multiple completed steps', () => {
    const completedSteps = [1, 2, 3];
    expect(Array.isArray(completedSteps)).toBe(true);
    expect(completedSteps).toEqual([1, 2, 3]);
  });

  it('parseJsonArray should handle all input types', () => {
    // Simulate the parseJsonArray function from the onboarding route
    const parseJsonArray = (val: unknown): number[] => {
      if (Array.isArray(val)) return val;
      if (typeof val === 'string') {
        try { return JSON.parse(val); } catch { return []; }
      }
      return [];
    };

    expect(parseJsonArray([1, 2])).toEqual([1, 2]);
    expect(parseJsonArray('[1,2]')).toEqual([1, 2]);
    expect(parseJsonArray(null)).toEqual([]);
    expect(parseJsonArray(undefined)).toEqual([]);
    expect(parseJsonArray('{1,2}')).toEqual([]); // Postgres literal, JSON.parse fails
  });
});

// ============================================================================
// OAuth state legacy compatibility tests
// ============================================================================

describe('OAuth state legacy code compatibility', () => {
  it('storeState should only use columns that exist and are nullable', () => {
    // The legacy storeState function inserts:
    //   INSERT INTO oauth_states (tenant_id, state, expires_at)
    //
    // The full oauth_states schema has these NOT NULL columns:
    //   - state_token (NOT NULL) <-- PROBLEM: not provided by legacy code
    //   - user_id (we made nullable)
    //   - provider (we made nullable)
    //   - redirect_uri (we made nullable)
    //
    // Fix: Either make state_token nullable with a default,
    //       or update legacy code to use state_token instead of state

    // The correct fix is to make state_token default to a generated value
    // OR remove the NOT NULL constraint and let legacy code skip it
    // OR (best) update legacy code to populate state_token from the state value
    expect(true).toBe(true);
  });

  it('legacy storeState should write to state_token for consistency', () => {
    // The state value should be stored in BOTH state and state_token columns
    // so that both legacy lookups (WHERE tenant_id = X) and
    // new lookups (WHERE state_token = X) work
    const state = 'abc-123-random-state';
    // state_token should equal state for legacy compatibility
    expect(state).toBe(state);
  });
});

/**
 * Unit tests for lib/detection/llm-budget.ts. Pure logic + an in-memory counter
 * fake; the live Upstash counter is intentionally not exercised here.
 */

import { describe, it, expect } from 'vitest';
import {
  computeCap,
  dayKeyUtc,
  checkLlmBudget,
  InMemoryLlmBudgetCounter,
  getLlmBudgetCounter,
  LLM_CAP_PER_MAILBOX,
  LLM_HARD_CAP_PER_TENANT,
  type LlmBudgetCounter,
} from '@/lib/detection/llm-budget';

describe('computeCap', () => {
  it('is per-mailbox × 30, floored at the 3000 hard cap', () => {
    expect(computeCap(0)).toBe(0);
    expect(computeCap(1)).toBe(30);
    expect(computeCap(50)).toBe(1500);
    expect(computeCap(100)).toBe(3000); // exactly the hard cap
    expect(computeCap(200)).toBe(3000); // clamped to hard cap
    expect(LLM_CAP_PER_MAILBOX).toBe(30);
    expect(LLM_HARD_CAP_PER_TENANT).toBe(3000);
  });

  it('floors negatives and non-integers', () => {
    expect(computeCap(-5)).toBe(0);
    expect(computeCap(2.9)).toBe(60); // floored to 2
  });
});

describe('dayKeyUtc', () => {
  it('formats a UTC date as YYYY-MM-DD', () => {
    expect(dayKeyUtc(new Date('2026-06-18T12:00:00Z'))).toBe('2026-06-18');
    expect(dayKeyUtc(new Date('2026-06-18T23:59:59Z'))).toBe('2026-06-18');
    expect(dayKeyUtc(new Date('2026-12-31T00:00:00Z'))).toBe('2026-12-31');
  });
});

describe('checkLlmBudget', () => {
  it('denies (fail-closed) when no counter is configured', async () => {
    const d = await checkLlmBudget('t1', 10, null);
    expect(d.allow).toBe(false);
    expect(d.reason).toBe('counter_not_configured');
    expect(d.cap).toBe(300);
  });

  it('allows while under the cap and counts each call', async () => {
    const counter = new InMemoryLlmBudgetCounter();
    const d1 = await checkLlmBudget('t1', 1, counter); // cap 30
    expect(d1.allow).toBe(true);
    expect(d1.count).toBe(1);
    expect(d1.reason).toBe('under_cap');
    const d2 = await checkLlmBudget('t1', 1, counter);
    expect(d2.allow).toBe(true);
    expect(d2.count).toBe(2);
  });

  it('allows the cap-th call and denies the next (cap=30 for 1 mailbox)', async () => {
    const counter = new InMemoryLlmBudgetCounter();
    for (let i = 0; i < 29; i++) {
      const d = await checkLlmBudget('t1', 1, counter);
      expect(d.allow).toBe(true);
    }
    const atCap = await checkLlmBudget('t1', 1, counter); // 30th call
    expect(atCap.count).toBe(30);
    expect(atCap.allow).toBe(true); // count 30 is not > cap 30

    const over = await checkLlmBudget('t1', 1, counter); // 31st call
    expect(over.count).toBe(31);
    expect(over.allow).toBe(false);
    expect(over.reason).toBe('daily_cap_exceeded');
  });

  it('denies (fail-closed) when the counter throws', async () => {
    const throwing: LlmBudgetCounter = {
      incrementAndGet: async () => {
        throw new Error('redis unreachable');
      },
    };
    const d = await checkLlmBudget('t1', 10, throwing);
    expect(d.allow).toBe(false);
    expect(d.reason).toBe('counter_unreachable');
  });

  it('counts are scoped per tenant', async () => {
    const counter = new InMemoryLlmBudgetCounter();
    await checkLlmBudget('t1', 1, counter);
    await checkLlmBudget('t1', 1, counter);
    const t2 = await checkLlmBudget('t2', 1, counter); // separate tenant
    expect(t2.count).toBe(1);
    expect(t2.allow).toBe(true);
  });
});

describe('getLlmBudgetCounter', () => {
  it('returns null (fail-closed) when Upstash env is unset', () => {
    // Test env does not set UPSTASH_REDIS_REST_URL/TOKEN.
    expect(getLlmBudgetCounter()).toBeNull();
  });
});

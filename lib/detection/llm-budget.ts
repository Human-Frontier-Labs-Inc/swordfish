/**
 * Per-tenant daily LLM budget.
 *
 * Caps LLM cost at the tenant level:
 *   tenant_daily_llm_cap = min(LLM_HARD_CAP_PER_TENANT, LLM_CAP_PER_MAILBOX × mailboxCount)
 * Counted per-tenant-per-day in Redis (Upstash REST). FAIL-CLOSED: when Redis is
 * unset or unreachable, the LLM call is DENIED — the 8 deterministic layers
 * still run, so detection degrades gracefully. Open self-serve means an
 * unbounded-LLM-cost blowout is the worse failure mode, so we deny loudly
 * rather than allow blindly.
 *
 * The pure logic (computeCap, dayKeyUtc, checkLlmBudget against the
 * LlmBudgetCounter interface) is unit-tested with an in-memory fake counter.
 * The Upstash counter is the LIVE impl — a documented Corn smoke-test with
 * real creds (UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN); it is not
 * exercised by the unit suite by design (no live Redis in CI/tests).
 */

import { Redis } from '@upstash/redis';

export const LLM_CAP_PER_MAILBOX = 30;
export const LLM_HARD_CAP_PER_TENANT = 3000;

/** Per-tenant-per-day LLM call counter. */
export interface LlmBudgetCounter {
  /** Atomically increment the count for (tenant, day) and return the NEW count. */
  incrementAndGet(tenantId: string, dayKey: string): Promise<number>;
}

export type BudgetReason =
  | 'under_cap'
  | 'daily_cap_exceeded'
  | 'counter_not_configured'
  | 'counter_unreachable'
  | 'not_requested';

export interface BudgetDecision {
  allow: boolean;
  cap: number;
  count: number;
  reason: BudgetReason;
}

/** Daily cap = min(hard cap, per-mailbox cap × mailbox count). */
export function computeCap(mailboxCount: number): number {
  const n = Math.max(0, Math.floor(mailboxCount));
  return Math.min(LLM_HARD_CAP_PER_TENANT, LLM_CAP_PER_MAILBOX * n);
}

/** UTC date key (YYYY-MM-DD) — the daily reset boundary. */
export function dayKeyUtc(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

/**
 * Check the LLM budget for one call. Atomically increments the counter (INCR
 * semantics: the returned count includes this call), then allows only while
 * under the cap. Fail-closed: a null or throwing counter denies the call.
 */
export async function checkLlmBudget(
  tenantId: string,
  mailboxCount: number,
  counter: LlmBudgetCounter | null
): Promise<BudgetDecision> {
  const cap = computeCap(mailboxCount);
  if (counter === null) {
    return { allow: false, cap, count: 0, reason: 'counter_not_configured' };
  }
  let count: number;
  try {
    count = await counter.incrementAndGet(tenantId, dayKeyUtc());
  } catch {
    return { allow: false, cap, count: 0, reason: 'counter_unreachable' };
  }
  if (count > cap) {
    return { allow: false, cap, count, reason: 'daily_cap_exceeded' };
  }
  return { allow: true, cap, count, reason: 'under_cap' };
}

/** In-memory counter — for tests and local dev only (NOT serverless-safe). */
export class InMemoryLlmBudgetCounter implements LlmBudgetCounter {
  private counts = new Map<string, number>();
  async incrementAndGet(tenantId: string, dayKey: string): Promise<number> {
    const key = `${tenantId}:${dayKey}`;
    const next = (this.counts.get(key) ?? 0) + 1;
    this.counts.set(key, next);
    return next;
  }
}

/**
 * Upstash REST counter. INCR is atomic; a ~25h expiry is set on first creation
 * so each per-day key resets and doesn't accumulate. Requires
 * UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN.
 */
export class UpstashLlmBudgetCounter implements LlmBudgetCounter {
  private redis: Redis;
  constructor() {
    const url = process.env.UPSTASH_REDIS_REST_URL;
    const token = process.env.UPSTASH_REDIS_REST_TOKEN;
    if (!url || !token) {
      throw new Error(
        'UpstashLlmBudgetCounter requires UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN'
      );
    }
    this.redis = new Redis({ url, token });
  }
  async incrementAndGet(tenantId: string, dayKey: string): Promise<number> {
    const key = `llm:budget:${tenantId}:${dayKey}`;
    const count = await this.redis.incr(key);
    if (count === 1) {
      // Expire shortly after the UTC day rolls over (25h) so keys self-clean.
      await this.redis.expire(key, 90000);
    }
    return count;
  }
}

let cachedCounter: LlmBudgetCounter | null | undefined;

/**
 * Returns the Upstash counter when the env vars are set, or null (=> the gate
 * fails closed) when they're not. Memoized.
 */
export function getLlmBudgetCounter(): LlmBudgetCounter | null {
  if (cachedCounter !== undefined) return cachedCounter;
  if (!process.env.UPSTASH_REDIS_REST_URL || !process.env.UPSTASH_REDIS_REST_TOKEN) {
    cachedCounter = null;
    return null;
  }
  try {
    cachedCounter = new UpstashLlmBudgetCounter();
  } catch {
    cachedCounter = null;
  }
  return cachedCounter;
}

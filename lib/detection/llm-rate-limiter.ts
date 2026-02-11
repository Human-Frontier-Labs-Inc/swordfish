/**
 * LLM Rate Limiter
 * Enforces per-tenant daily limits on Claude API calls to prevent unbounded costs
 */

import { sql, withTenant } from '@/lib/db';

export interface RateLimitConfig {
  dailyLimit: number;
  warningThreshold?: number; // Percentage at which to warn (e.g., 0.8 = 80%)
}

export interface RateLimitResult {
  allowed: boolean;
  currentCount: number;
  dailyLimit: number;
  remaining: number;
  resetAt: Date;
  warning?: string;
}

// Default limits by plan
const PLAN_LIMITS: Record<string, number> = {
  starter: 100,
  pro: 500,
  enterprise: 2000,
};

/**
 * Check if a tenant can make an LLM call, and increment counter if allowed
 */
export async function checkAndIncrementLLMUsage(
  tenantId: string,
  config?: RateLimitConfig
): Promise<RateLimitResult> {
  const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  const resetAt = new Date(today);
  resetAt.setDate(resetAt.getDate() + 1);

  try {
    // Get tenant's plan to determine limit
    const tenantInfo = await withTenant(tenantId, async () => {
      return sql`
        SELECT plan FROM tenants WHERE id = ${tenantId}::uuid
        UNION ALL
        SELECT plan FROM tenants WHERE clerk_org_id = ${tenantId}
        LIMIT 1
      `;
    });

    const plan = (tenantInfo[0]?.plan as string) || 'starter';
    const dailyLimit = config?.dailyLimit || PLAN_LIMITS[plan] || PLAN_LIMITS.starter;
    const warningThreshold = config?.warningThreshold || 0.8;

    // Get or create today's usage record
    const usageResult = await withTenant(tenantId, async () => {
      return sql`
        INSERT INTO usage_metrics (tenant_id, date, llm_calls)
        VALUES (${tenantId}::uuid, ${today}::date, 0)
        ON CONFLICT (tenant_id, date) DO NOTHING
        RETURNING llm_calls
      `;
    });

    // Get current count (might have been created by ON CONFLICT)
    const currentUsage = await withTenant(tenantId, async () => {
      return sql`
        SELECT llm_calls FROM usage_metrics
        WHERE date = ${today}::date
        LIMIT 1
      `;
    });

    const currentCount = Number(currentUsage[0]?.llm_calls) || 0;
    const remaining = Math.max(0, dailyLimit - currentCount);

    // Check if limit exceeded
    if (currentCount >= dailyLimit) {
      return {
        allowed: false,
        currentCount,
        dailyLimit,
        remaining: 0,
        resetAt,
        warning: `Daily LLM limit of ${dailyLimit} calls exceeded. Resets at midnight UTC.`,
      };
    }

    // Increment the counter
    await withTenant(tenantId, async () => {
      return sql`
        UPDATE usage_metrics
        SET llm_calls = llm_calls + 1, updated_at = NOW()
        WHERE date = ${today}::date
      `;
    });

    // Build result with optional warning
    const result: RateLimitResult = {
      allowed: true,
      currentCount: currentCount + 1,
      dailyLimit,
      remaining: remaining - 1,
      resetAt,
    };

    // Add warning if approaching limit
    if ((currentCount + 1) / dailyLimit >= warningThreshold) {
      result.warning = `Approaching daily LLM limit: ${currentCount + 1}/${dailyLimit} calls used (${Math.round(((currentCount + 1) / dailyLimit) * 100)}%)`;
    }

    return result;
  } catch (error) {
    console.error('[LLM Rate Limiter] Error checking usage:', error);
    
    // Fail open with warning - don't block detection due to rate limit errors
    // But log aggressively so we can fix the issue
    return {
      allowed: true,
      currentCount: 0,
      dailyLimit: config?.dailyLimit || 100,
      remaining: config?.dailyLimit || 100,
      resetAt,
      warning: 'Rate limit check failed - allowing request but logging error',
    };
  }
}

/**
 * Get current LLM usage for a tenant (for dashboard display)
 */
export async function getLLMUsage(tenantId: string): Promise<{
  today: number;
  dailyLimit: number;
  remaining: number;
  percentUsed: number;
}> {
  const today = new Date().toISOString().split('T')[0];

  try {
    // Get tenant's plan
    const tenantInfo = await withTenant(tenantId, async () => {
      return sql`
        SELECT plan FROM tenants WHERE id = ${tenantId}::uuid
        UNION ALL
        SELECT plan FROM tenants WHERE clerk_org_id = ${tenantId}
        LIMIT 1
      `;
    });

    const plan = (tenantInfo[0]?.plan as string) || 'starter';
    const dailyLimit = PLAN_LIMITS[plan] || PLAN_LIMITS.starter;

    // Get today's usage
    const usage = await withTenant(tenantId, async () => {
      return sql`
        SELECT llm_calls FROM usage_metrics
        WHERE date = ${today}::date
        LIMIT 1
      `;
    });

    const todayUsage = Number(usage[0]?.llm_calls) || 0;

    return {
      today: todayUsage,
      dailyLimit,
      remaining: Math.max(0, dailyLimit - todayUsage),
      percentUsed: Math.round((todayUsage / dailyLimit) * 100),
    };
  } catch (error) {
    console.error('[LLM Rate Limiter] Error getting usage:', error);
    return {
      today: 0,
      dailyLimit: 100,
      remaining: 100,
      percentUsed: 0,
    };
  }
}

/**
 * Record LLM token usage for cost tracking
 */
export async function recordLLMTokenUsage(
  tenantId: string,
  inputTokens: number,
  outputTokens: number
): Promise<void> {
  const today = new Date().toISOString().split('T')[0];

  try {
    await withTenant(tenantId, async () => {
      return sql`
        INSERT INTO usage_metrics (tenant_id, date, llm_tokens_input, llm_tokens_output)
        VALUES (${tenantId}::uuid, ${today}::date, ${inputTokens}, ${outputTokens})
        ON CONFLICT (tenant_id, date) DO UPDATE SET
          llm_tokens_input = usage_metrics.llm_tokens_input + ${inputTokens},
          llm_tokens_output = usage_metrics.llm_tokens_output + ${outputTokens},
          updated_at = NOW()
      `;
    });
  } catch (error) {
    console.error('[LLM Rate Limiter] Error recording token usage:', error);
    // Non-critical - don't throw
  }
}

/**
 * LLM Usage API
 * GET - Get current LLM usage for the tenant
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getLLMUsage } from '@/lib/detection/llm-rate-limiter';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const tenantId = orgId || `personal_${userId}`;
    const usage = await getLLMUsage(tenantId);

    return NextResponse.json({
      llmUsage: {
        today: usage.today,
        dailyLimit: usage.dailyLimit,
        remaining: usage.remaining,
        percentUsed: usage.percentUsed,
        resetAt: new Date(new Date().setHours(24, 0, 0, 0)).toISOString(),
      },
    });
  } catch (error) {
    console.error('LLM usage API error:', error);
    return NextResponse.json(
      { error: 'Failed to get LLM usage' },
      { status: 500 }
    );
  }
}

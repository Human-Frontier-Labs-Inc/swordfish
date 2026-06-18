/**
 * Email Analysis API Endpoint
 * POST /api/analyze
 *
 * Accepts email data and returns a security verdict
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { sql } from '@/lib/db';
import { rateLimit } from '@/lib/api/rate-limit';
import { parseEmail, parseGraphEmail, parseGmailEmail } from '@/lib/detection/parser';
import { analyzeEmail, quickCheck } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import { autoRemediate } from '@/lib/workers/remediation';
import { DEFAULT_DETECTION_CONFIG } from '@/lib/detection/types';
import type { ParsedEmail, EmailVerdict } from '@/lib/detection/types';

interface AnalyzeRequest {
  // Raw email formats
  rawMime?: string;

  // API formats
  graphMessage?: Record<string, unknown>;
  gmailMessage?: Record<string, unknown>;

  // Pre-parsed format
  parsed?: ParsedEmail;

  // Options
  quickCheckOnly?: boolean;
  skipLLM?: boolean;
}

export async function POST(request: NextRequest) {
  try {
    // Authenticate request
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Rate limit: 10 req/min (expensive LLM analysis)
    const limit = rateLimit(userId, 10, 60000);
    if (!limit.success) {
      return new Response('Too Many Requests', { status: 429 });
    }

    // Parse request body
    const body: AnalyzeRequest = await request.json();

    // Parse email from provided format
    let email: ParsedEmail;

    if (body.parsed) {
      email = body.parsed;
    } else if (body.rawMime) {
      email = parseEmail(body.rawMime);
    } else if (body.graphMessage) {
      email = parseGraphEmail(body.graphMessage);
    } else if (body.gmailMessage) {
      email = parseGmailEmail(body.gmailMessage);
    } else {
      return NextResponse.json(
        { error: 'No email data provided. Include rawMime, graphMessage, gmailMessage, or parsed.' },
        { status: 400 }
      );
    }

    // Get tenant ID (org or personal)
    const tenantId = orgId || `personal_${userId}`;

    // Quick check option for high-volume scanning
    if (body.quickCheckOnly) {
      const quickVerdict = await quickCheck(email);

      if (quickVerdict) {
        return NextResponse.json({
          messageId: email.messageId,
          verdict: quickVerdict,
          quickCheck: true,
          analyzedAt: new Date().toISOString(),
        });
      }

      // Quick check inconclusive, indicate full analysis needed
      return NextResponse.json({
        messageId: email.messageId,
        quickCheck: true,
        needsFullAnalysis: true,
        message: 'Quick check inconclusive, full analysis recommended',
      });
    }

    // Configure analysis
    const config = {
      ...DEFAULT_DETECTION_CONFIG,
    };

    // Option to skip LLM for cost savings
    if (body.skipLLM) {
      config.invokeLlmConfidenceRange = [1, 1]; // Never trigger LLM
    }

    // Run full analysis
    const verdict = await analyzeEmail(email, tenantId, config);

    // Persist the verdict and, for actionable threats, enqueue remediation.
    // These are best-effort: a storage/remediation failure must not prevent the
    // caller from receiving the analysis result.
    await persistAndRemediate(tenantId, email, verdict);

    // Return verdict
    return NextResponse.json({
      messageId: verdict.messageId,
      verdict: verdict.verdict,
      score: verdict.overallScore,
      confidence: verdict.confidence,
      explanation: verdict.explanation,
      recommendation: verdict.recommendation,
      signals: verdict.signals.map(s => ({
        type: s.type,
        severity: s.severity,
        detail: s.detail,
      })),
      processingTimeMs: verdict.processingTimeMs,
      llmUsed: !!verdict.llmTokensUsed,
      analyzedAt: verdict.analyzedAt.toISOString(),
    });

  } catch (error) {
    console.error('Analysis error:', error);

    return NextResponse.json(
      {
        error: 'Analysis failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    );
  }
}

/**
 * Persist the verdict and, for quarantine/block verdicts, enqueue mailbox
 * remediation through the same `autoRemediate` path the provider webhooks use.
 *
 * Best-effort: errors are logged but never thrown, so the API still returns the
 * verdict to the caller even if persistence or remediation fails.
 */
async function persistAndRemediate(
  tenantId: string,
  email: ParsedEmail,
  verdict: EmailVerdict
): Promise<void> {
  // 1. Persist the verdict.
  try {
    await storeVerdict(tenantId, verdict.messageId, verdict, email);
  } catch (error) {
    console.error('Failed to store verdict:', error instanceof Error ? error.message : error);
    // If we couldn't store the verdict, the threats row autoRemediate relies on
    // won't have email details; remediation can still run but skip on error.
  }

  // 2. Only quarantine/block verdicts trigger mailbox action.
  if (verdict.verdict !== 'quarantine' && verdict.verdict !== 'block') {
    return;
  }

  try {
    // Find the tenant's connected mailbox integration to act on.
    // /api/analyze can receive ad-hoc email payloads; without a connected
    // mailbox there is nothing to remediate, so we no-op gracefully.
    const integrations = await sql`
      SELECT id, type
      FROM integrations
      WHERE tenant_id = ${tenantId}
        AND status = 'connected'
        AND type IN ('o365', 'gmail')
      ORDER BY updated_at DESC
      LIMIT 1
    `;

    if (integrations.length === 0) {
      return;
    }

    const integration = integrations[0] as { id: string; type: 'o365' | 'gmail' };

    await autoRemediate({
      tenantId,
      messageId: verdict.messageId,
      externalMessageId: verdict.messageId,
      integrationId: integration.id,
      integrationType: integration.type,
      verdict: verdict.verdict,
      score: verdict.overallScore,
    });
  } catch (error) {
    console.error('Failed to enqueue remediation:', error instanceof Error ? error.message : error);
  }
}

// Health check endpoint
export async function GET() {
  return NextResponse.json({
    service: 'swordfish-analyze',
    status: 'healthy',
    version: '1.0.0',
    capabilities: [
      'mime-parsing',
      'graph-api',
      'gmail-api',
      'deterministic-analysis',
      'llm-analysis',
    ],
  });
}

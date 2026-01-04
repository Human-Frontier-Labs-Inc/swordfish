/**
 * Email Analysis API Endpoint
 * POST /api/analyze
 *
 * Accepts email data and returns a security verdict
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { parseEmail, parseGraphEmail, parseGmailEmail } from '@/lib/detection/parser';
import { analyzeEmail, quickCheck } from '@/lib/detection/pipeline';
import { DEFAULT_DETECTION_CONFIG } from '@/lib/detection/types';
import type { ParsedEmail } from '@/lib/detection/types';

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

    // TODO: Store verdict in database
    // await storeVerdict(verdict);

    // TODO: If quarantine/block, take action
    // if (verdict.verdict === 'quarantine' || verdict.verdict === 'block') {
    //   await handleThreat(email, verdict);
    // }

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

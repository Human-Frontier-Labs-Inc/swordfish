/**
 * Recent Threats API
 * GET /api/dashboard/threats
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getTopThreats } from '@/lib/detection/storage';

export async function GET(request: NextRequest) {
  try {
    const { userId, orgId } = await auth();

    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const tenantId = orgId || `personal_${userId}`;

    // Get limit parameter from query (default 50)
    const searchParams = request.nextUrl.searchParams;
    const limit = Math.min(parseInt(searchParams.get('limit') || '50'), 100);

    const threats = await getTopThreats(tenantId, limit);

    // Format threats for frontend
    const formattedThreats = threats.map((threat) => {
      // Extract key details from signals
      const primarySignal = threat.signals.find((s) => s.severity === 'critical')
        || threat.signals.find((s) => s.severity === 'warning')
        || threat.signals[0];

      return {
        id: threat.messageId,
        type: categorizeThreats(threat.signals),
        subject: threat.subject,
        sender: threat.sender,
        verdict: threat.verdict,
        score: threat.score,
        detail: primarySignal?.detail || 'Unknown threat',
        signalCount: threat.signals.length,
        timestamp: threat.createdAt,
      };
    });

    return NextResponse.json({
      threats: formattedThreats,
      total: formattedThreats.length,
    });

  } catch (error) {
    console.error('Threats API error:', error);

    // Return empty for new tenants
    return NextResponse.json({
      threats: [],
      total: 0,
    });
  }
}

/**
 * Categorize threat type based on signals
 */
function categorizeThreats(signals: Array<{ type: string }>): string {
  const types = signals.map((s) => s.type);

  if (types.includes('homoglyph') || types.includes('display_name_spoof')) {
    return 'Impersonation';
  }
  if (types.includes('credential_request')) {
    return 'Credential Phishing';
  }
  if (types.includes('financial_request')) {
    return 'BEC/Financial';
  }
  if (types.includes('executable') || types.includes('macro_enabled')) {
    return 'Malware';
  }
  if (types.includes('dangerous_url') || types.includes('ip_url')) {
    return 'Malicious Link';
  }
  if (types.includes('urgency_language')) {
    return 'Social Engineering';
  }

  return 'Suspicious';
}

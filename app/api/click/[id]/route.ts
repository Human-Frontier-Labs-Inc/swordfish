/**
 * Click Resolution API
 * Handles click-time URL checks and redirects
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';

import { checkUrlAtClickTime } from '@/lib/actions/links/click-time-check';
import { logClickAction, getClickMapping, updateClickStats } from '@/lib/actions/logger';

interface RouteParams {
  params: Promise<{ id: string }>;
}

/**
 * GET /api/click/[id]
 * Check URL safety and return result or redirect
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  const { userId, orgId } = await auth();

  try {
    // Get click mapping from database
    const mapping = await getClickMapping(id);

    if (!mapping) {
      return NextResponse.json(
        { error: 'Link not found' },
        { status: 404 }
      );
    }

    // Check if link has expired
    if (mapping.expiresAt && new Date(mapping.expiresAt) < new Date()) {
      return NextResponse.json(
        { error: 'Link has expired' },
        { status: 410 }
      );
    }

    const originalUrl = mapping.originalUrl;

    // Perform click-time safety check
    const result = await checkUrlAtClickTime(originalUrl);

    // Log the click action
    await logClickAction({
      clickId: id,
      originalUrl,
      verdict: result.verdict,
      action: result.action,
      riskScore: result.riskScore,
      signals: result.signals,
      userId: userId || undefined,
      tenantId: orgId || mapping.tenantId,
      emailId: mapping.emailId,
    });

    // Update click count
    await updateClickStats(id);

    // Check for redirect mode
    const mode = request.nextUrl.searchParams.get('mode');

    if (mode === 'redirect') {
      // Auto-redirect mode (for direct link access)
      if (result.action === 'block') {
        // Redirect to block page
        return NextResponse.redirect(new URL(`/click/${id}`, request.url));
      }

      if (result.action === 'warn') {
        // Redirect to warning page
        return NextResponse.redirect(new URL(`/click/${id}`, request.url));
      }

      // Safe - redirect directly
      return NextResponse.redirect(originalUrl);
    }

    // Default: return JSON result
    return NextResponse.json({
      clickId: id,
      originalUrl,
      result: {
        verdict: result.verdict,
        action: result.action,
        riskScore: result.riskScore,
        signals: result.signals,
        checkDurationMs: result.checkDurationMs,
        cachedResult: result.cachedResult,
      },
    });

  } catch (error) {
    console.error('Click resolution error:', error);
    return NextResponse.json(
      { error: 'Failed to process click' },
      { status: 500 }
    );
  }
}

/**
 * POST /api/click/[id]
 * Record click and get check result
 */
export async function POST(request: NextRequest, { params }: RouteParams) {
  const { id } = await params;
  const { userId, orgId } = await auth();

  try {
    const body = await request.json();
    const { bypassWarning = false } = body;

    // Get click mapping
    const mapping = await getClickMapping(id);

    if (!mapping) {
      return NextResponse.json(
        { error: 'Link not found' },
        { status: 404 }
      );
    }

    // Check expiry
    if (mapping.expiresAt && new Date(mapping.expiresAt) < new Date()) {
      return NextResponse.json(
        { error: 'Link has expired' },
        { status: 410 }
      );
    }

    const originalUrl = mapping.originalUrl;

    // Perform check
    const result = await checkUrlAtClickTime(originalUrl);

    // Log the action with bypass flag
    await logClickAction({
      clickId: id,
      originalUrl,
      verdict: result.verdict,
      action: result.action,
      riskScore: result.riskScore,
      signals: result.signals,
      userId: userId || undefined,
      tenantId: orgId || mapping.tenantId,
      emailId: mapping.emailId,
      bypassedWarning: bypassWarning,
    });

    // Update click count
    await updateClickStats(id);

    return NextResponse.json({
      clickId: id,
      originalUrl,
      result: {
        verdict: result.verdict,
        action: result.action,
        riskScore: result.riskScore,
        signals: result.signals,
      },
      // Allow proceed if warning bypassed
      allowProceed: result.action === 'allow' || (result.action === 'warn' && bypassWarning),
    });

  } catch (error) {
    console.error('Click POST error:', error);
    return NextResponse.json(
      { error: 'Failed to process click' },
      { status: 500 }
    );
  }
}

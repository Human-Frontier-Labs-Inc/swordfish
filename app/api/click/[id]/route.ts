/**
 * Click Resolution API
 * Handles click-time URL checks and redirects using the Click Scanner
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';

import { checkUrlAtClickTime } from '@/lib/actions/links/click-time-check';
import { logClickAction, getClickMapping, updateClickStats } from '@/lib/actions/logger';
import {
  getClickScanner,
  generateClickWarningPage,
  type ClickScanResult,
} from '@/lib/protection/click-scanner';

interface RouteParams {
  params: Promise<{ id: string }>;
}

/**
 * Convert ClickScanResult to legacy format for backward compatibility
 */
function convertToLegacySignals(scanResult: ClickScanResult) {
  return scanResult.threats.map((threat) => ({
    type: threat.type,
    severity: threat.severity === 'critical' ? 'critical' as const :
              threat.severity === 'high' ? 'critical' as const :
              threat.severity === 'medium' ? 'warning' as const : 'info' as const,
    detail: threat.details,
  }));
}

/**
 * Convert ClickScanResult verdict to legacy action
 */
function verdictToAction(verdict: ClickScanResult['verdict']): 'allow' | 'warn' | 'block' {
  switch (verdict) {
    case 'blocked':
    case 'malicious':
      return 'block';
    case 'suspicious':
      return 'warn';
    default:
      return 'allow';
  }
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

    // Check for mode parameter
    const mode = request.nextUrl.searchParams.get('mode');
    const useAdvancedScanner = request.nextUrl.searchParams.get('scanner') === 'advanced';

    // Use advanced Click Scanner if enabled or for warning page mode
    if (useAdvancedScanner || mode === 'warning') {
      const scanner = getClickScanner();
      const scanResult = await scanner.scanAtClickTime(id);

      // Record the click scan
      await scanner.recordClick(id, scanResult);

      // Log the click action (for audit trail)
      await logClickAction({
        clickId: id,
        originalUrl,
        verdict: scanResult.verdict,
        action: verdictToAction(scanResult.verdict),
        riskScore: Math.round(100 - scanResult.reputation.score),
        signals: convertToLegacySignals(scanResult),
        userId: userId || undefined,
        tenantId: orgId || mapping.tenantId,
        emailId: mapping.emailId,
      });

      // Update click count
      await updateClickStats(id);

      // If warning page mode, return HTML
      if (mode === 'warning' && (scanResult.shouldWarn || scanResult.shouldBlock)) {
        const warningHtml = generateClickWarningPage(scanResult);
        return new NextResponse(warningHtml, {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }

      // Redirect mode handling
      if (mode === 'redirect') {
        if (scanResult.shouldBlock) {
          // Redirect to warning page
          return NextResponse.redirect(new URL(`/api/click/${id}?mode=warning`, request.url));
        }

        if (scanResult.shouldWarn) {
          // Redirect to warning page
          return NextResponse.redirect(new URL(`/api/click/${id}?mode=warning`, request.url));
        }

        // Safe - redirect directly
        return NextResponse.redirect(scanResult.finalUrl);
      }

      // Return JSON result
      return NextResponse.json({
        clickId: id,
        originalUrl,
        finalUrl: scanResult.finalUrl,
        redirectChain: scanResult.redirectChain,
        result: {
          verdict: scanResult.verdict,
          action: verdictToAction(scanResult.verdict),
          riskScore: Math.round(100 - scanResult.reputation.score),
          threats: scanResult.threats,
          reputation: scanResult.reputation,
          scanTimeMs: scanResult.scanTimeMs,
          shouldWarn: scanResult.shouldWarn,
          shouldBlock: scanResult.shouldBlock,
        },
      });
    }

    // Fallback to legacy click-time check
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
    const { bypassWarning = false, useAdvancedScanner = false } = body;

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

    // Use advanced Click Scanner if requested
    if (useAdvancedScanner) {
      const scanner = getClickScanner();
      const scanResult = await scanner.scanAtClickTime(id);

      // Record the click scan
      await scanner.recordClick(id, scanResult);

      // Log the action with bypass flag
      await logClickAction({
        clickId: id,
        originalUrl,
        verdict: scanResult.verdict,
        action: verdictToAction(scanResult.verdict),
        riskScore: Math.round(100 - scanResult.reputation.score),
        signals: convertToLegacySignals(scanResult),
        userId: userId || undefined,
        tenantId: orgId || mapping.tenantId,
        emailId: mapping.emailId,
        bypassedWarning: bypassWarning,
      });

      // Update click count
      await updateClickStats(id);

      const action = verdictToAction(scanResult.verdict);
      return NextResponse.json({
        clickId: id,
        originalUrl,
        finalUrl: scanResult.finalUrl,
        redirectChain: scanResult.redirectChain,
        result: {
          verdict: scanResult.verdict,
          action,
          riskScore: Math.round(100 - scanResult.reputation.score),
          threats: scanResult.threats,
          reputation: scanResult.reputation,
          scanTimeMs: scanResult.scanTimeMs,
        },
        allowProceed: action === 'allow' || (action === 'warn' && bypassWarning),
      });
    }

    // Fallback to legacy click-time check
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

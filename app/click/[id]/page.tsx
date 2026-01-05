/**
 * Click-Time Protection Page
 * Displays safety information when users click rewritten links
 */

import { Suspense } from 'react';
import { notFound } from 'next/navigation';
import { Metadata } from 'next';
import { Shield, AlertTriangle, XCircle, ExternalLink, Clock, CheckCircle } from 'lucide-react';
import { auth } from '@clerk/nextjs/server';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';

import { checkUrlAtClickTime, type ClickTimeResult } from '@/lib/actions/links/click-time-check';
import { logClickAction, getClickMapping, updateClickStats } from '@/lib/actions/logger';

export const metadata: Metadata = {
  title: 'Link Safety Check | Swordfish',
  description: 'Verifying link safety before proceeding',
};

interface ClickPageProps {
  params: Promise<{ id: string }>;
}

// Verdict colors and icons
const VERDICT_CONFIG = {
  safe: {
    icon: CheckCircle,
    color: 'text-green-600',
    bgColor: 'bg-green-50',
    borderColor: 'border-green-200',
    badgeVariant: 'default' as const,
  },
  suspicious: {
    icon: AlertTriangle,
    color: 'text-yellow-600',
    bgColor: 'bg-yellow-50',
    borderColor: 'border-yellow-200',
    badgeVariant: 'secondary' as const,
  },
  malicious: {
    icon: XCircle,
    color: 'text-red-600',
    bgColor: 'bg-red-50',
    borderColor: 'border-red-200',
    badgeVariant: 'destructive' as const,
  },
  blocked: {
    icon: XCircle,
    color: 'text-red-700',
    bgColor: 'bg-red-100',
    borderColor: 'border-red-300',
    badgeVariant: 'destructive' as const,
  },
  unknown: {
    icon: Shield,
    color: 'text-gray-600',
    bgColor: 'bg-gray-50',
    borderColor: 'border-gray-200',
    badgeVariant: 'outline' as const,
  },
};

async function ClickContent({ clickId }: { clickId: string }) {
  const { userId, orgId } = await auth();

  // Get click mapping from database
  const mapping = await getClickMapping(clickId);

  if (!mapping) {
    notFound();
  }

  // Check if link has expired
  if (mapping.expiresAt && new Date(mapping.expiresAt) < new Date()) {
    return (
      <Card className="max-w-2xl mx-auto">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-red-600">
            <XCircle className="h-6 w-6" />
            Link Expired
          </CardTitle>
          <CardDescription>
            This protected link has expired and is no longer valid.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            For security reasons, protected links expire after 30 days.
            Please request a new link from the sender.
          </p>
        </CardContent>
      </Card>
    );
  }

  const originalUrl = mapping.originalUrl;

  // Perform click-time safety check
  const result = await checkUrlAtClickTime(originalUrl);

  // Log the click action
  await logClickAction({
    clickId,
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
  await updateClickStats(clickId);

  const config = VERDICT_CONFIG[result.verdict];
  const VerdictIcon = config.icon;

  return (
    <div className="space-y-6 max-w-2xl mx-auto">
      {/* Main verdict card */}
      <Card className={`${config.bgColor} ${config.borderColor} border-2`}>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className={`flex items-center gap-2 ${config.color}`}>
              <VerdictIcon className="h-6 w-6" />
              {result.verdict === 'safe' && 'Link Appears Safe'}
              {result.verdict === 'suspicious' && 'Caution: Suspicious Link'}
              {result.verdict === 'malicious' && 'Warning: Dangerous Link'}
              {result.verdict === 'blocked' && 'Access Blocked'}
              {result.verdict === 'unknown' && 'Unable to Verify'}
            </CardTitle>
            <Badge variant={config.badgeVariant}>
              Risk Score: {result.riskScore}/100
            </Badge>
          </div>
          <CardDescription className="mt-2">
            {result.verdict === 'safe' && 'Our security analysis indicates this link is likely safe to visit.'}
            {result.verdict === 'suspicious' && 'This link has some characteristics that warrant caution.'}
            {result.verdict === 'malicious' && 'This link has been identified as potentially dangerous.'}
            {result.verdict === 'blocked' && 'This link has been blocked due to high security risk.'}
            {result.verdict === 'unknown' && 'We were unable to fully verify the safety of this link.'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Destination URL */}
          <div className="mb-4 p-3 bg-white rounded-lg border">
            <p className="text-xs text-muted-foreground mb-1">Destination URL:</p>
            <p className="text-sm font-mono break-all">{originalUrl}</p>
          </div>

          {/* Signals */}
          {result.signals.length > 0 && (
            <div className="mb-4">
              <p className="text-sm font-medium mb-2">Security Signals:</p>
              <ul className="space-y-1">
                {result.signals.map((signal, idx) => (
                  <li key={idx} className="flex items-center gap-2 text-sm">
                    {signal.severity === 'critical' && (
                      <XCircle className="h-4 w-4 text-red-500 flex-shrink-0" />
                    )}
                    {signal.severity === 'warning' && (
                      <AlertTriangle className="h-4 w-4 text-yellow-500 flex-shrink-0" />
                    )}
                    {signal.severity === 'info' && (
                      <Shield className="h-4 w-4 text-blue-500 flex-shrink-0" />
                    )}
                    <span>{signal.detail}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Check duration */}
          <div className="flex items-center gap-1 text-xs text-muted-foreground">
            <Clock className="h-3 w-3" />
            <span>
              Checked in {result.checkDurationMs.toFixed(0)}ms
              {result.cachedResult && ' (cached)'}
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Action buttons */}
      <div className="flex flex-col sm:flex-row gap-3">
        {result.action === 'allow' && (
          <Button asChild className="flex-1">
            <a href={originalUrl} target="_blank" rel="noopener noreferrer">
              <ExternalLink className="h-4 w-4 mr-2" />
              Continue to Site
            </a>
          </Button>
        )}

        {result.action === 'warn' && (
          <>
            <Button variant="outline" asChild className="flex-1">
              <a href="/" onClick={() => window.history.back()}>
                Go Back (Recommended)
              </a>
            </Button>
            <Button variant="destructive" asChild className="flex-1">
              <a href={originalUrl} target="_blank" rel="noopener noreferrer">
                <AlertTriangle className="h-4 w-4 mr-2" />
                Proceed Anyway
              </a>
            </Button>
          </>
        )}

        {result.action === 'block' && (
          <Alert variant="destructive">
            <XCircle className="h-4 w-4" />
            <AlertTitle>Access Blocked</AlertTitle>
            <AlertDescription>
              This link has been blocked by your organization&apos;s security policy.
              If you believe this is an error, please contact your IT administrator.
            </AlertDescription>
          </Alert>
        )}
      </div>

      {/* Security tips */}
      {result.verdict !== 'safe' && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Security Tips</CardTitle>
          </CardHeader>
          <CardContent className="text-sm space-y-2">
            <p>• Verify the sender actually sent this email through a separate channel</p>
            <p>• Check that the URL matches the expected domain</p>
            <p>• Never enter passwords on unfamiliar sites</p>
            <p>• When in doubt, don&apos;t click - report to your security team</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function LoadingSkeleton() {
  return (
    <div className="space-y-6 max-w-2xl mx-auto">
      <Card>
        <CardHeader>
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-4 w-full mt-2" />
        </CardHeader>
        <CardContent>
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-4 w-32 mt-4" />
        </CardContent>
      </Card>
      <div className="flex gap-3">
        <Skeleton className="h-10 flex-1" />
        <Skeleton className="h-10 flex-1" />
      </div>
    </div>
  );
}

export default async function ClickPage({ params }: ClickPageProps) {
  const { id } = await params;

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-slate-100 py-12 px-4">
      <div className="max-w-3xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-2 mb-2">
            <Shield className="h-8 w-8 text-primary" />
            <h1 className="text-2xl font-bold">Swordfish Link Protection</h1>
          </div>
          <p className="text-muted-foreground">
            Analyzing link safety before you proceed
          </p>
        </div>

        <Suspense fallback={<LoadingSkeleton />}>
          <ClickContent clickId={id} />
        </Suspense>
      </div>
    </div>
  );
}

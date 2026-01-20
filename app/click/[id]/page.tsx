/**
 * Click-Time Protection Page
 * Displays safety information when users click rewritten links
 * Now integrated with the advanced Click Scanner for comprehensive analysis
 */

import { Suspense } from 'react';
import { notFound } from 'next/navigation';
import { Metadata } from 'next';
import {
  Shield,
  AlertTriangle,
  XCircle,
  ExternalLink,
  Clock,
  CheckCircle,
  ArrowRight,
  Link2,
  Globe,
  Lock,
  Unlock,
} from 'lucide-react';
import { auth } from '@clerk/nextjs/server';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Progress } from '@/components/ui/progress';

import { logClickAction, getClickMapping, updateClickStats } from '@/lib/actions/logger';
import {
  getClickScanner,
  type ClickScanResult,
  type UrlThreat,
} from '@/lib/protection/click-scanner';

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
    title: 'Link Appears Safe',
    description: 'Our security analysis indicates this link is likely safe to visit.',
  },
  suspicious: {
    icon: AlertTriangle,
    color: 'text-yellow-600',
    bgColor: 'bg-yellow-50',
    borderColor: 'border-yellow-200',
    badgeVariant: 'secondary' as const,
    title: 'Caution: Suspicious Link',
    description: 'This link has some characteristics that warrant caution.',
  },
  malicious: {
    icon: XCircle,
    color: 'text-red-600',
    bgColor: 'bg-red-50',
    borderColor: 'border-red-200',
    badgeVariant: 'destructive' as const,
    title: 'Warning: Dangerous Link',
    description: 'This link has been identified as potentially dangerous.',
  },
  blocked: {
    icon: XCircle,
    color: 'text-red-700',
    bgColor: 'bg-red-100',
    borderColor: 'border-red-300',
    badgeVariant: 'destructive' as const,
    title: 'Access Blocked',
    description: 'This link has been blocked due to high security risk.',
  },
};

// Severity colors
const SEVERITY_CONFIG = {
  critical: { color: 'text-red-700', bg: 'bg-red-100', border: 'border-red-300' },
  high: { color: 'text-orange-700', bg: 'bg-orange-100', border: 'border-orange-300' },
  medium: { color: 'text-yellow-700', bg: 'bg-yellow-100', border: 'border-yellow-300' },
  low: { color: 'text-blue-700', bg: 'bg-blue-100', border: 'border-blue-300' },
};

function ThreatItem({ threat }: { threat: UrlThreat }) {
  const severityConfig = SEVERITY_CONFIG[threat.severity];

  return (
    <div className={`flex items-start gap-3 p-3 rounded-lg ${severityConfig.bg} ${severityConfig.border} border`}>
      <Badge
        variant="outline"
        className={`${severityConfig.color} ${severityConfig.border} uppercase text-xs font-semibold`}
      >
        {threat.severity}
      </Badge>
      <div className="flex-1">
        <p className={`font-medium capitalize ${severityConfig.color}`}>
          {threat.type.replace('_', ' ')}
        </p>
        <p className="text-sm text-muted-foreground mt-1">{threat.details}</p>
        <p className="text-xs text-muted-foreground mt-1">Source: {threat.source}</p>
      </div>
    </div>
  );
}

function RedirectChainDisplay({ chain }: { chain: string[] }) {
  if (chain.length <= 1) return null;

  return (
    <div className="space-y-2">
      <p className="text-sm font-medium text-muted-foreground">Redirect Chain ({chain.length} hops):</p>
      <div className="space-y-1">
        {chain.map((url, idx) => (
          <div key={idx} className="flex items-center gap-2">
            {idx > 0 && <ArrowRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />}
            <code className="text-xs bg-muted px-2 py-1 rounded break-all flex-1">
              {idx === 0 ? url : new URL(url).hostname}
            </code>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReputationSources({ sources }: { sources: ClickScanResult['reputation']['sources'] }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
      {sources.virustotal && (
        <div className="p-3 bg-muted rounded-lg">
          <p className="text-xs font-medium text-muted-foreground mb-1">VirusTotal</p>
          <div className="flex gap-2 text-xs">
            <span className="text-red-600">{sources.virustotal.malicious} malicious</span>
            <span className="text-yellow-600">{sources.virustotal.suspicious} suspicious</span>
            <span className="text-green-600">{sources.virustotal.clean} clean</span>
          </div>
        </div>
      )}
      {sources.urlscan && (
        <div className="p-3 bg-muted rounded-lg">
          <p className="text-xs font-medium text-muted-foreground mb-1">URLScan</p>
          <div className="flex gap-2 text-xs">
            <Badge variant={sources.urlscan.verdict === 'malicious' ? 'destructive' : 'secondary'}>
              {sources.urlscan.verdict}
            </Badge>
            <span className="text-muted-foreground">Score: {sources.urlscan.score}</span>
          </div>
        </div>
      )}
      {sources.internal && (
        <div className="p-3 bg-muted rounded-lg">
          <p className="text-xs font-medium text-muted-foreground mb-1">Internal</p>
          <div className="text-xs">
            {sources.internal.previouslyBlocked && (
              <span className="text-red-600">Previously blocked</span>
            )}
            {sources.internal.reportCount > 0 && (
              <span className="text-yellow-600">
                {sources.internal.reportCount} user reports
              </span>
            )}
            {!sources.internal.previouslyBlocked && sources.internal.reportCount === 0 && (
              <span className="text-green-600">No issues found</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

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

  // Use advanced Click Scanner for comprehensive analysis
  const scanner = getClickScanner();
  let scanResult: ClickScanResult;

  try {
    scanResult = await scanner.scanAtClickTime(clickId);
  } catch (error) {
    console.error('Click scan error:', error);
    // Return error state
    return (
      <Card className="max-w-2xl mx-auto">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-yellow-600">
            <AlertTriangle className="h-6 w-6" />
            Unable to Verify Link
          </CardTitle>
          <CardDescription>
            We encountered an error while analyzing this link.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Please exercise caution when proceeding. If you&apos;re unsure, contact the sender to verify.
          </p>
          <div className="mt-4">
            <Button variant="outline" asChild>
              <a href="javascript:history.back()">Go Back</a>
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Record the click scan
  await scanner.recordClick(clickId, scanResult);

  // Log the click action
  await logClickAction({
    clickId,
    originalUrl: scanResult.originalUrl,
    verdict: scanResult.verdict,
    action: scanResult.shouldBlock ? 'block' : scanResult.shouldWarn ? 'warn' : 'allow',
    riskScore: Math.round(100 - scanResult.reputation.score),
    signals: scanResult.threats.map((t) => ({
      type: t.type,
      severity: t.severity === 'critical' ? 'critical' : t.severity === 'high' ? 'critical' : 'warning',
      detail: t.details,
    })),
    userId: userId || undefined,
    tenantId: orgId || mapping.tenantId,
    emailId: mapping.emailId,
  });

  // Update click count
  await updateClickStats(clickId);

  const config = VERDICT_CONFIG[scanResult.verdict];
  const VerdictIcon = config.icon;
  const reputationScore = scanResult.reputation.score;

  return (
    <div className="space-y-6 max-w-2xl mx-auto">
      {/* Main verdict card */}
      <Card className={`${config.bgColor} ${config.borderColor} border-2`}>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className={`flex items-center gap-2 ${config.color}`}>
              <VerdictIcon className="h-6 w-6" />
              {config.title}
            </CardTitle>
            <Badge variant={config.badgeVariant}>
              Score: {reputationScore}/100
            </Badge>
          </div>
          <CardDescription className="mt-2">
            {config.description}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Destination URL */}
          <div className="p-3 bg-white rounded-lg border">
            <div className="flex items-center gap-2 mb-1">
              <Link2 className="h-4 w-4 text-muted-foreground" />
              <p className="text-xs text-muted-foreground">Destination URL</p>
            </div>
            <p className="text-sm font-mono break-all">{scanResult.finalUrl}</p>
          </div>

          {/* Redirect chain if present */}
          {scanResult.redirectChain.length > 1 && (
            <div className="p-3 bg-white rounded-lg border">
              <RedirectChainDisplay chain={scanResult.redirectChain} />
            </div>
          )}

          {/* Reputation score bar */}
          <div className="p-3 bg-white rounded-lg border">
            <div className="flex items-center justify-between mb-2">
              <p className="text-xs text-muted-foreground">Security Reputation</p>
              <span className={`text-sm font-semibold ${
                reputationScore >= 70 ? 'text-green-600' :
                reputationScore >= 40 ? 'text-yellow-600' : 'text-red-600'
              }`}>
                {reputationScore}/100
              </span>
            </div>
            <Progress
              value={reputationScore}
              className={`h-2 ${
                reputationScore >= 70 ? '[&>div]:bg-green-500' :
                reputationScore >= 40 ? '[&>div]:bg-yellow-500' : '[&>div]:bg-red-500'
              }`}
            />
          </div>

          {/* Domain info */}
          <div className="flex flex-wrap gap-3">
            {scanResult.reputation.domainAge !== undefined && (
              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                <Globe className="h-3 w-3" />
                Domain age: {scanResult.reputation.domainAge} days
              </div>
            )}
            {scanResult.reputation.sslValid !== undefined && (
              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                {scanResult.reputation.sslValid ? (
                  <><Lock className="h-3 w-3 text-green-600" /> SSL Valid</>
                ) : (
                  <><Unlock className="h-3 w-3 text-red-600" /> SSL Invalid</>
                )}
              </div>
            )}
          </div>

          {/* Check duration */}
          <div className="flex items-center gap-1 text-xs text-muted-foreground">
            <Clock className="h-3 w-3" />
            <span>Checked in {scanResult.scanTimeMs.toFixed(0)}ms</span>
          </div>
        </CardContent>
      </Card>

      {/* Threats detected */}
      {scanResult.threats.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-600" />
              Risk Factors Detected ({scanResult.threats.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {scanResult.threats.map((threat, idx) => (
              <ThreatItem key={idx} threat={threat} />
            ))}
          </CardContent>
        </Card>
      )}

      {/* Reputation sources */}
      {(scanResult.reputation.sources.virustotal ||
        scanResult.reputation.sources.urlscan ||
        scanResult.reputation.sources.internal) && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Reputation Sources</CardTitle>
          </CardHeader>
          <CardContent>
            <ReputationSources sources={scanResult.reputation.sources} />
          </CardContent>
        </Card>
      )}

      {/* Action buttons */}
      <div className="flex flex-col sm:flex-row gap-3">
        {!scanResult.shouldBlock && !scanResult.shouldWarn && (
          <Button asChild className="flex-1">
            <a href={scanResult.finalUrl} target="_blank" rel="noopener noreferrer">
              <ExternalLink className="h-4 w-4 mr-2" />
              Continue to Site
            </a>
          </Button>
        )}

        {scanResult.shouldWarn && !scanResult.shouldBlock && (
          <>
            <Button variant="outline" asChild className="flex-1">
              <a href="javascript:history.back()">
                Go Back (Recommended)
              </a>
            </Button>
            <Button variant="destructive" asChild className="flex-1">
              <a
                href={scanResult.originalUrl}
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => {
                  // Log bypass attempt
                  fetch(`/api/click/${clickId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ bypassWarning: true }),
                  }).catch(() => {});
                }}
              >
                <AlertTriangle className="h-4 w-4 mr-2" />
                Proceed Anyway
              </a>
            </Button>
          </>
        )}

        {scanResult.shouldBlock && (
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
      {scanResult.verdict !== 'safe' && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Security Tips</CardTitle>
          </CardHeader>
          <CardContent className="text-sm space-y-2">
            <p>&#x2022; Verify the sender actually sent this email through a separate channel</p>
            <p>&#x2022; Check that the URL matches the expected domain</p>
            <p>&#x2022; Never enter passwords on unfamiliar sites</p>
            <p>&#x2022; When in doubt, don&apos;t click - report to your security team</p>
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
        <CardContent className="space-y-4">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-4 w-32" />
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

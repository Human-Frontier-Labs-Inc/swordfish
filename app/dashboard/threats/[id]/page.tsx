'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { useTenant } from '@/lib/auth/tenant-context';
import Link from 'next/link';

interface ThreatDetail {
  id: string;
  tenantId: string;
  messageId: string;
  subject: string;
  senderEmail: string;
  recipientEmail: string;
  verdict: string;
  score: number;
  status: string;
  provider: string;
  providerMessageId: string;
  quarantinedAt: string;
  releasedAt: string | null;
  releasedBy: string | null;
  signals: Signal[] | null;
  explanation: string | null;
  recommendation: string | null;
}

interface Signal {
  type: string;
  severity: string;
  description: string;
  score: number;
}

export default function ThreatDetailPage() {
  const params = useParams();
  const router = useRouter();
  const { currentTenant } = useTenant();
  const [threat, setThreat] = useState<ThreatDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  const threatId = params.id as string;

  useEffect(() => {
    async function fetchThreat() {
      if (!currentTenant || !threatId) return;

      try {
        const response = await fetch(`/api/threats/${threatId}`);
        if (!response.ok) {
          if (response.status === 404) {
            setError('Threat not found');
          } else {
            throw new Error('Failed to fetch threat details');
          }
          return;
        }

        const data = await response.json();
        setThreat(data.threat);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load threat');
      } finally {
        setLoading(false);
      }
    }

    fetchThreat();
  }, [currentTenant, threatId]);

  const handleRelease = async () => {
    if (!threat) return;
    setActionLoading(true);
    try {
      const response = await fetch(`/api/threats/${threat.id}/release`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ addToAllowlist: false }),
      });
      if (!response.ok) throw new Error('Failed to release');
      setThreat({ ...threat, status: 'released', releasedAt: new Date().toISOString() });
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Release failed');
    } finally {
      setActionLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!threat || !confirm('Are you sure you want to delete this threat?')) return;
    setActionLoading(true);
    try {
      const response = await fetch(`/api/threats/${threat.id}`, {
        method: 'DELETE',
      });
      if (!response.ok) throw new Error('Failed to delete');
      router.push('/dashboard/threats');
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Delete failed');
    } finally {
      setActionLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getVerdictColor = (verdict: string) => {
    switch (verdict?.toLowerCase()) {
      case 'block': return 'bg-red-600 text-white';
      case 'quarantine': return 'bg-orange-500 text-white';
      case 'warn': return 'bg-yellow-500 text-white';
      case 'pass': return 'bg-green-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const getStatusBadge = (status: string) => {
    const colors: Record<string, string> = {
      quarantined: 'bg-amber-100 text-amber-800',
      released: 'bg-green-100 text-green-800',
      deleted: 'bg-red-100 text-red-800',
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  if (error || !threat) {
    return (
      <div className="space-y-6">
        <Link href="/dashboard/threats" className="text-blue-600 hover:underline flex items-center gap-1">
          <ArrowLeftIcon className="h-4 w-4" /> Back to Threats
        </Link>
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <h2 className="text-lg font-medium text-red-800">{error || 'Threat not found'}</h2>
        </div>
      </div>
    );
  }

  const getVerdictLabel = (verdict: string): string => {
    switch (verdict?.toLowerCase()) {
      case 'block': return 'BLOCKED';
      case 'quarantine': return 'QUARANTINED';
      case 'suspicious': return 'SUSPICIOUS';
      case 'pass': return 'ALLOWED';
      default: return verdict?.toUpperCase() || 'UNKNOWN';
    }
  };

  const getVerdictIcon = (verdict: string): string => {
    switch (verdict?.toLowerCase()) {
      case 'block': return 'M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636';
      case 'quarantine': return 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z';
      case 'pass': return 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z';
      default: return 'M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z';
    }
  };

  const getSeverityIcon = (severity: string): string => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z';
      case 'high': return 'M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z';
      case 'warning': return 'M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z';
      case 'medium': return 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z';
      case 'low':
      case 'info':
      default: return 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z';
    }
  };

  const getSeverityIconColor = (severity: string): string => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-600';
      case 'high': return 'text-orange-500';
      case 'warning': return 'text-orange-500';
      case 'medium': return 'text-yellow-500';
      case 'low': return 'text-blue-500';
      case 'info': return 'text-blue-400';
      default: return 'text-gray-400';
    }
  };

  const getScoreColor = (score: number): string => {
    if (score >= 80) return 'text-red-600';
    if (score >= 50) return 'text-orange-500';
    if (score >= 30) return 'text-yellow-600';
    return 'text-green-600';
  };

  const getScoreBarColor = (score: number): string => {
    if (score >= 80) return 'bg-red-500';
    if (score >= 50) return 'bg-orange-500';
    if (score >= 30) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const sortedSignals = threat.signals
    ? [...threat.signals].sort((a, b) => {
        const severityOrder: Record<string, number> = { critical: 0, high: 1, warning: 2, medium: 3, low: 4, info: 5 };
        return (severityOrder[a.severity] ?? 6) - (severityOrder[b.severity] ?? 6);
      })
    : [];

  const criticalSignals = sortedSignals.filter(s => s.severity === 'critical' || s.severity === 'high');
  const warningSignals = sortedSignals.filter(s => s.severity === 'warning' || s.severity === 'medium');
  const infoSignals = sortedSignals.filter(s => s.severity === 'low' || s.severity === 'info');

  const generateWhyFlagged = (): string[] => {
    const reasons: string[] = [];
    for (const signal of criticalSignals.slice(0, 3)) {
      reasons.push(signal.description || signal.type);
    }
    for (const signal of warningSignals.slice(0, 2)) {
      if (reasons.length < 4) {
        reasons.push(signal.description || signal.type);
      }
    }
    if (reasons.length === 0 && threat.explanation) {
      reasons.push(threat.explanation);
    }
    return reasons;
  };

  const whyFlaggedReasons = generateWhyFlagged();

  return (
    <div className="space-y-6">
      {/* Header with Back Button */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/dashboard/threats" className="text-gray-500 hover:text-gray-700">
            <ArrowLeftIcon className="h-5 w-5" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Threat Details</h1>
            <p className="text-sm text-gray-500">ID: {threat.id}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {threat.status === 'quarantined' && (
            <>
              <button
                onClick={handleRelease}
                disabled={actionLoading}
                className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50"
              >
                Release Email
              </button>
              <button
                onClick={handleDelete}
                disabled={actionLoading}
                className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50"
              >
                Delete
              </button>
            </>
          )}
        </div>
      </div>

      {/* Verdict Banner */}
      <div className={`rounded-lg shadow-lg p-6 ${getVerdictColor(threat.verdict)}`}>
        <div className="flex items-center gap-4">
          <svg className="h-10 w-10" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d={getVerdictIcon(threat.verdict)} />
          </svg>
          <div className="flex-1">
            <h2 className="text-2xl font-bold tracking-wide">{getVerdictLabel(threat.verdict)}</h2>
            <p className="text-sm opacity-90 mt-1">
              {threat.verdict?.toLowerCase() === 'block' && 'This email was blocked from delivery due to high-confidence threat indicators.'}
              {threat.verdict?.toLowerCase() === 'quarantine' && 'This email was quarantined for review. It may contain threats.'}
              {threat.verdict?.toLowerCase() === 'suspicious' && 'This email has suspicious characteristics. Exercise caution.'}
              {threat.verdict?.toLowerCase() === 'pass' && 'This email passed security checks and was allowed through.'}
            </p>
          </div>
          <div className="text-right">
            <span className={`mt-1 inline-flex px-3 py-1 text-sm font-semibold rounded-full ${getStatusBadge(threat.status)}`}>
              {threat.status}
            </span>
          </div>
        </div>
      </div>

      {/* Confidence Score */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-lg font-semibold text-gray-900">Threat Confidence Score</h3>
          <span className={`text-3xl font-bold ${getScoreColor(threat.score)}`}>{threat.score}/100</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-4">
          <div
            className={`h-4 rounded-full transition-all duration-500 ${getScoreBarColor(threat.score)}`}
            style={{ width: `${threat.score}%` }}
          />
        </div>
        <div className="flex justify-between mt-2 text-xs text-gray-500">
          <span>Safe</span>
          <span>Suspicious</span>
          <span>Dangerous</span>
          <span>Critical</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          <div>
            <h4 className="text-sm font-medium text-gray-500">Provider</h4>
            <p className="mt-1 text-gray-900">{threat.provider || 'Unknown'}</p>
          </div>
          <div>
            <h4 className="text-sm font-medium text-gray-500">Detected</h4>
            <p className="mt-1 text-gray-900">
              {threat.quarantinedAt ? new Date(threat.quarantinedAt).toLocaleString() : 'N/A'}
            </p>
          </div>
        </div>
      </div>

      {/* Why Was This Flagged? */}
      {whyFlaggedReasons.length > 0 && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg shadow p-6">
          <div className="flex items-center gap-2 mb-4">
            <svg className="h-6 w-6 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <h2 className="text-lg font-semibold text-amber-900">Why was this flagged?</h2>
          </div>
          <ul className="space-y-2">
            {whyFlaggedReasons.map((reason, index) => (
              <li key={index} className="flex items-start gap-3">
                <span className="mt-1 flex-shrink-0 h-2 w-2 rounded-full bg-amber-500" />
                <span className="text-amber-900">{reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* AI Explanation - always visible when available */}
      {(threat.explanation || threat.recommendation) && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">AI Analysis</h2>
          {threat.explanation && (
            <div className="mb-4">
              <h3 className="text-sm font-medium text-gray-500 mb-2">Explanation</h3>
              <p className="text-gray-800 bg-gray-50 rounded-lg p-4 text-base leading-relaxed">{threat.explanation}</p>
            </div>
          )}
          {threat.recommendation && (
            <div>
              <h3 className="text-sm font-medium text-gray-500 mb-2">Recommendation</h3>
              <p className="text-gray-800 bg-blue-50 rounded-lg p-4 text-base leading-relaxed">{threat.recommendation}</p>
            </div>
          )}
        </div>
      )}

      {/* Email Details Card */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Email Details</h2>
        <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <dt className="text-sm font-medium text-gray-500">Subject</dt>
            <dd className="mt-1 text-gray-900">{threat.subject || '(No subject)'}</dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500">Message ID</dt>
            <dd className="mt-1 text-gray-900 text-sm font-mono break-all">{threat.messageId}</dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500">From</dt>
            <dd className="mt-1 text-gray-900">{threat.senderEmail}</dd>
          </div>
          <div>
            <dt className="text-sm font-medium text-gray-500">To</dt>
            <dd className="mt-1 text-gray-900">{threat.recipientEmail}</dd>
          </div>
          {threat.releasedAt && (
            <div>
              <dt className="text-sm font-medium text-gray-500">Released</dt>
              <dd className="mt-1 text-gray-900">
                {new Date(threat.releasedAt).toLocaleString()}
                {threat.releasedBy && ` by ${threat.releasedBy}`}
              </dd>
            </div>
          )}
        </dl>
      </div>

      {/* Detection Signals Card */}
      {sortedSignals.length > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-2">Detection Signals</h2>
          <p className="text-sm text-gray-500 mb-4">
            {criticalSignals.length} critical, {warningSignals.length} warning, {infoSignals.length} informational
          </p>
          <div className="space-y-3">
            {sortedSignals.map((signal, index) => (
              <div
                key={index}
                className={`border-l-4 rounded-lg p-4 ${getSeverityColor(signal.severity)}`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <svg className={`h-5 w-5 flex-shrink-0 ${getSeverityIconColor(signal.severity)}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d={getSeverityIcon(signal.severity)} />
                    </svg>
                    <span className="font-semibold text-gray-900">{signal.type.replace(/_/g, ' ')}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded ${
                      signal.severity === 'critical' ? 'bg-red-200 text-red-800' :
                      signal.severity === 'high' ? 'bg-orange-200 text-orange-800' :
                      signal.severity === 'warning' ? 'bg-orange-100 text-orange-700' :
                      signal.severity === 'medium' ? 'bg-yellow-200 text-yellow-800' :
                      signal.severity === 'info' ? 'bg-blue-100 text-blue-700' :
                      'bg-gray-200 text-gray-700'
                    }`}>{signal.severity}</span>
                    <span className="text-sm font-mono text-gray-600">+{signal.score}</span>
                  </div>
                </div>
                <p className="text-sm text-gray-700 ml-7">{signal.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ArrowLeftIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
    </svg>
  );
}

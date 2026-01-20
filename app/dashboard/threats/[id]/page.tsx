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
      const response = await fetch(`/api/quarantine/${threat.id}/release`, {
        method: 'POST',
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

      {/* Overview Card */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div>
            <h3 className="text-sm font-medium text-gray-500">Verdict</h3>
            <span className={`mt-1 inline-flex px-3 py-1 text-sm font-semibold rounded-full ${getVerdictColor(threat.verdict)}`}>
              {threat.verdict?.toUpperCase() || 'UNKNOWN'}
            </span>
          </div>
          <div>
            <h3 className="text-sm font-medium text-gray-500">Threat Score</h3>
            <div className="mt-1 flex items-center gap-3">
              <div className="flex-1 bg-gray-200 rounded-full h-3 max-w-24">
                <div
                  className={`h-3 rounded-full ${threat.score >= 80 ? 'bg-red-500' : threat.score >= 50 ? 'bg-yellow-500' : 'bg-green-500'}`}
                  style={{ width: `${threat.score}%` }}
                />
              </div>
              <span className="text-2xl font-bold text-gray-900">{threat.score}</span>
            </div>
          </div>
          <div>
            <h3 className="text-sm font-medium text-gray-500">Status</h3>
            <span className={`mt-1 inline-flex px-3 py-1 text-sm font-semibold rounded-full ${getStatusBadge(threat.status)}`}>
              {threat.status}
            </span>
          </div>
          <div>
            <h3 className="text-sm font-medium text-gray-500">Provider</h3>
            <p className="mt-1 text-lg text-gray-900">{threat.provider || 'Unknown'}</p>
          </div>
        </div>
      </div>

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
          <div>
            <dt className="text-sm font-medium text-gray-500">Detected</dt>
            <dd className="mt-1 text-gray-900">
              {threat.quarantinedAt ? new Date(threat.quarantinedAt).toLocaleString() : 'N/A'}
            </dd>
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

      {/* AI Explanation Card */}
      {(threat.explanation || threat.recommendation) && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">AI Analysis</h2>
          {threat.explanation && (
            <div className="mb-4">
              <h3 className="text-sm font-medium text-gray-500 mb-2">Explanation</h3>
              <p className="text-gray-700 bg-gray-50 rounded-lg p-4">{threat.explanation}</p>
            </div>
          )}
          {threat.recommendation && (
            <div>
              <h3 className="text-sm font-medium text-gray-500 mb-2">Recommendation</h3>
              <p className="text-gray-700 bg-blue-50 rounded-lg p-4">{threat.recommendation}</p>
            </div>
          )}
        </div>
      )}

      {/* Detection Signals Card */}
      {threat.signals && threat.signals.length > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Detection Signals</h2>
          <div className="space-y-3">
            {threat.signals.map((signal, index) => (
              <div
                key={index}
                className={`border rounded-lg p-4 ${getSeverityColor(signal.severity)}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium">{signal.type}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-sm uppercase">{signal.severity}</span>
                    <span className="text-sm font-mono">+{signal.score}</span>
                  </div>
                </div>
                <p className="text-sm">{signal.description}</p>
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

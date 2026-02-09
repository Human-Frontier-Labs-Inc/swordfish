'use client';

import { useState, useEffect, useCallback } from 'react';
import { useTenant } from '@/lib/auth/tenant-context';
import Link from 'next/link';

interface Threat {
  id: string;
  subject: string;
  sender_email: string;
  sender_name: string;
  threat_type: string;
  verdict: string;
  score: number;
  status: string;
  quarantined_at: string;
  explanation: string;
}

export default function ThreatsPage() {
  const { currentTenant } = useTenant();
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'quarantined' | 'released' | 'deleted'>('all');
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const fetchThreats = useCallback(async () => {
    if (!currentTenant) return;

    try {
      const params = new URLSearchParams();
      // Always send status parameter - API needs explicit 'all' to show all statuses
      params.set('status', filter);

      const response = await fetch(`/api/threats?${params}`);
      if (!response.ok) throw new Error('Failed to fetch threats');

      const data = await response.json();
      setThreats(data.threats || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load threats');
    } finally {
      setLoading(false);
    }
  }, [currentTenant, filter]);

  useEffect(() => {
    fetchThreats();
  }, [fetchThreats]);

  async function releaseThreat(threatId: string) {
    setActionLoading(threatId);
    try {
      const response = await fetch(`/api/threats/${threatId}/release`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ addToAllowlist: false }),
      });
      if (!response.ok) {
        const data = await response.json();
        setError(`Release failed: ${data.error || 'Unknown error'}`);
        return;
      }
      await fetchThreats();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Release failed');
    } finally {
      setActionLoading(null);
    }
  }

  async function deleteThreat(threatId: string) {
    if (!confirm('Permanently delete this email?')) return;
    setActionLoading(threatId);
    try {
      const response = await fetch(`/api/threats/${threatId}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        const data = await response.json();
        setError(`Delete failed: ${data.error || 'Unknown error'}`);
        return;
      }
      await fetchThreats();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed');
    } finally {
      setActionLoading(null);
    }
  }

  const getThreatTypeBadge = (type: string) => {
    const colors: Record<string, string> = {
      phishing: 'bg-red-100 text-red-800',
      malware: 'bg-purple-100 text-purple-800',
      spam: 'bg-yellow-100 text-yellow-800',
      bec: 'bg-orange-100 text-orange-800',
    };
    return colors[type] || 'bg-gray-100 text-gray-800';
  };

  const getStatusBadge = (status: string) => {
    const colors: Record<string, string> = {
      quarantined: 'bg-amber-100 text-amber-800',
      released: 'bg-green-100 text-green-800',
      deleted: 'bg-red-100 text-red-800',
      dismissed: 'bg-gray-100 text-gray-800',
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Threats</h1>
          <p className="mt-1 text-sm text-gray-500">
            View and manage detected email threats
          </p>
        </div>
        <Link
          href="/dashboard/threats/bulk"
          className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700"
        >
          Bulk Actions
        </Link>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow p-4">
        <div className="flex items-center gap-4">
          <span className="text-sm font-medium text-gray-700">Filter:</span>
          <div className="flex gap-2">
            {(['all', 'quarantined', 'released', 'deleted'] as const).map((status) => (
              <button
                key={status}
                onClick={() => setFilter(status)}
                className={`px-3 py-1 rounded-full text-sm font-medium transition-colors ${
                  filter === status
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                }`}
              >
                {status.charAt(0).toUpperCase() + status.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Error State */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <p className="text-red-800">{error}</p>
        </div>
      )}

      {/* Threats Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        {threats.length === 0 ? (
          <div className="p-8 text-center">
            <ShieldCheckIcon className="mx-auto h-12 w-12 text-green-500" />
            <h3 className="mt-2 text-lg font-medium text-gray-900">No threats found</h3>
            <p className="mt-1 text-sm text-gray-500">
              {filter === 'all'
                ? 'No email threats have been detected yet.'
                : `No ${filter} threats found.`}
            </p>
          </div>
        ) : (
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Email
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Threat Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Score
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Detected
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {threats.map((threat) => (
                <tr key={threat.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div className="text-sm font-medium text-gray-900 truncate max-w-xs">
                      {threat.subject || '(No subject)'}
                    </div>
                    <div className="text-sm text-gray-500">
                      {threat.sender_name ? `${threat.sender_name} <${threat.sender_email}>` : threat.sender_email}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getThreatTypeBadge(threat.threat_type)}`}>
                      {threat.threat_type || 'Unknown'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
                        <div
                          className={`h-2 rounded-full ${threat.score >= 80 ? 'bg-red-500' : threat.score >= 50 ? 'bg-yellow-500' : 'bg-green-500'}`}
                          style={{ width: `${threat.score}%` }}
                        />
                      </div>
                      <span className="text-sm text-gray-700">{threat.score}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusBadge(threat.status)}`}>
                      {threat.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {threat.quarantined_at ? new Date(threat.quarantined_at).toLocaleDateString() : '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <Link
                      href={`/dashboard/threats/${threat.id}`}
                      className="text-blue-600 hover:text-blue-900 mr-3"
                    >
                      View
                    </Link>
                    {threat.status === 'quarantined' && (
                      <>
                        <button
                          onClick={() => releaseThreat(threat.id)}
                          disabled={actionLoading === threat.id}
                          className="text-green-600 hover:text-green-900 mr-3 disabled:opacity-50"
                        >
                          {actionLoading === threat.id ? '...' : 'Release'}
                        </button>
                        <button
                          onClick={() => deleteThreat(threat.id)}
                          disabled={actionLoading === threat.id}
                          className="text-red-600 hover:text-red-900 disabled:opacity-50"
                        >
                          Delete
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function ShieldCheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  );
}

'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface Threat {
  id: string;
  tenantId: string;
  tenantName: string;
  messageId: string;
  subject: string;
  senderEmail: string;
  recipientEmail: string;
  verdict: 'malicious' | 'phishing' | 'suspicious';
  score: number;
  categories: string[];
  status: 'quarantined' | 'released' | 'deleted';
  integrationType: string | null;
  receivedAt: string | null;
  createdAt: string;
  releasedAt: string | null;
  releasedBy: string | null;
  deletedAt: string | null;
  deletedBy: string | null;
}

interface ThreatStats {
  total: number;
  quarantined: number;
  released: number;
  deleted: number;
  malicious: number;
  phishing: number;
  suspicious: number;
  last_24h: number;
  last_7d: number;
  avg_score: number;
}

interface TenantBreakdown {
  tenant_id: string;
  tenant_name: string | null;
  threat_count: number;
  quarantined: number;
}

interface Pagination {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export default function AdminThreatsPage() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [tenantBreakdown, setTenantBreakdown] = useState<TenantBreakdown[]>([]);
  const [loading, setLoading] = useState(true);
  const [pagination, setPagination] = useState<Pagination>({
    page: 1,
    limit: 50,
    total: 0,
    totalPages: 0,
  });
  const [filters, setFilters] = useState({
    status: 'all',
    tenantId: '',
    verdict: '',
    search: '',
  });
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [tenants, setTenants] = useState<{ id: string; name: string }[]>([]);

  useEffect(() => {
    loadTenants();
  }, []);

  useEffect(() => {
    loadThreats();
  }, [pagination.page, filters]);

  async function loadTenants() {
    try {
      const response = await fetch('/api/admin/tenants?limit=100');
      if (response.ok) {
        const data = await response.json();
        setTenants(data.tenants.map((t: { id: string; clerkOrgId: string; name: string }) => ({
          id: t.clerkOrgId || t.id,
          name: t.name,
        })));
      }
    } catch (error) {
      console.error('Failed to load tenants:', error);
    }
  }

  async function loadThreats() {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      params.set('page', pagination.page.toString());
      params.set('limit', pagination.limit.toString());
      params.set('stats', 'true');

      if (filters.status !== 'all') params.set('status', filters.status);
      if (filters.tenantId) params.set('tenantId', filters.tenantId);
      if (filters.verdict) params.set('verdict', filters.verdict);
      if (filters.search) params.set('search', filters.search);

      const response = await fetch(`/api/admin/threats?${params}`);
      if (response.ok) {
        const data = await response.json();
        setThreats(data.threats);
        setPagination(data.pagination);
        setStats(data.stats || null);
        setTenantBreakdown(data.tenantBreakdown || []);
      }
    } catch (error) {
      console.error('Failed to load threats:', error);
    } finally {
      setLoading(false);
    }
  }

  function handleFilterChange(key: keyof typeof filters, value: string) {
    setFilters({ ...filters, [key]: value });
    setPagination({ ...pagination, page: 1 });
  }

  function clearFilters() {
    setFilters({
      status: 'all',
      tenantId: '',
      verdict: '',
      search: '',
    });
    setPagination({ ...pagination, page: 1 });
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Threats Overview</h1>
        <button
          onClick={loadThreats}
          className="text-blue-600 hover:text-blue-800 text-sm font-medium"
        >
          Refresh
        </button>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          <StatCard label="Total Threats" value={stats.total} />
          <StatCard label="Quarantined" value={stats.quarantined} color="yellow" />
          <StatCard label="Released" value={stats.released} color="green" />
          <StatCard label="Last 24h" value={stats.last_24h} color="blue" />
          <StatCard label="Last 7 Days" value={stats.last_7d} color="purple" />
          <StatCard label="Avg Score" value={stats.avg_score || 0} suffix="%" color="red" />
        </div>
      )}

      {/* Tenant Breakdown */}
      {tenantBreakdown.length > 0 && !filters.tenantId && (
        <div className="bg-white rounded-lg border p-4">
          <h3 className="text-sm font-medium text-gray-900 mb-3">Threats by Tenant</h3>
          <div className="flex flex-wrap gap-2">
            {tenantBreakdown.map((tb) => (
              <button
                key={tb.tenant_id}
                onClick={() => handleFilterChange('tenantId', tb.tenant_id)}
                className="flex items-center gap-2 px-3 py-1.5 bg-gray-100 hover:bg-gray-200 rounded-full text-sm transition-colors"
              >
                <span>{tb.tenant_name || 'Unknown'}</span>
                <span className="bg-red-100 text-red-700 px-2 py-0.5 rounded-full text-xs font-medium">
                  {tb.quarantined}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-white rounded-lg border p-4">
        <div className="flex flex-wrap gap-4">
          <input
            type="text"
            placeholder="Search subject, sender, recipient..."
            value={filters.search}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            className="border rounded-lg px-4 py-2 w-64"
          />
          <select
            value={filters.status}
            onChange={(e) => handleFilterChange('status', e.target.value)}
            className="border rounded-lg px-4 py-2"
          >
            <option value="all">All Statuses</option>
            <option value="quarantined">Quarantined</option>
            <option value="released">Released</option>
            <option value="deleted">Deleted</option>
          </select>
          <select
            value={filters.verdict}
            onChange={(e) => handleFilterChange('verdict', e.target.value)}
            className="border rounded-lg px-4 py-2"
          >
            <option value="">All Verdicts</option>
            <option value="malicious">Malicious</option>
            <option value="phishing">Phishing</option>
            <option value="suspicious">Suspicious</option>
          </select>
          <select
            value={filters.tenantId}
            onChange={(e) => handleFilterChange('tenantId', e.target.value)}
            className="border rounded-lg px-4 py-2"
          >
            <option value="">All Tenants</option>
            {tenants.map((t) => (
              <option key={t.id} value={t.id}>{t.name}</option>
            ))}
          </select>
          {(filters.status !== 'all' || filters.tenantId || filters.verdict || filters.search) && (
            <button
              onClick={clearFilters}
              className="text-gray-600 hover:text-gray-800 text-sm px-3 py-2"
            >
              Clear Filters
            </button>
          )}
        </div>
      </div>

      {/* Threats Table */}
      <div className="bg-white rounded-lg border overflow-hidden">
        {loading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto" />
          </div>
        ) : threats.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            <svg className="w-12 h-12 mx-auto mb-4 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <p className="font-medium">No threats found</p>
            <p className="text-sm mt-1">
              {filters.status !== 'all' || filters.tenantId || filters.verdict || filters.search
                ? 'Try adjusting your filters'
                : 'Your tenants are secure!'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Tenant
                  </th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Email
                  </th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Verdict
                  </th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Score
                  </th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Status
                  </th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Detected
                  </th>
                  <th className="text-right px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {threats.map((threat) => (
                  <tr key={threat.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4">
                      <Link
                        href={`/admin/tenants/${threat.tenantId}`}
                        className="text-sm text-blue-600 hover:text-blue-800"
                      >
                        {threat.tenantName}
                      </Link>
                    </td>
                    <td className="px-6 py-4">
                      <div>
                        <p className="font-medium text-gray-900 truncate max-w-xs" title={threat.subject}>
                          {threat.subject || '(No Subject)'}
                        </p>
                        <p className="text-sm text-gray-500 truncate max-w-xs" title={threat.senderEmail}>
                          From: {threat.senderEmail}
                        </p>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <VerdictBadge verdict={threat.verdict} />
                    </td>
                    <td className="px-6 py-4">
                      <ScoreBar score={threat.score} />
                    </td>
                    <td className="px-6 py-4">
                      <StatusBadge status={threat.status} />
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {new Date(threat.createdAt).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => setSelectedThreat(threat)}
                        className="text-blue-600 hover:text-blue-800 text-sm"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {pagination.totalPages > 1 && (
          <div className="border-t px-6 py-4 flex items-center justify-between">
            <p className="text-sm text-gray-500">
              Showing {(pagination.page - 1) * pagination.limit + 1} to{' '}
              {Math.min(pagination.page * pagination.limit, pagination.total)} of{' '}
              {pagination.total} threats
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setPagination({ ...pagination, page: pagination.page - 1 })}
                disabled={pagination.page === 1}
                className="px-3 py-1 border rounded text-sm disabled:opacity-50"
              >
                Previous
              </button>
              <button
                onClick={() => setPagination({ ...pagination, page: pagination.page + 1 })}
                disabled={pagination.page === pagination.totalPages}
                className="px-3 py-1 border rounded text-sm disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selectedThreat && (
        <ThreatDetailModal threat={selectedThreat} onClose={() => setSelectedThreat(null)} />
      )}
    </div>
  );
}

function StatCard({ label, value, suffix = '', color = 'gray' }: {
  label: string;
  value: number;
  suffix?: string;
  color?: 'gray' | 'red' | 'yellow' | 'green' | 'blue' | 'purple';
}) {
  const colors = {
    gray: 'bg-gray-50',
    red: 'bg-red-50',
    yellow: 'bg-yellow-50',
    green: 'bg-green-50',
    blue: 'bg-blue-50',
    purple: 'bg-purple-50',
  };

  return (
    <div className={`rounded-lg p-4 ${colors[color]}`}>
      <p className="text-sm text-gray-600">{label}</p>
      <p className="text-2xl font-bold text-gray-900 mt-1">
        {value.toLocaleString()}{suffix}
      </p>
    </div>
  );
}

function VerdictBadge({ verdict }: { verdict: string }) {
  const colors: Record<string, string> = {
    malicious: 'bg-red-100 text-red-700',
    phishing: 'bg-orange-100 text-orange-700',
    suspicious: 'bg-yellow-100 text-yellow-700',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded ${colors[verdict] || 'bg-gray-100 text-gray-700'}`}>
      {verdict.charAt(0).toUpperCase() + verdict.slice(1)}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    quarantined: 'bg-yellow-100 text-yellow-700',
    released: 'bg-green-100 text-green-700',
    deleted: 'bg-gray-100 text-gray-500',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded ${colors[status] || 'bg-gray-100 text-gray-700'}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

function ScoreBar({ score }: { score: number }) {
  const getColor = () => {
    if (score >= 80) return 'bg-red-500';
    if (score >= 60) return 'bg-orange-500';
    if (score >= 40) return 'bg-yellow-500';
    return 'bg-gray-400';
  };

  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-2 bg-gray-200 rounded-full overflow-hidden">
        <div className={`h-full ${getColor()}`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-sm text-gray-600">{score}</span>
    </div>
  );
}

function ThreatDetailModal({ threat, onClose }: { threat: Threat; onClose: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
        <div className="sticky top-0 bg-white border-b px-6 py-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">Threat Details</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="p-6 space-y-6">
          {/* Header Info */}
          <div className="flex items-start justify-between">
            <div>
              <VerdictBadge verdict={threat.verdict} />
              <StatusBadge status={threat.status} />
            </div>
            <ScoreBar score={threat.score} />
          </div>

          {/* Email Details */}
          <div className="space-y-3">
            <div>
              <p className="text-sm text-gray-500">Subject</p>
              <p className="font-medium">{threat.subject || '(No Subject)'}</p>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-gray-500">From</p>
                <p className="font-medium">{threat.senderEmail}</p>
              </div>
              <div>
                <p className="text-sm text-gray-500">To</p>
                <p className="font-medium">{threat.recipientEmail}</p>
              </div>
            </div>
          </div>

          {/* Tenant & Timing */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-sm text-gray-500">Tenant</p>
              <Link
                href={`/admin/tenants/${threat.tenantId}`}
                className="font-medium text-blue-600 hover:text-blue-800"
              >
                {threat.tenantName}
              </Link>
            </div>
            <div>
              <p className="text-sm text-gray-500">Detected At</p>
              <p className="font-medium">{new Date(threat.createdAt).toLocaleString()}</p>
            </div>
          </div>

          {/* Categories */}
          {threat.categories && threat.categories.length > 0 && (
            <div>
              <p className="text-sm text-gray-500 mb-2">Threat Categories</p>
              <div className="flex flex-wrap gap-2">
                {threat.categories.map((cat, i) => (
                  <span key={i} className="px-2 py-1 bg-red-50 text-red-700 text-sm rounded">
                    {cat}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Status History */}
          {(threat.releasedAt || threat.deletedAt) && (
            <div>
              <p className="text-sm text-gray-500 mb-2">Status History</p>
              <div className="space-y-2 text-sm">
                {threat.releasedAt && (
                  <p>
                    <span className="text-green-600">Released</span> on{' '}
                    {new Date(threat.releasedAt).toLocaleString()}
                    {threat.releasedBy && ` by ${threat.releasedBy}`}
                  </p>
                )}
                {threat.deletedAt && (
                  <p>
                    <span className="text-gray-500">Deleted</span> on{' '}
                    {new Date(threat.deletedAt).toLocaleString()}
                    {threat.deletedBy && ` by ${threat.deletedBy}`}
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Integration */}
          {threat.integrationType && (
            <div>
              <p className="text-sm text-gray-500">Integration</p>
              <p className="font-medium capitalize">{threat.integrationType}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

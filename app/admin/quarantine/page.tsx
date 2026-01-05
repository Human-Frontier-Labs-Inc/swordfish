'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface QuarantineItem {
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
  integrationType: string | null;
  originalLocation: string | null;
  receivedAt: string | null;
  quarantinedAt: string;
}

interface QuarantineStats {
  total_quarantined: number;
  malicious: number;
  phishing: number;
  suspicious: number;
  high_severity: number;
  medium_severity: number;
  low_severity: number;
  last_24h: number;
}

interface Pagination {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export default function AdminQuarantinePage() {
  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [stats, setStats] = useState<QuarantineStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [pagination, setPagination] = useState<Pagination>({
    page: 1,
    limit: 50,
    total: 0,
    totalPages: 0,
  });
  const [filters, setFilters] = useState({
    tenantId: '',
    verdict: '',
    search: '',
  });
  const [selectedItems, setSelectedItems] = useState<Set<string>>(new Set());
  const [bulkActionLoading, setBulkActionLoading] = useState(false);
  const [tenants, setTenants] = useState<{ id: string; name: string }[]>([]);

  useEffect(() => {
    loadTenants();
  }, []);

  useEffect(() => {
    loadQuarantine();
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

  async function loadQuarantine() {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      params.set('page', pagination.page.toString());
      params.set('limit', pagination.limit.toString());

      if (filters.tenantId) params.set('tenantId', filters.tenantId);
      if (filters.verdict) params.set('verdict', filters.verdict);
      if (filters.search) params.set('search', filters.search);

      const response = await fetch(`/api/admin/quarantine?${params}`);
      if (response.ok) {
        const data = await response.json();
        setItems(data.quarantine);
        setPagination(data.pagination);
        setStats(data.stats || null);
        setSelectedItems(new Set());
      }
    } catch (error) {
      console.error('Failed to load quarantine:', error);
    } finally {
      setLoading(false);
    }
  }

  function handleFilterChange(key: keyof typeof filters, value: string) {
    setFilters({ ...filters, [key]: value });
    setPagination({ ...pagination, page: 1 });
  }

  function toggleSelectItem(id: string) {
    const newSelected = new Set(selectedItems);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedItems(newSelected);
  }

  function toggleSelectAll() {
    if (selectedItems.size === items.length) {
      setSelectedItems(new Set());
    } else {
      setSelectedItems(new Set(items.map(i => i.id)));
    }
  }

  async function handleBulkAction(action: 'release' | 'delete') {
    if (selectedItems.size === 0) return;

    const confirmMsg = action === 'release'
      ? `Release ${selectedItems.size} email(s) from quarantine?`
      : `Permanently delete ${selectedItems.size} email(s)?`;

    if (!confirm(confirmMsg)) return;

    try {
      setBulkActionLoading(true);
      const response = await fetch('/api/admin/quarantine', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threatIds: Array.from(selectedItems),
          action,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        alert(`Successfully ${action === 'release' ? 'released' : 'deleted'} ${data.results.success} email(s)`);
        loadQuarantine();
      } else {
        const error = await response.json();
        alert(error.error || 'Failed to perform action');
      }
    } catch (error) {
      console.error('Bulk action error:', error);
      alert('Failed to perform action');
    } finally {
      setBulkActionLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Quarantine Management</h1>
        <button
          onClick={loadQuarantine}
          className="text-blue-600 hover:text-blue-800 text-sm font-medium"
        >
          Refresh
        </button>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
          <StatCard label="Total" value={stats.total_quarantined} color="gray" />
          <StatCard label="New (24h)" value={stats.last_24h} color="blue" />
          <StatCard label="High Risk" value={stats.high_severity} color="red" />
          <StatCard label="Medium" value={stats.medium_severity} color="orange" />
          <StatCard label="Low" value={stats.low_severity} color="yellow" />
          <StatCard label="Malicious" value={stats.malicious} color="red" />
          <StatCard label="Phishing" value={stats.phishing} color="orange" />
          <StatCard label="Suspicious" value={stats.suspicious} color="yellow" />
        </div>
      )}

      {/* Filters and Bulk Actions */}
      <div className="bg-white rounded-lg border p-4">
        <div className="flex flex-wrap items-center gap-4">
          <input
            type="text"
            placeholder="Search subject, sender..."
            value={filters.search}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            className="border rounded-lg px-4 py-2 w-64"
          />
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

          {/* Bulk Actions */}
          {selectedItems.size > 0 && (
            <div className="flex items-center gap-2 ml-auto">
              <span className="text-sm text-gray-600">
                {selectedItems.size} selected
              </span>
              <button
                onClick={() => handleBulkAction('release')}
                disabled={bulkActionLoading}
                className="px-3 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 text-sm"
              >
                Release Selected
              </button>
              <button
                onClick={() => handleBulkAction('delete')}
                disabled={bulkActionLoading}
                className="px-3 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50 text-sm"
              >
                Delete Selected
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Quarantine Table */}
      <div className="bg-white rounded-lg border overflow-hidden">
        {loading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto" />
          </div>
        ) : items.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            <svg className="w-12 h-12 mx-auto mb-4 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
            </svg>
            <p className="font-medium">Quarantine is empty</p>
            <p className="text-sm mt-1">No emails currently in quarantine</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 w-10">
                    <input
                      type="checkbox"
                      checked={selectedItems.size === items.length && items.length > 0}
                      onChange={toggleSelectAll}
                      className="rounded"
                    />
                  </th>
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
                    Quarantined
                  </th>
                  <th className="text-right px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {items.map((item) => (
                  <tr key={item.id} className={`hover:bg-gray-50 ${selectedItems.has(item.id) ? 'bg-blue-50' : ''}`}>
                    <td className="px-6 py-4">
                      <input
                        type="checkbox"
                        checked={selectedItems.has(item.id)}
                        onChange={() => toggleSelectItem(item.id)}
                        className="rounded"
                      />
                    </td>
                    <td className="px-6 py-4">
                      <Link
                        href={`/admin/tenants/${item.tenantId}`}
                        className="text-sm text-blue-600 hover:text-blue-800"
                      >
                        {item.tenantName}
                      </Link>
                    </td>
                    <td className="px-6 py-4">
                      <div>
                        <p className="font-medium text-gray-900 truncate max-w-xs" title={item.subject}>
                          {item.subject || '(No Subject)'}
                        </p>
                        <p className="text-sm text-gray-500 truncate max-w-xs" title={item.senderEmail}>
                          From: {item.senderEmail}
                        </p>
                        <p className="text-sm text-gray-400 truncate max-w-xs" title={item.recipientEmail}>
                          To: {item.recipientEmail}
                        </p>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <VerdictBadge verdict={item.verdict} />
                    </td>
                    <td className="px-6 py-4">
                      <ScoreBar score={item.score} />
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {new Date(item.quarantinedAt).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => handleSingleAction(item.id, 'release')}
                          className="text-green-600 hover:text-green-800 text-sm"
                        >
                          Release
                        </button>
                        <button
                          onClick={() => handleSingleAction(item.id, 'delete')}
                          className="text-red-600 hover:text-red-800 text-sm"
                        >
                          Delete
                        </button>
                      </div>
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
              {pagination.total} items
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
    </div>
  );

  async function handleSingleAction(id: string, action: 'release' | 'delete') {
    const confirmMsg = action === 'release'
      ? 'Release this email from quarantine?'
      : 'Permanently delete this email?';

    if (!confirm(confirmMsg)) return;

    try {
      const response = await fetch('/api/admin/quarantine', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threatIds: [id],
          action,
        }),
      });

      if (response.ok) {
        loadQuarantine();
      } else {
        const error = await response.json();
        alert(error.error || 'Failed to perform action');
      }
    } catch (error) {
      console.error('Action error:', error);
      alert('Failed to perform action');
    }
  }
}

function StatCard({ label, value, color = 'gray' }: {
  label: string;
  value: number;
  color?: 'gray' | 'red' | 'orange' | 'yellow' | 'green' | 'blue';
}) {
  const colors = {
    gray: 'bg-gray-50',
    red: 'bg-red-50',
    orange: 'bg-orange-50',
    yellow: 'bg-yellow-50',
    green: 'bg-green-50',
    blue: 'bg-blue-50',
  };

  return (
    <div className={`rounded-lg p-3 ${colors[color]}`}>
      <p className="text-xs text-gray-600">{label}</p>
      <p className="text-xl font-bold text-gray-900">{value.toLocaleString()}</p>
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

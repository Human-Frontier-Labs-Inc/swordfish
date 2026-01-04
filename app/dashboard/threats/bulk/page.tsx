'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface ThreatItem {
  id: string;
  emailId: string;
  subject: string;
  fromAddress: string;
  toAddress: string;
  verdict: string;
  mlClassification: string;
  confidenceScore: number;
  createdAt: string;
}

export default function BulkThreatsPage() {
  const [threats, setThreats] = useState<ThreatItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [processing, setProcessing] = useState(false);
  const [filters, setFilters] = useState({
    verdict: '',
    classification: '',
    dateRange: '30',
  });

  useEffect(() => {
    loadThreats();
  }, [filters]);

  async function loadThreats() {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (filters.verdict) params.set('verdict', filters.verdict);
      if (filters.classification) params.set('classification', filters.classification);
      params.set('days', filters.dateRange);
      params.set('limit', '100');

      const response = await fetch(`/api/threats?${params}`);
      if (response.ok) {
        const data = await response.json();
        setThreats(data.threats);
      }
    } catch (error) {
      console.error('Failed to load threats:', error);
    } finally {
      setLoading(false);
    }
  }

  function toggleSelect(id: string) {
    const newSelected = new Set(selectedIds);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedIds(newSelected);
  }

  function toggleSelectAll() {
    if (selectedIds.size === threats.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(threats.map(t => t.id)));
    }
  }

  async function handleBulkAction(action: 'false_positive' | 'confirm_threat' | 'blocklist' | 'allowlist') {
    if (selectedIds.size === 0) return;

    const confirmMessage = {
      false_positive: `Mark ${selectedIds.size} items as false positives?`,
      confirm_threat: `Confirm ${selectedIds.size} items as threats?`,
      blocklist: `Add senders to blocklist?`,
      allowlist: `Add senders to allowlist?`,
    };

    if (!confirm(confirmMessage[action])) return;

    try {
      setProcessing(true);
      const response = await fetch('/api/threats/bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action,
          ids: Array.from(selectedIds),
        }),
      });

      if (response.ok) {
        const result = await response.json();
        alert(`Successfully processed ${result.processed} items`);
        setSelectedIds(new Set());
        loadThreats();
      } else {
        const error = await response.json();
        alert(`Error: ${error.error}`);
      }
    } catch (error) {
      console.error('Bulk action failed:', error);
      alert('Failed to process bulk action');
    } finally {
      setProcessing(false);
    }
  }

  function getVerdictColor(verdict: string): string {
    switch (verdict) {
      case 'block': return 'bg-red-100 text-red-700';
      case 'quarantine': return 'bg-yellow-100 text-yellow-700';
      case 'review': return 'bg-blue-100 text-blue-700';
      case 'pass': return 'bg-green-100 text-green-700';
      default: return 'bg-gray-100 text-gray-700';
    }
  }

  function getClassificationColor(classification: string): string {
    switch (classification) {
      case 'phishing': return 'text-red-600';
      case 'malware': return 'text-purple-600';
      case 'spam': return 'text-yellow-600';
      case 'suspicious': return 'text-orange-600';
      default: return 'text-gray-600';
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Link href="/dashboard" className="text-gray-400 hover:text-gray-600">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <h1 className="text-2xl font-bold text-gray-900">Bulk Threat Management</h1>
          </div>
          <p className="text-gray-600 mt-1">Review and process multiple threat detections at once</p>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg border p-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Verdict</label>
            <select
              value={filters.verdict}
              onChange={(e) => setFilters({ ...filters, verdict: e.target.value })}
              className="w-full border rounded-lg px-3 py-2"
            >
              <option value="">All Verdicts</option>
              <option value="block">Blocked</option>
              <option value="quarantine">Quarantined</option>
              <option value="review">Review</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Classification</label>
            <select
              value={filters.classification}
              onChange={(e) => setFilters({ ...filters, classification: e.target.value })}
              className="w-full border rounded-lg px-3 py-2"
            >
              <option value="">All Types</option>
              <option value="phishing">Phishing</option>
              <option value="malware">Malware</option>
              <option value="spam">Spam</option>
              <option value="suspicious">Suspicious</option>
              <option value="bec">Business Email Compromise</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Date Range</label>
            <select
              value={filters.dateRange}
              onChange={(e) => setFilters({ ...filters, dateRange: e.target.value })}
              className="w-full border rounded-lg px-3 py-2"
            >
              <option value="7">Last 7 days</option>
              <option value="14">Last 14 days</option>
              <option value="30">Last 30 days</option>
              <option value="90">Last 90 days</option>
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={loadThreats}
              className="w-full bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-lg"
            >
              Refresh
            </button>
          </div>
        </div>
      </div>

      {/* Bulk Actions */}
      <div className="bg-white rounded-lg border p-4">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-600">
              {selectedIds.size} of {threats.length} selected
            </span>
            {selectedIds.size > 0 && (
              <button
                onClick={() => setSelectedIds(new Set())}
                className="text-sm text-blue-600 hover:text-blue-800"
              >
                Clear selection
              </button>
            )}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => handleBulkAction('false_positive')}
              disabled={selectedIds.size === 0 || processing}
              className="bg-green-600 text-white px-3 py-2 rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed text-sm"
            >
              Mark False Positive
            </button>
            <button
              onClick={() => handleBulkAction('confirm_threat')}
              disabled={selectedIds.size === 0 || processing}
              className="bg-red-600 text-white px-3 py-2 rounded-lg hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed text-sm"
            >
              Confirm as Threat
            </button>
            <button
              onClick={() => handleBulkAction('blocklist')}
              disabled={selectedIds.size === 0 || processing}
              className="bg-orange-600 text-white px-3 py-2 rounded-lg hover:bg-orange-700 disabled:opacity-50 disabled:cursor-not-allowed text-sm"
            >
              Add to Blocklist
            </button>
            <button
              onClick={() => handleBulkAction('allowlist')}
              disabled={selectedIds.size === 0 || processing}
              className="bg-blue-600 text-white px-3 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-sm"
            >
              Add to Allowlist
            </button>
          </div>
        </div>
      </div>

      {/* Threats Table */}
      {loading ? (
        <div className="bg-white rounded-lg border p-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto" />
        </div>
      ) : threats.length === 0 ? (
        <div className="bg-white rounded-lg border p-12 text-center">
          <svg className="w-16 h-16 mx-auto text-gray-300 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <h3 className="text-lg font-medium text-gray-900 mb-2">No threats found</h3>
          <p className="text-gray-500">No threats match your current filters.</p>
        </div>
      ) : (
        <div className="bg-white rounded-lg border overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left">
                    <input
                      type="checkbox"
                      checked={selectedIds.size === threats.length && threats.length > 0}
                      onChange={toggleSelectAll}
                      className="rounded border-gray-300"
                    />
                  </th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">Subject</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">From</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">Verdict</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">Type</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">Confidence</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {threats.map((threat) => (
                  <tr
                    key={threat.id}
                    className={`hover:bg-gray-50 ${selectedIds.has(threat.id) ? 'bg-blue-50' : ''}`}
                  >
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedIds.has(threat.id)}
                        onChange={() => toggleSelect(threat.id)}
                        className="rounded border-gray-300"
                      />
                    </td>
                    <td className="px-4 py-3">
                      <p className="font-medium text-gray-900 truncate max-w-[200px]" title={threat.subject}>
                        {threat.subject || '(No subject)'}
                      </p>
                      <p className="text-xs text-gray-500 truncate max-w-[200px]">{threat.toAddress}</p>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600 truncate max-w-[150px]" title={threat.fromAddress}>
                      {threat.fromAddress}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 text-xs rounded capitalize ${getVerdictColor(threat.verdict)}`}>
                        {threat.verdict}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-sm capitalize ${getClassificationColor(threat.mlClassification)}`}>
                        {threat.mlClassification || 'unknown'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600">
                      {(threat.confidenceScore * 100).toFixed(0)}%
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-500">
                      {new Date(threat.createdAt).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-blue-600 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <h4 className="font-medium text-blue-900">False Positives</h4>
              <p className="text-sm text-blue-700 mt-1">
                Marking emails as false positives helps improve our ML model accuracy and prevents future misclassifications.
              </p>
            </div>
          </div>
        </div>
        <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-orange-600 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div>
              <h4 className="font-medium text-orange-900">Block/Allow Lists</h4>
              <p className="text-sm text-orange-700 mt-1">
                Adding senders to lists applies globally to all future emails from those addresses or domains.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

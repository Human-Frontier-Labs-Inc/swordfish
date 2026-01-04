'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface QuarantineItem {
  id: string;
  emailId: string;
  subject: string;
  fromAddress: string;
  toAddress: string;
  mlClassification: string;
  confidenceScore: number;
  status: string;
  createdAt: string;
}

export default function BulkQuarantinePage() {
  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [processing, setProcessing] = useState(false);
  const [filters, setFilters] = useState({
    classification: '',
    minConfidence: 0,
    maxAge: 30,
  });

  useEffect(() => {
    loadQuarantineItems();
  }, [filters]);

  async function loadQuarantineItems() {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (filters.classification) params.set('classification', filters.classification);
      if (filters.minConfidence) params.set('minConfidence', filters.minConfidence.toString());
      params.set('maxAge', filters.maxAge.toString());
      params.set('status', 'quarantined');
      params.set('limit', '100');

      const response = await fetch(`/api/quarantine?${params}`);
      if (response.ok) {
        const data = await response.json();
        setItems(data.items);
      }
    } catch (error) {
      console.error('Failed to load items:', error);
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
    if (selectedIds.size === items.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(items.map(i => i.id)));
    }
  }

  async function handleBulkAction(action: 'release' | 'delete' | 'block') {
    if (selectedIds.size === 0) return;

    const confirmMessage = {
      release: `Release ${selectedIds.size} emails from quarantine?`,
      delete: `Permanently delete ${selectedIds.size} emails?`,
      block: `Block senders of ${selectedIds.size} emails?`,
    };

    if (!confirm(confirmMessage[action])) return;

    try {
      setProcessing(true);
      const response = await fetch('/api/quarantine/bulk', {
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
        loadQuarantineItems();
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

  function getClassificationColor(classification: string): string {
    switch (classification) {
      case 'phishing': return 'bg-red-100 text-red-700';
      case 'malware': return 'bg-purple-100 text-purple-700';
      case 'spam': return 'bg-yellow-100 text-yellow-700';
      case 'suspicious': return 'bg-orange-100 text-orange-700';
      default: return 'bg-gray-100 text-gray-700';
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Link href="/dashboard/quarantine" className="text-gray-400 hover:text-gray-600">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <h1 className="text-2xl font-bold text-gray-900">Bulk Quarantine Management</h1>
          </div>
          <p className="text-gray-600 mt-1">Select multiple items for batch processing</p>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg border p-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
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
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Min Confidence</label>
            <select
              value={filters.minConfidence}
              onChange={(e) => setFilters({ ...filters, minConfidence: Number(e.target.value) })}
              className="w-full border rounded-lg px-3 py-2"
            >
              <option value={0}>Any</option>
              <option value={50}>50%+</option>
              <option value={70}>70%+</option>
              <option value={90}>90%+</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Age</label>
            <select
              value={filters.maxAge}
              onChange={(e) => setFilters({ ...filters, maxAge: Number(e.target.value) })}
              className="w-full border rounded-lg px-3 py-2"
            >
              <option value={7}>Last 7 days</option>
              <option value={14}>Last 14 days</option>
              <option value={30}>Last 30 days</option>
              <option value={90}>Last 90 days</option>
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={loadQuarantineItems}
              className="w-full bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-lg"
            >
              Refresh
            </button>
          </div>
        </div>
      </div>

      {/* Bulk Actions */}
      <div className="bg-white rounded-lg border p-4 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <span className="text-sm text-gray-600">
            {selectedIds.size} of {items.length} selected
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
        <div className="flex items-center gap-2">
          <button
            onClick={() => handleBulkAction('release')}
            disabled={selectedIds.size === 0 || processing}
            className="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Release Selected
          </button>
          <button
            onClick={() => handleBulkAction('block')}
            disabled={selectedIds.size === 0 || processing}
            className="bg-orange-600 text-white px-4 py-2 rounded-lg hover:bg-orange-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Block Senders
          </button>
          <button
            onClick={() => handleBulkAction('delete')}
            disabled={selectedIds.size === 0 || processing}
            className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Delete Selected
          </button>
        </div>
      </div>

      {/* Items Table */}
      {loading ? (
        <div className="bg-white rounded-lg border p-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto" />
        </div>
      ) : items.length === 0 ? (
        <div className="bg-white rounded-lg border p-12 text-center">
          <svg className="w-16 h-16 mx-auto text-gray-300 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
          </svg>
          <h3 className="text-lg font-medium text-gray-900 mb-2">No quarantined items</h3>
          <p className="text-gray-500">No items match your current filters.</p>
        </div>
      ) : (
        <div className="bg-white rounded-lg border overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left">
                  <input
                    type="checkbox"
                    checked={selectedIds.size === items.length && items.length > 0}
                    onChange={toggleSelectAll}
                    className="rounded border-gray-300"
                  />
                </th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">Subject</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">From</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">To</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">Classification</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">Confidence</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {items.map((item) => (
                <tr key={item.id} className={`hover:bg-gray-50 ${selectedIds.has(item.id) ? 'bg-blue-50' : ''}`}>
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={selectedIds.has(item.id)}
                      onChange={() => toggleSelect(item.id)}
                      className="rounded border-gray-300"
                    />
                  </td>
                  <td className="px-4 py-3">
                    <p className="font-medium text-gray-900 truncate max-w-[200px]" title={item.subject}>
                      {item.subject || '(No subject)'}
                    </p>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 truncate max-w-[150px]" title={item.fromAddress}>
                    {item.fromAddress}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 truncate max-w-[150px]" title={item.toAddress}>
                    {item.toAddress}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 text-xs rounded capitalize ${getClassificationColor(item.mlClassification)}`}>
                      {item.mlClassification || 'unknown'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600">
                    {(item.confidenceScore * 100).toFixed(0)}%
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500">
                    {new Date(item.createdAt).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Help Card */}
      <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <svg className="w-5 h-5 text-yellow-600 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <div>
            <h4 className="font-medium text-yellow-900">Bulk Action Tips</h4>
            <ul className="text-sm text-yellow-800 mt-1 space-y-1">
              <li>• <strong>Release</strong>: Delivers emails to recipients and marks as safe</li>
              <li>• <strong>Block Senders</strong>: Adds sender addresses to your blocklist</li>
              <li>• <strong>Delete</strong>: Permanently removes emails (cannot be undone)</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

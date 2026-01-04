'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface ExportJob {
  id: string;
  type: 'threats' | 'quarantine' | 'audit' | 'analytics' | 'custom';
  format: 'csv' | 'pdf' | 'xlsx' | 'json';
  status: 'pending' | 'processing' | 'completed' | 'failed';
  filters: Record<string, unknown>;
  fileUrl: string | null;
  fileSize: number | null;
  errorMessage: string | null;
  expiresAt: string | null;
  createdAt: string;
  completedAt: string | null;
}

const exportTypes = {
  threats: { name: 'Threat Report', icon: '🛡️' },
  quarantine: { name: 'Quarantine Export', icon: '📥' },
  audit: { name: 'Audit Log', icon: '📋' },
  analytics: { name: 'Analytics Data', icon: '📊' },
  custom: { name: 'Custom Export', icon: '📁' },
};

export default function ExportsPage() {
  const [exports, setExports] = useState<ExportJob[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadExports();
    // Poll for updates every 10 seconds
    const interval = setInterval(loadExports, 10000);
    return () => clearInterval(interval);
  }, []);

  async function loadExports() {
    try {
      const response = await fetch('/api/reports/exports');
      if (response.ok) {
        const data = await response.json();
        setExports(data.exports);
      }
    } catch (error) {
      console.error('Failed to load exports:', error);
    } finally {
      setLoading(false);
    }
  }

  function formatFileSize(bytes: number | null): string {
    if (!bytes) return '-';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function getStatusBadge(status: ExportJob['status']) {
    switch (status) {
      case 'completed':
        return <span className="px-2 py-1 text-xs rounded bg-green-100 text-green-700">Completed</span>;
      case 'processing':
        return <span className="px-2 py-1 text-xs rounded bg-blue-100 text-blue-700 animate-pulse">Processing</span>;
      case 'pending':
        return <span className="px-2 py-1 text-xs rounded bg-yellow-100 text-yellow-700">Pending</span>;
      case 'failed':
        return <span className="px-2 py-1 text-xs rounded bg-red-100 text-red-700">Failed</span>;
      default:
        return null;
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Link href="/dashboard/reports" className="text-gray-400 hover:text-gray-600">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <h1 className="text-2xl font-bold text-gray-900">Export History</h1>
          </div>
          <p className="text-gray-600 mt-1">Download your generated reports and exports</p>
        </div>
        <Link
          href="/dashboard/reports"
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
        >
          New Export
        </Link>
      </div>

      {/* Exports List */}
      {loading ? (
        <div className="bg-white rounded-lg border p-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto" />
        </div>
      ) : exports.length === 0 ? (
        <div className="bg-white rounded-lg border p-12 text-center">
          <svg className="w-16 h-16 mx-auto text-gray-300 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
          </svg>
          <h3 className="text-lg font-medium text-gray-900 mb-2">No exports yet</h3>
          <p className="text-gray-500 mb-4">Generate a report to see it here.</p>
          <Link
            href="/dashboard/reports"
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 inline-block"
          >
            Generate Report
          </Link>
        </div>
      ) : (
        <div className="bg-white rounded-lg border overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Report</th>
                <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Format</th>
                <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Status</th>
                <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Size</th>
                <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Created</th>
                <th className="text-right px-6 py-3 text-xs font-medium text-gray-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {exports.map((exportJob) => (
                <tr key={exportJob.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <span className="text-xl">{exportTypes[exportJob.type]?.icon || '📁'}</span>
                      <div>
                        <p className="font-medium text-gray-900">
                          {exportTypes[exportJob.type]?.name || 'Export'}
                        </p>
                        {exportJob.errorMessage && (
                          <p className="text-xs text-red-600">{exportJob.errorMessage}</p>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="px-2 py-1 text-xs bg-gray-100 rounded uppercase">
                      {exportJob.format}
                    </span>
                  </td>
                  <td className="px-6 py-4">{getStatusBadge(exportJob.status)}</td>
                  <td className="px-6 py-4 text-sm text-gray-500">
                    {formatFileSize(exportJob.fileSize)}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-500">
                    {new Date(exportJob.createdAt).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 text-right">
                    {exportJob.status === 'completed' && exportJob.fileUrl ? (
                      <a
                        href={exportJob.fileUrl}
                        download
                        className="text-blue-600 hover:text-blue-800 text-sm font-medium"
                      >
                        Download
                      </a>
                    ) : exportJob.status === 'processing' ? (
                      <span className="text-gray-400 text-sm">Processing...</span>
                    ) : exportJob.status === 'failed' ? (
                      <button className="text-blue-600 hover:text-blue-800 text-sm">
                        Retry
                      </button>
                    ) : (
                      <span className="text-gray-400 text-sm">Waiting...</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Info Card */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <svg className="w-5 h-5 text-blue-600 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <h4 className="font-medium text-blue-900">Export Retention</h4>
            <p className="text-sm text-blue-700 mt-1">
              Completed exports are available for download for 7 days. After that, they are automatically deleted.
              You can regenerate any report at any time from the Reports page.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

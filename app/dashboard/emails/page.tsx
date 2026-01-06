'use client';

import { useState, useEffect } from 'react';
import clsx from 'clsx';

interface ScannedEmail {
  id: string;
  messageId: string;
  verdict: 'pass' | 'suspicious' | 'quarantine' | 'block';
  score: number;
  confidence: number;
  signalCount: number;
  primarySignal: string;
  processingTimeMs: number;
  scannedAt: string;
}

const verdictConfig = {
  pass: {
    label: 'Safe',
    bgClass: 'bg-green-100',
    textClass: 'text-green-800',
    icon: '✓',
  },
  suspicious: {
    label: 'Suspicious',
    bgClass: 'bg-orange-100',
    textClass: 'text-orange-800',
    icon: '⚠',
  },
  quarantine: {
    label: 'Quarantined',
    bgClass: 'bg-yellow-100',
    textClass: 'text-yellow-800',
    icon: '📦',
  },
  block: {
    label: 'Blocked',
    bgClass: 'bg-red-100',
    textClass: 'text-red-800',
    icon: '🛑',
  },
};

export default function ScannedEmailsPage() {
  const [emails, setEmails] = useState<ScannedEmail[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [filter, setFilter] = useState<string>('all');

  useEffect(() => {
    fetchEmails();
  }, [filter]);

  async function fetchEmails() {
    setIsLoading(true);
    try {
      const params = new URLSearchParams({ limit: '100' });
      if (filter !== 'all') {
        params.set('verdict', filter);
      }

      const res = await fetch(`/api/dashboard/emails?${params}`);
      if (res.ok) {
        const data = await res.json();
        setEmails(data.emails);
        setTotal(data.total);
      }
    } catch (error) {
      console.error('Failed to fetch emails:', error);
    } finally {
      setIsLoading(false);
    }
  }

  function formatDate(dateStr: string) {
    const date = new Date(dateStr);
    return date.toLocaleString();
  }

  // Count by verdict
  const verdictCounts = emails.reduce((acc, email) => {
    acc[email.verdict] = (acc[email.verdict] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scanned Emails</h1>
          <p className="mt-1 text-sm text-gray-500">
            All emails analyzed by Swordfish ({total} total)
          </p>
        </div>
        <button
          onClick={fetchEmails}
          className="inline-flex items-center gap-2 rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
        >
          <RefreshIcon className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {/* Filter Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {[
            { key: 'all', label: 'All', count: total },
            { key: 'pass', label: 'Safe', count: verdictCounts.pass || 0 },
            { key: 'suspicious', label: 'Suspicious', count: verdictCounts.suspicious || 0 },
            { key: 'quarantine', label: 'Quarantined', count: verdictCounts.quarantine || 0 },
            { key: 'block', label: 'Blocked', count: verdictCounts.block || 0 },
          ].map((tab) => (
            <button
              key={tab.key}
              onClick={() => setFilter(tab.key)}
              className={clsx(
                'whitespace-nowrap border-b-2 py-4 px-1 text-sm font-medium',
                filter === tab.key
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
              )}
            >
              {tab.label}
              <span
                className={clsx(
                  'ml-2 rounded-full px-2.5 py-0.5 text-xs font-medium',
                  filter === tab.key
                    ? 'bg-blue-100 text-blue-600'
                    : 'bg-gray-100 text-gray-900'
                )}
              >
                {tab.count}
              </span>
            </button>
          ))}
        </nav>
      </div>

      {/* Email List */}
      <div className="overflow-hidden rounded-lg bg-white shadow">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <div className="h-8 w-8 animate-spin rounded-full border-4 border-blue-600 border-t-transparent"></div>
          </div>
        ) : emails.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <MailIcon className="mx-auto h-12 w-12 text-gray-300" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No emails found</h3>
            <p className="mt-1 text-sm text-gray-500">
              {filter === 'all'
                ? 'No emails have been scanned yet.'
                : `No emails with verdict "${filter}" found.`}
            </p>
          </div>
        ) : (
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                  Message ID
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                  Result
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                  Score
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                  Signals
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                  Time
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                  Scanned
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 bg-white">
              {emails.map((email) => {
                const config = verdictConfig[email.verdict] || verdictConfig.pass;
                return (
                  <tr key={email.id} className="hover:bg-gray-50">
                    <td className="whitespace-nowrap px-6 py-4">
                      <span
                        className={clsx(
                          'inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium',
                          config.bgClass,
                          config.textClass
                        )}
                      >
                        {config.icon} {config.label}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="max-w-xs truncate text-sm text-gray-900" title={email.messageId}>
                        {email.messageId.substring(0, 30)}...
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {email.primarySignal}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4">
                      <span
                        className={clsx(
                          'text-sm font-medium',
                          email.score >= 70 ? 'text-red-600' :
                          email.score >= 40 ? 'text-orange-600' :
                          email.score >= 20 ? 'text-yellow-600' :
                          'text-green-600'
                        )}
                      >
                        {email.score}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                      {email.signalCount}
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                      {email.processingTimeMs}ms
                    </td>
                    <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                      {formatDate(email.scannedAt)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function RefreshIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
      />
    </svg>
  );
}

function MailIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75"
      />
    </svg>
  );
}

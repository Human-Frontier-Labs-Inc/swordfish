'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import clsx from 'clsx';

interface Signal {
  type: string;
  severity: string;
  detail: string;
}

interface ScannedEmail {
  id: string;
  messageId: string;
  subject: string;
  from: string;
  fromAddress: string;
  to: Array<{ address: string; displayName?: string }>;
  receivedAt: string;
  verdict: 'pass' | 'suspicious' | 'quarantine' | 'block';
  score: number;
  confidence: number;
  signals: Signal[];
  signalCount: number;
  primarySignal: string;
  processingTimeMs: number;
  scannedAt: string;
}

const LIVE_POLL_INTERVAL = 10000; // 10 seconds

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
  const [selectedEmail, setSelectedEmail] = useState<ScannedEmail | null>(null);
  const [isLive, setIsLive] = useState(false);
  const [lastPolled, setLastPolled] = useState<Date | null>(null);
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const fetchEmails = useCallback(async (showLoading = true) => {
    if (showLoading) setIsLoading(true);
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
        setLastPolled(new Date());
      }
    } catch (error) {
      console.error('Failed to fetch emails:', error);
    } finally {
      if (showLoading) setIsLoading(false);
    }
  }, [filter]);

  // Initial fetch and filter change
  useEffect(() => {
    fetchEmails();
  }, [fetchEmails]);

  // Live polling effect
  useEffect(() => {
    if (isLive) {
      // Start polling
      pollIntervalRef.current = setInterval(() => {
        fetchEmails(false); // Don't show loading spinner during live updates
      }, LIVE_POLL_INTERVAL);
    } else {
      // Stop polling
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    }

    // Cleanup on unmount
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [isLive, fetchEmails]);

  function formatDate(dateStr: string | null) {
    if (!dateStr) return 'N/A';
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
            {lastPolled && isLive && (
              <span className="ml-2 text-xs text-gray-400">
                Last updated: {lastPolled.toLocaleTimeString()}
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Live Toggle */}
          <button
            onClick={() => setIsLive(!isLive)}
            className={clsx(
              'inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm font-medium transition-all',
              isLive
                ? 'bg-green-100 text-green-800 ring-2 ring-green-500 ring-offset-1'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            )}
          >
            <span
              className={clsx(
                'h-2 w-2 rounded-full',
                isLive ? 'bg-green-500 animate-pulse' : 'bg-gray-400'
              )}
            />
            {isLive ? 'Live' : 'Live'}
          </button>
          {/* Refresh Button */}
          <button
            onClick={() => fetchEmails()}
            disabled={isLoading}
            className="inline-flex items-center gap-2 rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            <RefreshIcon className={clsx('h-4 w-4', isLoading && 'animate-spin')} />
            Refresh
          </button>
        </div>
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
                ? 'No emails have been scanned yet. Click "Sync Now" on the Integrations page.'
                : `No emails with verdict "${filter}" found.`}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {emails.map((email) => {
              const config = verdictConfig[email.verdict] || verdictConfig.pass;
              return (
                <div
                  key={email.id}
                  className="px-6 py-4 hover:bg-gray-50 cursor-pointer"
                  onClick={() => setSelectedEmail(email)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3">
                        <span
                          className={clsx(
                            'inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium',
                            config.bgClass,
                            config.textClass
                          )}
                        >
                          {config.icon} {config.label}
                        </span>
                        <span
                          className={clsx(
                            'text-xs font-medium',
                            email.score >= 70 ? 'text-red-600' :
                            email.score >= 40 ? 'text-orange-600' :
                            email.score >= 20 ? 'text-yellow-600' :
                            'text-green-600'
                          )}
                        >
                          Score: {email.score}
                        </span>
                      </div>
                      <p className="mt-1 truncate font-medium text-gray-900">
                        {email.subject}
                      </p>
                      <p className="mt-1 truncate text-sm text-gray-500">
                        From: {email.from}
                      </p>
                      {email.signalCount > 0 && (
                        <p className="mt-1 text-sm text-gray-500">
                          {email.primarySignal}
                        </p>
                      )}
                    </div>
                    <div className="ml-4 text-right text-xs text-gray-400">
                      <div>{formatDate(email.receivedAt)}</div>
                      <div className="mt-1">{email.processingTimeMs}ms</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Detail Slide-over */}
      {selectedEmail && (
        <div className="fixed inset-0 z-50 overflow-hidden">
          <div className="absolute inset-0 bg-gray-500 bg-opacity-75" onClick={() => setSelectedEmail(null)} />
          <div className="pointer-events-none fixed inset-y-0 right-0 flex max-w-full pl-10">
            <div className="pointer-events-auto w-screen max-w-lg">
              <div className="flex h-full flex-col overflow-y-scroll bg-white shadow-xl">
                {/* Header */}
                <div className="bg-gray-50 px-4 py-6 sm:px-6">
                  <div className="flex items-start justify-between">
                    <div>
                      <h2 className="text-lg font-medium text-gray-900">Email Details</h2>
                      <p className="mt-1 text-sm text-gray-500">
                        Analysis results and metadata
                      </p>
                    </div>
                    <button
                      onClick={() => setSelectedEmail(null)}
                      className="rounded-md bg-white text-gray-400 hover:text-gray-500"
                    >
                      <span className="sr-only">Close</span>
                      <XIcon className="h-6 w-6" />
                    </button>
                  </div>
                </div>

                {/* Content */}
                <div className="flex-1 px-4 py-6 sm:px-6">
                  <dl className="space-y-6">
                    {/* Verdict */}
                    <div>
                      <dt className="text-sm font-medium text-gray-500">Verdict</dt>
                      <dd className="mt-1 flex items-center gap-2">
                        <span
                          className={clsx(
                            'inline-flex items-center gap-1 rounded-full px-3 py-1 text-sm font-medium',
                            verdictConfig[selectedEmail.verdict].bgClass,
                            verdictConfig[selectedEmail.verdict].textClass
                          )}
                        >
                          {verdictConfig[selectedEmail.verdict].icon} {verdictConfig[selectedEmail.verdict].label}
                        </span>
                        <span className="text-sm text-gray-500">Score: {selectedEmail.score}/100</span>
                      </dd>
                    </div>

                    {/* Subject */}
                    <div>
                      <dt className="text-sm font-medium text-gray-500">Subject</dt>
                      <dd className="mt-1 text-sm text-gray-900">{selectedEmail.subject}</dd>
                    </div>

                    {/* From */}
                    <div>
                      <dt className="text-sm font-medium text-gray-500">From</dt>
                      <dd className="mt-1 text-sm text-gray-900">{selectedEmail.from}</dd>
                    </div>

                    {/* To */}
                    {selectedEmail.to && selectedEmail.to.length > 0 && (
                      <div>
                        <dt className="text-sm font-medium text-gray-500">To</dt>
                        <dd className="mt-1 text-sm text-gray-900">
                          {selectedEmail.to.map(t => t.displayName ? `${t.displayName} <${t.address}>` : t.address).join(', ')}
                        </dd>
                      </div>
                    )}

                    {/* Received */}
                    <div>
                      <dt className="text-sm font-medium text-gray-500">Received</dt>
                      <dd className="mt-1 text-sm text-gray-900">{formatDate(selectedEmail.receivedAt)}</dd>
                    </div>

                    {/* Message ID */}
                    <div>
                      <dt className="text-sm font-medium text-gray-500">Message ID</dt>
                      <dd className="mt-1 text-sm text-gray-500 break-all font-mono text-xs">{selectedEmail.messageId}</dd>
                    </div>

                    {/* Signals */}
                    <div>
                      <dt className="text-sm font-medium text-gray-500">Detection Signals ({selectedEmail.signalCount})</dt>
                      <dd className="mt-2">
                        {selectedEmail.signals.length === 0 ? (
                          <p className="text-sm text-green-600">No security signals detected</p>
                        ) : (
                          <ul className="space-y-2">
                            {selectedEmail.signals.map((signal, idx) => (
                              <li
                                key={idx}
                                className={clsx(
                                  'rounded-md px-3 py-2 text-sm',
                                  signal.severity === 'critical' ? 'bg-red-50 text-red-700' :
                                  signal.severity === 'warning' ? 'bg-yellow-50 text-yellow-700' :
                                  'bg-gray-50 text-gray-700'
                                )}
                              >
                                <div className="font-medium capitalize">{signal.type.replace(/_/g, ' ')}</div>
                                <div className="mt-0.5 text-xs opacity-75">{signal.detail}</div>
                              </li>
                            ))}
                          </ul>
                        )}
                      </dd>
                    </div>

                    {/* Processing */}
                    <div>
                      <dt className="text-sm font-medium text-gray-500">Processing</dt>
                      <dd className="mt-1 text-sm text-gray-500">
                        Analyzed in {selectedEmail.processingTimeMs}ms • Confidence: {Math.round(selectedEmail.confidence * 100)}%
                      </dd>
                    </div>

                    {/* Scanned At */}
                    <div>
                      <dt className="text-sm font-medium text-gray-500">Scanned At</dt>
                      <dd className="mt-1 text-sm text-gray-900">{formatDate(selectedEmail.scannedAt)}</dd>
                    </div>
                  </dl>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
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

function XIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

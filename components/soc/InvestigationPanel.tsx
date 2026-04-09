/**
 * SOC Investigation Panel Component
 *
 * Detailed threat investigation interface for SOC analysts.
 * Composes sub-components for threat details, actions, signals, and notes.
 */

'use client';

import { useState } from 'react';
import clsx from 'clsx';
import { ThreatDetailsView } from './ThreatDetailsView';
import { InvestigationActions } from './InvestigationActions';
import { SignalsList } from './SignalsList';
import { InvestigationNotes } from './InvestigationNotes';

// --- Shared types (re-exported for consumers) ---

export interface ThreatDetails {
  id: string;
  subject: string;
  fromAddress: string;
  fromDisplayName?: string;
  toAddresses: string[];
  receivedAt: Date;
  verdict: string;
  confidence: number;
  classification: string;
  signals: ThreatSignal[];
  headers: Record<string, string>;
  urls: ExtractedUrl[];
  attachments: Attachment[];
  bodyPreview?: string;
  rawHeaders?: string;
  investigation?: InvestigationNote[];
}

export interface ThreatSignal {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  evidence?: string;
  score: number;
}

export interface ExtractedUrl {
  url: string;
  displayText?: string;
  reputation: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  checkedAt?: Date;
}

export interface Attachment {
  filename: string;
  contentType: string;
  size: number;
  hash?: string;
  verdict?: 'malicious' | 'suspicious' | 'clean' | 'unknown';
}

export interface InvestigationNote {
  id: string;
  author: string;
  content: string;
  createdAt: Date;
}

// --- Component props ---

interface InvestigationPanelProps {
  threat: ThreatDetails | null;
  onClose?: () => void;
  onAction?: (action: 'release' | 'delete' | 'block_sender' | 'add_note') => void;
  onAddNote?: (note: string) => Promise<void>;
}

type TabId = 'overview' | 'signals' | 'urls' | 'headers' | 'attachments' | 'notes';

// --- Main component ---

export function InvestigationPanel({
  threat,
  onClose,
  onAction,
  onAddNote,
}: InvestigationPanelProps) {
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [noteContent, setNoteContent] = useState('');
  const [isSubmittingNote, setIsSubmittingNote] = useState(false);

  if (!threat) {
    return (
      <div className="bg-white rounded-lg shadow h-full flex items-center justify-center">
        <div className="text-center py-12 px-4">
          <SearchIcon className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-sm font-medium text-gray-900">No threat selected</h3>
          <p className="mt-1 text-sm text-gray-500">
            Select a threat from the timeline to investigate
          </p>
        </div>
      </div>
    );
  }

  const tabs: { id: TabId; label: string; count?: number }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'signals', label: 'Signals', count: threat.signals.length },
    { id: 'urls', label: 'URLs', count: threat.urls.length },
    { id: 'headers', label: 'Headers' },
    { id: 'attachments', label: 'Attachments', count: threat.attachments.length },
    { id: 'notes', label: 'Notes', count: threat.investigation?.length || 0 },
  ];

  const handleAddNote = async () => {
    if (!noteContent.trim() || !onAddNote) return;
    setIsSubmittingNote(true);
    try {
      await onAddNote(noteContent);
      setNoteContent('');
    } finally {
      setIsSubmittingNote(false);
    }
  };

  return (
    <div className="bg-white rounded-lg shadow h-full flex flex-col">
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-200 flex items-center justify-between bg-gray-50">
        <div className="flex items-center gap-2">
          <ShieldExclamationIcon className="h-5 w-5 text-red-500" />
          <h3 className="text-lg font-semibold text-gray-900">Investigation</h3>
        </div>
        {onClose && (
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <XIcon className="h-5 w-5" />
          </button>
        )}
      </div>

      {/* Threat Summary */}
      <div className="px-4 py-3 border-b border-gray-200 bg-red-50">
        <div className="flex items-start justify-between">
          <div className="flex-1 min-w-0">
            <h4 className="text-sm font-medium text-gray-900 truncate">
              {threat.subject || '(No subject)'}
            </h4>
            <p className="mt-1 text-sm text-gray-600">
              From: {threat.fromDisplayName ? `${threat.fromDisplayName} <${threat.fromAddress}>` : threat.fromAddress}
            </p>
            <p className="text-xs text-gray-500">
              {new Date(threat.receivedAt).toLocaleString()}
            </p>
          </div>
          <div className="ml-4 flex flex-col items-end gap-2">
            <VerdictBadge verdict={threat.verdict} confidence={threat.confidence} />
            <span className="text-xs text-gray-500">{threat.classification}</span>
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <InvestigationActions onAction={onAction} />

      {/* Tabs */}
      <div className="border-b border-gray-200 px-4">
        <nav className="-mb-px flex space-x-4 overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={clsx(
                'whitespace-nowrap py-2 px-1 border-b-2 text-sm font-medium',
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              )}
            >
              {tab.label}
              {tab.count !== undefined && (
                <span
                  className={clsx(
                    'ml-1 px-1.5 py-0.5 rounded-full text-xs',
                    activeTab === tab.id ? 'bg-blue-100 text-blue-600' : 'bg-gray-100 text-gray-600'
                  )}
                >
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {activeTab === 'overview' && (
          <ThreatDetailsView threat={threat} />
        )}
        {activeTab === 'signals' && (
          <SignalsList signals={threat.signals} />
        )}
        {activeTab === 'urls' && (
          <UrlsTab urls={threat.urls} />
        )}
        {activeTab === 'headers' && (
          <HeadersTab headers={threat.headers} rawHeaders={threat.rawHeaders} />
        )}
        {activeTab === 'attachments' && (
          <AttachmentsTab attachments={threat.attachments} />
        )}
        {activeTab === 'notes' && (
          <InvestigationNotes
            notes={threat.investigation || []}
            noteContent={noteContent}
            setNoteContent={setNoteContent}
            onAddNote={handleAddNote}
            isSubmitting={isSubmittingNote}
          />
        )}
      </div>
    </div>
  );
}

// --- Inline tab components (URLs, Headers, Attachments kept here as they are small) ---

function UrlsTab({ urls }: { urls: ExtractedUrl[] }) {
  const reputationOrder = { malicious: 0, suspicious: 1, unknown: 2, clean: 3 };
  const sortedUrls = [...urls].sort(
    (a, b) => reputationOrder[a.reputation] - reputationOrder[b.reputation]
  );

  return (
    <div className="space-y-2">
      {sortedUrls.length === 0 ? (
        <p className="text-sm text-gray-500 text-center py-4">No URLs found</p>
      ) : (
        sortedUrls.map((url, i) => (
          <UrlCard key={i} url={url} />
        ))
      )}
    </div>
  );
}

function HeadersTab({
  headers,
  rawHeaders,
}: {
  headers: Record<string, string>;
  rawHeaders?: string;
}) {
  const [showRaw, setShowRaw] = useState(false);

  const importantHeaders = [
    'From',
    'To',
    'Subject',
    'Date',
    'Return-Path',
    'Reply-To',
    'X-Originating-IP',
    'Received-SPF',
    'DKIM-Signature',
    'Authentication-Results',
  ];

  const sortedHeaders = Object.entries(headers).sort(([a], [b]) => {
    const aIdx = importantHeaders.indexOf(a);
    const bIdx = importantHeaders.indexOf(b);
    if (aIdx === -1 && bIdx === -1) return a.localeCompare(b);
    if (aIdx === -1) return 1;
    if (bIdx === -1) return -1;
    return aIdx - bIdx;
  });

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <button
          onClick={() => setShowRaw(!showRaw)}
          className="text-xs text-blue-600 hover:text-blue-800"
        >
          {showRaw ? 'Show Parsed' : 'Show Raw'}
        </button>
      </div>

      {showRaw && rawHeaders ? (
        <pre className="bg-gray-50 p-3 rounded text-xs overflow-x-auto whitespace-pre-wrap">
          {rawHeaders}
        </pre>
      ) : (
        <dl className="space-y-2">
          {sortedHeaders.map(([key, value]) => (
            <div key={key} className="border-b border-gray-100 pb-2">
              <dt className="text-xs font-medium text-gray-500">{key}</dt>
              <dd className="text-sm text-gray-900 break-all">{value}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

function AttachmentsTab({ attachments }: { attachments: Attachment[] }) {
  return (
    <div className="space-y-2">
      {attachments.length === 0 ? (
        <p className="text-sm text-gray-500 text-center py-4">No attachments</p>
      ) : (
        attachments.map((attachment, i) => (
          <AttachmentCard key={i} attachment={attachment} />
        ))
      )}
    </div>
  );
}

// --- Helper components ---

function VerdictBadge({ verdict, confidence }: { verdict: string; confidence: number }) {
  const config: Record<string, { bg: string; text: string }> = {
    block: { bg: 'bg-red-100', text: 'text-red-800' },
    quarantine: { bg: 'bg-amber-100', text: 'text-amber-800' },
    review: { bg: 'bg-blue-100', text: 'text-blue-800' },
    allow: { bg: 'bg-green-100', text: 'text-green-800' },
  };
  const style = config[verdict] || { bg: 'bg-gray-100', text: 'text-gray-800' };

  return (
    <span className={clsx('px-2 py-1 rounded text-xs font-semibold', style.bg, style.text)}>
      {verdict.toUpperCase()} ({confidence}%)
    </span>
  );
}

function UrlCard({ url }: { url: ExtractedUrl }) {
  const reputationColors = {
    malicious: 'bg-red-100 text-red-800',
    suspicious: 'bg-yellow-100 text-yellow-800',
    clean: 'bg-green-100 text-green-800',
    unknown: 'bg-gray-100 text-gray-800',
  };

  return (
    <div className="border rounded p-2">
      <div className="flex items-center justify-between">
        <span className={clsx('text-xs px-2 py-0.5 rounded font-medium', reputationColors[url.reputation])}>
          {url.reputation}
        </span>
        {url.checkedAt && (
          <span className="text-xs text-gray-400">
            Checked {new Date(url.checkedAt).toLocaleString()}
          </span>
        )}
      </div>
      <p className="text-sm text-gray-900 mt-1 break-all font-mono">{url.url}</p>
      {url.displayText && url.displayText !== url.url && (
        <p className="text-xs text-gray-500 mt-1">Display: {url.displayText}</p>
      )}
    </div>
  );
}

function AttachmentCard({ attachment }: { attachment: Attachment }) {
  const verdictColors = {
    malicious: 'bg-red-100 text-red-800',
    suspicious: 'bg-yellow-100 text-yellow-800',
    clean: 'bg-green-100 text-green-800',
    unknown: 'bg-gray-100 text-gray-800',
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="border rounded p-2 flex items-center justify-between">
      <div className="flex items-center gap-2">
        <PaperClipIcon className="h-5 w-5 text-gray-400" />
        <div>
          <p className="text-sm font-medium text-gray-900">{attachment.filename}</p>
          <p className="text-xs text-gray-500">
            {attachment.contentType} - {formatSize(attachment.size)}
          </p>
        </div>
      </div>
      {attachment.verdict && (
        <span className={clsx('text-xs px-2 py-0.5 rounded font-medium', verdictColors[attachment.verdict])}>
          {attachment.verdict}
        </span>
      )}
    </div>
  );
}

// --- Icons ---

function SearchIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
    </svg>
  );
}

function ShieldExclamationIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z" />
    </svg>
  );
}

function XIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  );
}

function PaperClipIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M18.375 12.739l-7.693 7.693a4.5 4.5 0 01-6.364-6.364l10.94-10.94A3 3 0 1119.5 7.372L8.552 18.32m.009-.01l-.01.01m5.699-9.941l-7.81 7.81a1.5 1.5 0 002.112 2.13" />
    </svg>
  );
}

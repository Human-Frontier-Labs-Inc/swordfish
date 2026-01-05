/**
 * SOC Threat Timeline Component
 *
 * Real-time visualization of threat events for SOC analysts
 */

'use client';

import { useState, useEffect } from 'react';
import clsx from 'clsx';

export interface TimelineEvent {
  id: string;
  timestamp: Date;
  type: 'threat_detected' | 'quarantine' | 'release' | 'investigation' | 'alert' | 'action';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  threatId?: string;
  metadata?: Record<string, unknown>;
}

interface ThreatTimelineProps {
  events: TimelineEvent[];
  onEventClick?: (event: TimelineEvent) => void;
  maxHeight?: string;
  autoRefresh?: boolean;
  refreshInterval?: number;
}

const severityConfig = {
  critical: {
    dotClass: 'bg-red-500',
    borderClass: 'border-red-500',
    bgClass: 'bg-red-50',
    textClass: 'text-red-700',
    icon: CriticalIcon,
  },
  high: {
    dotClass: 'bg-orange-500',
    borderClass: 'border-orange-500',
    bgClass: 'bg-orange-50',
    textClass: 'text-orange-700',
    icon: HighIcon,
  },
  medium: {
    dotClass: 'bg-yellow-500',
    borderClass: 'border-yellow-500',
    bgClass: 'bg-yellow-50',
    textClass: 'text-yellow-700',
    icon: MediumIcon,
  },
  low: {
    dotClass: 'bg-blue-500',
    borderClass: 'border-blue-500',
    bgClass: 'bg-blue-50',
    textClass: 'text-blue-700',
    icon: LowIcon,
  },
  info: {
    dotClass: 'bg-gray-400',
    borderClass: 'border-gray-400',
    bgClass: 'bg-gray-50',
    textClass: 'text-gray-700',
    icon: InfoIcon,
  },
};

const eventTypeLabels: Record<TimelineEvent['type'], string> = {
  threat_detected: 'Threat Detected',
  quarantine: 'Quarantined',
  release: 'Released',
  investigation: 'Investigation',
  alert: 'Alert',
  action: 'Action Taken',
};

export function ThreatTimeline({
  events,
  onEventClick,
  maxHeight = '600px',
  autoRefresh = false,
  refreshInterval = 30000,
}: ThreatTimelineProps) {
  const [filter, setFilter] = useState<TimelineEvent['severity'] | 'all'>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filteredEvents = filter === 'all'
    ? events
    : events.filter((e) => e.severity === filter);

  const sortedEvents = [...filteredEvents].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  return (
    <div className="bg-white rounded-lg shadow overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-200 bg-gray-50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <TimelineIcon className="h-5 w-5 text-gray-500" />
            <h3 className="text-lg font-semibold text-gray-900">Threat Timeline</h3>
            {autoRefresh && (
              <span className="flex items-center gap-1 text-xs text-green-600">
                <span className="h-2 w-2 bg-green-500 rounded-full animate-pulse" />
                Live
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-500">{sortedEvents.length} events</span>
          </div>
        </div>

        {/* Severity Filter */}
        <div className="mt-3 flex gap-2 flex-wrap">
          <FilterButton
            active={filter === 'all'}
            onClick={() => setFilter('all')}
            label="All"
            count={events.length}
          />
          {(['critical', 'high', 'medium', 'low'] as const).map((severity) => {
            const count = events.filter((e) => e.severity === severity).length;
            const config = severityConfig[severity];
            return (
              <FilterButton
                key={severity}
                active={filter === severity}
                onClick={() => setFilter(severity)}
                label={severity.charAt(0).toUpperCase() + severity.slice(1)}
                count={count}
                colorClass={config.dotClass}
              />
            );
          })}
        </div>
      </div>

      {/* Timeline */}
      <div
        className="overflow-y-auto px-4 py-4"
        style={{ maxHeight }}
      >
        {sortedEvents.length === 0 ? (
          <div className="text-center py-12">
            <CheckCircleIcon className="mx-auto h-12 w-12 text-green-400" />
            <p className="mt-2 text-sm text-gray-500">No events to display</p>
          </div>
        ) : (
          <div className="relative">
            {/* Vertical line */}
            <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-gray-200" />

            {/* Events */}
            <div className="space-y-4">
              {sortedEvents.map((event, index) => {
                const config = severityConfig[event.severity];
                const Icon = config.icon;
                const isExpanded = expandedId === event.id;

                return (
                  <div
                    key={event.id}
                    className={clsx(
                      'relative pl-10 cursor-pointer transition-all',
                      isExpanded && 'bg-gray-50 -mx-4 px-4 py-2 rounded-lg'
                    )}
                    onClick={() => {
                      setExpandedId(isExpanded ? null : event.id);
                      onEventClick?.(event);
                    }}
                  >
                    {/* Dot */}
                    <div
                      className={clsx(
                        'absolute left-2 w-5 h-5 rounded-full flex items-center justify-center',
                        config.dotClass
                      )}
                    >
                      <Icon className="h-3 w-3 text-white" />
                    </div>

                    {/* Content */}
                    <div
                      className={clsx(
                        'border rounded-lg p-3 hover:shadow-sm transition-shadow',
                        config.borderClass,
                        config.bgClass
                      )}
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <span
                            className={clsx(
                              'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium',
                              config.bgClass,
                              config.textClass
                            )}
                          >
                            {eventTypeLabels[event.type]}
                          </span>
                          <h4 className="mt-1 text-sm font-medium text-gray-900">
                            {event.title}
                          </h4>
                        </div>
                        <span className="text-xs text-gray-500 whitespace-nowrap">
                          {formatTimestamp(event.timestamp)}
                        </span>
                      </div>

                      <p className="mt-1 text-sm text-gray-600">{event.description}</p>

                      {/* Expanded Details */}
                      {isExpanded && event.metadata && (
                        <div className="mt-3 pt-3 border-t border-gray-200">
                          <h5 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
                            Details
                          </h5>
                          <dl className="grid grid-cols-2 gap-2 text-sm">
                            {Object.entries(event.metadata).map(([key, value]) => (
                              <div key={key}>
                                <dt className="text-gray-500 text-xs">{formatKey(key)}</dt>
                                <dd className="text-gray-900 font-medium">{String(value)}</dd>
                              </div>
                            ))}
                          </dl>
                          {event.threatId && (
                            <a
                              href={`/dashboard/threats/${event.threatId}`}
                              className="mt-2 inline-flex items-center text-sm text-blue-600 hover:text-blue-800"
                              onClick={(e) => e.stopPropagation()}
                            >
                              View Threat Details →
                            </a>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// Helper Components
function FilterButton({
  active,
  onClick,
  label,
  count,
  colorClass,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  count: number;
  colorClass?: string;
}) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium transition-colors',
        active
          ? 'bg-gray-900 text-white'
          : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
      )}
    >
      {colorClass && <span className={clsx('h-2 w-2 rounded-full', colorClass)} />}
      {label}
      <span className={clsx('px-1.5 py-0.5 rounded-full text-xs', active ? 'bg-white/20' : 'bg-gray-200')}>
        {count}
      </span>
    </button>
  );
}

// Helper Functions
function formatTimestamp(date: Date | string): string {
  const d = new Date(date);
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;

  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function formatKey(key: string): string {
  return key
    .replace(/_/g, ' ')
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, (c) => c.toUpperCase())
    .trim();
}

// Icons
function TimelineIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  );
}

function CheckCircleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  );
}

function CriticalIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="currentColor" viewBox="0 0 20 20">
      <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
    </svg>
  );
}

function HighIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="currentColor" viewBox="0 0 20 20">
      <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
    </svg>
  );
}

function MediumIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="currentColor" viewBox="0 0 20 20">
      <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-8-3a1 1 0 00-.867.5 1 1 0 11-1.731-1A3 3 0 0113 8a3.001 3.001 0 01-2 2.83V11a1 1 0 11-2 0v-1a1 1 0 011-1 1 1 0 100-2zm0 8a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
    </svg>
  );
}

function LowIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="currentColor" viewBox="0 0 20 20">
      <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
    </svg>
  );
}

function InfoIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="currentColor" viewBox="0 0 20 20">
      <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
    </svg>
  );
}

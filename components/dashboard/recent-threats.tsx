'use client';

import clsx from 'clsx';

interface Threat {
  id: string;
  subject: string;
  from: string;
  verdict: 'block' | 'quarantine' | 'review' | 'suspicious';
  signals: string[];
  timestamp: Date;
}

interface RecentThreatsProps {
  threats: Threat[];
  isDemo?: boolean;
}

const verdictConfig = {
  block: {
    label: 'Blocked',
    bgClass: 'bg-red-100',
    textClass: 'text-red-800',
  },
  quarantine: {
    label: 'Quarantined',
    bgClass: 'bg-yellow-100',
    textClass: 'text-yellow-800',
  },
  review: {
    label: 'Review',
    bgClass: 'bg-blue-100',
    textClass: 'text-blue-800',
  },
  suspicious: {
    label: 'Suspicious',
    bgClass: 'bg-orange-100',
    textClass: 'text-orange-800',
  },
};

export function RecentThreats({ threats, isDemo = false }: RecentThreatsProps) {
  return (
    <div className="overflow-hidden rounded-lg bg-white shadow">
      <div className="border-b border-gray-200 px-5 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h3 className="text-lg font-medium text-gray-900">Recent Threats</h3>
            {isDemo && (
              <span className="inline-flex items-center rounded-full bg-gray-100 px-2 py-0.5 text-xs text-gray-500">
                Demo
              </span>
            )}
          </div>
          <a
            href="/dashboard/threats"
            className="text-sm font-medium text-blue-600 hover:text-blue-500"
          >
            View all
          </a>
        </div>
      </div>

      {threats.length === 0 ? (
        <div className="px-5 py-12 text-center">
          <ShieldCheckIcon className="mx-auto h-12 w-12 text-green-300" />
          <h3 className="mt-2 text-sm font-medium text-gray-900">No threats detected</h3>
          <p className="mt-1 text-sm text-gray-500">
            Your inbox is clean. We&apos;ll alert you when threats are detected.
          </p>
        </div>
      ) : (
        <ul className="divide-y divide-gray-200">
          {threats.map((threat) => {
            const verdict = verdictConfig[threat.verdict];

            return (
              <li key={threat.id} className="px-5 py-4 hover:bg-gray-50">
                <a href={`/dashboard/threats/${threat.id}`} className="block">
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <p className="truncate font-medium text-gray-900">{threat.subject}</p>
                      <p className="mt-1 truncate text-sm text-gray-500">{threat.from}</p>
                    </div>
                    <span
                      className={clsx(
                        'ml-3 inline-flex flex-shrink-0 items-center rounded-full px-2.5 py-0.5 text-xs font-medium',
                        verdict.bgClass,
                        verdict.textClass
                      )}
                    >
                      {verdict.label}
                    </span>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {threat.signals.slice(0, 3).map((signal, idx) => (
                      <span
                        key={idx}
                        className="inline-flex items-center rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-600"
                      >
                        {signal}
                      </span>
                    ))}
                    {threat.signals.length > 3 && (
                      <span className="text-xs text-gray-400">
                        +{threat.signals.length - 3} more
                      </span>
                    )}
                  </div>
                  <p className="mt-2 text-xs text-gray-400">
                    {formatRelativeTime(threat.timestamp)}
                  </p>
                </a>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function formatRelativeTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins} minutes ago`;
  if (diffHours < 24) return `${diffHours} hours ago`;
  if (diffDays === 1) return 'Yesterday';
  return `${diffDays} days ago`;
}

function ShieldCheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
      />
    </svg>
  );
}

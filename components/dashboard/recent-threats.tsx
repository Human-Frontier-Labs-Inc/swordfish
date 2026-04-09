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
    bgClass: 'bg-red-500/15 border border-red-500/25',
    textClass: 'text-red-600 dark:text-red-400',
    dotColor: 'bg-red-500',
    shouldPulse: true,
  },
  quarantine: {
    label: 'Quarantined',
    bgClass: 'bg-amber-500/15 border border-amber-500/25',
    textClass: 'text-amber-600 dark:text-amber-400',
    dotColor: 'bg-amber-500',
    shouldPulse: false,
  },
  review: {
    label: 'Review',
    bgClass: 'bg-blue-500/15 border border-blue-500/25',
    textClass: 'text-blue-600 dark:text-blue-400',
    dotColor: 'bg-blue-500',
    shouldPulse: false,
  },
  suspicious: {
    label: 'Suspicious',
    bgClass: 'bg-orange-500/15 border border-orange-500/25',
    textClass: 'text-orange-600 dark:text-orange-400',
    dotColor: 'bg-orange-500',
    shouldPulse: false,
  },
};

export function RecentThreats({ threats, isDemo = false }: RecentThreatsProps) {
  return (
    <div className="overflow-hidden rounded-lg bg-white shadow-sm dark:bg-slate-800 dark:shadow-slate-900/50">
      <div className="border-b border-slate-200 px-5 py-4 dark:border-slate-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Recent Threats</h3>
            {isDemo ? (
              <span className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-500 dark:bg-slate-700 dark:text-slate-400">
                Demo
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-600 dark:text-emerald-400">
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
                </span>
                Live
              </span>
            )}
          </div>
          <a
            href="/dashboard/threats"
            className="text-sm font-medium text-blue-500 hover:text-blue-400 transition-colors duration-200"
          >
            View all
          </a>
        </div>
      </div>

      {threats.length === 0 ? (
        <div className="px-5 py-12 text-center">
          <ShieldCheckIcon className="mx-auto h-12 w-12 text-emerald-400/60" />
          <h3 className="mt-2 text-sm font-medium text-slate-900 dark:text-white">No threats detected</h3>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Your inbox is clean. We&apos;ll alert you when threats are detected.
          </p>
        </div>
      ) : (
        <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
          {threats.map((threat) => {
            const verdict = verdictConfig[threat.verdict];

            return (
              <li
                key={threat.id}
                className="group transition-all duration-200 hover:bg-slate-50 hover:translate-x-1 dark:hover:bg-slate-700/30"
              >
                <a href={`/dashboard/threats/${threat.id}`} className="block px-5 py-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3 flex-1 min-w-0">
                      {/* Pulsing dot for blocked threats */}
                      {verdict.shouldPulse && (
                        <span className="relative mt-1.5 flex h-2.5 w-2.5 flex-shrink-0">
                          <span className={clsx(
                            'absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping',
                            verdict.dotColor
                          )} />
                          <span className={clsx(
                            'relative inline-flex h-2.5 w-2.5 rounded-full',
                            verdict.dotColor
                          )} />
                        </span>
                      )}
                      <div className="flex-1 min-w-0">
                        <p className="truncate font-medium text-slate-900 group-hover:text-blue-600 transition-colors duration-200 dark:text-white dark:group-hover:text-blue-400">
                          {threat.subject}
                        </p>
                        <p className="mt-1 truncate text-sm text-slate-500 dark:text-slate-400">{threat.from}</p>
                      </div>
                    </div>
                    <span
                      className={clsx(
                        'ml-3 inline-flex flex-shrink-0 items-center rounded-full px-2.5 py-0.5 text-xs font-semibold',
                        verdict.bgClass,
                        verdict.textClass
                      )}
                    >
                      {verdict.label}
                    </span>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {threat.signals.slice(0, 3).map((signal, idx) => (
                      <span
                        key={idx}
                        className="inline-flex items-center rounded-md bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600 dark:bg-slate-700 dark:text-slate-300"
                      >
                        {signal}
                      </span>
                    ))}
                    {threat.signals.length > 3 && (
                      <span className="text-xs text-slate-400">
                        +{threat.signals.length - 3} more
                      </span>
                    )}
                  </div>
                  <p className="mt-2 text-xs text-slate-400 dark:text-slate-500">
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

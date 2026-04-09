'use client';

import clsx from 'clsx';
import { useEffect, useRef, useState } from 'react';

interface StatCardProps {
  title: string;
  value: string | number;
  change?: {
    value: number;
    type: 'increase' | 'decrease';
  };
  icon: React.ComponentType<{ className?: string }>;
  color?: 'blue' | 'green' | 'yellow' | 'red' | 'gray';
  testId?: string;
}

const colorClasses = {
  blue: {
    border: 'border-l-blue-500',
    iconBg: 'bg-gradient-to-br from-blue-500/20 to-blue-600/10',
    iconText: 'text-blue-500',
    gradient: 'from-blue-500/5 via-transparent to-transparent',
  },
  green: {
    border: 'border-l-emerald-500',
    iconBg: 'bg-gradient-to-br from-emerald-500/20 to-emerald-600/10',
    iconText: 'text-emerald-500',
    gradient: 'from-emerald-500/5 via-transparent to-transparent',
  },
  yellow: {
    border: 'border-l-amber-500',
    iconBg: 'bg-gradient-to-br from-amber-500/20 to-amber-600/10',
    iconText: 'text-amber-500',
    gradient: 'from-amber-500/5 via-transparent to-transparent',
  },
  red: {
    border: 'border-l-red-500',
    iconBg: 'bg-gradient-to-br from-red-500/20 to-red-600/10',
    iconText: 'text-red-500',
    gradient: 'from-red-500/5 via-transparent to-transparent',
  },
  gray: {
    border: 'border-l-slate-500',
    iconBg: 'bg-gradient-to-br from-slate-500/20 to-slate-600/10',
    iconText: 'text-slate-500',
    gradient: 'from-slate-500/5 via-transparent to-transparent',
  },
};

function useCountUp(target: number, duration: number = 1200): number {
  const [current, setCurrent] = useState(0);
  const frameRef = useRef<number | null>(null);

  useEffect(() => {
    if (target === 0) {
      setCurrent(0);
      return;
    }
    const startTime = performance.now();
    const animate = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setCurrent(Math.round(eased * target));
      if (progress < 1) {
        frameRef.current = requestAnimationFrame(animate);
      }
    };
    frameRef.current = requestAnimationFrame(animate);
    return () => {
      if (frameRef.current) cancelAnimationFrame(frameRef.current);
    };
  }, [target, duration]);

  return current;
}

export function StatCard({
  title,
  value,
  change,
  icon: Icon,
  color = 'blue',
  testId,
}: StatCardProps) {
  const colors = colorClasses[color];
  const numericValue = typeof value === 'number' ? value : null;
  const animatedValue = useCountUp(numericValue ?? 0);
  const displayValue = numericValue !== null ? animatedValue : value;

  // Pulsing glow for red (threats) when value > 0
  const shouldPulse = color === 'red' && numericValue !== null && numericValue > 0;

  return (
    <div
      className={clsx(
        'relative overflow-hidden rounded-lg border-l-4 bg-white shadow-sm transition-all duration-200 hover:shadow-md',
        'dark:bg-slate-800 dark:shadow-slate-900/50',
        colors.border,
        shouldPulse && 'ring-1 ring-red-500/30 animate-[threat-pulse_2s_ease-in-out_infinite]'
      )}
      data-testid={testId}
    >
      {/* Subtle gradient overlay */}
      <div className={clsx('absolute inset-0 bg-gradient-to-br', colors.gradient)} />

      <div className="relative p-5">
        <div className="flex items-center">
          <div className={clsx(
            'flex-shrink-0 rounded-lg p-3 backdrop-blur-sm',
            colors.iconBg,
            'animate-[shimmer_3s_ease-in-out_infinite]'
          )}>
            <Icon className={clsx('h-6 w-6', colors.iconText)} />
          </div>
          <div className="ml-5 w-0 flex-1">
            <dl>
              <dt className="truncate text-sm font-medium text-slate-500 dark:text-slate-400">{title}</dt>
              <dd className="flex items-baseline">
                <div className="text-2xl font-bold text-slate-900 dark:text-white tabular-nums">
                  {displayValue}
                </div>
                {change && (
                  <div
                    className={clsx(
                      'ml-2 flex items-center gap-0.5 rounded-full px-2 py-0.5 text-xs font-semibold',
                      change.type === 'increase'
                        ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400'
                        : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                    )}
                  >
                    {change.type === 'increase' ? (
                      <ArrowUpIcon className="h-3 w-3" />
                    ) : (
                      <ArrowDownIcon className="h-3 w-3" />
                    )}
                    <span>{Math.abs(change.value)}%</span>
                  </div>
                )}
              </dd>
            </dl>
          </div>
        </div>
      </div>
    </div>
  );
}

function ArrowUpIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="currentColor" viewBox="0 0 20 20">
      <path
        fillRule="evenodd"
        d="M5.293 9.707a1 1 0 010-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 01-1.414 1.414L11 7.414V15a1 1 0 11-2 0V7.414L6.707 9.707a1 1 0 01-1.414 0z"
        clipRule="evenodd"
      />
    </svg>
  );
}

function ArrowDownIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="currentColor" viewBox="0 0 20 20">
      <path
        fillRule="evenodd"
        d="M14.707 10.293a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 111.414-1.414L9 12.586V5a1 1 0 012 0v7.586l2.293-2.293a1 1 0 011.414 0z"
        clipRule="evenodd"
      />
    </svg>
  );
}

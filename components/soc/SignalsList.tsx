/**
 * SignalsList - Detection signals display for threat investigation
 *
 * Shows sorted list of threat detection signals with severity indicators.
 */

import clsx from 'clsx';
import type { ThreatSignal } from './InvestigationPanel';

interface SignalsListProps {
  signals: ThreatSignal[];
}

export function SignalsList({ signals }: SignalsListProps) {
  const sortedSignals = [...signals].sort((a, b) => b.score - a.score);

  return (
    <div className="space-y-3">
      {sortedSignals.length === 0 ? (
        <p className="text-sm text-gray-500 text-center py-4">No signals detected</p>
      ) : (
        sortedSignals.map((signal, i) => (
          <SignalCard key={i} signal={signal} />
        ))
      )}
    </div>
  );
}

function SignalCard({ signal }: { signal: ThreatSignal }) {
  const severityColors = {
    critical: 'border-red-500 bg-red-50',
    high: 'border-orange-500 bg-orange-50',
    medium: 'border-yellow-500 bg-yellow-50',
    low: 'border-blue-500 bg-blue-50',
  };

  return (
    <div className={clsx('border-l-4 rounded p-3', severityColors[signal.severity])}>
      <div className="flex items-center justify-between">
        <span className="font-medium text-sm text-gray-900">{signal.type}</span>
        <span className="text-xs bg-gray-200 px-2 py-0.5 rounded">+{signal.score}</span>
      </div>
      <p className="text-sm text-gray-600 mt-1">{signal.description}</p>
      {signal.evidence && (
        <p className="text-xs text-gray-500 mt-1 font-mono bg-white/50 p-1 rounded">
          {signal.evidence}
        </p>
      )}
    </div>
  );
}

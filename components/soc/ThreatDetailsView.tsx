/**
 * ThreatDetailsView - Overview tab for threat investigation
 *
 * Shows threat score, recipients, body preview, and key indicators.
 */

import clsx from 'clsx';
import type { ThreatDetails } from './InvestigationPanel';

interface ThreatDetailsViewProps {
  threat: ThreatDetails;
}

export function ThreatDetailsView({ threat }: ThreatDetailsViewProps) {
  return (
    <div className="space-y-4">
      {/* Confidence Score */}
      <div>
        <h5 className="text-sm font-medium text-gray-700 mb-2">Threat Score</h5>
        <div className="flex items-center gap-3">
          <div className="flex-1 bg-gray-200 rounded-full h-3">
            <div
              className={clsx(
                'h-3 rounded-full transition-all',
                threat.confidence >= 80 ? 'bg-red-500' :
                threat.confidence >= 60 ? 'bg-orange-500' :
                threat.confidence >= 40 ? 'bg-yellow-500' : 'bg-green-500'
              )}
              style={{ width: `${threat.confidence}%` }}
            />
          </div>
          <span className="text-lg font-bold text-gray-900">{threat.confidence}</span>
        </div>
      </div>

      {/* Recipients */}
      <div>
        <h5 className="text-sm font-medium text-gray-700 mb-2">Recipients</h5>
        <div className="flex flex-wrap gap-1">
          {threat.toAddresses.map((addr, i) => (
            <span
              key={i}
              className="inline-flex items-center px-2 py-1 rounded text-xs bg-gray-100 text-gray-700"
            >
              {addr}
            </span>
          ))}
        </div>
      </div>

      {/* Body Preview */}
      {threat.bodyPreview && (
        <div>
          <h5 className="text-sm font-medium text-gray-700 mb-2">Body Preview</h5>
          <div className="bg-gray-50 rounded p-3 text-sm text-gray-600 max-h-40 overflow-y-auto">
            {threat.bodyPreview}
          </div>
        </div>
      )}

      {/* Key Indicators */}
      <div>
        <h5 className="text-sm font-medium text-gray-700 mb-2">Key Indicators</h5>
        <div className="grid grid-cols-2 gap-2">
          <StatCard label="Signals" value={threat.signals.length} />
          <StatCard label="URLs" value={threat.urls.length} />
          <StatCard label="Attachments" value={threat.attachments.length} />
          <StatCard
            label="Malicious URLs"
            value={threat.urls.filter((u) => u.reputation === 'malicious').length}
            variant="danger"
          />
        </div>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  variant,
}: {
  label: string;
  value: number;
  variant?: 'danger';
}) {
  return (
    <div className={clsx('p-2 rounded', variant === 'danger' ? 'bg-red-50' : 'bg-gray-50')}>
      <p className="text-xs text-gray-500">{label}</p>
      <p className={clsx('text-lg font-bold', variant === 'danger' ? 'text-red-600' : 'text-gray-900')}>
        {value}
      </p>
    </div>
  );
}

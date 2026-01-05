/**
 * Compliance Reports Page
 *
 * Generate and download SOC 2 and HIPAA compliance reports
 */

'use client';

import { useState } from 'react';

type ReportType = 'soc2' | 'hipaa';
type ReportFormat = 'json' | 'html';

interface ReportConfig {
  type: ReportType;
  startDate: string;
  endDate: string;
  format: ReportFormat;
}

interface ReportData {
  executive?: {
    overallStatus?: string;
    score?: number;
  };
  organization?: {
    name?: string;
  };
  findings?: Array<{ severity: string }>;
}

export default function ComplianceReportsPage() {
  const [config, setConfig] = useState<ReportConfig>({
    type: 'soc2',
    startDate: getDefaultStartDate(),
    endDate: getDefaultEndDate(),
    format: 'html',
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ReportData | null>(null);

  const handleGenerateReport = async () => {
    setLoading(true);
    setError(null);
    setReport(null);

    try {
      const response = await fetch('/api/reports/compliance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to generate report');
      }

      if (config.format === 'html') {
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${config.type}-report-${Date.now()}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } else {
        const data = await response.json();
        setReport(data.report);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate report');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Compliance Reports</h1>
        <p className="mt-1 text-sm text-gray-500">
          Generate SOC 2 Type II and HIPAA Security Rule compliance reports
        </p>
      </div>

      {/* Report Configuration */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Generate Report</h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Report Type */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Report Type
            </label>
            <div className="grid grid-cols-2 gap-3">
              <ReportTypeCard
                type="soc2"
                title="SOC 2 Type II"
                description="Trust Services Criteria"
                icon="🔒"
                selected={config.type === 'soc2'}
                onClick={() => setConfig({ ...config, type: 'soc2' })}
              />
              <ReportTypeCard
                type="hipaa"
                title="HIPAA"
                description="Security Rule Compliance"
                icon="🏥"
                selected={config.type === 'hipaa'}
                onClick={() => setConfig({ ...config, type: 'hipaa' })}
              />
            </div>
          </div>

          {/* Date Range */}
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Audit Period Start
              </label>
              <input
                type="date"
                value={config.startDate}
                onChange={(e) => setConfig({ ...config, startDate: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Audit Period End
              </label>
              <input
                type="date"
                value={config.endDate}
                onChange={(e) => setConfig({ ...config, endDate: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>
        </div>

        {/* Format Selection */}
        <div className="mt-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Output Format
          </label>
          <div className="flex gap-4">
            <label className="flex items-center">
              <input
                type="radio"
                name="format"
                value="html"
                checked={config.format === 'html'}
                onChange={() => setConfig({ ...config, format: 'html' })}
                className="mr-2"
              />
              <span className="text-sm text-gray-700">HTML (Download)</span>
            </label>
            <label className="flex items-center">
              <input
                type="radio"
                name="format"
                value="json"
                checked={config.format === 'json'}
                onChange={() => setConfig({ ...config, format: 'json' })}
                className="mr-2"
              />
              <span className="text-sm text-gray-700">JSON (Preview)</span>
            </label>
          </div>
        </div>

        {/* Generate Button */}
        <div className="mt-6">
          <button
            onClick={handleGenerateReport}
            disabled={loading}
            className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-md font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <LoadingSpinner className="w-4 h-4 mr-2" />
                Generating...
              </>
            ) : (
              <>
                <DocumentIcon className="w-4 h-4 mr-2" />
                Generate Report
              </>
            )}
          </button>
        </div>

        {/* Error */}
        {error && (
          <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-md">
            <p className="text-red-800">{error}</p>
          </div>
        )}
      </div>

      {/* Report Preview (JSON format) */}
      {report && config.format === 'json' && (
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">Report Preview</h2>
            <button
              onClick={() => {
                const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${config.type}-report-${Date.now()}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
              }}
              className="text-sm text-blue-600 hover:text-blue-800"
            >
              Download JSON
            </button>
          </div>

          <ReportSummary report={report} />

          <details className="mt-4">
            <summary className="cursor-pointer text-sm text-gray-500 hover:text-gray-700">
              View Raw JSON
            </summary>
            <pre className="mt-2 p-4 bg-gray-50 rounded overflow-x-auto text-xs">
              {JSON.stringify(report, null, 2)}
            </pre>
          </details>
        </div>
      )}

      {/* Report Types Info */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <InfoCard
          title="SOC 2 Type II"
          icon="🔒"
          items={[
            'Control Environment (CC1)',
            'Communication and Information (CC2)',
            'Risk Assessment (CC3)',
            'Logical and Physical Access (CC6)',
            'System Operations (CC7)',
          ]}
        />
        <InfoCard
          title="HIPAA Security Rule"
          icon="🏥"
          items={[
            'Administrative Safeguards (164.308)',
            'Technical Safeguards (164.312)',
            'PHI Protection Metrics',
            'Access Control Requirements',
            'Transmission Security',
          ]}
        />
      </div>
    </div>
  );
}

// Helper Components
function ReportTypeCard({
  type,
  title,
  description,
  icon,
  selected,
  onClick,
}: {
  type: ReportType;
  title: string;
  description: string;
  icon: string;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`p-4 rounded-lg border-2 text-left transition-all ${
        selected
          ? 'border-blue-500 bg-blue-50'
          : 'border-gray-200 hover:border-gray-300'
      }`}
    >
      <span className="text-2xl">{icon}</span>
      <h3 className="mt-2 font-semibold text-gray-900">{title}</h3>
      <p className="text-sm text-gray-500">{description}</p>
    </button>
  );
}

function ReportSummary({ report }: { report: ReportData }) {
  const r = report;

  return (
    <div className="grid grid-cols-3 gap-4">
      <div className="p-4 bg-gray-50 rounded-lg">
        <p className="text-sm text-gray-500">Status</p>
        <p className={`text-lg font-bold ${
          r.executive?.overallStatus === 'compliant' ? 'text-green-600' :
          r.executive?.overallStatus === 'partially_compliant' ? 'text-yellow-600' : 'text-red-600'
        }`}>
          {formatStatus(r.executive?.overallStatus || 'unknown')}
        </p>
      </div>
      <div className="p-4 bg-gray-50 rounded-lg">
        <p className="text-sm text-gray-500">Score</p>
        <p className="text-lg font-bold text-gray-900">{r.executive?.score || 0}%</p>
      </div>
      <div className="p-4 bg-gray-50 rounded-lg">
        <p className="text-sm text-gray-500">Findings</p>
        <p className="text-lg font-bold text-gray-900">{r.findings?.length || 0}</p>
      </div>
    </div>
  );
}

function InfoCard({
  title,
  icon,
  items,
}: {
  title: string;
  icon: string;
  items: string[];
}) {
  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center gap-2 mb-4">
        <span className="text-2xl">{icon}</span>
        <h3 className="text-lg font-semibold text-gray-900">{title}</h3>
      </div>
      <ul className="space-y-2">
        {items.map((item, i) => (
          <li key={i} className="flex items-center text-sm text-gray-600">
            <CheckIcon className="w-4 h-4 text-green-500 mr-2" />
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}

// Helper Functions
function getDefaultStartDate(): string {
  const date = new Date();
  date.setMonth(date.getMonth() - 3);
  return date.toISOString().split('T')[0];
}

function getDefaultEndDate(): string {
  return new Date().toISOString().split('T')[0];
}

function formatStatus(status: string): string {
  const map: Record<string, string> = {
    compliant: 'Compliant',
    partially_compliant: 'Partially Compliant',
    non_compliant: 'Non-Compliant',
    unknown: 'Unknown',
  };
  return map[status] || status;
}

// Icons
function DocumentIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
    </svg>
  );
}

function LoadingSpinner({ className }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
    </svg>
  );
}

function CheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
    </svg>
  );
}

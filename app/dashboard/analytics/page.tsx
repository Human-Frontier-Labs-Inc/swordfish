'use client';

import { useEffect, useState } from 'react';

interface AnalyticsData {
  overview: {
    totalEmails: number;
    threatsBlocked: number;
    quarantined: number;
    falsePositives: number;
    detectionRate: number;
  };
  trends: {
    date: string;
    emails: number;
    threats: number;
    quarantined: number;
  }[];
  threatTypes: {
    type: string;
    count: number;
    percentage: number;
  }[];
  topSenders: {
    email: string;
    domain: string;
    threatCount: number;
  }[];
  verdictDistribution: {
    verdict: string;
    count: number;
    percentage: number;
  }[];
  responseMetrics: {
    avgProcessingTime: number;
    avgReleaseTime: number;
    autoQuarantineRate: number;
  };
}

export default function AnalyticsPage() {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState<'7d' | '30d' | '90d'>('30d');

  useEffect(() => {
    loadAnalytics();
  }, [timeRange]);

  async function loadAnalytics() {
    try {
      setLoading(true);
      const response = await fetch(`/api/analytics/overview?range=${timeRange}`);
      if (response.ok) {
        const result = await response.json();
        setData(result);
      }
    } catch (error) {
      console.error('Failed to load analytics:', error);
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-8 bg-gray-200 rounded w-48 animate-pulse" />
        <div className="grid grid-cols-4 gap-6">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-32 bg-gray-200 rounded-lg animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Threat Analytics</h1>
        <div className="flex gap-2">
          {(['7d', '30d', '90d'] as const).map((range) => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                timeRange === range
                  ? 'bg-blue-600 text-white'
                  : 'bg-white border hover:bg-gray-50'
              }`}
            >
              {range === '7d' ? '7 Days' : range === '30d' ? '30 Days' : '90 Days'}
            </button>
          ))}
        </div>
      </div>

      {/* Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          label="Total Emails"
          value={data?.overview.totalEmails || 0}
          format="number"
        />
        <StatCard
          label="Threats Blocked"
          value={data?.overview.threatsBlocked || 0}
          format="number"
          color="red"
        />
        <StatCard
          label="Quarantined"
          value={data?.overview.quarantined || 0}
          format="number"
          color="yellow"
        />
        <StatCard
          label="False Positives"
          value={data?.overview.falsePositives || 0}
          format="number"
          color="blue"
        />
        <StatCard
          label="Detection Rate"
          value={data?.overview.detectionRate || 0}
          format="percent"
          color="green"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Trends Chart */}
        <div className="bg-white rounded-lg border p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Email & Threat Trends</h3>
          <div className="h-64">
            <TrendChart data={data?.trends || []} />
          </div>
        </div>

        {/* Threat Types */}
        <div className="bg-white rounded-lg border p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Threat Types Distribution</h3>
          <div className="space-y-3">
            {data?.threatTypes.map((type) => (
              <div key={type.type}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="capitalize">{type.type.replace('_', ' ')}</span>
                  <span className="text-gray-500">{type.count} ({type.percentage.toFixed(1)}%)</span>
                </div>
                <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-red-500 rounded-full"
                    style={{ width: `${type.percentage}%` }}
                  />
                </div>
              </div>
            )) || (
              <p className="text-gray-500 text-sm">No threat data available</p>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Verdict Distribution */}
        <div className="bg-white rounded-lg border p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Verdict Distribution</h3>
          <div className="space-y-3">
            {data?.verdictDistribution.map((v) => (
              <div key={v.verdict} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className={`w-3 h-3 rounded-full ${getVerdictColor(v.verdict)}`} />
                  <span className="capitalize">{v.verdict}</span>
                </div>
                <span className="text-sm text-gray-500">{v.count}</span>
              </div>
            )) || (
              <p className="text-gray-500 text-sm">No data available</p>
            )}
          </div>
        </div>

        {/* Top Threat Senders */}
        <div className="bg-white rounded-lg border p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Top Threat Sources</h3>
          <div className="space-y-3">
            {data?.topSenders.slice(0, 5).map((sender, i) => (
              <div key={sender.email} className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="w-6 h-6 rounded-full bg-gray-100 flex items-center justify-center text-xs font-medium">
                    {i + 1}
                  </span>
                  <div>
                    <p className="text-sm font-medium truncate max-w-[180px]" title={sender.email}>
                      {sender.domain}
                    </p>
                  </div>
                </div>
                <span className="text-sm text-red-600 font-medium">{sender.threatCount}</span>
              </div>
            )) || (
              <p className="text-gray-500 text-sm">No data available</p>
            )}
          </div>
        </div>

        {/* Response Metrics */}
        <div className="bg-white rounded-lg border p-6">
          <h3 className="font-semibold text-gray-900 mb-4">Response Metrics</h3>
          <div className="space-y-4">
            <div>
              <p className="text-sm text-gray-500">Avg Processing Time</p>
              <p className="text-2xl font-bold text-gray-900">
                {data?.responseMetrics.avgProcessingTime || 0}ms
              </p>
            </div>
            <div>
              <p className="text-sm text-gray-500">Avg Time to Release</p>
              <p className="text-2xl font-bold text-gray-900">
                {formatDuration(data?.responseMetrics.avgReleaseTime || 0)}
              </p>
            </div>
            <div>
              <p className="text-sm text-gray-500">Auto-Quarantine Rate</p>
              <p className="text-2xl font-bold text-gray-900">
                {(data?.responseMetrics.autoQuarantineRate || 0).toFixed(1)}%
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  format,
  color = 'gray',
}: {
  label: string;
  value: number;
  format: 'number' | 'percent';
  color?: 'gray' | 'red' | 'yellow' | 'blue' | 'green';
}) {
  const colors = {
    gray: 'bg-gray-50 border-gray-200',
    red: 'bg-red-50 border-red-200',
    yellow: 'bg-yellow-50 border-yellow-200',
    blue: 'bg-blue-50 border-blue-200',
    green: 'bg-green-50 border-green-200',
  };

  const formatValue = () => {
    if (format === 'percent') return `${value.toFixed(1)}%`;
    if (value >= 1000000) return `${(value / 1000000).toFixed(1)}M`;
    if (value >= 1000) return `${(value / 1000).toFixed(1)}K`;
    return value.toLocaleString();
  };

  return (
    <div className={`rounded-lg border p-4 ${colors[color]}`}>
      <p className="text-sm text-gray-600">{label}</p>
      <p className="text-2xl font-bold text-gray-900 mt-1">{formatValue()}</p>
    </div>
  );
}

function TrendChart({ data }: { data: { date: string; emails: number; threats: number }[] }) {
  if (data.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-gray-400">
        No trend data available
      </div>
    );
  }

  const maxEmails = Math.max(...data.map(d => d.emails), 1);

  return (
    <div className="h-full flex items-end gap-1">
      {data.map((point, i) => (
        <div key={i} className="flex-1 flex flex-col items-center gap-1">
          <div className="w-full flex flex-col gap-0.5" style={{ height: '200px' }}>
            <div
              className="w-full bg-blue-200 rounded-t"
              style={{ height: `${(point.emails / maxEmails) * 100}%` }}
              title={`${point.emails} emails`}
            />
            <div
              className="w-full bg-red-400 rounded-b"
              style={{ height: `${(point.threats / maxEmails) * 100}%` }}
              title={`${point.threats} threats`}
            />
          </div>
          {i % 5 === 0 && (
            <span className="text-xs text-gray-400">
              {new Date(point.date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
            </span>
          )}
        </div>
      ))}
    </div>
  );
}

function getVerdictColor(verdict: string): string {
  switch (verdict) {
    case 'pass': return 'bg-green-500';
    case 'quarantine': return 'bg-yellow-500';
    case 'block': return 'bg-red-500';
    case 'review': return 'bg-blue-500';
    default: return 'bg-gray-500';
  }
}

function formatDuration(minutes: number): string {
  if (minutes < 60) return `${minutes.toFixed(0)}m`;
  if (minutes < 1440) return `${(minutes / 60).toFixed(1)}h`;
  return `${(minutes / 1440).toFixed(1)}d`;
}

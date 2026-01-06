'use client';

import { useEffect, useState } from 'react';

interface OverviewReport {
  summary: {
    totalThreats: number;
    changeFromPrevious: number;
    byVerdict: { malicious: number; phishing: number; suspicious: number };
    byStatus: { quarantined: number; released: number; deleted: number };
    averageScore: number;
    affectedTenants: number;
  };
  topSources: Array<{ email: string; count: number; avgScore: number }>;
  topTargets: Array<{ email: string; count: number }>;
}

interface TrendData {
  daily: Array<{
    date: string;
    total: number;
    malicious: number;
    phishing: number;
    suspicious: number;
  }>;
  hourlyDistribution: Array<{ hour: number; count: number }>;
  weekdayDistribution: Array<{ day: string; dayIndex: number; count: number }>;
}

interface TenantReport {
  tenants: Array<{
    tenantId: string;
    tenantName: string;
    totalThreats: number;
    malicious: number;
    phishing: number;
    quarantined: number;
    avgScore: number;
    riskScore: number;
    riskLevel: 'high' | 'medium' | 'low';
  }>;
  summary: {
    totalTenants: number;
    highRisk: number;
    mediumRisk: number;
    lowRisk: number;
  };
}

interface ThreatBreakdown {
  categories: Array<{ category: string; count: number }>;
  signals: Array<{ signal: string; count: number }>;
  scoreDistribution: Array<{ range: string; count: number }>;
  integrations: Array<{ type: string; count: number }>;
}

type Period = '7d' | '30d' | '90d';

export default function AdminReportsPage() {
  const [period, setPeriod] = useState<Period>('30d');
  const [activeTab, setActiveTab] = useState<'overview' | 'trends' | 'tenants' | 'breakdown'>('overview');
  const [loading, setLoading] = useState(true);
  const [overview, setOverview] = useState<OverviewReport | null>(null);
  const [trends, setTrends] = useState<TrendData | null>(null);
  const [tenantReport, setTenantReport] = useState<TenantReport | null>(null);
  const [breakdown, setBreakdown] = useState<ThreatBreakdown | null>(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    loadData();
  }, [period, activeTab]);

  async function loadData() {
    setLoading(true);
    try {
      if (activeTab === 'overview') {
        const res = await fetch(`/api/admin/reports?type=overview&period=${period}`);
        if (res.ok) setOverview(await res.json());
      } else if (activeTab === 'trends') {
        const res = await fetch(`/api/admin/reports?type=trends&period=${period}`);
        if (res.ok) setTrends(await res.json());
      } else if (activeTab === 'tenants') {
        const res = await fetch(`/api/admin/reports?type=tenants&period=${period}`);
        if (res.ok) setTenantReport(await res.json());
      } else if (activeTab === 'breakdown') {
        const res = await fetch(`/api/admin/reports?type=threats&period=${period}`);
        if (res.ok) setBreakdown(await res.json());
      }
    } catch (error) {
      console.error('Failed to load report:', error);
    } finally {
      setLoading(false);
    }
  }

  async function handleExport(format: 'json' | 'csv') {
    setExporting(true);
    try {
      const res = await fetch(`/api/admin/reports?type=export&period=${period}&format=${format}`);
      if (res.ok) {
        if (format === 'csv') {
          const blob = await res.blob();
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `threats-export-${new Date().toISOString().split('T')[0]}.csv`;
          a.click();
          URL.revokeObjectURL(url);
        } else {
          const data = await res.json();
          const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `threats-export-${new Date().toISOString().split('T')[0]}.json`;
          a.click();
          URL.revokeObjectURL(url);
        }
      }
    } catch (error) {
      console.error('Export failed:', error);
    } finally {
      setExporting(false);
    }
  }

  const riskLevelColors = {
    high: 'bg-red-100 text-red-800',
    medium: 'bg-yellow-100 text-yellow-800',
    low: 'bg-green-100 text-green-800',
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Reports & Analytics</h1>
          <p className="text-gray-600">Comprehensive threat intelligence across all tenants</p>
        </div>
        <div className="flex items-center gap-4">
          {/* Period Selector */}
          <select
            value={period}
            onChange={(e) => setPeriod(e.target.value as Period)}
            className="px-3 py-2 border rounded-lg text-sm"
          >
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="90d">Last 90 days</option>
          </select>

          {/* Export Buttons */}
          <div className="flex gap-2">
            <button
              onClick={() => handleExport('csv')}
              disabled={exporting}
              className="px-4 py-2 bg-green-600 text-white rounded-lg text-sm hover:bg-green-700 disabled:opacity-50"
            >
              Export CSV
            </button>
            <button
              onClick={() => handleExport('json')}
              disabled={exporting}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 disabled:opacity-50"
            >
              Export JSON
            </button>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b">
        <nav className="flex gap-4">
          {[
            { id: 'overview', label: 'Overview' },
            { id: 'trends', label: 'Trends' },
            { id: 'tenants', label: 'Tenant Comparison' },
            { id: 'breakdown', label: 'Threat Breakdown' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`px-4 py-2 border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-600 hover:text-gray-900'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
        </div>
      ) : (
        <>
          {/* Overview Tab */}
          {activeTab === 'overview' && overview && (
            <div className="space-y-6">
              {/* Summary Cards */}
              <div className="grid grid-cols-4 gap-4">
                <div className="bg-white rounded-lg shadow p-6">
                  <p className="text-sm text-gray-600">Total Threats</p>
                  <p className="text-3xl font-bold text-gray-900">{overview.summary.totalThreats.toLocaleString()}</p>
                  <p className={`text-sm ${overview.summary.changeFromPrevious >= 0 ? 'text-red-600' : 'text-green-600'}`}>
                    {overview.summary.changeFromPrevious >= 0 ? '+' : ''}{overview.summary.changeFromPrevious}% from previous period
                  </p>
                </div>
                <div className="bg-white rounded-lg shadow p-6">
                  <p className="text-sm text-gray-600">Average Score</p>
                  <p className="text-3xl font-bold text-gray-900">{overview.summary.averageScore}</p>
                  <p className="text-sm text-gray-500">Threat severity</p>
                </div>
                <div className="bg-white rounded-lg shadow p-6">
                  <p className="text-sm text-gray-600">Affected Tenants</p>
                  <p className="text-3xl font-bold text-gray-900">{overview.summary.affectedTenants}</p>
                  <p className="text-sm text-gray-500">With detected threats</p>
                </div>
                <div className="bg-white rounded-lg shadow p-6">
                  <p className="text-sm text-gray-600">Quarantine Rate</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {overview.summary.totalThreats > 0
                      ? Math.round((overview.summary.byStatus.quarantined / overview.summary.totalThreats) * 100)
                      : 0}%
                  </p>
                  <p className="text-sm text-gray-500">Threats contained</p>
                </div>
              </div>

              {/* Verdict & Status Breakdown */}
              <div className="grid grid-cols-2 gap-6">
                <div className="bg-white rounded-lg shadow p-6">
                  <h3 className="text-lg font-semibold mb-4">By Verdict</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-700">Malicious</span>
                      <span className="font-semibold text-red-600">{overview.summary.byVerdict.malicious.toLocaleString()}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-700">Phishing</span>
                      <span className="font-semibold text-orange-600">{overview.summary.byVerdict.phishing.toLocaleString()}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-700">Suspicious</span>
                      <span className="font-semibold text-yellow-600">{overview.summary.byVerdict.suspicious.toLocaleString()}</span>
                    </div>
                  </div>
                </div>

                <div className="bg-white rounded-lg shadow p-6">
                  <h3 className="text-lg font-semibold mb-4">By Status</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-700">Quarantined</span>
                      <span className="font-semibold text-blue-600">{overview.summary.byStatus.quarantined.toLocaleString()}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-700">Released</span>
                      <span className="font-semibold text-green-600">{overview.summary.byStatus.released.toLocaleString()}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-700">Deleted</span>
                      <span className="font-semibold text-gray-600">{overview.summary.byStatus.deleted.toLocaleString()}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Top Sources & Targets */}
              <div className="grid grid-cols-2 gap-6">
                <div className="bg-white rounded-lg shadow p-6">
                  <h3 className="text-lg font-semibold mb-4">Top Threat Sources</h3>
                  {overview.topSources.length === 0 ? (
                    <p className="text-gray-500 text-center py-4">No data available</p>
                  ) : (
                    <table className="w-full">
                      <thead>
                        <tr className="text-left text-sm text-gray-500">
                          <th className="pb-2">Email</th>
                          <th className="pb-2 text-right">Count</th>
                          <th className="pb-2 text-right">Avg Score</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y">
                        {overview.topSources.slice(0, 5).map((source, i) => (
                          <tr key={i}>
                            <td className="py-2 text-sm truncate max-w-[200px]">{source.email}</td>
                            <td className="py-2 text-sm text-right font-medium">{source.count}</td>
                            <td className="py-2 text-sm text-right">{source.avgScore}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>

                <div className="bg-white rounded-lg shadow p-6">
                  <h3 className="text-lg font-semibold mb-4">Most Targeted Recipients</h3>
                  {overview.topTargets.length === 0 ? (
                    <p className="text-gray-500 text-center py-4">No data available</p>
                  ) : (
                    <table className="w-full">
                      <thead>
                        <tr className="text-left text-sm text-gray-500">
                          <th className="pb-2">Email</th>
                          <th className="pb-2 text-right">Count</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y">
                        {overview.topTargets.slice(0, 5).map((target, i) => (
                          <tr key={i}>
                            <td className="py-2 text-sm truncate max-w-[200px]">{target.email}</td>
                            <td className="py-2 text-sm text-right font-medium">{target.count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Trends Tab */}
          {activeTab === 'trends' && trends && (
            <div className="space-y-6">
              {/* Daily Trend Chart (simplified bar representation) */}
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold mb-4">Daily Threat Volume</h3>
                {trends.daily.length === 0 ? (
                  <p className="text-gray-500 text-center py-8">No trend data available</p>
                ) : (
                  <div className="overflow-x-auto">
                    <div className="flex items-end gap-1 h-48 min-w-[600px]">
                      {trends.daily.map((day, i) => {
                        const maxTotal = Math.max(...trends.daily.map(d => d.total));
                        const height = maxTotal > 0 ? (day.total / maxTotal) * 100 : 0;
                        return (
                          <div key={i} className="flex-1 flex flex-col items-center">
                            <div
                              className="w-full bg-blue-500 rounded-t hover:bg-blue-600 transition-colors"
                              style={{ height: `${height}%`, minHeight: day.total > 0 ? '4px' : '0' }}
                              title={`${day.date}: ${day.total} threats`}
                            />
                            <span className="text-xs text-gray-500 mt-1 rotate-45 origin-left">
                              {new Date(day.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>

              <div className="grid grid-cols-2 gap-6">
                {/* Hourly Distribution */}
                <div className="bg-white rounded-lg shadow p-6">
                  <h3 className="text-lg font-semibold mb-4">Hourly Distribution</h3>
                  {trends.hourlyDistribution.length === 0 ? (
                    <p className="text-gray-500 text-center py-4">No data available</p>
                  ) : (
                    <div className="flex items-end gap-0.5 h-32">
                      {Array.from({ length: 24 }, (_, hour) => {
                        const data = trends.hourlyDistribution.find(h => h.hour === hour);
                        const count = data?.count || 0;
                        const maxCount = Math.max(...trends.hourlyDistribution.map(h => h.count));
                        const height = maxCount > 0 ? (count / maxCount) * 100 : 0;
                        return (
                          <div key={hour} className="flex-1 flex flex-col items-center">
                            <div
                              className="w-full bg-purple-500 rounded-t"
                              style={{ height: `${height}%`, minHeight: count > 0 ? '2px' : '0' }}
                              title={`${hour}:00 - ${count} threats`}
                            />
                          </div>
                        );
                      })}
                    </div>
                  )}
                  <div className="flex justify-between text-xs text-gray-500 mt-2">
                    <span>12am</span>
                    <span>6am</span>
                    <span>12pm</span>
                    <span>6pm</span>
                    <span>12am</span>
                  </div>
                </div>

                {/* Day of Week Distribution */}
                <div className="bg-white rounded-lg shadow p-6">
                  <h3 className="text-lg font-semibold mb-4">Day of Week</h3>
                  <div className="space-y-2">
                    {trends.weekdayDistribution.map((day) => {
                      const maxCount = Math.max(...trends.weekdayDistribution.map(d => d.count));
                      const width = maxCount > 0 ? (day.count / maxCount) * 100 : 0;
                      return (
                        <div key={day.dayIndex} className="flex items-center gap-3">
                          <span className="w-16 text-sm text-gray-600">{day.day.slice(0, 3)}</span>
                          <div className="flex-1 bg-gray-100 rounded h-6">
                            <div
                              className="h-full bg-green-500 rounded"
                              style={{ width: `${width}%` }}
                            />
                          </div>
                          <span className="w-12 text-sm text-right font-medium">{day.count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Tenants Tab */}
          {activeTab === 'tenants' && tenantReport && (
            <div className="space-y-6">
              {/* Risk Summary */}
              <div className="grid grid-cols-4 gap-4">
                <div className="bg-white rounded-lg shadow p-6">
                  <p className="text-sm text-gray-600">Total Tenants</p>
                  <p className="text-3xl font-bold text-gray-900">{tenantReport.summary.totalTenants}</p>
                </div>
                <div className="bg-red-50 rounded-lg shadow p-6">
                  <p className="text-sm text-red-600">High Risk</p>
                  <p className="text-3xl font-bold text-red-700">{tenantReport.summary.highRisk}</p>
                </div>
                <div className="bg-yellow-50 rounded-lg shadow p-6">
                  <p className="text-sm text-yellow-600">Medium Risk</p>
                  <p className="text-3xl font-bold text-yellow-700">{tenantReport.summary.mediumRisk}</p>
                </div>
                <div className="bg-green-50 rounded-lg shadow p-6">
                  <p className="text-sm text-green-600">Low Risk</p>
                  <p className="text-3xl font-bold text-green-700">{tenantReport.summary.lowRisk}</p>
                </div>
              </div>

              {/* Tenant Table */}
              <div className="bg-white rounded-lg shadow overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-4 py-3 text-left text-sm font-medium text-gray-600">Tenant</th>
                      <th className="px-4 py-3 text-right text-sm font-medium text-gray-600">Threats</th>
                      <th className="px-4 py-3 text-right text-sm font-medium text-gray-600">Malicious</th>
                      <th className="px-4 py-3 text-right text-sm font-medium text-gray-600">Phishing</th>
                      <th className="px-4 py-3 text-right text-sm font-medium text-gray-600">Quarantined</th>
                      <th className="px-4 py-3 text-right text-sm font-medium text-gray-600">Avg Score</th>
                      <th className="px-4 py-3 text-center text-sm font-medium text-gray-600">Risk Level</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {tenantReport.tenants.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                          No tenant data available
                        </td>
                      </tr>
                    ) : (
                      tenantReport.tenants.map((tenant) => (
                        <tr key={tenant.tenantId} className="hover:bg-gray-50">
                          <td className="px-4 py-3 font-medium">{tenant.tenantName}</td>
                          <td className="px-4 py-3 text-right">{tenant.totalThreats.toLocaleString()}</td>
                          <td className="px-4 py-3 text-right text-red-600">{tenant.malicious}</td>
                          <td className="px-4 py-3 text-right text-orange-600">{tenant.phishing}</td>
                          <td className="px-4 py-3 text-right">{tenant.quarantined}</td>
                          <td className="px-4 py-3 text-right">{tenant.avgScore}</td>
                          <td className="px-4 py-3 text-center">
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${riskLevelColors[tenant.riskLevel]}`}>
                              {tenant.riskLevel.toUpperCase()}
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Breakdown Tab */}
          {activeTab === 'breakdown' && breakdown && (
            <div className="grid grid-cols-2 gap-6">
              {/* Categories */}
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold mb-4">Threat Categories</h3>
                {breakdown.categories.length === 0 ? (
                  <p className="text-gray-500 text-center py-4">No category data available</p>
                ) : (
                  <div className="space-y-2">
                    {breakdown.categories.slice(0, 10).map((cat, i) => {
                      const maxCount = breakdown.categories[0]?.count || 1;
                      const width = (cat.count / maxCount) * 100;
                      return (
                        <div key={i} className="flex items-center gap-3">
                          <span className="w-32 text-sm text-gray-600 truncate">{cat.category}</span>
                          <div className="flex-1 bg-gray-100 rounded h-4">
                            <div className="h-full bg-blue-500 rounded" style={{ width: `${width}%` }} />
                          </div>
                          <span className="w-12 text-sm text-right font-medium">{cat.count}</span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Signals */}
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold mb-4">Detection Signals</h3>
                {breakdown.signals.length === 0 ? (
                  <p className="text-gray-500 text-center py-4">No signal data available</p>
                ) : (
                  <div className="space-y-2">
                    {breakdown.signals.slice(0, 10).map((sig, i) => {
                      const maxCount = breakdown.signals[0]?.count || 1;
                      const width = (sig.count / maxCount) * 100;
                      return (
                        <div key={i} className="flex items-center gap-3">
                          <span className="w-32 text-sm text-gray-600 truncate">{sig.signal}</span>
                          <div className="flex-1 bg-gray-100 rounded h-4">
                            <div className="h-full bg-purple-500 rounded" style={{ width: `${width}%` }} />
                          </div>
                          <span className="w-12 text-sm text-right font-medium">{sig.count}</span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Score Distribution */}
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold mb-4">Score Distribution</h3>
                {breakdown.scoreDistribution.length === 0 ? (
                  <p className="text-gray-500 text-center py-4">No score data available</p>
                ) : (
                  <div className="space-y-3">
                    {breakdown.scoreDistribution.map((score, i) => {
                      const maxCount = Math.max(...breakdown.scoreDistribution.map(s => s.count));
                      const width = maxCount > 0 ? (score.count / maxCount) * 100 : 0;
                      const colors = ['bg-red-500', 'bg-orange-500', 'bg-yellow-500', 'bg-blue-500', 'bg-green-500'];
                      return (
                        <div key={i} className="flex items-center gap-3">
                          <span className="w-32 text-sm text-gray-600">{score.range}</span>
                          <div className="flex-1 bg-gray-100 rounded h-6">
                            <div className={`h-full ${colors[i] || 'bg-gray-500'} rounded`} style={{ width: `${width}%` }} />
                          </div>
                          <span className="w-12 text-sm text-right font-medium">{score.count}</span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Integration Types */}
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold mb-4">By Integration</h3>
                {breakdown.integrations.length === 0 ? (
                  <p className="text-gray-500 text-center py-4">No integration data available</p>
                ) : (
                  <div className="space-y-3">
                    {breakdown.integrations.map((int, i) => {
                      const total = breakdown.integrations.reduce((sum, i) => sum + i.count, 0);
                      const percent = total > 0 ? Math.round((int.count / total) * 100) : 0;
                      return (
                        <div key={i} className="flex items-center justify-between p-3 bg-gray-50 rounded">
                          <span className="font-medium">{int.type}</span>
                          <div className="flex items-center gap-2">
                            <span className="text-gray-600">{int.count.toLocaleString()}</span>
                            <span className="text-sm text-gray-500">({percent}%)</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

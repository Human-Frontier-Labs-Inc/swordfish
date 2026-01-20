'use client';

import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';

interface ScheduledReport {
  id: string;
  name: string;
  type: 'executive_summary' | 'threat_report' | 'audit_report';
  frequency: 'daily' | 'weekly' | 'monthly';
  recipients: string[];
  enabled: boolean;
  lastRunAt?: string;
  nextRunAt: string;
  createdAt: string;
}

interface PerformanceData {
  performance: {
    avgLatency: number;
    p95Latency: number;
    p99Latency: number;
    llmUsageRate: number;
    avgTokensPerLLM: number;
  };
  policyEffectiveness: {
    allowlistHits: number;
    blocklistHits: number;
    customPolicyHits: number;
    falsePositives: number;
    falseNegatives: number;
  };
  topSenders: Array<{
    email: string;
    domain: string;
    threatCount: number;
    avgScore: number;
  }>;
  topDomains: Array<{
    domain: string;
    count: number;
    avgScore: number;
  }>;
}

export default function ReportsPage() {
  const [activeTab, setActiveTab] = useState<'overview' | 'scheduled' | 'export'>('overview');
  const [reports, setReports] = useState<ScheduledReport[]>([]);
  const [performance, setPerformance] = useState<PerformanceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [exporting, setExporting] = useState<string | null>(null);

  // Form state
  const [newReport, setNewReport] = useState({
    name: '',
    type: 'executive_summary' as ScheduledReport['type'],
    frequency: 'weekly' as ScheduledReport['frequency'],
    recipients: '',
  });
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState('');

  const fetchReports = useCallback(async () => {
    try {
      const response = await fetch('/api/reports/scheduled');
      const data = await response.json();
      setReports(data.reports || []);
    } catch (error) {
      console.error('Failed to fetch reports:', error);
    }
  }, []);

  const fetchPerformance = useCallback(async () => {
    try {
      const response = await fetch('/api/analytics/performance?days=30');
      const data = await response.json();
      setPerformance(data);
    } catch (error) {
      console.error('Failed to fetch performance:', error);
    }
  }, []);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      await Promise.all([fetchReports(), fetchPerformance()]);
      setLoading(false);
    }
    loadData();
  }, [fetchReports, fetchPerformance]);

  async function createReport() {
    setCreateError('');

    if (!newReport.name.trim()) {
      setCreateError('Please enter a report name');
      return;
    }
    if (!newReport.recipients.trim()) {
      setCreateError('Please enter at least one recipient email');
      return;
    }

    setCreating(true);
    try {
      const response = await fetch('/api/reports/scheduled', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newReport.name,
          type: newReport.type,
          frequency: newReport.frequency,
          recipients: newReport.recipients.split(',').map((r) => r.trim()).filter(Boolean),
        }),
      });

      if (response.ok) {
        setNewReport({ name: '', type: 'executive_summary', frequency: 'weekly', recipients: '' });
        setShowCreateForm(false);
        fetchReports();
      } else {
        const data = await response.json();
        setCreateError(data.error || 'Failed to create report');
      }
    } catch (error) {
      console.error('Failed to create report:', error);
      setCreateError('Failed to create report. Please try again.');
    } finally {
      setCreating(false);
    }
  }

  async function toggleReport(reportId: string, enabled: boolean) {
    try {
      await fetch(`/api/reports/scheduled/${reportId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !enabled }),
      });
      fetchReports();
    } catch (error) {
      console.error('Failed to toggle report:', error);
    }
  }

  async function deleteReport(reportId: string) {
    if (!confirm('Delete this scheduled report?')) return;

    try {
      await fetch(`/api/reports/scheduled/${reportId}`, { method: 'DELETE' });
      fetchReports();
    } catch (error) {
      console.error('Failed to delete report:', error);
    }
  }

  async function exportReport(type: string, format: 'csv' | 'json') {
    setExporting(type);
    try {
      const response = await fetch(`/api/reports/export?type=${type}&format=${format}&days=30`);
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = response.headers.get('content-disposition')?.split('filename=')[1]?.replace(/"/g, '') || `report.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to export:', error);
    }
    setExporting(null);
  }

  function getFrequencyBadge(frequency: string) {
    const colors = {
      daily: 'bg-blue-100 text-blue-800',
      weekly: 'bg-green-100 text-green-800',
      monthly: 'bg-purple-100 text-purple-800',
    };
    return <Badge className={colors[frequency as keyof typeof colors]}>{frequency}</Badge>;
  }

  function formatDate(dateString: string) {
    return new Date(dateString).toLocaleString();
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Reports</h1>
        <p className="text-muted-foreground">
          View analytics, export data, and configure scheduled reports.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b">
        {(['overview', 'scheduled', 'export'] as const).map((tab) => (
          <button
            key={tab}
            className={`px-4 py-2 font-medium capitalize ${
              activeTab === tab
                ? 'border-b-2 border-blue-500 text-blue-600'
                : 'text-gray-500 hover:text-gray-700'
            }`}
            onClick={() => setActiveTab(tab)}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && performance && (
        <div className="space-y-6">
          {/* Performance Metrics */}
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardContent className="pt-6">
                <div className="text-2xl font-bold">{performance.performance.avgLatency}ms</div>
                <p className="text-sm text-muted-foreground">Avg Latency</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="text-2xl font-bold">{performance.performance.p95Latency}ms</div>
                <p className="text-sm text-muted-foreground">P95 Latency</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="text-2xl font-bold">{performance.performance.llmUsageRate}%</div>
                <p className="text-sm text-muted-foreground">LLM Usage Rate</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="text-2xl font-bold">{performance.performance.avgTokensPerLLM}</div>
                <p className="text-sm text-muted-foreground">Avg Tokens/LLM</p>
              </CardContent>
            </Card>
          </div>

          {/* Policy Effectiveness */}
          <Card>
            <CardHeader>
              <CardTitle>Policy Effectiveness</CardTitle>
              <CardDescription>How your security policies are performing</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-5">
                <div className="text-center p-4 bg-green-50 rounded-lg">
                  <div className="text-2xl font-bold text-green-600">{performance.policyEffectiveness.allowlistHits}</div>
                  <p className="text-sm text-muted-foreground">Allowlist Hits</p>
                </div>
                <div className="text-center p-4 bg-red-50 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{performance.policyEffectiveness.blocklistHits}</div>
                  <p className="text-sm text-muted-foreground">Blocklist Hits</p>
                </div>
                <div className="text-center p-4 bg-blue-50 rounded-lg">
                  <div className="text-2xl font-bold text-blue-600">{performance.policyEffectiveness.customPolicyHits}</div>
                  <p className="text-sm text-muted-foreground">Policy Matches</p>
                </div>
                <div className="text-center p-4 bg-yellow-50 rounded-lg">
                  <div className="text-2xl font-bold text-yellow-600">{performance.policyEffectiveness.falsePositives}</div>
                  <p className="text-sm text-muted-foreground">False Positives</p>
                </div>
                <div className="text-center p-4 bg-orange-50 rounded-lg">
                  <div className="text-2xl font-bold text-orange-600">{performance.policyEffectiveness.falseNegatives}</div>
                  <p className="text-sm text-muted-foreground">False Negatives</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Top Threat Senders & Domains */}
          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Top Threat Senders</CardTitle>
                <CardDescription>Most frequent sources of threats (30 days)</CardDescription>
              </CardHeader>
              <CardContent>
                {performance.topSenders.length === 0 ? (
                  <p className="text-muted-foreground text-center py-4">No threat data</p>
                ) : (
                  <div className="space-y-3">
                    {performance.topSenders.slice(0, 5).map((sender, i) => (
                      <div key={i} className="flex items-center justify-between">
                        <div className="truncate max-w-[200px]">
                          <p className="font-medium truncate">{sender.email}</p>
                          <p className="text-xs text-muted-foreground">{sender.domain}</p>
                        </div>
                        <div className="text-right">
                          <p className="font-medium">{sender.threatCount} threats</p>
                          <p className="text-xs text-muted-foreground">Avg: {sender.avgScore}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Top Threat Domains</CardTitle>
                <CardDescription>Domains sending the most threats (30 days)</CardDescription>
              </CardHeader>
              <CardContent>
                {performance.topDomains.length === 0 ? (
                  <p className="text-muted-foreground text-center py-4">No threat data</p>
                ) : (
                  <div className="space-y-3">
                    {performance.topDomains.slice(0, 5).map((domain, i) => (
                      <div key={i} className="flex items-center justify-between">
                        <p className="font-medium">{domain.domain}</p>
                        <div className="text-right">
                          <p className="font-medium">{domain.count} threats</p>
                          <p className="text-xs text-muted-foreground">Avg: {domain.avgScore}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      )}

      {/* Scheduled Reports Tab */}
      {activeTab === 'scheduled' && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle>Scheduled Reports</CardTitle>
              <CardDescription>Automated reports delivered on a schedule</CardDescription>
            </div>
            <Button onClick={() => setShowCreateForm(!showCreateForm)}>
              {showCreateForm ? 'Cancel' : 'Create Report'}
            </Button>
          </CardHeader>
          <CardContent>
            {/* Create Form */}
            {showCreateForm && (
              <div className="mb-6 p-4 bg-gray-50 rounded-lg space-y-4">
                {createError && (
                  <div className="bg-red-50 text-red-700 px-4 py-3 rounded text-sm">
                    {createError}
                  </div>
                )}
                <div className="grid grid-cols-2 gap-4">
                  <Input
                    placeholder="Report name"
                    value={newReport.name}
                    onChange={(e) => setNewReport({ ...newReport, name: e.target.value })}
                  />
                  <Input
                    placeholder="Recipients (comma-separated emails)"
                    value={newReport.recipients}
                    onChange={(e) => setNewReport({ ...newReport, recipients: e.target.value })}
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <select
                    className="rounded-md border border-gray-300 px-3 py-2"
                    value={newReport.type}
                    onChange={(e) => setNewReport({ ...newReport, type: e.target.value as ScheduledReport['type'] })}
                  >
                    <option value="executive_summary">Executive Summary</option>
                    <option value="threat_report">Threat Report</option>
                    <option value="audit_report">Audit Report</option>
                  </select>
                  <select
                    className="rounded-md border border-gray-300 px-3 py-2"
                    value={newReport.frequency}
                    onChange={(e) => setNewReport({ ...newReport, frequency: e.target.value as ScheduledReport['frequency'] })}
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </div>
                <div className="flex justify-end">
                  <Button onClick={createReport} disabled={creating}>
                    {creating ? 'Creating...' : 'Create'}
                  </Button>
                </div>
              </div>
            )}

            {/* Reports List */}
            {reports.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                <div className="text-4xl mb-4">📊</div>
                <p>No scheduled reports</p>
                <p className="text-sm mt-2">Create a report to receive automated updates</p>
              </div>
            ) : (
              <div className="space-y-4">
                {reports.map((report) => (
                  <div key={report.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="font-medium">{report.name}</h3>
                        {getFrequencyBadge(report.frequency)}
                        <Badge variant={report.enabled ? 'default' : 'secondary'}>
                          {report.enabled ? 'Active' : 'Paused'}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {report.recipients.length} recipient(s) | Next: {formatDate(report.nextRunAt)}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => toggleReport(report.id, report.enabled)}
                      >
                        {report.enabled ? 'Pause' : 'Resume'}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-red-600 hover:bg-red-50"
                        onClick={() => deleteReport(report.id)}
                      >
                        Delete
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Export Tab */}
      {activeTab === 'export' && (
        <div className="grid gap-6 md:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Executive Summary</CardTitle>
              <CardDescription>Comprehensive overview of security posture</CardDescription>
            </CardHeader>
            <CardContent className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => exportReport('executive', 'csv')}
                disabled={exporting === 'executive'}
              >
                Export CSV
              </Button>
              <Button
                variant="outline"
                onClick={() => exportReport('executive', 'json')}
                disabled={exporting === 'executive'}
              >
                Export JSON
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Verdict History</CardTitle>
              <CardDescription>All email analysis results</CardDescription>
            </CardHeader>
            <CardContent className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => exportReport('verdicts', 'csv')}
                disabled={exporting === 'verdicts'}
              >
                Export CSV
              </Button>
              <Button
                variant="outline"
                onClick={() => exportReport('verdicts', 'json')}
                disabled={exporting === 'verdicts'}
              >
                Export JSON
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Threat Log</CardTitle>
              <CardDescription>All quarantined and blocked threats</CardDescription>
            </CardHeader>
            <CardContent className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => exportReport('threats', 'csv')}
                disabled={exporting === 'threats'}
              >
                Export CSV
              </Button>
              <Button
                variant="outline"
                onClick={() => exportReport('threats', 'json')}
                disabled={exporting === 'threats'}
              >
                Export JSON
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Audit Log</CardTitle>
              <CardDescription>All system and user activities</CardDescription>
            </CardHeader>
            <CardContent className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => exportReport('audit', 'csv')}
                disabled={exporting === 'audit'}
              >
                Export CSV
              </Button>
              <Button
                variant="outline"
                onClick={() => exportReport('audit', 'json')}
                disabled={exporting === 'audit'}
              >
                Export JSON
              </Button>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

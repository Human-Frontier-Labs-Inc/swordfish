'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface ScheduledReport {
  id: string;
  name: string;
  type: 'threat_summary' | 'quarantine_digest' | 'user_activity' | 'compliance' | 'custom';
  schedule: 'daily' | 'weekly' | 'monthly';
  recipients: string[];
  format: 'pdf' | 'csv' | 'xlsx';
  filters: Record<string, unknown>;
  isActive: boolean;
  lastRunAt: string | null;
  nextRunAt: string | null;
  createdAt: string;
}

const reportTypes = {
  threat_summary: { name: 'Threat Summary', icon: '🛡️', description: 'Overview of detected threats and actions taken' },
  quarantine_digest: { name: 'Quarantine Digest', icon: '📥', description: 'Summary of quarantined emails and status' },
  user_activity: { name: 'User Activity', icon: '👥', description: 'User actions and login activity' },
  compliance: { name: 'Compliance Report', icon: '📋', description: 'Audit trail and compliance metrics' },
  custom: { name: 'Custom Report', icon: '📊', description: 'Custom filtered report' },
};

export default function ScheduledReportsPage() {
  const [reports, setReports] = useState<ScheduledReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);

  useEffect(() => {
    loadReports();
  }, []);

  async function loadReports() {
    try {
      const response = await fetch('/api/reports/scheduled');
      if (response.ok) {
        const data = await response.json();
        setReports(data.reports);
      }
    } catch (error) {
      console.error('Failed to load reports:', error);
    } finally {
      setLoading(false);
    }
  }

  async function toggleReport(id: string, isActive: boolean) {
    try {
      await fetch(`/api/reports/scheduled/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ isActive: !isActive }),
      });
      loadReports();
    } catch (error) {
      console.error('Failed to toggle report:', error);
    }
  }

  async function deleteReport(id: string) {
    if (!confirm('Are you sure you want to delete this scheduled report?')) return;

    try {
      await fetch(`/api/reports/scheduled/${id}`, { method: 'DELETE' });
      loadReports();
    } catch (error) {
      console.error('Failed to delete report:', error);
    }
  }

  async function runNow(id: string) {
    try {
      const response = await fetch(`/api/reports/scheduled/${id}/run`, { method: 'POST' });
      if (response.ok) {
        alert('Report generation started. You will receive it via email shortly.');
      }
    } catch (error) {
      console.error('Failed to run report:', error);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Link href="/dashboard/reports" className="text-gray-400 hover:text-gray-600">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <h1 className="text-2xl font-bold text-gray-900">Scheduled Reports</h1>
          </div>
          <p className="text-gray-600 mt-1">Automated reports delivered to your inbox</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
        >
          Create Schedule
        </button>
      </div>

      {/* Reports List */}
      {loading ? (
        <div className="bg-white rounded-lg border p-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto" />
        </div>
      ) : reports.length === 0 ? (
        <div className="bg-white rounded-lg border p-12 text-center">
          <svg className="w-16 h-16 mx-auto text-gray-300 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h3 className="text-lg font-medium text-gray-900 mb-2">No scheduled reports</h3>
          <p className="text-gray-500 mb-4">Create your first scheduled report to receive automated insights.</p>
          <button
            onClick={() => setShowCreateModal(true)}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
          >
            Create Schedule
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {reports.map((report) => (
            <div key={report.id} className="bg-white rounded-lg border p-6">
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-4">
                  <div className="text-3xl">{reportTypes[report.type]?.icon || '📊'}</div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold text-gray-900">{report.name}</h3>
                      <span className={`px-2 py-0.5 text-xs rounded ${
                        report.isActive ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'
                      }`}>
                        {report.isActive ? 'Active' : 'Paused'}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500 mt-1">
                      {reportTypes[report.type]?.name} • {report.schedule} • {report.format.toUpperCase()}
                    </p>
                    <div className="flex items-center gap-4 mt-2 text-sm text-gray-500">
                      <span>Recipients: {report.recipients.join(', ')}</span>
                    </div>
                    <div className="flex items-center gap-4 mt-1 text-xs text-gray-400">
                      {report.lastRunAt && (
                        <span>Last run: {new Date(report.lastRunAt).toLocaleString()}</span>
                      )}
                      {report.nextRunAt && (
                        <span>Next run: {new Date(report.nextRunAt).toLocaleString()}</span>
                      )}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => runNow(report.id)}
                    className="px-3 py-1.5 text-sm border rounded hover:bg-gray-50"
                  >
                    Run Now
                  </button>
                  <button
                    onClick={() => toggleReport(report.id, report.isActive)}
                    className={`px-3 py-1.5 text-sm border rounded ${
                      report.isActive ? 'hover:bg-yellow-50 text-yellow-600' : 'hover:bg-green-50 text-green-600'
                    }`}
                  >
                    {report.isActive ? 'Pause' : 'Resume'}
                  </button>
                  <button
                    onClick={() => deleteReport(report.id)}
                    className="px-3 py-1.5 text-sm border rounded hover:bg-red-50 text-red-600"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create Modal */}
      {showCreateModal && (
        <CreateReportModal
          onClose={() => setShowCreateModal(false)}
          onSuccess={() => {
            setShowCreateModal(false);
            loadReports();
          }}
        />
      )}
    </div>
  );
}

function CreateReportModal({
  onClose,
  onSuccess,
}: {
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [name, setName] = useState('');
  const [type, setType] = useState<ScheduledReport['type']>('threat_summary');
  const [schedule, setSchedule] = useState<ScheduledReport['schedule']>('weekly');
  const [format, setFormat] = useState<ScheduledReport['format']>('pdf');
  const [recipients, setRecipients] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('/api/reports/scheduled', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          type,
          schedule,
          format,
          recipients: recipients.split(',').map(r => r.trim()).filter(Boolean),
        }),
      });

      if (response.ok) {
        onSuccess();
      } else {
        const data = await response.json();
        setError(data.error || 'Failed to create report');
      }
    } catch (error) {
      setError('Failed to create report');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg max-w-lg w-full mx-4">
        <div className="border-b px-6 py-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">Create Scheduled Report</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="bg-red-50 text-red-700 px-4 py-3 rounded text-sm">{error}</div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Report Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="w-full border rounded-lg px-4 py-2"
              placeholder="Weekly Threat Summary"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Report Type</label>
            <select
              value={type}
              onChange={(e) => setType(e.target.value as ScheduledReport['type'])}
              className="w-full border rounded-lg px-4 py-2"
            >
              {Object.entries(reportTypes).map(([key, { name }]) => (
                <option key={key} value={key}>{name}</option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Schedule</label>
              <select
                value={schedule}
                onChange={(e) => setSchedule(e.target.value as ScheduledReport['schedule'])}
                className="w-full border rounded-lg px-4 py-2"
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Format</label>
              <select
                value={format}
                onChange={(e) => setFormat(e.target.value as ScheduledReport['format'])}
                className="w-full border rounded-lg px-4 py-2"
              >
                <option value="pdf">PDF</option>
                <option value="csv">CSV</option>
                <option value="xlsx">Excel</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Recipients</label>
            <input
              type="text"
              value={recipients}
              onChange={(e) => setRecipients(e.target.value)}
              required
              className="w-full border rounded-lg px-4 py-2"
              placeholder="email1@example.com, email2@example.com"
            />
            <p className="text-xs text-gray-500 mt-1">Comma-separated email addresses</p>
          </div>

          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 border rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              {loading ? 'Creating...' : 'Create Schedule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

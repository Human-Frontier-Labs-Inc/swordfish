/**
 * SOC Dashboard Page
 *
 * Security Operations Center dashboard with threat timeline and investigation panel
 */

'use client';

import { useState, useEffect, useCallback } from 'react';
import { ThreatTimeline, TimelineEvent } from '@/components/soc/ThreatTimeline';
import { InvestigationPanel, ThreatDetails } from '@/components/soc/InvestigationPanel';

export default function SOCDashboardPage() {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [selectedThreat, setSelectedThreat] = useState<ThreatDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState({
    totalThreats: 0,
    criticalThreats: 0,
    pendingReview: 0,
    avgResponseTime: '0s',
  });

  // Fetch timeline events
  const fetchEvents = useCallback(async () => {
    try {
      const response = await fetch('/api/soc/timeline');
      if (!response.ok) throw new Error('Failed to fetch timeline');
      const data = await response.json();
      setEvents(data.events || []);
      setStats(data.stats || stats);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load timeline');
    } finally {
      setLoading(false);
    }
  }, []);

  // Fetch threat details
  const fetchThreatDetails = useCallback(async (threatId: string) => {
    try {
      const response = await fetch(`/api/soc/threats/${threatId}`);
      if (!response.ok) throw new Error('Failed to fetch threat details');
      const data = await response.json();
      setSelectedThreat(data.threat);
    } catch (err) {
      console.error('Error fetching threat:', err);
    }
  }, []);

  // Handle timeline event click
  const handleEventClick = (event: TimelineEvent) => {
    if (event.threatId) {
      fetchThreatDetails(event.threatId);
    }
  };

  // Handle investigation actions
  const handleAction = async (action: 'release' | 'delete' | 'block_sender' | 'add_note') => {
    if (!selectedThreat) return;

    try {
      const response = await fetch(`/api/soc/threats/${selectedThreat.id}/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      });

      if (!response.ok) throw new Error('Action failed');

      // Refresh data
      await fetchEvents();
      if (action === 'release' || action === 'delete') {
        setSelectedThreat(null);
      }
    } catch (err) {
      console.error('Action error:', err);
    }
  };

  // Handle adding investigation note
  const handleAddNote = async (note: string) => {
    if (!selectedThreat) return;

    const response = await fetch(`/api/soc/threats/${selectedThreat.id}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: note }),
    });

    if (!response.ok) throw new Error('Failed to add note');

    // Refresh threat details
    await fetchThreatDetails(selectedThreat.id);
  };

  useEffect(() => {
    fetchEvents();

    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchEvents, 30000);
    return () => clearInterval(interval);
  }, [fetchEvents]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto" />
          <p className="mt-4 text-gray-500">Loading SOC Dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Header */}
      <div className="bg-gray-900 text-white">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <ShieldIcon className="h-8 w-8 text-blue-400" />
              <div>
                <h1 className="text-xl font-bold">Security Operations Center</h1>
                <p className="text-sm text-gray-400">Real-time threat monitoring & investigation</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 bg-green-500 rounded-full animate-pulse" />
                <span className="text-sm text-green-400">Live</span>
              </div>
              <button
                onClick={fetchEvents}
                className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 rounded text-sm font-medium transition-colors"
              >
                Refresh
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-4 py-3">
          <div className="grid grid-cols-4 gap-4">
            <StatCard
              label="Total Threats (24h)"
              value={stats.totalThreats}
              icon={<ThreatIcon className="h-5 w-5" />}
            />
            <StatCard
              label="Critical"
              value={stats.criticalThreats}
              icon={<CriticalIcon className="h-5 w-5" />}
              variant="danger"
            />
            <StatCard
              label="Pending Review"
              value={stats.pendingReview}
              icon={<ClockIcon className="h-5 w-5" />}
              variant="warning"
            />
            <StatCard
              label="Avg Response Time"
              value={stats.avgResponseTime}
              icon={<SpeedIcon className="h-5 w-5" />}
            />
          </div>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="max-w-7xl mx-auto px-4 mt-4">
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ExclamationIcon className="h-5 w-5 text-red-500" />
              <span className="text-red-800">{error}</span>
            </div>
            <button
              onClick={() => setError(null)}
              className="text-red-500 hover:text-red-700"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Threat Timeline */}
          <div className="lg:col-span-1">
            <ThreatTimeline
              events={events}
              onEventClick={handleEventClick}
              autoRefresh={true}
              maxHeight="calc(100vh - 280px)"
            />
          </div>

          {/* Investigation Panel */}
          <div className="lg:col-span-1">
            <InvestigationPanel
              threat={selectedThreat}
              onClose={() => setSelectedThreat(null)}
              onAction={handleAction}
              onAddNote={handleAddNote}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

// Helper Components
function StatCard({
  label,
  value,
  icon,
  variant,
}: {
  label: string;
  value: number | string;
  icon: React.ReactNode;
  variant?: 'danger' | 'warning';
}) {
  const variantClasses = {
    danger: 'text-red-600',
    warning: 'text-yellow-600',
  };

  return (
    <div className="flex items-center gap-3 p-3 rounded-lg bg-gray-50">
      <div className={variant ? variantClasses[variant] : 'text-gray-400'}>
        {icon}
      </div>
      <div>
        <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
        <p className={`text-xl font-bold ${variant ? variantClasses[variant] : 'text-gray-900'}`}>
          {value}
        </p>
      </div>
    </div>
  );
}

// Icons
function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  );
}

function ThreatIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
    </svg>
  );
}

function CriticalIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
    </svg>
  );
}

function ClockIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  );
}

function SpeedIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
    </svg>
  );
}

function ExclamationIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
    </svg>
  );
}

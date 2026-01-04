'use client';

import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';

interface Threat {
  id: string;
  messageId: string;
  subject: string;
  senderEmail: string;
  recipientEmail: string;
  verdict: 'block' | 'quarantine' | 'suspicious' | 'pass';
  score: number;
  status: 'quarantined' | 'released' | 'deleted';
  provider: 'microsoft' | 'google' | 'smtp';
  quarantinedAt: string;
  releasedAt?: string;
  releasedBy?: string;
}

interface ThreatStats {
  quarantinedCount: number;
  releasedCount: number;
  deletedCount: number;
  last24Hours: number;
  last7Days: number;
  avgScore: number;
}

export default function QuarantinePage() {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'quarantined' | 'released' | 'deleted' | 'all'>('quarantined');
  const [selectedThreats, setSelectedThreats] = useState<Set<string>>(new Set());
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const fetchThreats = useCallback(async () => {
    try {
      const response = await fetch(`/api/threats?status=${statusFilter}&stats=true`);
      const data = await response.json();
      setThreats(data.threats || []);
      setStats(data.stats);
    } catch (error) {
      console.error('Failed to fetch threats:', error);
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    fetchThreats();
  }, [fetchThreats]);

  async function releaseThreat(threatId: string, addToAllowlist: boolean = false) {
    setActionLoading(threatId);
    try {
      await fetch(`/api/threats/${threatId}/release`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ addToAllowlist }),
      });
      setSelectedThreats(new Set());
      await fetchThreats();
    } catch (error) {
      console.error('Failed to release threat:', error);
    } finally {
      setActionLoading(null);
    }
  }

  async function deleteThreat(threatId: string) {
    if (!confirm('Are you sure you want to permanently delete this email?')) {
      return;
    }

    setActionLoading(threatId);
    try {
      await fetch(`/api/threats/${threatId}`, { method: 'DELETE' });
      setSelectedThreats(new Set());
      await fetchThreats();
    } catch (error) {
      console.error('Failed to delete threat:', error);
    } finally {
      setActionLoading(null);
    }
  }

  async function bulkAction(action: 'release' | 'delete') {
    if (selectedThreats.size === 0) return;

    if (action === 'delete' && !confirm(`Are you sure you want to permanently delete ${selectedThreats.size} emails?`)) {
      return;
    }

    setActionLoading('bulk');
    try {
      await fetch('/api/threats/bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action,
          threatIds: Array.from(selectedThreats),
        }),
      });
      setSelectedThreats(new Set());
      await fetchThreats();
    } catch (error) {
      console.error(`Failed to ${action} threats:`, error);
    } finally {
      setActionLoading(null);
    }
  }

  function toggleSelectAll() {
    if (selectedThreats.size === threats.length) {
      setSelectedThreats(new Set());
    } else {
      setSelectedThreats(new Set(threats.map(t => t.id)));
    }
  }

  function toggleSelect(threatId: string) {
    const newSelected = new Set(selectedThreats);
    if (newSelected.has(threatId)) {
      newSelected.delete(threatId);
    } else {
      newSelected.add(threatId);
    }
    setSelectedThreats(newSelected);
  }

  function getVerdictBadge(verdict: Threat['verdict'], score: number) {
    if (verdict === 'block' || score >= 80) {
      return <Badge className="bg-red-100 text-red-800">Block</Badge>;
    }
    if (verdict === 'quarantine' || score >= 50) {
      return <Badge className="bg-orange-100 text-orange-800">Quarantine</Badge>;
    }
    if (verdict === 'suspicious') {
      return <Badge className="bg-yellow-100 text-yellow-800">Suspicious</Badge>;
    }
    return <Badge className="bg-green-100 text-green-800">Pass</Badge>;
  }

  function getStatusBadge(status: Threat['status']) {
    switch (status) {
      case 'quarantined':
        return <Badge className="bg-orange-100 text-orange-800">Quarantined</Badge>;
      case 'released':
        return <Badge className="bg-green-100 text-green-800">Released</Badge>;
      case 'deleted':
        return <Badge className="bg-gray-100 text-gray-800">Deleted</Badge>;
    }
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
        <h1 className="text-2xl font-bold">Quarantine</h1>
        <p className="text-muted-foreground">
          Review and manage quarantined emails. Release safe emails or permanently delete threats.
        </p>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-orange-600">{stats.quarantinedCount}</div>
              <p className="text-sm text-muted-foreground">Quarantined</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-green-600">{stats.releasedCount}</div>
              <p className="text-sm text-muted-foreground">Released</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-red-600">{stats.last24Hours}</div>
              <p className="text-sm text-muted-foreground">Last 24 Hours</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold">{stats.avgScore}</div>
              <p className="text-sm text-muted-foreground">Avg Score</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Status Filter Tabs */}
      <div className="flex gap-2 border-b">
        {(['quarantined', 'released', 'deleted', 'all'] as const).map((status) => (
          <button
            key={status}
            className={`px-4 py-2 font-medium capitalize ${
              statusFilter === status
                ? 'border-b-2 border-blue-500 text-blue-600'
                : 'text-gray-500 hover:text-gray-700'
            }`}
            onClick={() => {
              setStatusFilter(status);
              setSelectedThreats(new Set());
            }}
          >
            {status}
          </button>
        ))}
      </div>

      {/* Controls */}
      <div className="flex flex-col sm:flex-row gap-4 justify-between">
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => fetchThreats()}>
            Refresh
          </Button>
        </div>

        {selectedThreats.size > 0 && statusFilter === 'quarantined' && (
          <div className="flex gap-2">
            <Button
              variant="outline"
              onClick={() => bulkAction('release')}
              disabled={actionLoading === 'bulk'}
            >
              Release Selected ({selectedThreats.size})
            </Button>
            <Button
              variant="destructive"
              onClick={() => bulkAction('delete')}
              disabled={actionLoading === 'bulk'}
            >
              Delete Selected ({selectedThreats.size})
            </Button>
          </div>
        )}
      </div>

      {/* Threat List */}
      <Card>
        <CardHeader>
          <CardTitle>Threats</CardTitle>
          <CardDescription>
            {threats.length === 0
              ? `No ${statusFilter === 'all' ? '' : statusFilter} threats`
              : `Showing ${threats.length} ${statusFilter === 'all' ? '' : statusFilter} threats`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {threats.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <div className="text-4xl mb-4">
                {statusFilter === 'quarantined' ? '🛡️' : statusFilter === 'released' ? '✅' : '📭'}
              </div>
              <p>No threats found</p>
              <p className="text-sm mt-2">
                Detected threats will appear here for review
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {/* Header */}
              <div className="flex items-center gap-4 p-3 bg-gray-50 rounded-lg font-medium text-sm">
                <input
                  type="checkbox"
                  checked={selectedThreats.size === threats.length && threats.length > 0}
                  onChange={toggleSelectAll}
                  className="h-4 w-4 rounded border-gray-300"
                />
                <div className="flex-1 grid grid-cols-12 gap-4">
                  <div className="col-span-3">From</div>
                  <div className="col-span-3">Subject</div>
                  <div className="col-span-1">Score</div>
                  <div className="col-span-2">Status</div>
                  <div className="col-span-2">Date</div>
                  <div className="col-span-1">Actions</div>
                </div>
              </div>

              {/* Rows */}
              {threats.map((threat) => (
                <div
                  key={threat.id}
                  className={`flex items-center gap-4 p-3 rounded-lg border ${
                    selectedThreats.has(threat.id) ? 'bg-blue-50 border-blue-200' : 'hover:bg-gray-50'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selectedThreats.has(threat.id)}
                    onChange={() => toggleSelect(threat.id)}
                    className="h-4 w-4 rounded border-gray-300"
                  />
                  <div className="flex-1 grid grid-cols-12 gap-4 items-center">
                    <div className="col-span-3">
                      <p className="font-medium truncate">{threat.senderEmail}</p>
                      <p className="text-xs text-muted-foreground">
                        To: {threat.recipientEmail}
                      </p>
                    </div>
                    <div className="col-span-3 truncate" title={threat.subject}>
                      {threat.subject}
                    </div>
                    <div className="col-span-1">
                      <span
                        className={`font-bold ${
                          threat.score >= 80
                            ? 'text-red-600'
                            : threat.score >= 50
                            ? 'text-orange-600'
                            : 'text-yellow-600'
                        }`}
                      >
                        {threat.score}
                      </span>
                    </div>
                    <div className="col-span-2">
                      {getStatusBadge(threat.status)}
                    </div>
                    <div className="col-span-2 text-sm text-muted-foreground">
                      {formatDate(threat.quarantinedAt)}
                    </div>
                    <div className="col-span-1 flex gap-1">
                      {threat.status === 'quarantined' && (
                        <>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-green-600 hover:bg-green-50 px-2"
                            onClick={() => releaseThreat(threat.id)}
                            disabled={actionLoading === threat.id}
                            title="Release"
                          >
                            ✓
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-red-600 hover:bg-red-50 px-2"
                            onClick={() => deleteThreat(threat.id)}
                            disabled={actionLoading === threat.id}
                            title="Delete"
                          >
                            ✕
                          </Button>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

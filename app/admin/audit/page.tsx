'use client';

import { useEffect, useState } from 'react';

interface AuditLogEntry {
  id: string;
  tenantId: string;
  tenantName: string | null;
  actorId: string;
  actorEmail: string | null;
  action: string;
  resourceType: string;
  resourceId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  beforeState: Record<string, unknown> | null;
  afterState: Record<string, unknown> | null;
  metadata: Record<string, unknown> | null;
  createdAt: string;
}

interface Pagination {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export default function AuditLogPage() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [pagination, setPagination] = useState<Pagination>({
    page: 1,
    limit: 50,
    total: 0,
    totalPages: 0,
  });
  const [filters, setFilters] = useState({
    tenantId: '',
    action: '',
    resourceType: '',
    actorEmail: '',
    startDate: '',
    endDate: '',
  });
  const [selectedLog, setSelectedLog] = useState<AuditLogEntry | null>(null);

  useEffect(() => {
    loadAuditLogs();
  }, [pagination.page, filters]);

  async function loadAuditLogs() {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      params.set('page', pagination.page.toString());
      params.set('limit', pagination.limit.toString());

      if (filters.tenantId) params.set('tenantId', filters.tenantId);
      if (filters.action) params.set('action', filters.action);
      if (filters.resourceType) params.set('resourceType', filters.resourceType);
      if (filters.actorEmail) params.set('actorEmail', filters.actorEmail);
      if (filters.startDate) params.set('startDate', filters.startDate);
      if (filters.endDate) params.set('endDate', filters.endDate);

      const response = await fetch(`/api/admin/audit?${params}`);
      if (response.ok) {
        const data = await response.json();
        setLogs(data.logs);
        setPagination(data.pagination);
      }
    } catch (error) {
      console.error('Failed to load audit logs:', error);
    } finally {
      setLoading(false);
    }
  }

  function handleFilterChange(key: keyof typeof filters, value: string) {
    setFilters({ ...filters, [key]: value });
    setPagination({ ...pagination, page: 1 });
  }

  function clearFilters() {
    setFilters({
      tenantId: '',
      action: '',
      resourceType: '',
      actorEmail: '',
      startDate: '',
      endDate: '',
    });
    setPagination({ ...pagination, page: 1 });
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Audit Log</h1>
        <button
          onClick={loadAuditLogs}
          className="text-blue-600 hover:text-blue-800 text-sm font-medium"
        >
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg border p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <input
            type="text"
            placeholder="Actor email..."
            value={filters.actorEmail}
            onChange={(e) => handleFilterChange('actorEmail', e.target.value)}
            className="border rounded-lg px-3 py-2 text-sm"
          />
          <select
            value={filters.action}
            onChange={(e) => handleFilterChange('action', e.target.value)}
            className="border rounded-lg px-3 py-2 text-sm"
          >
            <option value="">All Actions</option>
            <option value="tenant.created">Tenant Created</option>
            <option value="tenant.updated">Tenant Updated</option>
            <option value="user.created">User Created</option>
            <option value="user.updated">User Updated</option>
            <option value="policy.created">Policy Created</option>
            <option value="policy.updated">Policy Updated</option>
            <option value="threat.released">Threat Released</option>
            <option value="threat.deleted">Threat Deleted</option>
            <option value="settings.updated">Settings Updated</option>
          </select>
          <select
            value={filters.resourceType}
            onChange={(e) => handleFilterChange('resourceType', e.target.value)}
            className="border rounded-lg px-3 py-2 text-sm"
          >
            <option value="">All Resources</option>
            <option value="tenant">Tenant</option>
            <option value="user">User</option>
            <option value="policy">Policy</option>
            <option value="threat">Threat</option>
            <option value="settings">Settings</option>
            <option value="integration">Integration</option>
          </select>
          <input
            type="date"
            value={filters.startDate}
            onChange={(e) => handleFilterChange('startDate', e.target.value)}
            className="border rounded-lg px-3 py-2 text-sm"
          />
          <input
            type="date"
            value={filters.endDate}
            onChange={(e) => handleFilterChange('endDate', e.target.value)}
            className="border rounded-lg px-3 py-2 text-sm"
          />
          <button
            onClick={clearFilters}
            className="text-gray-600 hover:text-gray-800 text-sm"
          >
            Clear Filters
          </button>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-white rounded-lg border overflow-hidden">
        {loading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto" />
          </div>
        ) : logs.length === 0 ? (
          <div className="p-8 text-center text-gray-500">No audit logs found</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Timestamp
                  </th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Actor
                  </th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Tenant
                  </th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Action
                  </th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Resource
                  </th>
                  <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    IP Address
                  </th>
                  <th className="text-right px-6 py-3 text-xs font-medium text-gray-500 uppercase">
                    Details
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 text-sm text-gray-500 whitespace-nowrap">
                      {new Date(log.createdAt).toLocaleString()}
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-sm text-gray-900">
                        {log.actorEmail || (log.actorId ? log.actorId.substring(0, 12) + '...' : 'System')}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600">
                      {log.tenantName || (log.tenantId ? log.tenantId.substring(0, 12) + '...' : 'Global')}
                    </td>
                    <td className="px-6 py-4">
                      <ActionBadge action={log.action} />
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600">
                      <span className="capitalize">{log.resourceType}</span>
                      {log.resourceId && (
                        <span className="text-gray-400 ml-1">
                          #{log.resourceId.substring(0, 8)}
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500">
                      {log.ipAddress || '-'}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => setSelectedLog(log)}
                        className="text-blue-600 hover:text-blue-800 text-sm"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {pagination.totalPages > 1 && (
          <div className="border-t px-6 py-4 flex items-center justify-between">
            <p className="text-sm text-gray-500">
              Showing {(pagination.page - 1) * pagination.limit + 1} to{' '}
              {Math.min(pagination.page * pagination.limit, pagination.total)} of{' '}
              {pagination.total} entries
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setPagination({ ...pagination, page: pagination.page - 1 })}
                disabled={pagination.page === 1}
                className="px-3 py-1 border rounded text-sm disabled:opacity-50"
              >
                Previous
              </button>
              <button
                onClick={() => setPagination({ ...pagination, page: pagination.page + 1 })}
                disabled={pagination.page === pagination.totalPages}
                className="px-3 py-1 border rounded text-sm disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selectedLog && (
        <AuditDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />
      )}
    </div>
  );
}

function ActionBadge({ action }: { action: string }) {
  const getColor = () => {
    if (action.includes('created')) return 'bg-green-100 text-green-700';
    if (action.includes('updated')) return 'bg-blue-100 text-blue-700';
    if (action.includes('deleted')) return 'bg-red-100 text-red-700';
    if (action.includes('released')) return 'bg-yellow-100 text-yellow-700';
    return 'bg-gray-100 text-gray-700';
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium rounded ${getColor()}`}>
      {action}
    </span>
  );
}

function AuditDetailModal({
  log,
  onClose,
}: {
  log: AuditLogEntry;
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
        <div className="sticky top-0 bg-white border-b px-6 py-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">Audit Log Details</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-sm text-gray-500">Timestamp</p>
              <p className="font-medium">{new Date(log.createdAt).toLocaleString()}</p>
            </div>
            <div>
              <p className="text-sm text-gray-500">Action</p>
              <ActionBadge action={log.action} />
            </div>
            <div>
              <p className="text-sm text-gray-500">Actor</p>
              <p className="font-medium">{log.actorEmail || log.actorId}</p>
            </div>
            <div>
              <p className="text-sm text-gray-500">Tenant</p>
              <p className="font-medium">{log.tenantName || log.tenantId}</p>
            </div>
            <div>
              <p className="text-sm text-gray-500">Resource Type</p>
              <p className="font-medium capitalize">{log.resourceType}</p>
            </div>
            <div>
              <p className="text-sm text-gray-500">Resource ID</p>
              <p className="font-medium font-mono text-sm">{log.resourceId || '-'}</p>
            </div>
            <div>
              <p className="text-sm text-gray-500">IP Address</p>
              <p className="font-medium">{log.ipAddress || '-'}</p>
            </div>
            <div>
              <p className="text-sm text-gray-500">User Agent</p>
              <p className="font-medium text-sm truncate" title={log.userAgent || ''}>
                {log.userAgent || '-'}
              </p>
            </div>
          </div>

          {log.beforeState && (
            <div>
              <p className="text-sm text-gray-500 mb-2">Before State</p>
              <pre className="bg-gray-50 rounded p-3 text-sm overflow-x-auto">
                {JSON.stringify(log.beforeState, null, 2)}
              </pre>
            </div>
          )}

          {log.afterState && (
            <div>
              <p className="text-sm text-gray-500 mb-2">After State</p>
              <pre className="bg-gray-50 rounded p-3 text-sm overflow-x-auto">
                {JSON.stringify(log.afterState, null, 2)}
              </pre>
            </div>
          )}

          {log.metadata && (
            <div>
              <p className="text-sm text-gray-500 mb-2">Metadata</p>
              <pre className="bg-gray-50 rounded p-3 text-sm overflow-x-auto">
                {JSON.stringify(log.metadata, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

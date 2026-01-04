'use client';

import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';

type ListType = 'allowlist' | 'blocklist';
type EntryType = 'email' | 'domain' | 'ip' | 'url';

interface Policy {
  id: string;
  name: string;
  description?: string;
  type: string;
  status: 'active' | 'inactive' | 'draft';
  priority: 'low' | 'medium' | 'high' | 'critical';
  rules: unknown[];
  createdAt: string;
}

interface ListEntry {
  id: string;
  listType: ListType;
  entryType: EntryType;
  value: string;
  reason?: string;
  expiresAt?: string;
  createdAt: string;
}

export default function PoliciesPage() {
  const [activeTab, setActiveTab] = useState<'policies' | 'allowlist' | 'blocklist'>('policies');
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [listEntries, setListEntries] = useState<ListEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddForm, setShowAddForm] = useState(false);

  // Form state
  const [newEntry, setNewEntry] = useState({
    entryType: 'domain' as EntryType,
    value: '',
    reason: '',
  });

  const fetchPolicies = useCallback(async () => {
    try {
      const response = await fetch('/api/policies');
      const data = await response.json();
      setPolicies(data.policies || []);
    } catch (error) {
      console.error('Failed to fetch policies:', error);
    }
  }, []);

  const fetchListEntries = useCallback(async (type: ListType) => {
    try {
      const response = await fetch(`/api/lists?type=${type}`);
      const data = await response.json();
      setListEntries(data.entries || []);
    } catch (error) {
      console.error('Failed to fetch list entries:', error);
    }
  }, []);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      if (activeTab === 'policies') {
        await fetchPolicies();
      } else {
        await fetchListEntries(activeTab);
      }
      setLoading(false);
    }
    loadData();
  }, [activeTab, fetchPolicies, fetchListEntries]);

  async function addListEntry() {
    if (!newEntry.value.trim()) return;

    try {
      const response = await fetch('/api/lists', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          listType: activeTab,
          entryType: newEntry.entryType,
          value: newEntry.value,
          reason: newEntry.reason || undefined,
        }),
      });

      if (response.ok) {
        setNewEntry({ entryType: 'domain', value: '', reason: '' });
        setShowAddForm(false);
        fetchListEntries(activeTab as ListType);
      }
    } catch (error) {
      console.error('Failed to add entry:', error);
    }
  }

  async function deleteEntry(id: string) {
    if (!confirm('Are you sure you want to remove this entry?')) return;

    try {
      await fetch(`/api/lists/${id}`, { method: 'DELETE' });
      fetchListEntries(activeTab as ListType);
    } catch (error) {
      console.error('Failed to delete entry:', error);
    }
  }

  async function togglePolicyStatus(id: string, currentStatus: string) {
    const newStatus = currentStatus === 'active' ? 'inactive' : 'active';

    try {
      await fetch(`/api/policies/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
      fetchPolicies();
    } catch (error) {
      console.error('Failed to toggle policy:', error);
    }
  }

  function getStatusBadge(status: string) {
    switch (status) {
      case 'active':
        return <Badge className="bg-green-100 text-green-800">Active</Badge>;
      case 'inactive':
        return <Badge className="bg-gray-100 text-gray-800">Inactive</Badge>;
      case 'draft':
        return <Badge className="bg-yellow-100 text-yellow-800">Draft</Badge>;
      default:
        return null;
    }
  }

  function getPriorityBadge(priority: string) {
    switch (priority) {
      case 'critical':
        return <Badge className="bg-red-100 text-red-800">Critical</Badge>;
      case 'high':
        return <Badge className="bg-orange-100 text-orange-800">High</Badge>;
      case 'medium':
        return <Badge className="bg-blue-100 text-blue-800">Medium</Badge>;
      case 'low':
        return <Badge className="bg-gray-100 text-gray-800">Low</Badge>;
      default:
        return null;
    }
  }

  function formatDate(dateString: string) {
    return new Date(dateString).toLocaleDateString();
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
        <h1 className="text-2xl font-bold">Policies</h1>
        <p className="text-muted-foreground">
          Configure detection rules, allowlists, and blocklists for your organization.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b">
        <button
          className={`px-4 py-2 font-medium ${
            activeTab === 'policies'
              ? 'border-b-2 border-blue-500 text-blue-600'
              : 'text-gray-500 hover:text-gray-700'
          }`}
          onClick={() => setActiveTab('policies')}
        >
          Detection Policies
        </button>
        <button
          className={`px-4 py-2 font-medium ${
            activeTab === 'allowlist'
              ? 'border-b-2 border-green-500 text-green-600'
              : 'text-gray-500 hover:text-gray-700'
          }`}
          onClick={() => setActiveTab('allowlist')}
        >
          Allowlist
        </button>
        <button
          className={`px-4 py-2 font-medium ${
            activeTab === 'blocklist'
              ? 'border-b-2 border-red-500 text-red-600'
              : 'text-gray-500 hover:text-gray-700'
          }`}
          onClick={() => setActiveTab('blocklist')}
        >
          Blocklist
        </button>
      </div>

      {/* Content */}
      {activeTab === 'policies' ? (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle>Detection Policies</CardTitle>
              <CardDescription>
                Rules that control how emails are analyzed and what actions are taken
              </CardDescription>
            </div>
            <Button>Create Policy</Button>
          </CardHeader>
          <CardContent>
            {policies.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                <div className="text-4xl mb-4">📋</div>
                <p>No policies configured</p>
                <p className="text-sm mt-2">
                  Create policies to customize threat detection behavior
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {policies.map((policy) => (
                  <div
                    key={policy.id}
                    className="flex items-center justify-between p-4 bg-gray-50 rounded-lg"
                  >
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="font-medium">{policy.name}</h3>
                        {getStatusBadge(policy.status)}
                        {getPriorityBadge(policy.priority)}
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {policy.description || `${policy.type} policy with ${policy.rules?.length || 0} rules`}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => togglePolicyStatus(policy.id, policy.status)}
                      >
                        {policy.status === 'active' ? 'Disable' : 'Enable'}
                      </Button>
                      <Button variant="outline" size="sm">
                        Edit
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle>
                {activeTab === 'allowlist' ? 'Allowlist' : 'Blocklist'}
              </CardTitle>
              <CardDescription>
                {activeTab === 'allowlist'
                  ? 'Senders and domains that bypass threat detection'
                  : 'Senders and domains that are always blocked'}
              </CardDescription>
            </div>
            <Button onClick={() => setShowAddForm(!showAddForm)}>
              {showAddForm ? 'Cancel' : 'Add Entry'}
            </Button>
          </CardHeader>
          <CardContent>
            {/* Add Form */}
            {showAddForm && (
              <div className="mb-6 p-4 bg-gray-50 rounded-lg space-y-4">
                <div className="grid grid-cols-4 gap-4">
                  <select
                    className="col-span-1 rounded-md border border-gray-300 px-3 py-2"
                    value={newEntry.entryType}
                    onChange={(e) =>
                      setNewEntry({ ...newEntry, entryType: e.target.value as EntryType })
                    }
                  >
                    <option value="domain">Domain</option>
                    <option value="email">Email</option>
                    <option value="ip">IP Address</option>
                  </select>
                  <Input
                    className="col-span-2"
                    placeholder={
                      newEntry.entryType === 'email'
                        ? 'user@example.com'
                        : newEntry.entryType === 'domain'
                        ? 'example.com'
                        : '192.168.1.1'
                    }
                    value={newEntry.value}
                    onChange={(e) => setNewEntry({ ...newEntry, value: e.target.value })}
                  />
                  <Input
                    placeholder="Reason (optional)"
                    value={newEntry.reason}
                    onChange={(e) => setNewEntry({ ...newEntry, reason: e.target.value })}
                  />
                </div>
                <div className="flex justify-end">
                  <Button onClick={addListEntry}>Add to {activeTab}</Button>
                </div>
              </div>
            )}

            {/* Entries List */}
            {listEntries.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                <div className="text-4xl mb-4">
                  {activeTab === 'allowlist' ? '✅' : '🚫'}
                </div>
                <p>No entries in {activeTab}</p>
                <p className="text-sm mt-2">
                  Add senders or domains to customize detection behavior
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {/* Header */}
                <div className="grid grid-cols-12 gap-4 p-3 bg-gray-100 rounded-lg font-medium text-sm">
                  <div className="col-span-2">Type</div>
                  <div className="col-span-4">Value</div>
                  <div className="col-span-3">Reason</div>
                  <div className="col-span-2">Added</div>
                  <div className="col-span-1">Actions</div>
                </div>

                {/* Rows */}
                {listEntries.map((entry) => (
                  <div
                    key={entry.id}
                    className="grid grid-cols-12 gap-4 p-3 rounded-lg border hover:bg-gray-50 items-center"
                  >
                    <div className="col-span-2">
                      <Badge variant="outline" className="capitalize">
                        {entry.entryType}
                      </Badge>
                    </div>
                    <div className="col-span-4 font-mono text-sm">{entry.value}</div>
                    <div className="col-span-3 text-sm text-muted-foreground truncate">
                      {entry.reason || '-'}
                    </div>
                    <div className="col-span-2 text-sm text-muted-foreground">
                      {formatDate(entry.createdAt)}
                    </div>
                    <div className="col-span-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-red-600 hover:text-red-700 hover:bg-red-50"
                        onClick={() => deleteEntry(entry.id)}
                      >
                        Remove
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface Webhook {
  id: string;
  name: string;
  url: string;
  events: string[];
  secret: string;
  isActive: boolean;
  lastTriggeredAt: string | null;
  lastStatus: 'success' | 'failed' | null;
  failureCount: number;
  createdAt: string;
}

const eventTypes = [
  { id: 'threat.detected', name: 'Threat Detected', description: 'When a new threat is identified' },
  { id: 'threat.quarantined', name: 'Email Quarantined', description: 'When an email is moved to quarantine' },
  { id: 'threat.released', name: 'Email Released', description: 'When a quarantined email is released' },
  { id: 'threat.deleted', name: 'Email Deleted', description: 'When a quarantined email is deleted' },
  { id: 'policy.matched', name: 'Policy Matched', description: 'When an email matches a policy rule' },
  { id: 'integration.error', name: 'Integration Error', description: 'When an email integration fails' },
  { id: 'report.generated', name: 'Report Generated', description: 'When a scheduled report is ready' },
];

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);

  useEffect(() => {
    loadWebhooks();
  }, []);

  async function loadWebhooks() {
    try {
      const response = await fetch('/api/settings/webhooks');
      if (response.ok) {
        const data = await response.json();
        setWebhooks(data.webhooks);
      }
    } catch (error) {
      console.error('Failed to load webhooks:', error);
    } finally {
      setLoading(false);
    }
  }

  async function toggleWebhook(id: string, isActive: boolean) {
    try {
      await fetch(`/api/settings/webhooks/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ isActive: !isActive }),
      });
      loadWebhooks();
    } catch (error) {
      console.error('Failed to toggle webhook:', error);
    }
  }

  async function deleteWebhook(id: string) {
    if (!confirm('Are you sure you want to delete this webhook?')) return;

    try {
      await fetch(`/api/settings/webhooks/${id}`, { method: 'DELETE' });
      loadWebhooks();
    } catch (error) {
      console.error('Failed to delete webhook:', error);
    }
  }

  async function testWebhook(id: string) {
    setTestingId(id);
    try {
      const response = await fetch(`/api/settings/webhooks/${id}/test`, { method: 'POST' });
      const data = await response.json();
      if (response.ok) {
        alert(`Test successful! Response time: ${data.responseTime}ms`);
      } else {
        alert(`Test failed: ${data.error}`);
      }
      loadWebhooks();
    } catch (error) {
      alert('Test failed: Network error');
    } finally {
      setTestingId(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Link href="/dashboard/settings" className="text-gray-400 hover:text-gray-600">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <h1 className="text-2xl font-bold text-gray-900">Webhooks</h1>
          </div>
          <p className="text-gray-600 mt-1">Send real-time notifications to external services</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
        >
          Add Webhook
        </button>
      </div>

      {/* Webhooks List */}
      {loading ? (
        <div className="bg-white rounded-lg border p-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto" />
        </div>
      ) : webhooks.length === 0 ? (
        <div className="bg-white rounded-lg border p-12 text-center">
          <svg className="w-16 h-16 mx-auto text-gray-300 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
          </svg>
          <h3 className="text-lg font-medium text-gray-900 mb-2">No webhooks configured</h3>
          <p className="text-gray-500 mb-4">Add a webhook to receive real-time event notifications.</p>
          <button
            onClick={() => setShowCreateModal(true)}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
          >
            Add Webhook
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {webhooks.map((webhook) => (
            <div key={webhook.id} className="bg-white rounded-lg border p-6">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-gray-900">{webhook.name}</h3>
                    <span className={`px-2 py-0.5 text-xs rounded ${
                      webhook.isActive ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'
                    }`}>
                      {webhook.isActive ? 'Active' : 'Disabled'}
                    </span>
                    {webhook.lastStatus === 'failed' && (
                      <span className="px-2 py-0.5 text-xs rounded bg-red-100 text-red-700">
                        Failed ({webhook.failureCount}x)
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-gray-500 mt-1 font-mono">{webhook.url}</p>
                  <div className="flex flex-wrap gap-2 mt-3">
                    {webhook.events.map((event) => (
                      <span key={event} className="px-2 py-1 text-xs bg-gray-100 text-gray-600 rounded">
                        {event}
                      </span>
                    ))}
                  </div>
                  {webhook.lastTriggeredAt && (
                    <p className="text-xs text-gray-400 mt-2">
                      Last triggered: {new Date(webhook.lastTriggeredAt).toLocaleString()}
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-2 ml-4">
                  <button
                    onClick={() => testWebhook(webhook.id)}
                    disabled={testingId === webhook.id}
                    className="px-3 py-1.5 text-sm border rounded hover:bg-gray-50 disabled:opacity-50"
                  >
                    {testingId === webhook.id ? 'Testing...' : 'Test'}
                  </button>
                  <button
                    onClick={() => toggleWebhook(webhook.id, webhook.isActive)}
                    className={`px-3 py-1.5 text-sm border rounded ${
                      webhook.isActive ? 'hover:bg-yellow-50 text-yellow-600' : 'hover:bg-green-50 text-green-600'
                    }`}
                  >
                    {webhook.isActive ? 'Disable' : 'Enable'}
                  </button>
                  <button
                    onClick={() => deleteWebhook(webhook.id)}
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
        <CreateWebhookModal
          onClose={() => setShowCreateModal(false)}
          onSuccess={() => {
            setShowCreateModal(false);
            loadWebhooks();
          }}
        />
      )}
    </div>
  );
}

function CreateWebhookModal({
  onClose,
  onSuccess,
}: {
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [selectedEvents, setSelectedEvents] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  function toggleEvent(eventId: string) {
    setSelectedEvents(prev =>
      prev.includes(eventId)
        ? prev.filter(e => e !== eventId)
        : [...prev, eventId]
    );
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');

    if (selectedEvents.length === 0) {
      setError('Please select at least one event');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch('/api/settings/webhooks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, url, events: selectedEvents }),
      });

      if (response.ok) {
        onSuccess();
      } else {
        const data = await response.json();
        setError(data.error || 'Failed to create webhook');
      }
    } catch (error) {
      setError('Failed to create webhook');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg max-w-lg w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div className="sticky top-0 bg-white border-b px-6 py-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">Add Webhook</h2>
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
            <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="w-full border rounded-lg px-4 py-2"
              placeholder="My SIEM Integration"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Endpoint URL</label>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
              className="w-full border rounded-lg px-4 py-2"
              placeholder="https://example.com/webhook"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Events</label>
            <div className="space-y-2 max-h-64 overflow-y-auto border rounded-lg p-3">
              {eventTypes.map((event) => (
                <label
                  key={event.id}
                  className="flex items-start gap-3 p-2 hover:bg-gray-50 rounded cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={selectedEvents.includes(event.id)}
                    onChange={() => toggleEvent(event.id)}
                    className="mt-1 rounded"
                  />
                  <div>
                    <p className="text-sm font-medium text-gray-900">{event.name}</p>
                    <p className="text-xs text-gray-500">{event.description}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          <div className="bg-gray-50 rounded-lg p-4">
            <p className="text-sm text-gray-600">
              A signing secret will be generated automatically. Use it to verify webhook payloads.
            </p>
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
              {loading ? 'Creating...' : 'Create Webhook'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

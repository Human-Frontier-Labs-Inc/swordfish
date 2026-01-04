'use client';

import { useState, useEffect } from 'react';

interface TenantSettings {
  detection: {
    suspiciousThreshold: number;
    quarantineThreshold: number;
    blockThreshold: number;
    enableLlmAnalysis: boolean;
    llmDailyLimit: number;
  };
  notifications: {
    emailEnabled: boolean;
    emailRecipients: string[];
    slackEnabled: boolean;
    slackWebhookUrl?: string;
    webhookEnabled: boolean;
    webhookUrl?: string;
    severityThreshold: 'info' | 'warning' | 'critical';
  };
  quarantine: {
    autoDeleteAfterDays: number;
    allowUserRelease: boolean;
    notifyOnRelease: boolean;
  };
  integrations: {
    microsoftConnected: boolean;
    googleConnected: boolean;
    webhookToken?: string;
  };
  display: {
    timezone: string;
    dateFormat: string;
    itemsPerPage: number;
  };
}

type TabId = 'detection' | 'notifications' | 'quarantine' | 'integrations' | 'display';

export default function SettingsPage() {
  const [settings, setSettings] = useState<TenantSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('detection');

  useEffect(() => {
    loadSettings();
  }, []);

  async function loadSettings() {
    try {
      const response = await fetch('/api/settings');
      const data = await response.json();
      if (data.settings) {
        setSettings(data.settings);
      }
    } catch (err) {
      setError('Failed to load settings');
    } finally {
      setLoading(false);
    }
  }

  async function saveSettings(section: keyof TenantSettings, values: Partial<TenantSettings[keyof TenantSettings]>) {
    if (!settings) return;

    setSaving(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await fetch('/api/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          settings: { [section]: values },
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to save settings');
      }

      setSettings(data.settings);
      setSuccess('Settings saved successfully');
      setTimeout(() => setSuccess(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="p-8">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-200 rounded w-48" />
          <div className="h-64 bg-gray-200 rounded" />
        </div>
      </div>
    );
  }

  if (!settings) {
    return (
      <div className="p-8">
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">
          Failed to load settings. Please refresh the page.
        </div>
      </div>
    );
  }

  const tabs: { id: TabId; label: string }[] = [
    { id: 'detection', label: 'Detection' },
    { id: 'notifications', label: 'Notifications' },
    { id: 'quarantine', label: 'Quarantine' },
    { id: 'integrations', label: 'Integrations' },
    { id: 'display', label: 'Display' },
  ];

  return (
    <div className="p-8 max-w-4xl">
      <h1 className="text-2xl font-bold mb-6">Settings</h1>

      {/* Status messages */}
      {error && (
        <div className="mb-4 bg-red-50 border border-red-200 rounded-lg p-4 text-red-700">
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 bg-green-50 border border-green-200 rounded-lg p-4 text-green-700">
          {success}
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200 mb-6">
        <nav className="flex gap-4">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`pb-3 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Detection Settings */}
      {activeTab === 'detection' && (
        <DetectionSettings
          settings={settings.detection}
          onSave={(values) => saveSettings('detection', values)}
          saving={saving}
        />
      )}

      {/* Notification Settings */}
      {activeTab === 'notifications' && (
        <NotificationSettings
          settings={settings.notifications}
          onSave={(values) => saveSettings('notifications', values)}
          saving={saving}
        />
      )}

      {/* Quarantine Settings */}
      {activeTab === 'quarantine' && (
        <QuarantineSettings
          settings={settings.quarantine}
          onSave={(values) => saveSettings('quarantine', values)}
          saving={saving}
        />
      )}

      {/* Integration Settings */}
      {activeTab === 'integrations' && (
        <IntegrationSettings
          settings={settings.integrations}
          onSave={(values) => saveSettings('integrations', values)}
          saving={saving}
        />
      )}

      {/* Display Settings */}
      {activeTab === 'display' && (
        <DisplaySettings
          settings={settings.display}
          onSave={(values) => saveSettings('display', values)}
          saving={saving}
        />
      )}
    </div>
  );
}

// Detection Settings Component
function DetectionSettings({
  settings,
  onSave,
  saving,
}: {
  settings: TenantSettings['detection'];
  onSave: (values: Partial<TenantSettings['detection']>) => void;
  saving: boolean;
}) {
  const [values, setValues] = useState(settings);

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg border p-6">
        <h3 className="font-semibold mb-4">Score Thresholds</h3>
        <p className="text-sm text-gray-600 mb-4">
          Configure the score thresholds for email classification. Higher scores indicate more suspicious emails.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">
              Suspicious Threshold ({values.suspiciousThreshold})
            </label>
            <input
              type="range"
              min="0"
              max="100"
              value={values.suspiciousThreshold}
              onChange={(e) => setValues({ ...values, suspiciousThreshold: Number(e.target.value) })}
              className="w-full"
            />
            <p className="text-xs text-gray-500">Emails above this score will be marked as suspicious</p>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">
              Quarantine Threshold ({values.quarantineThreshold})
            </label>
            <input
              type="range"
              min="0"
              max="100"
              value={values.quarantineThreshold}
              onChange={(e) => setValues({ ...values, quarantineThreshold: Number(e.target.value) })}
              className="w-full"
            />
            <p className="text-xs text-gray-500">Emails above this score will be quarantined</p>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">
              Block Threshold ({values.blockThreshold})
            </label>
            <input
              type="range"
              min="0"
              max="100"
              value={values.blockThreshold}
              onChange={(e) => setValues({ ...values, blockThreshold: Number(e.target.value) })}
              className="w-full"
            />
            <p className="text-xs text-gray-500">Emails above this score will be blocked</p>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg border p-6">
        <h3 className="font-semibold mb-4">AI Analysis</h3>

        <div className="space-y-4">
          <label className="flex items-center gap-3">
            <input
              type="checkbox"
              checked={values.enableLlmAnalysis}
              onChange={(e) => setValues({ ...values, enableLlmAnalysis: e.target.checked })}
              className="rounded"
            />
            <span className="text-sm">Enable LLM analysis for uncertain emails</span>
          </label>

          <div>
            <label className="block text-sm font-medium mb-1">Daily LLM Request Limit</label>
            <input
              type="number"
              min="0"
              max="1000"
              value={values.llmDailyLimit}
              onChange={(e) => setValues({ ...values, llmDailyLimit: Number(e.target.value) })}
              className="border rounded px-3 py-2 w-32"
            />
          </div>
        </div>
      </div>

      <button
        onClick={() => onSave(values)}
        disabled={saving}
        className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
      >
        {saving ? 'Saving...' : 'Save Changes'}
      </button>
    </div>
  );
}

// Notification Settings Component
function NotificationSettings({
  settings,
  onSave,
  saving,
}: {
  settings: TenantSettings['notifications'];
  onSave: (values: Partial<TenantSettings['notifications']>) => void;
  saving: boolean;
}) {
  const [values, setValues] = useState(settings);
  const [newEmail, setNewEmail] = useState('');

  const addEmail = () => {
    if (newEmail && !values.emailRecipients.includes(newEmail)) {
      setValues({
        ...values,
        emailRecipients: [...values.emailRecipients, newEmail],
      });
      setNewEmail('');
    }
  };

  const removeEmail = (email: string) => {
    setValues({
      ...values,
      emailRecipients: values.emailRecipients.filter((e) => e !== email),
    });
  };

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg border p-6">
        <h3 className="font-semibold mb-4">Email Notifications</h3>

        <div className="space-y-4">
          <label className="flex items-center gap-3">
            <input
              type="checkbox"
              checked={values.emailEnabled}
              onChange={(e) => setValues({ ...values, emailEnabled: e.target.checked })}
              className="rounded"
            />
            <span className="text-sm">Enable email notifications</span>
          </label>

          {values.emailEnabled && (
            <div>
              <label className="block text-sm font-medium mb-2">Recipients</label>
              <div className="flex gap-2 mb-2">
                <input
                  type="email"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  placeholder="email@example.com"
                  className="border rounded px-3 py-2 flex-1"
                />
                <button
                  onClick={addEmail}
                  className="bg-gray-100 px-4 py-2 rounded hover:bg-gray-200"
                >
                  Add
                </button>
              </div>
              <div className="flex flex-wrap gap-2">
                {values.emailRecipients.map((email) => (
                  <span
                    key={email}
                    className="bg-gray-100 px-3 py-1 rounded-full text-sm flex items-center gap-2"
                  >
                    {email}
                    <button onClick={() => removeEmail(email)} className="text-gray-500 hover:text-red-500">
                      ×
                    </button>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="bg-white rounded-lg border p-6">
        <h3 className="font-semibold mb-4">Slack Notifications</h3>

        <div className="space-y-4">
          <label className="flex items-center gap-3">
            <input
              type="checkbox"
              checked={values.slackEnabled}
              onChange={(e) => setValues({ ...values, slackEnabled: e.target.checked })}
              className="rounded"
            />
            <span className="text-sm">Enable Slack notifications</span>
          </label>

          {values.slackEnabled && (
            <div>
              <label className="block text-sm font-medium mb-1">Webhook URL</label>
              <input
                type="url"
                value={values.slackWebhookUrl || ''}
                onChange={(e) => setValues({ ...values, slackWebhookUrl: e.target.value })}
                placeholder="https://hooks.slack.com/services/..."
                className="border rounded px-3 py-2 w-full"
              />
            </div>
          )}
        </div>
      </div>

      <div className="bg-white rounded-lg border p-6">
        <h3 className="font-semibold mb-4">Severity Filter</h3>

        <div>
          <label className="block text-sm font-medium mb-2">Minimum Severity</label>
          <select
            value={values.severityThreshold}
            onChange={(e) => setValues({ ...values, severityThreshold: e.target.value as 'info' | 'warning' | 'critical' })}
            className="border rounded px-3 py-2"
          >
            <option value="info">All notifications</option>
            <option value="warning">Warning and critical only</option>
            <option value="critical">Critical only</option>
          </select>
        </div>
      </div>

      <button
        onClick={() => onSave(values)}
        disabled={saving}
        className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
      >
        {saving ? 'Saving...' : 'Save Changes'}
      </button>
    </div>
  );
}

// Quarantine Settings Component
function QuarantineSettings({
  settings,
  onSave,
  saving,
}: {
  settings: TenantSettings['quarantine'];
  onSave: (values: Partial<TenantSettings['quarantine']>) => void;
  saving: boolean;
}) {
  const [values, setValues] = useState(settings);

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg border p-6">
        <h3 className="font-semibold mb-4">Quarantine Behavior</h3>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Auto-delete after (days)</label>
            <input
              type="number"
              min="1"
              max="365"
              value={values.autoDeleteAfterDays}
              onChange={(e) => setValues({ ...values, autoDeleteAfterDays: Number(e.target.value) })}
              className="border rounded px-3 py-2 w-32"
            />
            <p className="text-xs text-gray-500 mt-1">
              Quarantined emails will be automatically deleted after this period
            </p>
          </div>

          <label className="flex items-center gap-3">
            <input
              type="checkbox"
              checked={values.allowUserRelease}
              onChange={(e) => setValues({ ...values, allowUserRelease: e.target.checked })}
              className="rounded"
            />
            <span className="text-sm">Allow users to release their own quarantined emails</span>
          </label>

          <label className="flex items-center gap-3">
            <input
              type="checkbox"
              checked={values.notifyOnRelease}
              onChange={(e) => setValues({ ...values, notifyOnRelease: e.target.checked })}
              className="rounded"
            />
            <span className="text-sm">Send notification when emails are released from quarantine</span>
          </label>
        </div>
      </div>

      <button
        onClick={() => onSave(values)}
        disabled={saving}
        className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
      >
        {saving ? 'Saving...' : 'Save Changes'}
      </button>
    </div>
  );
}

// Integration Settings Component
function IntegrationSettings({
  settings,
  onSave,
  saving,
}: {
  settings: TenantSettings['integrations'];
  onSave: (values: Partial<TenantSettings['integrations']>) => void;
  saving: boolean;
}) {
  const [webhookToken, setWebhookToken] = useState(settings.webhookToken || '');

  const generateToken = () => {
    const token = 'swf_' + Array.from(crypto.getRandomValues(new Uint8Array(24)))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    setWebhookToken(token);
  };

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg border p-6">
        <h3 className="font-semibold mb-4">Email Providers</h3>

        <div className="space-y-4">
          <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                <span className="text-blue-600 font-bold">M</span>
              </div>
              <div>
                <p className="font-medium">Microsoft 365</p>
                <p className="text-sm text-gray-500">
                  {settings.microsoftConnected ? 'Connected' : 'Not connected'}
                </p>
              </div>
            </div>
            <button
              onClick={() => window.location.href = '/api/auth/microsoft'}
              className={`px-4 py-2 rounded ${
                settings.microsoftConnected
                  ? 'bg-gray-100 text-gray-700'
                  : 'bg-blue-600 text-white hover:bg-blue-700'
              }`}
            >
              {settings.microsoftConnected ? 'Reconnect' : 'Connect'}
            </button>
          </div>

          <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-red-100 rounded-lg flex items-center justify-center">
                <span className="text-red-600 font-bold">G</span>
              </div>
              <div>
                <p className="font-medium">Google Workspace</p>
                <p className="text-sm text-gray-500">
                  {settings.googleConnected ? 'Connected' : 'Not connected'}
                </p>
              </div>
            </div>
            <button
              onClick={() => window.location.href = '/api/auth/google'}
              className={`px-4 py-2 rounded ${
                settings.googleConnected
                  ? 'bg-gray-100 text-gray-700'
                  : 'bg-blue-600 text-white hover:bg-blue-700'
              }`}
            >
              {settings.googleConnected ? 'Reconnect' : 'Connect'}
            </button>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg border p-6">
        <h3 className="font-semibold mb-4">Webhook API</h3>
        <p className="text-sm text-gray-600 mb-4">
          Use this token to authenticate webhook requests to the email processing API.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Webhook Token</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={webhookToken}
                readOnly
                className="border rounded px-3 py-2 flex-1 bg-gray-50 font-mono text-sm"
                placeholder="Click generate to create a token"
              />
              <button
                onClick={generateToken}
                className="bg-gray-100 px-4 py-2 rounded hover:bg-gray-200"
              >
                Generate
              </button>
            </div>
          </div>

          <div className="bg-gray-50 rounded p-4">
            <p className="text-sm font-medium mb-2">Webhook Endpoint</p>
            <code className="text-sm text-gray-700 break-all">
              POST /api/webhooks/email
            </code>
            <p className="text-xs text-gray-500 mt-2">
              Include header: <code>X-Webhook-Token: {webhookToken || '<your-token>'}</code>
            </p>
          </div>
        </div>

        <button
          onClick={() => onSave({ webhookToken })}
          disabled={saving || !webhookToken}
          className="mt-4 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
        >
          {saving ? 'Saving...' : 'Save Token'}
        </button>
      </div>
    </div>
  );
}

// Display Settings Component
function DisplaySettings({
  settings,
  onSave,
  saving,
}: {
  settings: TenantSettings['display'];
  onSave: (values: Partial<TenantSettings['display']>) => void;
  saving: boolean;
}) {
  const [values, setValues] = useState(settings);

  const timezones = [
    'UTC',
    'America/New_York',
    'America/Chicago',
    'America/Denver',
    'America/Los_Angeles',
    'Europe/London',
    'Europe/Paris',
    'Asia/Tokyo',
    'Asia/Shanghai',
    'Australia/Sydney',
  ];

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg border p-6">
        <h3 className="font-semibold mb-4">Display Preferences</h3>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Timezone</label>
            <select
              value={values.timezone}
              onChange={(e) => setValues({ ...values, timezone: e.target.value })}
              className="border rounded px-3 py-2 w-64"
            >
              {timezones.map((tz) => (
                <option key={tz} value={tz}>
                  {tz}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Date Format</label>
            <select
              value={values.dateFormat}
              onChange={(e) => setValues({ ...values, dateFormat: e.target.value })}
              className="border rounded px-3 py-2"
            >
              <option value="YYYY-MM-DD">2024-01-15 (ISO)</option>
              <option value="MM/DD/YYYY">01/15/2024 (US)</option>
              <option value="DD/MM/YYYY">15/01/2024 (EU)</option>
              <option value="DD MMM YYYY">15 Jan 2024</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Items Per Page</label>
            <select
              value={values.itemsPerPage}
              onChange={(e) => setValues({ ...values, itemsPerPage: Number(e.target.value) })}
              className="border rounded px-3 py-2"
            >
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>
        </div>
      </div>

      <button
        onClick={() => onSave(values)}
        disabled={saving}
        className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
      >
        {saving ? 'Saving...' : 'Save Changes'}
      </button>
    </div>
  );
}

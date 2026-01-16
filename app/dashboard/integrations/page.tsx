'use client';

import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { useSearchParams } from 'next/navigation';

interface Integration {
  id: string;
  type: 'o365' | 'gmail' | 'smtp';
  status: 'connected' | 'disconnected' | 'error' | 'pending';
  email?: string;
  displayName?: string;
  syncEnabled: boolean;
  lastSyncAt?: string;
  errorMessage?: string;
  createdAt: string;
}

interface SyncResult {
  totalIntegrations: number;
  totalEmailsProcessed: number;
  totalThreatsFound: number;
  totalErrors: number;
}

const integrationInfo = {
  o365: {
    name: 'Microsoft 365',
    description: 'Connect to Exchange Online and Outlook mailboxes',
    icon: '📧',
    color: 'bg-blue-500',
  },
  gmail: {
    name: 'Gmail / Google Workspace',
    description: 'Connect to Gmail and Google Workspace accounts',
    icon: '📬',
    color: 'bg-red-500',
  },
  smtp: {
    name: 'SMTP Relay',
    description: 'Forward emails via SMTP webhook for analysis',
    icon: '📨',
    color: 'bg-gray-500',
  },
};

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const searchParams = useSearchParams();

  const successMessage = searchParams.get('success');
  const errorMessage = searchParams.get('error');

  // Sync Nango connections to database
  const syncNangoConnections = useCallback(async () => {
    try {
      await fetch('/api/integrations/sync-nango', { method: 'POST' });
    } catch (error) {
      console.error('Failed to sync Nango connections:', error);
    }
  }, []);

  useEffect(() => {
    // Sync Nango connections first, then fetch integrations
    syncNangoConnections().then(() => fetchIntegrations());
  }, [syncNangoConnections]);

  async function fetchIntegrations() {
    try {
      const response = await fetch('/api/integrations');
      const data = await response.json();
      setIntegrations(data.integrations || []);
    } catch (error) {
      console.error('Failed to fetch integrations:', error);
    } finally {
      setLoading(false);
    }
  }

  async function connectIntegration(type: 'o365' | 'gmail') {
    setConnecting(type);
    try {
      const response = await fetch(`/api/integrations/${type}`);
      const data = await response.json();

      if (data.authUrl) {
        window.location.href = data.authUrl;
      } else {
        console.error('No auth URL returned');
      }
    } catch (error) {
      console.error(`Failed to connect ${type}:`, error);
    } finally {
      setConnecting(null);
    }
  }

  async function disconnectIntegration(type: 'o365' | 'gmail') {
    if (!confirm('Are you sure you want to disconnect this integration?')) {
      return;
    }

    try {
      await fetch(`/api/integrations/${type}`, { method: 'DELETE' });
      await fetchIntegrations();
    } catch (error) {
      console.error(`Failed to disconnect ${type}:`, error);
    }
  }

  async function triggerSync() {
    setSyncing(true);
    setSyncMessage(null);

    try {
      const response = await fetch('/api/sync', { method: 'POST' });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Sync failed');
      }

      const result = data as SyncResult;

      if (result.totalEmailsProcessed > 0 || result.totalThreatsFound > 0) {
        setSyncMessage({
          type: 'success',
          message: `Sync complete: ${result.totalEmailsProcessed} emails processed, ${result.totalThreatsFound} threats found`,
        });
      } else if (result.totalErrors > 0) {
        setSyncMessage({
          type: 'error',
          message: `Sync completed with ${result.totalErrors} errors`,
        });
      } else {
        setSyncMessage({
          type: 'success',
          message: 'Sync complete: No new emails to process',
        });
      }

      // Refresh integrations to update last sync time
      await fetchIntegrations();
    } catch (error) {
      console.error('Sync failed:', error);
      setSyncMessage({
        type: 'error',
        message: error instanceof Error ? error.message : 'Sync failed',
      });
    } finally {
      setSyncing(false);
    }
  }

  function getIntegration(type: 'o365' | 'gmail' | 'smtp'): Integration | undefined {
    return integrations.find((i) => i.type === type);
  }

  function getStatusBadge(status: Integration['status']) {
    switch (status) {
      case 'connected':
        return <Badge className="bg-green-100 text-green-800">Connected</Badge>;
      case 'disconnected':
        return <Badge className="bg-gray-100 text-gray-800">Disconnected</Badge>;
      case 'error':
        return <Badge className="bg-red-100 text-red-800">Error</Badge>;
      case 'pending':
        return <Badge className="bg-yellow-100 text-yellow-800">Pending</Badge>;
      default:
        return null;
    }
  }

  function formatDate(dateString?: string) {
    if (!dateString) return 'Never';
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
        <h1 className="text-2xl font-bold">Email Integrations</h1>
        <p className="text-muted-foreground">
          Connect your email providers to enable threat detection and protection.
        </p>
      </div>

      {/* Status Messages */}
      {successMessage && (
        <div className="bg-green-50 border border-green-200 text-green-800 px-4 py-3 rounded-lg">
          ✓ {successMessage}
        </div>
      )}
      {errorMessage && (
        <div className="bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded-lg">
          ✕ {errorMessage}
        </div>
      )}
      {syncMessage && (
        <div className={`px-4 py-3 rounded-lg ${
          syncMessage.type === 'success'
            ? 'bg-green-50 border border-green-200 text-green-800'
            : 'bg-red-50 border border-red-200 text-red-800'
        }`}>
          {syncMessage.type === 'success' ? '✓' : '✕'} {syncMessage.message}
        </div>
      )}

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {/* Microsoft 365 Card */}
        <IntegrationCard
          type="o365"
          info={integrationInfo.o365}
          integration={getIntegration('o365')}
          connecting={connecting === 'o365'}
          syncing={syncing}
          onConnect={() => connectIntegration('o365')}
          onDisconnect={() => disconnectIntegration('o365')}
          onSync={triggerSync}
          getStatusBadge={getStatusBadge}
          formatDate={formatDate}
        />

        {/* Gmail Card */}
        <IntegrationCard
          type="gmail"
          info={integrationInfo.gmail}
          integration={getIntegration('gmail')}
          connecting={connecting === 'gmail'}
          syncing={syncing}
          onConnect={() => connectIntegration('gmail')}
          onDisconnect={() => disconnectIntegration('gmail')}
          onSync={triggerSync}
          getStatusBadge={getStatusBadge}
          formatDate={formatDate}
        />

        {/* SMTP Card */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 rounded-lg ${integrationInfo.smtp.color} flex items-center justify-center text-white text-xl`}>
                {integrationInfo.smtp.icon}
              </div>
              <div>
                <CardTitle className="text-lg">{integrationInfo.smtp.name}</CardTitle>
                <CardDescription>{integrationInfo.smtp.description}</CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="bg-gray-50 p-4 rounded-lg">
                <p className="text-sm text-muted-foreground mb-2">Webhook Endpoint:</p>
                <code className="text-xs bg-gray-100 px-2 py-1 rounded break-all">
                  {typeof window !== 'undefined' ? `${window.location.origin}/api/webhooks/smtp` : '/api/webhooks/smtp'}
                </code>
              </div>
              <p className="text-sm text-muted-foreground">
                Configure your mail server to forward emails to this webhook for analysis.
              </p>
              <Badge className="bg-blue-100 text-blue-800">Coming Soon</Badge>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Connected Integrations Details */}
      {integrations.filter((i) => i.status === 'connected').length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Connected Accounts</CardTitle>
            <CardDescription>Details of your connected email integrations</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {integrations
                .filter((i) => i.status === 'connected')
                .map((integration) => (
                  <div
                    key={integration.id}
                    className="flex items-center justify-between p-4 bg-gray-50 rounded-lg"
                  >
                    <div className="flex items-center gap-4">
                      <div
                        className={`w-10 h-10 rounded-lg ${integrationInfo[integration.type].color} flex items-center justify-center text-white text-xl`}
                      >
                        {integrationInfo[integration.type].icon}
                      </div>
                      <div>
                        <p className="font-medium">{integration.email || integration.displayName}</p>
                        <p className="text-sm text-muted-foreground">
                          {integrationInfo[integration.type].name}
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm">
                        Last sync: {formatDate(integration.lastSyncAt)}
                      </p>
                      {integration.syncEnabled ? (
                        <Badge variant="outline" className="text-green-600">
                          Sync Enabled
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-gray-600">
                          Sync Disabled
                        </Badge>
                      )}
                    </div>
                  </div>
                ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

interface IntegrationCardProps {
  type: 'o365' | 'gmail';
  info: { name: string; description: string; icon: string; color: string };
  integration?: Integration;
  connecting: boolean;
  syncing: boolean;
  onConnect: () => void;
  onDisconnect: () => void;
  onSync: () => void;
  getStatusBadge: (status: Integration['status']) => React.ReactNode;
  formatDate: (date?: string) => string;
}

function IntegrationCard({
  type,
  info,
  integration,
  connecting,
  syncing,
  onConnect,
  onDisconnect,
  onSync,
  getStatusBadge,
  formatDate,
}: IntegrationCardProps) {
  const isConnected = integration?.status === 'connected';

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`w-10 h-10 rounded-lg ${info.color} flex items-center justify-center text-white text-xl`}
            >
              {info.icon}
            </div>
            <div>
              <CardTitle className="text-lg">{info.name}</CardTitle>
              <CardDescription>{info.description}</CardDescription>
            </div>
          </div>
          {integration && getStatusBadge(integration.status)}
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {isConnected && integration ? (
            <>
              <div className="space-y-2">
                <p className="text-sm">
                  <span className="text-muted-foreground">Account:</span>{' '}
                  {integration.email || integration.displayName}
                </p>
                <p className="text-sm">
                  <span className="text-muted-foreground">Last sync:</span>{' '}
                  {formatDate(integration.lastSyncAt)}
                </p>
                {integration.errorMessage && (
                  <p className="text-sm text-red-600">
                    Error: {integration.errorMessage}
                  </p>
                )}
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-1"
                  onClick={onSync}
                  disabled={syncing}
                >
                  {syncing ? (
                    <>
                      <span className="animate-spin mr-2">⏳</span>
                      Syncing...
                    </>
                  ) : (
                    'Sync Now'
                  )}
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={onDisconnect}
                  disabled={syncing}
                >
                  Disconnect
                </Button>
              </div>
            </>
          ) : (
            <Button
              className="w-full"
              onClick={onConnect}
              disabled={connecting}
            >
              {connecting ? (
                <>
                  <span className="animate-spin mr-2">⏳</span>
                  Connecting...
                </>
              ) : (
                <>Connect {info.name}</>
              )}
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

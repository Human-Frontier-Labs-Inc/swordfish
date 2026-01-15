/**
 * Integration Types
 */

export type IntegrationType = 'o365' | 'gmail' | 'smtp';
export type IntegrationStatus = 'pending' | 'connected' | 'error' | 'disconnected';

export interface Integration {
  id: string;
  tenantId: string;
  type: IntegrationType;
  status: IntegrationStatus;
  nangoConnectionId: string | null; // Nango connection ID for OAuth token management
  config: IntegrationConfig;
  lastSyncAt: Date | null;
  errorMessage: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export type IntegrationConfig = O365Config | GmailConfig | SMTPConfig;

export interface O365Config {
  type: 'o365';
  tenantId: string; // Azure AD tenant ID
  clientId: string;
  // Tokens stored encrypted
  accessToken?: string;
  refreshToken?: string;
  tokenExpiresAt?: Date;
  // Sync settings
  syncEnabled: boolean;
  syncFolders: string[];
  webhookSubscriptionId?: string;
  webhookExpiresAt?: Date;
}

export interface GmailConfig {
  type: 'gmail';
  email: string;
  // Tokens stored encrypted
  accessToken?: string;
  refreshToken?: string;
  tokenExpiresAt?: Date;
  // Sync settings
  syncEnabled: boolean;
  watchExpiration?: Date;
  historyId?: string;
}

export interface SMTPConfig {
  type: 'smtp';
  webhookSecret: string;
  allowedSenders: string[];
  enabled: boolean;
}

export interface OAuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
  scope: string;
}

export interface SyncJob {
  id: string;
  integrationId: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startedAt: Date;
  completedAt: Date | null;
  emailsProcessed: number;
  emailsQuarantined: number;
  errorMessage: string | null;
}

/**
 * Domain-Wide Monitoring Types
 * Shared types for Google Workspace and Microsoft 365 domain-wide integrations
 */

export type DomainProvider = 'google_workspace' | 'microsoft_365';
export type DomainConfigStatus = 'pending' | 'active' | 'error' | 'disabled';
export type DomainUserStatus = 'active' | 'suspended' | 'deleted' | 'excluded';

export interface DomainWideConfig {
  id: string;
  tenantId: string;
  provider: DomainProvider;
  status: DomainConfigStatus;
  errorMessage: string | null;

  // Google Workspace specific
  googleServiceAccountEmail?: string;
  googleAdminEmail?: string;
  googleCustomerId?: string;

  // Microsoft 365 specific
  azureTenantId?: string;
  azureClientId?: string;

  // Sync settings
  syncEnabled: boolean;
  syncAllUsers: boolean;
  syncIncludeGroups?: string[];
  syncExcludeGroups?: string[];

  // Monitoring scope
  monitorIncoming: boolean;
  monitorOutgoing: boolean;
  monitorInternal: boolean;

  // Stats
  totalUsersDiscovered: number;
  totalUsersActive: number;
  lastUserSyncAt: Date | null;
  lastEmailSyncAt: Date | null;

  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
}

export interface DomainUser {
  id: string;
  domainConfigId: string;
  tenantId: string;
  email: string;
  displayName: string | null;
  providerUserId: string | null;
  status: DomainUserStatus;
  excludedReason: string | null;
  isMonitored: boolean;
  lastSyncAt: Date | null;
  lastHistoryId: string | null;
  webhookSubscriptionId: string | null;
  webhookExpiresAt: Date | null;
  emailsScanned: number;
  threatsDetected: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface GoogleWorkspaceSetupParams {
  tenantId: string;
  serviceAccountKey: string; // JSON key file content
  adminEmail: string; // Admin email for impersonation
  createdBy: string;
}

export interface Microsoft365SetupParams {
  tenantId: string;
  azureTenantId: string;
  clientId: string;
  clientSecret: string;
  createdBy: string;
}

export interface DirectoryUser {
  email: string;
  displayName: string;
  providerId: string;
  suspended?: boolean;
  deleted?: boolean;
}

export interface DomainSyncResult {
  usersDiscovered: number;
  usersAdded: number;
  usersUpdated: number;
  usersRemoved: number;
  errors: string[];
}

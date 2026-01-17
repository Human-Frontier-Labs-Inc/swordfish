/**
 * Response Actions
 *
 * Implements ATO response actions including session termination,
 * password reset triggers, MFA enforcement, notifications,
 * account locking, and audit trail creation.
 */

import { sendAdminNotification, sendUserNotification, type NotificationChannel } from './notifications';

export interface SessionInfo {
  id: string;
  userId: string;
  createdAt: Date;
  lastActivity: Date;
  ip: string;
  device: string;
}

export interface TerminationOptions {
  excludeSessionIds?: string[];
  createAuditEntry?: boolean;
  reason?: string;
  triggeredBy?: string;
}

export interface TerminationResult {
  success: boolean;
  terminatedCount: number;
  terminatedSessionIds: string[];
  auditEntryId?: string;
}

export interface PasswordRequirements {
  minLength?: number;
  requireSpecialChar?: boolean;
  requireNumber?: boolean;
  requireUppercase?: boolean;
  cannotReuseLastN?: number;
}

export interface PasswordResetOptions {
  forceReset?: boolean;
  reason?: string;
  requirements?: PasswordRequirements;
  sendNotification?: boolean;
  notificationChannels?: string[];
}

export interface PasswordResetResult {
  success: boolean;
  resetToken: string;
  expiresAt: Date;
  previousTokensInvalidated: boolean;
  requirements?: PasswordRequirements;
  notificationSent?: boolean;
}

export interface MFAOptions {
  required: boolean;
  methods: string[];
  forceSetup?: boolean;
  upgradeFromWeaker?: boolean;
  allowTemporaryBypass?: boolean;
  bypassDuration?: number;
}

export interface MFAResult {
  success: boolean;
  mfaRequired: boolean;
  allowedMethods: string[];
  setupRequired?: boolean;
  setupDeadline?: Date;
  upgradeRequired?: boolean;
  bypassAvailable?: boolean;
  bypassExpiresAt?: Date;
}

export interface NotificationPayload {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | 'warning';
  userId: string;
  userEmail: string;
  details: Record<string, unknown>;
  recommendedActions?: string[];
}

export interface AdminNotificationOptions {
  escalate?: boolean;
  escalationLevel?: string;
  channels?: string[];
}

export interface AdminNotificationResult {
  success: boolean;
  notifiedAdmins: string[];
  escalated?: boolean;
  escalationGroup?: string;
  includesRecommendations?: boolean;
  channelsNotified?: string[];
}

export interface UserNotificationOptions {
  includeVerificationLink?: boolean;
  allowFalsePositiveReport?: boolean;
  preferences?: Record<string, boolean>;
}

export interface UserNotificationResult {
  success: boolean;
  deliveredVia: string[];
  verificationLink?: string;
  verificationExpiry?: Date;
  falsePositiveReportLink?: string;
}

export interface LockOptions {
  reason: string;
  duration?: number;
  permanent?: boolean;
  triggeredBy?: string;
  allowSelfUnlock?: boolean;
}

export interface LockResult {
  success: boolean;
  locked: boolean;
  permanent?: boolean;
  unlocksAt: Date | null;
  selfUnlockAvailable?: boolean;
  selfUnlockVerification?: string;
}

export interface UnlockOptions {
  unlockedBy: string;
  reason?: string;
}

export interface UnlockResult {
  success: boolean;
  locked: boolean;
}

export interface AuditEntry {
  id?: string;
  timestamp: Date;
  userId: string;
  actionType: string;
  actionDetails: Record<string, unknown>;
  triggeredBy: string;
  ipAddress: string;
  userAgent?: string;
  correlationId?: string;
}

export interface AuditTrailOptions {
  actionType?: string;
  startDate?: Date;
  endDate?: Date;
  correlationId?: string;
}

export interface CreateAuditResult {
  success: boolean;
  entryId: string;
}

export interface ResponseAction {
  type: string;
  params: Record<string, unknown>;
}

export interface ExecuteActionsOptions {
  stopOnFailure?: boolean;
  createAuditTrail?: boolean;
}

export interface ExecuteActionsResult {
  executedActions: Array<{ type: string; success: boolean; error?: string }>;
  allSuccessful: boolean;
  failedActions: Array<{ type: string; error: string }>;
  auditEntries?: AuditEntry[];
}

// In-memory storage for demo purposes
const auditStore: Map<string, AuditEntry[]> = new Map();
const lockedAccounts: Map<string, { locked: boolean; unlocksAt: Date | null; permanent: boolean; selfUnlockAvailable: boolean }> = new Map();
const resetTokens: Map<string, { token: string; invalidated: boolean }> = new Map();

/**
 * Generate a unique ID
 */
function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
}

/**
 * Generate a secure token
 */
function generateToken(): string {
  return `reset-${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
}

/**
 * Terminate user sessions
 */
export async function terminateUserSessions(
  userId: string,
  sessions: SessionInfo[],
  options: TerminationOptions = {}
): Promise<TerminationResult> {
  const excludeSet = new Set(options.excludeSessionIds || []);
  const sessionsToTerminate = sessions.filter((s) => !excludeSet.has(s.id));
  const terminatedSessionIds = sessionsToTerminate.map((s) => s.id);

  let auditEntryId: string | undefined;

  if (options.createAuditEntry) {
    const result = await createAuditEntry({
      timestamp: new Date(),
      userId,
      actionType: 'session_termination',
      actionDetails: {
        terminatedSessions: terminatedSessionIds,
        reason: options.reason,
      },
      triggeredBy: options.triggeredBy || 'system',
      ipAddress: '10.0.0.1',
    });
    auditEntryId = result.entryId;
  }

  return {
    success: true,
    terminatedCount: terminatedSessionIds.length,
    terminatedSessionIds,
    auditEntryId,
  };
}

/**
 * Trigger password reset for user
 */
export async function triggerPasswordReset(
  userId: string,
  userEmail: string,
  options: PasswordResetOptions = {}
): Promise<PasswordResetResult> {
  // Invalidate previous tokens
  const existingToken = resetTokens.get(userId);
  if (existingToken) {
    existingToken.invalidated = true;
  }

  const newToken = generateToken();
  resetTokens.set(userId, { token: newToken, invalidated: false });

  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  let notificationSent = false;
  if (options.sendNotification) {
    await sendUserNotification(
      { email: userEmail },
      'Password Reset Required',
      'Your password reset has been triggered.',
      { channels: (options.notificationChannels || ['email']) as NotificationChannel[] }
    );
    notificationSent = true;
  }

  return {
    success: true,
    resetToken: newToken,
    expiresAt,
    previousTokensInvalidated: existingToken !== undefined,
    requirements: options.requirements,
    notificationSent,
  };
}

/**
 * Enforce MFA for user
 */
export async function enforceMFA(userId: string, options: MFAOptions): Promise<MFAResult> {
  const result: MFAResult = {
    success: true,
    mfaRequired: options.required,
    allowedMethods: options.methods,
  };

  if (options.forceSetup) {
    result.setupRequired = true;
    result.setupDeadline = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  }

  if (options.upgradeFromWeaker) {
    result.upgradeRequired = true;
  }

  if (options.allowTemporaryBypass && options.bypassDuration) {
    result.bypassAvailable = true;
    result.bypassExpiresAt = new Date(Date.now() + options.bypassDuration * 1000);
  }

  return result;
}

/**
 * Notify admin of security event
 */
export async function notifyAdmin(
  notification: NotificationPayload,
  options: AdminNotificationOptions = {}
): Promise<AdminNotificationResult> {
  const admins = ['admin@company.com', 'security@company.com'];
  const channels = options.channels || ['email'];

  await sendAdminNotification(
    `ATO Alert: ${notification.type}`,
    JSON.stringify(notification.details),
    { channels: channels as NotificationChannel[] }
  );

  const result: AdminNotificationResult = {
    success: true,
    notifiedAdmins: admins,
    channelsNotified: channels,
  };

  if (options.escalate) {
    result.escalated = true;
    result.escalationGroup = options.escalationLevel;
  }

  if (notification.recommendedActions && notification.recommendedActions.length > 0) {
    result.includesRecommendations = true;
  }

  return result;
}

/**
 * Notify user of security event
 */
export async function notifyUser(
  notification: NotificationPayload,
  options: UserNotificationOptions = {}
): Promise<UserNotificationResult> {
  let deliveredVia: string[] = ['email'];

  if (options.preferences) {
    deliveredVia = Object.entries(options.preferences)
      .filter(([, enabled]) => enabled)
      .map(([channel]) => channel);
  }

  await sendUserNotification(
    { email: notification.userEmail },
    `Security Alert: ${notification.type}`,
    JSON.stringify(notification.details),
    { channels: deliveredVia as NotificationChannel[] }
  );

  const result: UserNotificationResult = {
    success: true,
    deliveredVia,
  };

  if (options.includeVerificationLink) {
    result.verificationLink = `https://app.swordfish.io/verify/${generateId()}`;
    result.verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
  }

  if (options.allowFalsePositiveReport) {
    result.falsePositiveReportLink = `https://app.swordfish.io/report/${generateId()}`;
  }

  return result;
}

/**
 * Lock user account
 */
export async function lockAccount(userId: string, options: LockOptions): Promise<LockResult> {
  const unlocksAt = options.permanent ? null : new Date(Date.now() + (options.duration || 3600) * 1000);

  lockedAccounts.set(userId, {
    locked: true,
    unlocksAt,
    permanent: options.permanent || false,
    selfUnlockAvailable: options.allowSelfUnlock || false,
  });

  // Create audit entry
  await createAuditEntry({
    timestamp: new Date(),
    userId,
    actionType: 'account_lock',
    actionDetails: {
      reason: options.reason,
      duration: options.duration,
      permanent: options.permanent,
    },
    triggeredBy: options.triggeredBy || 'system',
    ipAddress: '10.0.0.1',
  });

  const result: LockResult = {
    success: true,
    locked: true,
    permanent: options.permanent,
    unlocksAt,
  };

  if (options.allowSelfUnlock) {
    result.selfUnlockAvailable = true;
    result.selfUnlockVerification = 'email';
  }

  return result;
}

/**
 * Unlock user account
 */
export async function unlockAccount(userId: string, options: UnlockOptions): Promise<UnlockResult> {
  lockedAccounts.set(userId, {
    locked: false,
    unlocksAt: null,
    permanent: false,
    selfUnlockAvailable: false,
  });

  // Create audit entry
  await createAuditEntry({
    timestamp: new Date(),
    userId,
    actionType: 'account_lock',
    actionDetails: {
      action: 'unlock',
      reason: options.reason,
    },
    triggeredBy: options.unlockedBy,
    ipAddress: '10.0.0.1',
  });

  return {
    success: true,
    locked: false,
  };
}

/**
 * Create audit entry
 */
export async function createAuditEntry(entry: AuditEntry): Promise<CreateAuditResult> {
  const entryId = generateId();
  const fullEntry: AuditEntry = {
    ...entry,
    id: entryId,
  };

  const userEntries = auditStore.get(entry.userId) || [];
  userEntries.push(fullEntry);
  auditStore.set(entry.userId, userEntries);

  return {
    success: true,
    entryId,
  };
}

/**
 * Get audit trail for user
 */
export async function getAuditTrail(
  userId: string,
  options: AuditTrailOptions = {}
): Promise<AuditEntry[]> {
  let entries = auditStore.get(userId) || [];

  // Filter by action type
  if (options.actionType) {
    entries = entries.filter((e) => e.actionType === options.actionType);
  }

  // Filter by date range
  if (options.startDate) {
    entries = entries.filter((e) => e.timestamp >= options.startDate!);
  }

  if (options.endDate) {
    entries = entries.filter((e) => e.timestamp <= options.endDate!);
  }

  // Filter by correlation ID
  if (options.correlationId) {
    entries = entries.filter((e) => e.correlationId === options.correlationId);
  }

  // Sort by timestamp descending
  entries.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

  return entries;
}

/**
 * Response Action Executor class
 */
export class ResponseActionExecutor {
  async executeActions(
    userId: string,
    actions: ResponseAction[],
    options: ExecuteActionsOptions = {}
  ): Promise<ExecuteActionsResult> {
    const executedActions: Array<{ type: string; success: boolean; error?: string }> = [];
    const failedActions: Array<{ type: string; error: string }> = [];
    const auditEntries: AuditEntry[] = [];

    for (const action of actions) {
      let success = true;
      let error: string | undefined;

      try {
        switch (action.type) {
          case 'terminate_sessions':
            await terminateUserSessions(userId, []);
            break;
          case 'force_password_reset':
            await triggerPasswordReset(userId, 'user@example.com', action.params as PasswordResetOptions);
            break;
          case 'enforce_mfa':
            await enforceMFA(userId, action.params as MFAOptions);
            break;
          case 'notify_admin':
            await notifyAdmin({
              type: 'ato_response',
              severity: (action.params.severity as 'critical') || 'high',
              userId,
              userEmail: 'user@example.com',
              details: {},
            });
            break;
          case 'notify_user':
            await notifyUser({
              type: 'security_alert',
              severity: 'warning',
              userId,
              userEmail: 'user@example.com',
              details: { message: action.params.message },
            });
            break;
          case 'lock_account':
            await lockAccount(userId, action.params as LockOptions);
            break;
          default:
            success = false;
            error = `Unknown action type: ${action.type}`;
        }
      } catch (e) {
        success = false;
        error = e instanceof Error ? e.message : 'Unknown error';
      }

      executedActions.push({ type: action.type, success, error });

      if (!success) {
        failedActions.push({ type: action.type, error: error || 'Unknown error' });

        if (options.stopOnFailure) {
          break;
        }
      }

      if (options.createAuditTrail && success) {
        const auditEntry: AuditEntry = {
          timestamp: new Date(),
          userId,
          actionType: action.type,
          actionDetails: action.params,
          triggeredBy: 'system',
          ipAddress: '10.0.0.1',
        };
        await createAuditEntry(auditEntry);
        auditEntries.push(auditEntry);
      }
    }

    return {
      executedActions,
      allSuccessful: failedActions.length === 0,
      failedActions,
      auditEntries: options.createAuditTrail ? auditEntries : undefined,
    };
  }
}

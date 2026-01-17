/**
 * Response Actions Tests
 *
 * Tests for ATO response actions including session termination,
 * password reset triggers, MFA enforcement, notifications,
 * account locking, and audit trail creation.
 */

import {
  ResponseActionExecutor,
  terminateUserSessions,
  triggerPasswordReset,
  enforceMFA,
  notifyAdmin,
  notifyUser,
  lockAccount,
  unlockAccount,
  createAuditEntry,
  getAuditTrail,
  type ResponseAction,
  type AuditEntry,
  type NotificationPayload,
  type SessionInfo,
} from '@/lib/ato/response-actions';
import {
  sendAdminNotification,
  sendUserNotification,
  NotificationService,
  type NotificationChannel,
} from '@/lib/ato/notifications';

describe('Response Actions', () => {
  describe('Session Termination', () => {
    it('should terminate all active sessions for a user', async () => {
      const userId = 'user123';
      const mockSessions: SessionInfo[] = [
        { id: 'session1', userId, createdAt: new Date(), lastActivity: new Date(), ip: '192.168.1.1', device: 'Chrome/Windows' },
        { id: 'session2', userId, createdAt: new Date(), lastActivity: new Date(), ip: '10.0.0.1', device: 'Safari/Mac' },
        { id: 'session3', userId, createdAt: new Date(), lastActivity: new Date(), ip: '172.16.0.1', device: 'Firefox/Linux' },
      ];

      const result = await terminateUserSessions(userId, mockSessions);

      expect(result.success).toBe(true);
      expect(result.terminatedCount).toBe(3);
      expect(result.terminatedSessionIds).toEqual(['session1', 'session2', 'session3']);
    });

    it('should selectively terminate specific sessions', async () => {
      const userId = 'user123';
      const mockSessions: SessionInfo[] = [
        { id: 'session1', userId, createdAt: new Date(), lastActivity: new Date(), ip: '192.168.1.1', device: 'Chrome/Windows' },
        { id: 'session2', userId, createdAt: new Date(), lastActivity: new Date(), ip: '10.0.0.1', device: 'Safari/Mac' },
      ];

      const result = await terminateUserSessions(userId, mockSessions, {
        excludeSessionIds: ['session1'], // Keep current session
      });

      expect(result.terminatedCount).toBe(1);
      expect(result.terminatedSessionIds).toEqual(['session2']);
    });

    it('should handle no active sessions gracefully', async () => {
      const userId = 'user123';
      const mockSessions: SessionInfo[] = [];

      const result = await terminateUserSessions(userId, mockSessions);

      expect(result.success).toBe(true);
      expect(result.terminatedCount).toBe(0);
    });

    it('should create audit entry when terminating sessions', async () => {
      const userId = 'user123';
      const mockSessions: SessionInfo[] = [
        { id: 'session1', userId, createdAt: new Date(), lastActivity: new Date(), ip: '192.168.1.1', device: 'Chrome' },
      ];

      const result = await terminateUserSessions(userId, mockSessions, {
        createAuditEntry: true,
        reason: 'ATO detected',
        triggeredBy: 'system',
      });

      expect(result.auditEntryId).toBeDefined();
    });
  });

  describe('Password Reset Trigger', () => {
    it('should trigger password reset for user', async () => {
      const userId = 'user123';
      const userEmail = 'user@example.com';

      const result = await triggerPasswordReset(userId, userEmail, {
        forceReset: true,
        reason: 'ATO detection',
      });

      expect(result.success).toBe(true);
      expect(result.resetToken).toBeDefined();
      expect(result.expiresAt).toBeDefined();
    });

    it('should invalidate existing reset tokens', async () => {
      const userId = 'user123';
      const userEmail = 'user@example.com';

      // First reset
      const firstReset = await triggerPasswordReset(userId, userEmail);
      const firstToken = firstReset.resetToken;

      // Second reset should invalidate first
      const secondReset = await triggerPasswordReset(userId, userEmail);

      expect(secondReset.resetToken).not.toBe(firstToken);
      expect(secondReset.previousTokensInvalidated).toBe(true);
    });

    it('should set password requirements for reset', async () => {
      const userId = 'user123';
      const userEmail = 'user@example.com';

      const result = await triggerPasswordReset(userId, userEmail, {
        requirements: {
          minLength: 16,
          requireSpecialChar: true,
          requireNumber: true,
          requireUppercase: true,
          cannotReuseLastN: 5,
        },
      });

      expect(result.requirements).toBeDefined();
      expect(result.requirements?.minLength).toBe(16);
    });

    it('should send password reset notification', async () => {
      const userId = 'user123';
      const userEmail = 'user@example.com';

      const result = await triggerPasswordReset(userId, userEmail, {
        sendNotification: true,
        notificationChannels: ['email', 'sms'],
      });

      expect(result.notificationSent).toBe(true);
    });
  });

  describe('MFA Enforcement', () => {
    it('should enforce MFA for user account', async () => {
      const userId = 'user123';

      const result = await enforceMFA(userId, {
        required: true,
        methods: ['totp', 'sms'],
      });

      expect(result.success).toBe(true);
      expect(result.mfaRequired).toBe(true);
      expect(result.allowedMethods).toContain('totp');
    });

    it('should require MFA setup if not already configured', async () => {
      const userId = 'user123';
      const userHasMFA = false;

      const result = await enforceMFA(userId, {
        required: true,
        methods: ['totp'],
        forceSetup: !userHasMFA,
      });

      expect(result.setupRequired).toBe(true);
      expect(result.setupDeadline).toBeDefined();
    });

    it('should upgrade to stronger MFA method', async () => {
      const userId = 'user123';

      const result = await enforceMFA(userId, {
        required: true,
        methods: ['hardware_key'],
        upgradeFromWeaker: true,
      });

      expect(result.upgradeRequired).toBe(true);
      expect(result.allowedMethods).toContain('hardware_key');
    });

    it('should handle temporary MFA bypass gracefully', async () => {
      const userId = 'user123';

      const result = await enforceMFA(userId, {
        required: true,
        methods: ['totp'],
        allowTemporaryBypass: true,
        bypassDuration: 3600, // 1 hour
      });

      expect(result.bypassAvailable).toBe(true);
      expect(result.bypassExpiresAt).toBeDefined();
    });
  });

  describe('Admin Notification', () => {
    it('should send notification to admin team', async () => {
      const notification: NotificationPayload = {
        type: 'ato_alert',
        severity: 'critical',
        userId: 'user123',
        userEmail: 'user@example.com',
        details: {
          detectionType: 'impossible_travel',
          riskScore: 95,
          location1: 'New York, USA',
          location2: 'London, UK',
          timeDifference: '30 minutes',
        },
      };

      const result = await notifyAdmin(notification);

      expect(result.success).toBe(true);
      expect(result.notifiedAdmins).toBeDefined();
      expect(result.notifiedAdmins.length).toBeGreaterThan(0);
    });

    it('should escalate critical alerts', async () => {
      const notification: NotificationPayload = {
        type: 'ato_alert',
        severity: 'critical',
        userId: 'user123',
        userEmail: 'user@example.com',
        details: { riskScore: 100 },
      };

      const result = await notifyAdmin(notification, {
        escalate: true,
        escalationLevel: 'security_team',
      });

      expect(result.escalated).toBe(true);
      expect(result.escalationGroup).toBe('security_team');
    });

    it('should include recommended actions in notification', async () => {
      const notification: NotificationPayload = {
        type: 'ato_alert',
        severity: 'high',
        userId: 'user123',
        userEmail: 'user@example.com',
        details: { detectionType: 'new_device' },
        recommendedActions: ['terminate_sessions', 'force_password_reset', 'enable_mfa'],
      };

      const result = await notifyAdmin(notification);

      expect(result.includesRecommendations).toBe(true);
    });

    it('should send to multiple notification channels', async () => {
      const notification: NotificationPayload = {
        type: 'ato_alert',
        severity: 'high',
        userId: 'user123',
        userEmail: 'user@example.com',
        details: {},
      };

      const result = await notifyAdmin(notification, {
        channels: ['email', 'slack', 'pagerduty'],
      });

      expect(result.channelsNotified).toContain('email');
      expect(result.channelsNotified).toContain('slack');
    });
  });

  describe('User Notification', () => {
    it('should notify user of suspicious activity', async () => {
      const notification: NotificationPayload = {
        type: 'security_alert',
        severity: 'warning',
        userId: 'user123',
        userEmail: 'user@example.com',
        details: {
          message: 'Unusual login detected',
          location: 'London, UK',
          time: new Date().toISOString(),
        },
      };

      const result = await notifyUser(notification);

      expect(result.success).toBe(true);
      expect(result.deliveredVia).toBeDefined();
    });

    it('should include verification link in notification', async () => {
      const notification: NotificationPayload = {
        type: 'verify_activity',
        severity: 'warning',
        userId: 'user123',
        userEmail: 'user@example.com',
        details: { activity: 'login' },
      };

      const result = await notifyUser(notification, {
        includeVerificationLink: true,
      });

      expect(result.verificationLink).toBeDefined();
      expect(result.verificationExpiry).toBeDefined();
    });

    it('should allow user to report false positive', async () => {
      const notification: NotificationPayload = {
        type: 'security_alert',
        severity: 'warning',
        userId: 'user123',
        userEmail: 'user@example.com',
        details: {},
      };

      const result = await notifyUser(notification, {
        allowFalsePositiveReport: true,
      });

      expect(result.falsePositiveReportLink).toBeDefined();
    });

    it('should respect user notification preferences', async () => {
      const notification: NotificationPayload = {
        type: 'security_alert',
        severity: 'medium',
        userId: 'user123',
        userEmail: 'user@example.com',
        details: {},
      };

      const userPreferences = {
        email: true,
        sms: false,
        push: true,
      };

      const result = await notifyUser(notification, { preferences: userPreferences });

      expect(result.deliveredVia).toContain('email');
      expect(result.deliveredVia).toContain('push');
      expect(result.deliveredVia).not.toContain('sms');
    });
  });

  describe('Account Locking', () => {
    it('should temporarily lock user account', async () => {
      const userId = 'user123';

      const result = await lockAccount(userId, {
        reason: 'ATO detected',
        duration: 3600, // 1 hour
        triggeredBy: 'system',
      });

      expect(result.success).toBe(true);
      expect(result.locked).toBe(true);
      expect(result.unlocksAt).toBeDefined();
    });

    it('should permanently lock account when specified', async () => {
      const userId = 'user123';

      const result = await lockAccount(userId, {
        reason: 'Confirmed ATO',
        permanent: true,
        triggeredBy: 'admin@company.com',
      });

      expect(result.locked).toBe(true);
      expect(result.permanent).toBe(true);
      expect(result.unlocksAt).toBeNull();
    });

    it('should allow self-service unlock with verification', async () => {
      const userId = 'user123';

      const lockResult = await lockAccount(userId, {
        reason: 'Suspicious activity',
        duration: 86400, // 24 hours
        allowSelfUnlock: true,
      });

      expect(lockResult.selfUnlockAvailable).toBe(true);
      expect(lockResult.selfUnlockVerification).toBe('email');
    });

    it('should unlock account manually', async () => {
      const userId = 'user123';

      // First lock the account
      await lockAccount(userId, {
        reason: 'Testing',
        duration: 3600,
      });

      // Then unlock
      const unlockResult = await unlockAccount(userId, {
        unlockedBy: 'admin@company.com',
        reason: 'Verified legitimate user',
      });

      expect(unlockResult.success).toBe(true);
      expect(unlockResult.locked).toBe(false);
    });

    it('should preserve unlock history', async () => {
      const userId = 'user123';

      // Lock and unlock multiple times
      await lockAccount(userId, { reason: 'First lock', duration: 3600 });
      await unlockAccount(userId, { unlockedBy: 'admin', reason: 'First unlock' });
      await lockAccount(userId, { reason: 'Second lock', duration: 3600 });
      await unlockAccount(userId, { unlockedBy: 'admin', reason: 'Second unlock' });

      const history = await getAuditTrail(userId, { actionType: 'account_lock' });

      expect(history.length).toBeGreaterThanOrEqual(4);
    });
  });

  describe('Audit Trail Creation', () => {
    it('should create detailed audit entry for response action', async () => {
      const entry: AuditEntry = {
        timestamp: new Date(),
        userId: 'user123',
        actionType: 'session_termination',
        actionDetails: {
          terminatedSessions: ['session1', 'session2'],
          reason: 'ATO detected',
        },
        triggeredBy: 'system',
        ipAddress: '10.0.0.1',
        userAgent: 'ATO Detection System',
      };

      const result = await createAuditEntry(entry);

      expect(result.success).toBe(true);
      expect(result.entryId).toBeDefined();
    });

    it('should retrieve audit trail for user', async () => {
      const userId = 'user123';

      // Create multiple audit entries
      await createAuditEntry({
        timestamp: new Date(Date.now() - 3600000),
        userId,
        actionType: 'login_attempt',
        actionDetails: { success: false },
        triggeredBy: 'user',
        ipAddress: '192.168.1.1',
      });

      await createAuditEntry({
        timestamp: new Date(Date.now() - 1800000),
        userId,
        actionType: 'password_reset',
        actionDetails: { forced: true },
        triggeredBy: 'system',
        ipAddress: '10.0.0.1',
      });

      const trail = await getAuditTrail(userId);

      expect(trail.length).toBeGreaterThanOrEqual(2);
      expect(trail[0].timestamp.getTime()).toBeGreaterThanOrEqual(trail[1].timestamp.getTime());
    });

    it('should filter audit trail by action type', async () => {
      const userId = 'user123';

      await createAuditEntry({
        timestamp: new Date(),
        userId,
        actionType: 'session_termination',
        actionDetails: {},
        triggeredBy: 'system',
        ipAddress: '10.0.0.1',
      });

      await createAuditEntry({
        timestamp: new Date(),
        userId,
        actionType: 'mfa_enforcement',
        actionDetails: {},
        triggeredBy: 'admin',
        ipAddress: '10.0.0.1',
      });

      const filtered = await getAuditTrail(userId, {
        actionType: 'session_termination',
      });

      expect(filtered.every(e => e.actionType === 'session_termination')).toBe(true);
    });

    it('should filter audit trail by date range', async () => {
      const userId = 'user123';
      const now = new Date();
      const yesterday = new Date(now.getTime() - 86400000);
      const twoDaysAgo = new Date(now.getTime() - 172800000);

      await createAuditEntry({
        timestamp: twoDaysAgo,
        userId,
        actionType: 'login',
        actionDetails: {},
        triggeredBy: 'user',
        ipAddress: '10.0.0.1',
      });

      await createAuditEntry({
        timestamp: yesterday,
        userId,
        actionType: 'login',
        actionDetails: {},
        triggeredBy: 'user',
        ipAddress: '10.0.0.1',
      });

      const filtered = await getAuditTrail(userId, {
        startDate: yesterday,
        endDate: now,
      });

      expect(filtered.every(e => e.timestamp >= yesterday)).toBe(true);
    });

    it('should include correlation ID for related actions', async () => {
      const userId = 'user123';
      const correlationId = 'ato-incident-001';

      await createAuditEntry({
        timestamp: new Date(),
        userId,
        actionType: 'ato_detected',
        actionDetails: { riskScore: 95 },
        triggeredBy: 'system',
        ipAddress: '10.0.0.1',
        correlationId,
      });

      await createAuditEntry({
        timestamp: new Date(),
        userId,
        actionType: 'session_termination',
        actionDetails: { count: 3 },
        triggeredBy: 'system',
        ipAddress: '10.0.0.1',
        correlationId,
      });

      await createAuditEntry({
        timestamp: new Date(),
        userId,
        actionType: 'password_reset',
        actionDetails: { forced: true },
        triggeredBy: 'system',
        ipAddress: '10.0.0.1',
        correlationId,
      });

      const correlated = await getAuditTrail(userId, { correlationId });

      expect(correlated.length).toBe(3);
      expect(correlated.every(e => e.correlationId === correlationId)).toBe(true);
    });
  });

  describe('Response Action Executor', () => {
    let executor: ResponseActionExecutor;

    beforeEach(() => {
      executor = new ResponseActionExecutor();
    });

    it('should execute multiple response actions in sequence', async () => {
      const userId = 'user123';
      const actions: ResponseAction[] = [
        { type: 'terminate_sessions', params: {} },
        { type: 'force_password_reset', params: { sendNotification: true } },
        { type: 'enforce_mfa', params: { methods: ['totp'] } },
        { type: 'notify_admin', params: { severity: 'critical' } },
      ];

      const results = await executor.executeActions(userId, actions);

      expect(results.executedActions).toHaveLength(4);
      expect(results.allSuccessful).toBe(true);
    });

    it('should handle action failure gracefully', async () => {
      const userId = 'user123';
      const actions: ResponseAction[] = [
        { type: 'terminate_sessions', params: {} },
        { type: 'invalid_action' as any, params: {} }, // Should fail
        { type: 'notify_admin', params: {} },
      ];

      const results = await executor.executeActions(userId, actions);

      expect(results.allSuccessful).toBe(false);
      expect(results.failedActions).toHaveLength(1);
      expect(results.executedActions.length).toBe(3); // All attempted
    });

    it('should stop on critical failure if configured', async () => {
      const userId = 'user123';
      const actions: ResponseAction[] = [
        { type: 'lock_account', params: { reason: 'ATO' } },
        { type: 'critical_failing_action' as any, params: {} },
        { type: 'notify_admin', params: {} },
      ];

      const results = await executor.executeActions(userId, actions, {
        stopOnFailure: true,
      });

      expect(results.executedActions.length).toBeLessThan(3);
    });

    it('should create comprehensive audit trail', async () => {
      const userId = 'user123';
      const actions: ResponseAction[] = [
        { type: 'terminate_sessions', params: {} },
        { type: 'notify_user', params: { message: 'Security alert' } },
      ];

      const results = await executor.executeActions(userId, actions, {
        createAuditTrail: true,
      });

      expect(results.auditEntries).toHaveLength(2);
    });
  });
});

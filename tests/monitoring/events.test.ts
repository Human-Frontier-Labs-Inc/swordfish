/**
 * Business Event Tracking Tests
 * TDD: Track domain-specific events for analytics and alerting
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import {
  EventTracker,
  createEventTracker,
  EventType,
  ThreatEvent,
  EmailEvent,
  IntegrationEvent,
  PolicyEvent,
} from '@/lib/monitoring/events';

describe('Business Event Tracking', () => {
  let tracker: EventTracker;
  let mockEmit: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T12:00:00.000Z'));
    mockEmit = vi.fn();
    tracker = createEventTracker({ emit: mockEmit });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('EventType', () => {
    it('should have threat event types', () => {
      expect(EventType.THREAT_DETECTED).toBe('threat.detected');
      expect(EventType.THREAT_QUARANTINED).toBe('threat.quarantined');
      expect(EventType.THREAT_RELEASED).toBe('threat.released');
      expect(EventType.THREAT_DELETED).toBe('threat.deleted');
    });

    it('should have email event types', () => {
      expect(EventType.EMAIL_SCANNED).toBe('email.scanned');
      expect(EventType.EMAIL_SYNCED).toBe('email.synced');
    });

    it('should have integration event types', () => {
      expect(EventType.INTEGRATION_CONNECTED).toBe('integration.connected');
      expect(EventType.INTEGRATION_DISCONNECTED).toBe('integration.disconnected');
      expect(EventType.INTEGRATION_ERROR).toBe('integration.error');
    });

    it('should have policy event types', () => {
      expect(EventType.POLICY_CREATED).toBe('policy.created');
      expect(EventType.POLICY_UPDATED).toBe('policy.updated');
      expect(EventType.POLICY_TRIGGERED).toBe('policy.triggered');
    });
  });

  describe('Threat Events', () => {
    it('should track threat detected event', () => {
      tracker.trackThreatDetected({
        threatId: 'threat-123',
        tenantId: 'org-abc',
        severity: 'high',
        threatType: 'phishing',
        emailId: 'email-456',
      });

      expect(mockEmit).toHaveBeenCalledWith(
        expect.objectContaining({
          type: EventType.THREAT_DETECTED,
          tenantId: 'org-abc',
          data: expect.objectContaining({
            threatId: 'threat-123',
            severity: 'high',
            threatType: 'phishing',
          }),
        })
      );
    });

    it('should track threat quarantined event', () => {
      tracker.trackThreatQuarantined({
        threatId: 'threat-123',
        tenantId: 'org-abc',
        action: 'auto',
      });

      expect(mockEmit).toHaveBeenCalledWith(
        expect.objectContaining({
          type: EventType.THREAT_QUARANTINED,
          data: expect.objectContaining({
            action: 'auto',
          }),
        })
      );
    });

    it('should track threat released event', () => {
      tracker.trackThreatReleased({
        threatId: 'threat-123',
        tenantId: 'org-abc',
        releasedBy: 'user-789',
        reason: 'False positive',
      });

      expect(mockEmit).toHaveBeenCalledWith(
        expect.objectContaining({
          type: EventType.THREAT_RELEASED,
          data: expect.objectContaining({
            releasedBy: 'user-789',
            reason: 'False positive',
          }),
        })
      );
    });
  });

  describe('Email Events', () => {
    it('should track email scanned event', () => {
      tracker.trackEmailScanned({
        emailId: 'email-123',
        tenantId: 'org-abc',
        verdict: 'clean',
        processingTimeMs: 150,
      });

      expect(mockEmit).toHaveBeenCalledWith(
        expect.objectContaining({
          type: EventType.EMAIL_SCANNED,
          data: expect.objectContaining({
            verdict: 'clean',
            processingTimeMs: 150,
          }),
        })
      );
    });

    it('should track email sync batch', () => {
      tracker.trackEmailsSynced({
        tenantId: 'org-abc',
        integrationId: 'int-456',
        emailCount: 100,
        threatsFound: 3,
        durationMs: 5000,
      });

      expect(mockEmit).toHaveBeenCalledWith(
        expect.objectContaining({
          type: EventType.EMAIL_SYNCED,
          data: expect.objectContaining({
            emailCount: 100,
            threatsFound: 3,
          }),
        })
      );
    });
  });

  describe('Integration Events', () => {
    it('should track integration connected event', () => {
      tracker.trackIntegrationConnected({
        integrationId: 'int-123',
        tenantId: 'org-abc',
        provider: 'gmail',
        email: 'user@example.com',
      });

      expect(mockEmit).toHaveBeenCalledWith(
        expect.objectContaining({
          type: EventType.INTEGRATION_CONNECTED,
          data: expect.objectContaining({
            provider: 'gmail',
          }),
        })
      );
    });

    it('should track integration error event', () => {
      tracker.trackIntegrationError({
        integrationId: 'int-123',
        tenantId: 'org-abc',
        provider: 'gmail',
        error: 'Token expired',
        errorCode: 'AUTH_EXPIRED',
      });

      expect(mockEmit).toHaveBeenCalledWith(
        expect.objectContaining({
          type: EventType.INTEGRATION_ERROR,
          data: expect.objectContaining({
            error: 'Token expired',
            errorCode: 'AUTH_EXPIRED',
          }),
        })
      );
    });
  });

  describe('Policy Events', () => {
    it('should track policy triggered event', () => {
      tracker.trackPolicyTriggered({
        policyId: 'policy-123',
        tenantId: 'org-abc',
        emailId: 'email-456',
        action: 'quarantine',
        ruleName: 'Block suspicious domains',
      });

      expect(mockEmit).toHaveBeenCalledWith(
        expect.objectContaining({
          type: EventType.POLICY_TRIGGERED,
          data: expect.objectContaining({
            action: 'quarantine',
            ruleName: 'Block suspicious domains',
          }),
        })
      );
    });
  });

  describe('Event metadata', () => {
    it('should include timestamp in all events', () => {
      tracker.trackThreatDetected({
        threatId: 'threat-123',
        tenantId: 'org-abc',
        severity: 'high',
        threatType: 'phishing',
        emailId: 'email-456',
      });

      expect(mockEmit).toHaveBeenCalledWith(
        expect.objectContaining({
          timestamp: '2024-01-01T12:00:00.000Z',
        })
      );
    });

    it('should include event ID for deduplication', () => {
      tracker.trackThreatDetected({
        threatId: 'threat-123',
        tenantId: 'org-abc',
        severity: 'high',
        threatType: 'phishing',
        emailId: 'email-456',
      });

      expect(mockEmit).toHaveBeenCalledWith(
        expect.objectContaining({
          eventId: expect.stringMatching(/^evt_/),
        })
      );
    });

    it('should include tenant ID in all events', () => {
      tracker.trackEmailScanned({
        emailId: 'email-123',
        tenantId: 'org-abc',
        verdict: 'clean',
        processingTimeMs: 100,
      });

      expect(mockEmit).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: 'org-abc',
        })
      );
    });
  });

  describe('Event buffering', () => {
    it('should support buffered event emission', async () => {
      const bufferedTracker = createEventTracker({
        emit: mockEmit,
        bufferSize: 3,
      });

      bufferedTracker.trackEmailScanned({
        emailId: 'e1',
        tenantId: 'org-abc',
        verdict: 'clean',
        processingTimeMs: 100,
      });
      bufferedTracker.trackEmailScanned({
        emailId: 'e2',
        tenantId: 'org-abc',
        verdict: 'clean',
        processingTimeMs: 100,
      });

      // Not flushed yet
      expect(mockEmit).not.toHaveBeenCalled();

      bufferedTracker.trackEmailScanned({
        emailId: 'e3',
        tenantId: 'org-abc',
        verdict: 'clean',
        processingTimeMs: 100,
      });

      // Buffer is full, should flush
      expect(mockEmit).toHaveBeenCalledTimes(3);
    });

    it('should flush on explicit call', () => {
      const bufferedTracker = createEventTracker({
        emit: mockEmit,
        bufferSize: 10,
      });

      bufferedTracker.trackEmailScanned({
        emailId: 'e1',
        tenantId: 'org-abc',
        verdict: 'clean',
        processingTimeMs: 100,
      });

      expect(mockEmit).not.toHaveBeenCalled();

      bufferedTracker.flush();

      expect(mockEmit).toHaveBeenCalledTimes(1);
    });
  });

  describe('Event aggregation', () => {
    it('should provide event counts by type', () => {
      tracker.trackThreatDetected({
        threatId: 't1',
        tenantId: 'org-abc',
        severity: 'high',
        threatType: 'phishing',
        emailId: 'e1',
      });
      tracker.trackThreatDetected({
        threatId: 't2',
        tenantId: 'org-abc',
        severity: 'medium',
        threatType: 'spam',
        emailId: 'e2',
      });
      tracker.trackEmailScanned({
        emailId: 'e3',
        tenantId: 'org-abc',
        verdict: 'clean',
        processingTimeMs: 100,
      });

      const counts = tracker.getEventCounts();

      expect(counts[EventType.THREAT_DETECTED]).toBe(2);
      expect(counts[EventType.EMAIL_SCANNED]).toBe(1);
    });

    it('should reset counts', () => {
      tracker.trackThreatDetected({
        threatId: 't1',
        tenantId: 'org-abc',
        severity: 'high',
        threatType: 'phishing',
        emailId: 'e1',
      });

      tracker.resetCounts();

      const counts = tracker.getEventCounts();
      expect(counts[EventType.THREAT_DETECTED]).toBe(0);
    });
  });
});

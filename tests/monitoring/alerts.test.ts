/**
 * Alert Thresholds Tests
 * TDD: Define and check alert conditions
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import {
  AlertManager,
  createAlertManager,
  AlertSeverity,
  AlertRule,
  Alert,
  AlertCondition,
} from '@/lib/monitoring/alerts';

describe('Alert Thresholds', () => {
  let alertManager: AlertManager;
  let mockNotify: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T12:00:00.000Z'));
    mockNotify = vi.fn();
    alertManager = createAlertManager({ notify: mockNotify });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('AlertSeverity', () => {
    it('should have standard severity levels', () => {
      expect(AlertSeverity.INFO).toBe('info');
      expect(AlertSeverity.WARNING).toBe('warning');
      expect(AlertSeverity.CRITICAL).toBe('critical');
    });
  });

  describe('AlertRule', () => {
    it('should create a rule with threshold condition', () => {
      const rule: AlertRule = {
        id: 'high-threat-rate',
        name: 'High Threat Detection Rate',
        condition: {
          metric: 'threats_detected_total',
          operator: 'gt',
          threshold: 100,
          window: '5m',
        },
        severity: AlertSeverity.WARNING,
      };

      alertManager.registerRule(rule);

      expect(alertManager.getRules()).toContainEqual(rule);
    });

    it('should support multiple conditions (AND)', () => {
      const rule: AlertRule = {
        id: 'critical-situation',
        name: 'Critical Threat Situation',
        conditions: [
          { metric: 'threats_detected_total', operator: 'gt', threshold: 50, window: '5m' },
          { metric: 'threat_severity_high_count', operator: 'gt', threshold: 10, window: '5m' },
        ],
        severity: AlertSeverity.CRITICAL,
      };

      alertManager.registerRule(rule);

      expect(alertManager.getRules()).toHaveLength(1);
    });
  });

  describe('Alert evaluation', () => {
    it('should fire alert when threshold exceeded', () => {
      alertManager.registerRule({
        id: 'high-error-rate',
        name: 'High Error Rate',
        condition: {
          metric: 'errors_total',
          operator: 'gt',
          threshold: 10,
          window: '1m',
        },
        severity: AlertSeverity.WARNING,
      });

      alertManager.evaluate({ errors_total: 15 });

      expect(mockNotify).toHaveBeenCalledWith(
        expect.objectContaining({
          ruleId: 'high-error-rate',
          severity: AlertSeverity.WARNING,
          status: 'firing',
        })
      );
    });

    it('should not fire alert when under threshold', () => {
      alertManager.registerRule({
        id: 'high-error-rate',
        name: 'High Error Rate',
        condition: {
          metric: 'errors_total',
          operator: 'gt',
          threshold: 10,
          window: '1m',
        },
        severity: AlertSeverity.WARNING,
      });

      alertManager.evaluate({ errors_total: 5 });

      expect(mockNotify).not.toHaveBeenCalled();
    });

    it('should support different operators', () => {
      alertManager.registerRule({
        id: 'low-success-rate',
        name: 'Low Success Rate',
        condition: {
          metric: 'success_rate',
          operator: 'lt',
          threshold: 0.95,
          window: '5m',
        },
        severity: AlertSeverity.WARNING,
      });

      alertManager.evaluate({ success_rate: 0.90 });

      expect(mockNotify).toHaveBeenCalled();
    });

    it('should support equality operator', () => {
      alertManager.registerRule({
        id: 'exact-count',
        name: 'Exact Count',
        condition: {
          metric: 'active_connections',
          operator: 'eq',
          threshold: 0,
          window: '1m',
        },
        severity: AlertSeverity.CRITICAL,
      });

      alertManager.evaluate({ active_connections: 0 });

      expect(mockNotify).toHaveBeenCalled();
    });
  });

  describe('Alert state management', () => {
    it('should track alert state (firing/resolved)', () => {
      alertManager.registerRule({
        id: 'test-alert',
        name: 'Test Alert',
        condition: {
          metric: 'errors',
          operator: 'gt',
          threshold: 5,
          window: '1m',
        },
        severity: AlertSeverity.WARNING,
      });

      // Fire alert
      alertManager.evaluate({ errors: 10 });
      expect(alertManager.getActiveAlerts()).toHaveLength(1);

      // Resolve alert
      alertManager.evaluate({ errors: 2 });
      expect(alertManager.getActiveAlerts()).toHaveLength(0);
    });

    it('should send resolved notification', () => {
      alertManager.registerRule({
        id: 'test-alert',
        name: 'Test Alert',
        condition: {
          metric: 'errors',
          operator: 'gt',
          threshold: 5,
          window: '1m',
        },
        severity: AlertSeverity.WARNING,
      });

      alertManager.evaluate({ errors: 10 }); // Fire
      alertManager.evaluate({ errors: 2 }); // Resolve

      expect(mockNotify).toHaveBeenLastCalledWith(
        expect.objectContaining({
          status: 'resolved',
        })
      );
    });

    it('should not re-fire already firing alert', () => {
      alertManager.registerRule({
        id: 'test-alert',
        name: 'Test Alert',
        condition: {
          metric: 'errors',
          operator: 'gt',
          threshold: 5,
          window: '1m',
        },
        severity: AlertSeverity.WARNING,
      });

      alertManager.evaluate({ errors: 10 });
      alertManager.evaluate({ errors: 15 }); // Still above threshold

      // Should only notify once (on initial fire)
      expect(mockNotify).toHaveBeenCalledTimes(1);
    });
  });

  describe('Alert metadata', () => {
    it('should include timestamp in alert', () => {
      alertManager.registerRule({
        id: 'test-alert',
        name: 'Test Alert',
        condition: { metric: 'errors', operator: 'gt', threshold: 0, window: '1m' },
        severity: AlertSeverity.WARNING,
      });

      alertManager.evaluate({ errors: 1 });

      expect(mockNotify).toHaveBeenCalledWith(
        expect.objectContaining({
          timestamp: '2024-01-01T12:00:00.000Z',
        })
      );
    });

    it('should include current value in alert', () => {
      alertManager.registerRule({
        id: 'test-alert',
        name: 'Test Alert',
        condition: { metric: 'errors', operator: 'gt', threshold: 5, window: '1m' },
        severity: AlertSeverity.WARNING,
      });

      alertManager.evaluate({ errors: 10 });

      expect(mockNotify).toHaveBeenCalledWith(
        expect.objectContaining({
          value: 10,
          threshold: 5,
        })
      );
    });
  });

  describe('Alert cooldown', () => {
    it('should respect cooldown period', () => {
      alertManager.registerRule({
        id: 'test-alert',
        name: 'Test Alert',
        condition: { metric: 'errors', operator: 'gt', threshold: 5, window: '1m' },
        severity: AlertSeverity.WARNING,
        cooldown: '5m',
      });

      // Fire, resolve, fire again within cooldown
      alertManager.evaluate({ errors: 10 }); // Fire
      alertManager.evaluate({ errors: 2 }); // Resolve
      alertManager.evaluate({ errors: 10 }); // Try to fire again

      // Should only fire once due to cooldown
      expect(mockNotify).toHaveBeenCalledTimes(2); // fire + resolve, no re-fire
    });

    it('should fire again after cooldown expires', () => {
      alertManager.registerRule({
        id: 'test-alert',
        name: 'Test Alert',
        condition: { metric: 'errors', operator: 'gt', threshold: 5, window: '1m' },
        severity: AlertSeverity.WARNING,
        cooldown: '5m',
      });

      alertManager.evaluate({ errors: 10 }); // Fire
      alertManager.evaluate({ errors: 2 }); // Resolve

      // Advance past cooldown
      vi.advanceTimersByTime(6 * 60 * 1000);

      alertManager.evaluate({ errors: 10 }); // Fire again

      expect(mockNotify).toHaveBeenCalledTimes(3); // fire, resolve, fire again
    });
  });

  describe('Predefined alert rules', () => {
    it('should provide common alert rules', () => {
      const rules = alertManager.getPredefinedRules();

      expect(rules).toContainEqual(
        expect.objectContaining({
          id: 'high-threat-rate',
        })
      );
      expect(rules).toContainEqual(
        expect.objectContaining({
          id: 'integration-errors',
        })
      );
    });
  });
});

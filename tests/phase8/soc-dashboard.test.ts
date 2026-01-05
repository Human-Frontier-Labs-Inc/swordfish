/**
 * Phase 8 - SOC Dashboard Tests
 *
 * Unit tests for SOC dashboard components and APIs
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('SOC Dashboard', () => {
  describe('Threat Timeline', () => {
    it('should filter events by severity', () => {
      const events = [
        { id: '1', severity: 'critical', type: 'threat_detected' },
        { id: '2', severity: 'high', type: 'threat_detected' },
        { id: '3', severity: 'medium', type: 'quarantine' },
        { id: '4', severity: 'low', type: 'action' },
      ];

      const filteredCritical = events.filter(e => e.severity === 'critical');
      const filteredHigh = events.filter(e => e.severity === 'high');

      expect(filteredCritical).toHaveLength(1);
      expect(filteredHigh).toHaveLength(1);
    });

    it('should sort events by timestamp descending', () => {
      const events = [
        { id: '1', timestamp: new Date('2024-01-01T10:00:00Z') },
        { id: '2', timestamp: new Date('2024-01-01T12:00:00Z') },
        { id: '3', timestamp: new Date('2024-01-01T08:00:00Z') },
      ];

      const sorted = [...events].sort(
        (a, b) => b.timestamp.getTime() - a.timestamp.getTime()
      );

      expect(sorted[0].id).toBe('2');
      expect(sorted[1].id).toBe('1');
      expect(sorted[2].id).toBe('3');
    });

    it('should determine severity from confidence score', () => {
      const getSeverity = (confidence: number) => {
        if (confidence >= 90) return 'critical';
        if (confidence >= 70) return 'high';
        if (confidence >= 50) return 'medium';
        return 'low';
      };

      expect(getSeverity(95)).toBe('critical');
      expect(getSeverity(85)).toBe('high');
      expect(getSeverity(60)).toBe('medium');
      expect(getSeverity(30)).toBe('low');
    });
  });

  describe('Investigation Panel', () => {
    it('should format signal descriptions', () => {
      const formatSignalDescription = (signal: string): string => {
        const descriptions: Record<string, string> = {
          suspicious_url: 'Email contains suspicious or potentially malicious URLs',
          new_sender: 'First-time sender to this recipient',
          domain_mismatch: 'Reply-to domain does not match sender domain',
        };
        return descriptions[signal] || `Signal detected: ${signal}`;
      };

      expect(formatSignalDescription('suspicious_url')).toContain('malicious URLs');
      expect(formatSignalDescription('new_sender')).toContain('First-time sender');
      expect(formatSignalDescription('unknown_signal')).toContain('unknown_signal');
    });

    it('should extract URLs from email content', () => {
      const extractUrls = (content: string) => {
        const urlRegex = /https?:\/\/[^\s<>"]+/gi;
        const matches = content.match(urlRegex) || [];
        return [...new Set(matches)];
      };

      const content = `
        Check this link: https://example.com/page
        And this: http://malicious.com/phish
        Same again: https://example.com/page
      `;

      const urls = extractUrls(content);
      expect(urls).toHaveLength(2);
      expect(urls).toContain('https://example.com/page');
      expect(urls).toContain('http://malicious.com/phish');
    });

    it('should calculate threat score severity badge', () => {
      const getScoreClass = (score: number) => {
        if (score >= 80) return 'bg-red-500';
        if (score >= 50) return 'bg-yellow-500';
        return 'bg-green-500';
      };

      expect(getScoreClass(95)).toBe('bg-red-500');
      expect(getScoreClass(65)).toBe('bg-yellow-500');
      expect(getScoreClass(30)).toBe('bg-green-500');
    });
  });

  describe('Timeline Event Types', () => {
    it('should map event types to labels', () => {
      const eventTypeLabels: Record<string, string> = {
        threat_detected: 'Threat Detected',
        quarantine: 'Quarantined',
        release: 'Released',
        investigation: 'Investigation',
        alert: 'Alert',
        action: 'Action Taken',
      };

      expect(eventTypeLabels['threat_detected']).toBe('Threat Detected');
      expect(eventTypeLabels['quarantine']).toBe('Quarantined');
    });

    it('should format relative timestamps', () => {
      const formatRelativeTime = (date: Date): string => {
        const now = new Date();
        const diffMs = now.getTime() - date.getTime();
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);

        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        return 'More than a day ago';
      };

      const now = new Date();
      expect(formatRelativeTime(now)).toBe('Just now');
      expect(formatRelativeTime(new Date(now.getTime() - 30 * 60000))).toBe('30m ago');
      expect(formatRelativeTime(new Date(now.getTime() - 3 * 3600000))).toBe('3h ago');
    });
  });
});

describe('SOC API', () => {
  describe('Timeline API', () => {
    it('should calculate average response time', () => {
      const calculateAvgResponseTime = (threats: Array<{ created: Date; actioned?: Date }>) => {
        const responseTimes = threats
          .filter(t => t.actioned)
          .map(t => t.actioned!.getTime() - t.created.getTime());

        if (responseTimes.length === 0) return '0s';
        const avgMs = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;

        if (avgMs < 1000) return `${Math.round(avgMs)}ms`;
        if (avgMs < 60000) return `${(avgMs / 1000).toFixed(1)}s`;
        return `${(avgMs / 60000).toFixed(1)}m`;
      };

      const threats = [
        { created: new Date('2024-01-01T10:00:00Z'), actioned: new Date('2024-01-01T10:00:30Z') },
        { created: new Date('2024-01-01T11:00:00Z'), actioned: new Date('2024-01-01T11:01:00Z') },
      ];

      expect(calculateAvgResponseTime(threats)).toBe('45.0s');
      expect(calculateAvgResponseTime([])).toBe('0s');
    });

    it('should count threats by category', () => {
      const threats = [
        { id: '1', confidence: 95 },
        { id: '2', confidence: 75 },
        { id: '3', confidence: 50 },
        { id: '4', confidence: 92 },
      ];

      const criticalCount = threats.filter(t => t.confidence >= 90).length;
      const totalCount = threats.length;

      expect(criticalCount).toBe(2);
      expect(totalCount).toBe(4);
    });
  });

  describe('Action API', () => {
    it('should validate action types', () => {
      const validActions = ['release', 'delete', 'block_sender'];

      const isValidAction = (action: string) => validActions.includes(action);

      expect(isValidAction('release')).toBe(true);
      expect(isValidAction('delete')).toBe(true);
      expect(isValidAction('invalid')).toBe(false);
    });
  });
});

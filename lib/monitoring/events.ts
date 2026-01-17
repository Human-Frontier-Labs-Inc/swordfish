/**
 * Business Event Tracking Module
 *
 * Tracks domain-specific events for analytics, alerting, and audit trails.
 * Supports buffered emission and event aggregation.
 */

import { nanoid } from 'nanoid';

/**
 * Event types
 */
export const EventType = {
  // Threat events
  THREAT_DETECTED: 'threat.detected',
  THREAT_QUARANTINED: 'threat.quarantined',
  THREAT_RELEASED: 'threat.released',
  THREAT_DELETED: 'threat.deleted',

  // Email events
  EMAIL_SCANNED: 'email.scanned',
  EMAIL_SYNCED: 'email.synced',

  // Integration events
  INTEGRATION_CONNECTED: 'integration.connected',
  INTEGRATION_DISCONNECTED: 'integration.disconnected',
  INTEGRATION_ERROR: 'integration.error',

  // Policy events
  POLICY_CREATED: 'policy.created',
  POLICY_UPDATED: 'policy.updated',
  POLICY_TRIGGERED: 'policy.triggered',
} as const;

export type EventTypeValue = (typeof EventType)[keyof typeof EventType];

/**
 * Base event structure
 */
export interface BaseEvent {
  eventId: string;
  type: EventTypeValue;
  timestamp: string;
  tenantId: string;
  data: Record<string, unknown>;
}

/**
 * Threat event data
 */
export interface ThreatEvent {
  threatId: string;
  tenantId: string;
  severity?: string;
  threatType?: string;
  emailId?: string;
  action?: string;
  releasedBy?: string;
  reason?: string;
}

/**
 * Email event data
 */
export interface EmailEvent {
  emailId?: string;
  tenantId: string;
  integrationId?: string;
  verdict?: string;
  processingTimeMs?: number;
  emailCount?: number;
  threatsFound?: number;
  durationMs?: number;
}

/**
 * Integration event data
 */
export interface IntegrationEvent {
  integrationId: string;
  tenantId: string;
  provider: string;
  email?: string;
  error?: string;
  errorCode?: string;
}

/**
 * Policy event data
 */
export interface PolicyEvent {
  policyId: string;
  tenantId: string;
  emailId?: string;
  action?: string;
  ruleName?: string;
}

/**
 * Event emitter function type
 */
type EventEmitter = (event: BaseEvent) => void;

/**
 * Event tracker configuration
 */
interface EventTrackerConfig {
  emit: EventEmitter;
  bufferSize?: number;
}

/**
 * Event tracker class
 */
export class EventTracker {
  private emit: EventEmitter;
  private buffer: BaseEvent[] = [];
  private bufferSize: number;
  private counts: Record<string, number> = {};

  constructor(config: EventTrackerConfig) {
    this.emit = config.emit;
    this.bufferSize = config.bufferSize || 0;

    // Initialize counts
    for (const type of Object.values(EventType)) {
      this.counts[type] = 0;
    }
  }

  private createEvent(type: EventTypeValue, tenantId: string, data: Record<string, unknown>): BaseEvent {
    return {
      eventId: 'evt_' + nanoid(21),
      type,
      timestamp: new Date().toISOString(),
      tenantId,
      data,
    };
  }

  private track(event: BaseEvent): void {
    this.counts[event.type] = (this.counts[event.type] || 0) + 1;

    if (this.bufferSize > 0) {
      this.buffer.push(event);
      if (this.buffer.length >= this.bufferSize) {
        this.flush();
      }
    } else {
      this.emit(event);
    }
  }

  flush(): void {
    for (const event of this.buffer) {
      this.emit(event);
    }
    this.buffer = [];
  }

  getEventCounts(): Record<string, number> {
    return { ...this.counts };
  }

  resetCounts(): void {
    for (const type of Object.values(EventType)) {
      this.counts[type] = 0;
    }
  }

  trackThreatDetected(data: ThreatEvent): void {
    this.track(this.createEvent(EventType.THREAT_DETECTED, data.tenantId, data as unknown as Record<string, unknown>));
  }

  trackThreatQuarantined(data: ThreatEvent): void {
    this.track(this.createEvent(EventType.THREAT_QUARANTINED, data.tenantId, data as unknown as Record<string, unknown>));
  }

  trackThreatReleased(data: ThreatEvent): void {
    this.track(this.createEvent(EventType.THREAT_RELEASED, data.tenantId, data as unknown as Record<string, unknown>));
  }

  trackThreatDeleted(data: ThreatEvent): void {
    this.track(this.createEvent(EventType.THREAT_DELETED, data.tenantId, data as unknown as Record<string, unknown>));
  }

  trackEmailScanned(data: EmailEvent): void {
    this.track(this.createEvent(EventType.EMAIL_SCANNED, data.tenantId, data as unknown as Record<string, unknown>));
  }

  trackEmailsSynced(data: EmailEvent): void {
    this.track(this.createEvent(EventType.EMAIL_SYNCED, data.tenantId, data as unknown as Record<string, unknown>));
  }

  trackIntegrationConnected(data: IntegrationEvent): void {
    this.track(this.createEvent(EventType.INTEGRATION_CONNECTED, data.tenantId, data as unknown as Record<string, unknown>));
  }

  trackIntegrationDisconnected(data: IntegrationEvent): void {
    this.track(this.createEvent(EventType.INTEGRATION_DISCONNECTED, data.tenantId, data as unknown as Record<string, unknown>));
  }

  trackIntegrationError(data: IntegrationEvent): void {
    this.track(this.createEvent(EventType.INTEGRATION_ERROR, data.tenantId, data as unknown as Record<string, unknown>));
  }

  trackPolicyCreated(data: PolicyEvent): void {
    this.track(this.createEvent(EventType.POLICY_CREATED, data.tenantId, data as unknown as Record<string, unknown>));
  }

  trackPolicyUpdated(data: PolicyEvent): void {
    this.track(this.createEvent(EventType.POLICY_UPDATED, data.tenantId, data as unknown as Record<string, unknown>));
  }

  trackPolicyTriggered(data: PolicyEvent): void {
    this.track(this.createEvent(EventType.POLICY_TRIGGERED, data.tenantId, data as unknown as Record<string, unknown>));
  }
}

export function createEventTracker(config: EventTrackerConfig): EventTracker {
  return new EventTracker(config);
}

export const consoleEmitter: EventEmitter = (event) => {
  console.log(JSON.stringify(event));
};

export const defaultEventTracker = createEventTracker({ emit: consoleEmitter });

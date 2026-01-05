/**
 * Splunk Integration
 *
 * Sends security events to Splunk using CEF (Common Event Format)
 * and HEC (HTTP Event Collector)
 */

import { sql } from '@/lib/db';
import { nanoid } from 'nanoid';

export interface SplunkConfig {
  id: string;
  tenantId: string;
  name: string;
  hecUrl: string;
  hecToken: string;
  index: string;
  source: string;
  sourceType: string;
  isActive: boolean;
  eventTypes: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface CEFEvent {
  version: string;
  deviceVendor: string;
  deviceProduct: string;
  deviceVersion: string;
  signatureId: string;
  name: string;
  severity: number;
  extensions: Record<string, string | number>;
}

// CEF severity mapping
const SEVERITY_MAP: Record<string, number> = {
  info: 0,
  low: 3,
  medium: 5,
  high: 7,
  critical: 10,
};

/**
 * Build CEF formatted event string
 */
export function buildCEFEvent(event: CEFEvent): string {
  // CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
  const header = [
    `CEF:${event.version}`,
    escapeField(event.deviceVendor),
    escapeField(event.deviceProduct),
    escapeField(event.deviceVersion),
    escapeField(event.signatureId),
    escapeField(event.name),
    event.severity.toString(),
  ].join('|');

  // Build extension string
  const extensions = Object.entries(event.extensions)
    .map(([key, value]) => `${key}=${escapeExtension(String(value))}`)
    .join(' ');

  return `${header}|${extensions}`;
}

/**
 * Escape CEF header field
 */
function escapeField(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|');
}

/**
 * Escape CEF extension value
 */
function escapeExtension(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/=/g, '\\=')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

/**
 * Convert threat event to CEF format
 */
export function threatToCEF(threat: Record<string, unknown>): CEFEvent {
  const severity = SEVERITY_MAP[threat.severity as string] || SEVERITY_MAP.medium;

  return {
    version: '0',
    deviceVendor: 'Swordfish',
    deviceProduct: 'Email Security',
    deviceVersion: '1.0',
    signatureId: threat.verdict as string || 'unknown',
    name: `Email Threat: ${threat.verdict}`,
    severity,
    extensions: {
      src: threat.fromAddress as string || '',
      dst: Array.isArray(threat.toAddresses) ? threat.toAddresses.join(',') : '',
      msg: threat.subject as string || '',
      cs1: threat.id as string || '',
      cs1Label: 'ThreatID',
      cs2: threat.verdictReason as string || '',
      cs2Label: 'Reason',
      cn1: threat.confidence as number || 0,
      cn1Label: 'Confidence',
      act: threat.actionTaken as string || 'none',
      rt: new Date(threat.receivedAt as string || Date.now()).getTime(),
      externalId: threat.messageId as string || '',
    },
  };
}

/**
 * Convert policy event to CEF format
 */
export function policyToCEF(
  action: 'created' | 'updated' | 'deleted',
  policy: Record<string, unknown>
): CEFEvent {
  return {
    version: '0',
    deviceVendor: 'Swordfish',
    deviceProduct: 'Email Security',
    deviceVersion: '1.0',
    signatureId: `policy.${action}`,
    name: `Policy ${action}`,
    severity: 3,
    extensions: {
      cs1: policy.id as string || '',
      cs1Label: 'PolicyID',
      cs2: policy.type as string || '',
      cs2Label: 'PolicyType',
      cs3: policy.target as string || '',
      cs3Label: 'Target',
      cs4: policy.value as string || '',
      cs4Label: 'Value',
      act: policy.action as string || '',
      rt: Date.now(),
    },
  };
}

/**
 * Convert quarantine event to CEF format
 */
export function quarantineToCEF(
  action: 'added' | 'released' | 'deleted' | 'expired',
  item: Record<string, unknown>
): CEFEvent {
  return {
    version: '0',
    deviceVendor: 'Swordfish',
    deviceProduct: 'Email Security',
    deviceVersion: '1.0',
    signatureId: `quarantine.${action}`,
    name: `Quarantine ${action}`,
    severity: action === 'added' ? 5 : 3,
    extensions: {
      cs1: item.id as string || '',
      cs1Label: 'QuarantineID',
      cs2: item.verdictId as string || '',
      cs2Label: 'ThreatID',
      act: action,
      rt: Date.now(),
    },
  };
}

/**
 * Send event to Splunk HEC
 */
export async function sendToSplunk(
  config: SplunkConfig,
  cefEvent: CEFEvent
): Promise<{ success: boolean; error?: string }> {
  const cefString = buildCEFEvent(cefEvent);

  const payload = {
    event: cefString,
    source: config.source,
    sourcetype: config.sourceType,
    index: config.index,
    time: Date.now() / 1000,
  };

  try {
    const response = await fetch(config.hecUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Splunk ${config.hecToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const text = await response.text();
      return { success: false, error: `Splunk HEC error: ${response.status} - ${text}` };
    }

    return { success: true };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Send batch of events to Splunk HEC
 */
export async function sendBatchToSplunk(
  config: SplunkConfig,
  events: CEFEvent[]
): Promise<{ success: boolean; sent: number; failed: number; errors: string[] }> {
  const results = await Promise.all(
    events.map((event) => sendToSplunk(config, event))
  );

  const sent = results.filter((r) => r.success).length;
  const failed = results.filter((r) => !r.success).length;
  const errors = results.filter((r) => r.error).map((r) => r.error!);

  return { success: failed === 0, sent, failed, errors };
}

/**
 * Get Splunk config for tenant
 */
export async function getSplunkConfig(tenantId: string): Promise<SplunkConfig | null> {
  const result = await sql`
    SELECT * FROM splunk_integrations
    WHERE tenant_id = ${tenantId} AND is_active = true
    LIMIT 1
  `;

  if (result.length === 0) return null;

  const row = result[0];
  return {
    id: row.id as string,
    tenantId: row.tenant_id as string,
    name: row.name as string,
    hecUrl: row.hec_url as string,
    hecToken: row.hec_token as string,
    index: row.index_name as string,
    source: row.source_name as string,
    sourceType: row.source_type as string,
    isActive: row.is_active as boolean,
    eventTypes: row.event_types as string[],
    createdAt: row.created_at as Date,
    updatedAt: row.updated_at as Date,
  };
}

/**
 * Dispatch threat event to Splunk
 */
export async function dispatchThreatToSplunk(
  tenantId: string,
  threat: Record<string, unknown>
): Promise<void> {
  const config = await getSplunkConfig(tenantId);
  if (!config || !config.eventTypes.includes('threat')) return;

  const cefEvent = threatToCEF(threat);
  const result = await sendToSplunk(config, cefEvent);

  // Log the delivery
  await sql`
    INSERT INTO splunk_deliveries (id, integration_id, tenant_id, event_type, cef_event, success, error, created_at)
    VALUES (
      ${nanoid()},
      ${config.id},
      ${tenantId},
      'threat',
      ${buildCEFEvent(cefEvent)},
      ${result.success},
      ${result.error || null},
      NOW()
    )
  `;
}

/**
 * Dispatch policy event to Splunk
 */
export async function dispatchPolicyToSplunk(
  tenantId: string,
  action: 'created' | 'updated' | 'deleted',
  policy: Record<string, unknown>
): Promise<void> {
  const config = await getSplunkConfig(tenantId);
  if (!config || !config.eventTypes.includes('policy')) return;

  const cefEvent = policyToCEF(action, policy);
  const result = await sendToSplunk(config, cefEvent);

  await sql`
    INSERT INTO splunk_deliveries (id, integration_id, tenant_id, event_type, cef_event, success, error, created_at)
    VALUES (
      ${nanoid()},
      ${config.id},
      ${tenantId},
      'policy',
      ${buildCEFEvent(cefEvent)},
      ${result.success},
      ${result.error || null},
      NOW()
    )
  `;
}

/**
 * Dispatch quarantine event to Splunk
 */
export async function dispatchQuarantineToSplunk(
  tenantId: string,
  action: 'added' | 'released' | 'deleted' | 'expired',
  item: Record<string, unknown>
): Promise<void> {
  const config = await getSplunkConfig(tenantId);
  if (!config || !config.eventTypes.includes('quarantine')) return;

  const cefEvent = quarantineToCEF(action, item);
  const result = await sendToSplunk(config, cefEvent);

  await sql`
    INSERT INTO splunk_deliveries (id, integration_id, tenant_id, event_type, cef_event, success, error, created_at)
    VALUES (
      ${nanoid()},
      ${config.id},
      ${tenantId},
      'quarantine',
      ${buildCEFEvent(cefEvent)},
      ${result.success},
      ${result.error || null},
      NOW()
    )
  `;
}

/**
 * Test Splunk connection
 */
export async function testSplunkConnection(config: SplunkConfig): Promise<{ success: boolean; error?: string }> {
  const testEvent: CEFEvent = {
    version: '0',
    deviceVendor: 'Swordfish',
    deviceProduct: 'Email Security',
    deviceVersion: '1.0',
    signatureId: 'test',
    name: 'Connection Test',
    severity: 0,
    extensions: {
      msg: 'Swordfish connection test event',
      rt: Date.now(),
    },
  };

  return sendToSplunk(config, testEvent);
}

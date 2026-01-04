/**
 * Policy Evaluation Engine
 * Evaluates emails against tenant policies
 */

import type { ParsedEmail } from '@/lib/detection/types';
import type {
  Policy,
  PolicyRule,
  PolicyCondition,
  PolicyEvaluationResult,
  ListEntry,
  ConditionField,
} from './types';
import { sql } from '@/lib/db';

/**
 * Evaluate an email against all tenant policies
 * Returns the first matching policy result (based on priority)
 */
export async function evaluatePolicies(
  email: ParsedEmail,
  tenantId: string,
  options?: {
    skipAllowlists?: boolean;
    skipBlocklists?: boolean;
    threatScore?: number;
  }
): Promise<PolicyEvaluationResult> {
  // First check allowlists (highest priority)
  if (!options?.skipAllowlists) {
    const allowlistResult = await checkAllowlist(email, tenantId);
    if (allowlistResult.matched) {
      return allowlistResult;
    }
  }

  // Then check blocklists
  if (!options?.skipBlocklists) {
    const blocklistResult = await checkBlocklist(email, tenantId);
    if (blocklistResult.matched) {
      return blocklistResult;
    }
  }

  // Load active policies ordered by priority
  const policies = await getActivePolicies(tenantId);

  // Evaluate each policy
  for (const policy of policies) {
    const result = evaluatePolicy(email, policy, options?.threatScore);
    if (result.matched) {
      return result;
    }
  }

  // No policy matched
  return { matched: false };
}

/**
 * Check if sender is in allowlist
 */
async function checkAllowlist(
  email: ParsedEmail,
  tenantId: string
): Promise<PolicyEvaluationResult> {
  const senderEmail = email.from.address.toLowerCase();
  const senderDomain = senderEmail.split('@')[1];

  const entries = await sql`
    SELECT * FROM list_entries
    WHERE tenant_id = ${tenantId}
    AND list_type = 'allowlist'
    AND (expires_at IS NULL OR expires_at > NOW())
    AND (
      (entry_type = 'email' AND LOWER(value) = ${senderEmail})
      OR (entry_type = 'domain' AND LOWER(value) = ${senderDomain})
    )
    LIMIT 1
  ` as ListEntry[];

  if (entries.length > 0) {
    return {
      matched: true,
      action: 'allow',
      reason: `Sender ${entries[0].entryType === 'email' ? 'email' : 'domain'} is in allowlist: ${entries[0].value}`,
    };
  }

  return { matched: false };
}

/**
 * Check if sender is in blocklist
 */
async function checkBlocklist(
  email: ParsedEmail,
  tenantId: string
): Promise<PolicyEvaluationResult> {
  const senderEmail = email.from.address.toLowerCase();
  const senderDomain = senderEmail.split('@')[1];

  const entries = await sql`
    SELECT * FROM list_entries
    WHERE tenant_id = ${tenantId}
    AND list_type = 'blocklist'
    AND (expires_at IS NULL OR expires_at > NOW())
    AND (
      (entry_type = 'email' AND LOWER(value) = ${senderEmail})
      OR (entry_type = 'domain' AND LOWER(value) = ${senderDomain})
    )
    LIMIT 1
  ` as ListEntry[];

  if (entries.length > 0) {
    return {
      matched: true,
      action: 'block',
      reason: `Sender ${entries[0].entryType === 'email' ? 'email' : 'domain'} is in blocklist: ${entries[0].value}`,
    };
  }

  return { matched: false };
}

/**
 * Get active policies for a tenant, ordered by priority
 */
async function getActivePolicies(tenantId: string): Promise<Policy[]> {
  const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };

  const results = await sql`
    SELECT * FROM policies
    WHERE tenant_id = ${tenantId}
    AND status = 'active'
    ORDER BY
      CASE priority
        WHEN 'critical' THEN 0
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 3
      END,
      created_at ASC
  `;

  return results.map((r: Record<string, unknown>) => ({
    id: r.id as string,
    tenantId: r.tenant_id as string,
    name: r.name as string,
    description: r.description as string,
    type: r.type as Policy['type'],
    status: r.status as Policy['status'],
    priority: r.priority as Policy['priority'],
    rules: (r.rules as PolicyRule[]) || [],
    scope: r.scope as Policy['scope'],
    createdAt: r.created_at as Date,
    updatedAt: r.updated_at as Date,
    createdBy: r.created_by as string,
  }));
}

/**
 * Evaluate a single policy against an email
 */
function evaluatePolicy(
  email: ParsedEmail,
  policy: Policy,
  threatScore?: number
): PolicyEvaluationResult {
  // Check each rule in order
  for (const rule of policy.rules) {
    if (!rule.enabled) continue;

    const ruleMatches = evaluateRule(email, rule, threatScore);
    if (ruleMatches) {
      return {
        matched: true,
        policyId: policy.id,
        policyName: policy.name,
        ruleId: rule.id,
        ruleName: rule.name,
        action: rule.action,
        actionParams: rule.actionParams,
        reason: `Matched policy "${policy.name}" rule "${rule.name}"`,
      };
    }
  }

  return { matched: false };
}

/**
 * Evaluate a single rule against an email
 */
function evaluateRule(
  email: ParsedEmail,
  rule: PolicyRule,
  threatScore?: number
): boolean {
  const { conditions, conditionLogic } = rule;

  if (conditions.length === 0) {
    return false;
  }

  const results = conditions.map((condition) =>
    evaluateCondition(email, condition, threatScore)
  );

  if (conditionLogic === 'and') {
    return results.every((r) => r);
  } else {
    return results.some((r) => r);
  }
}

/**
 * Evaluate a single condition
 */
function evaluateCondition(
  email: ParsedEmail,
  condition: PolicyCondition,
  threatScore?: number
): boolean {
  const fieldValue = getFieldValue(email, condition.field, condition.headerName, threatScore);
  const { operator, value } = condition;

  // Handle null/undefined field values
  if (fieldValue === null || fieldValue === undefined) {
    return operator === 'not_equals' || operator === 'not_contains' || operator === 'not_in_list';
  }

  const fieldStr = String(fieldValue).toLowerCase();
  const valueStr = typeof value === 'string' ? value.toLowerCase() : value;

  switch (operator) {
    case 'equals':
      return fieldStr === String(valueStr).toLowerCase();

    case 'not_equals':
      return fieldStr !== String(valueStr).toLowerCase();

    case 'contains':
      return fieldStr.includes(String(valueStr).toLowerCase());

    case 'not_contains':
      return !fieldStr.includes(String(valueStr).toLowerCase());

    case 'starts_with':
      return fieldStr.startsWith(String(valueStr).toLowerCase());

    case 'ends_with':
      return fieldStr.endsWith(String(valueStr).toLowerCase());

    case 'matches_regex':
      try {
        const regex = new RegExp(String(value), 'i');
        return regex.test(fieldStr);
      } catch {
        return false;
      }

    case 'in_list':
      if (Array.isArray(value)) {
        return value.some((v) => String(v).toLowerCase() === fieldStr);
      }
      return false;

    case 'not_in_list':
      if (Array.isArray(value)) {
        return !value.some((v) => String(v).toLowerCase() === fieldStr);
      }
      return true;

    case 'greater_than':
      return Number(fieldValue) > Number(value);

    case 'less_than':
      return Number(fieldValue) < Number(value);

    case 'between':
      if (Array.isArray(value) && value.length === 2) {
        const num = Number(fieldValue);
        return num >= Number(value[0]) && num <= Number(value[1]);
      }
      return false;

    default:
      return false;
  }
}

/**
 * Extract field value from email
 */
function getFieldValue(
  email: ParsedEmail,
  field: ConditionField,
  headerName?: string,
  threatScore?: number
): string | number | boolean | null {
  switch (field) {
    case 'sender_email':
      return email.from.address;

    case 'sender_domain':
      return email.from.address.split('@')[1] || '';

    case 'sender_name':
      return email.from.displayName || '';

    case 'recipient_email':
      return email.to[0]?.address || '';

    case 'recipient_domain':
      return email.to[0]?.address?.split('@')[1] || '';

    case 'subject':
      return email.subject;

    case 'body_text':
      return email.body.text || '';

    case 'body_html':
      return email.body.html || '';

    case 'attachment_name':
      return email.attachments.map((a) => a.filename).join(',');

    case 'attachment_type':
      return email.attachments.map((a) => a.contentType).join(',');

    case 'attachment_count':
      return email.attachments.length;

    case 'has_attachments':
      return email.attachments.length > 0;

    case 'has_links':
      const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
      return urlRegex.test(email.body.text || '') || urlRegex.test(email.body.html || '');

    case 'link_domain':
      const linkRegex = /https?:\/\/([^\/\s<>"{}|\\^`[\]]+)/gi;
      const matches = [...((email.body.text || '') + (email.body.html || '')).matchAll(linkRegex)];
      return matches.map((m) => m[1]).join(',');

    case 'spf_result':
      return email.headers['received-spf'] || email.headers['authentication-results'] || '';

    case 'dkim_result':
      return email.headers['dkim-signature'] ? 'pass' : 'none';

    case 'dmarc_result':
      const authResults = email.headers['authentication-results'] || '';
      if (authResults.includes('dmarc=pass')) return 'pass';
      if (authResults.includes('dmarc=fail')) return 'fail';
      return 'none';

    case 'threat_score':
      return threatScore ?? 0;

    case 'header':
      if (headerName) {
        return email.headers[headerName.toLowerCase()] || null;
      }
      return null;

    case 'ip_address':
      // Extract from Received header
      const received = email.headers['received'] || '';
      const ipMatch = received.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
      return ipMatch ? ipMatch[1] : null;

    case 'country':
      // Would need GeoIP lookup - return null for now
      return null;

    default:
      return null;
  }
}

/**
 * Create default policies for a new tenant
 */
export async function createDefaultPolicies(
  tenantId: string,
  createdBy: string
): Promise<void> {
  const { DEFAULT_POLICIES } = await import('./types');

  for (const policyTemplate of DEFAULT_POLICIES) {
    await sql`
      INSERT INTO policies (
        tenant_id, name, description, type, status, priority, rules, created_by
      ) VALUES (
        ${tenantId},
        ${policyTemplate.name},
        ${policyTemplate.description || null},
        ${policyTemplate.type},
        ${policyTemplate.status},
        ${policyTemplate.priority},
        ${JSON.stringify(policyTemplate.rules)}::jsonb,
        ${createdBy}
      )
    `;
  }
}

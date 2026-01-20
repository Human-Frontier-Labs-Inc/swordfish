/**
 * API Request Validation Schemas
 *
 * Zod schemas for validating API request bodies.
 * All API endpoints should use these schemas.
 */

import { z } from 'zod';

// ============================================================================
// Base Types
// ============================================================================

/**
 * Email address schema with length and format validation
 */
export const emailSchema = z
  .string()
  .transform((val) => val.trim().toLowerCase())
  .pipe(z.string().email('Invalid email format').max(254, 'Email too long'));

/**
 * Domain schema with format validation
 */
export const domainSchema = z
  .string()
  .min(1, 'Domain is required')
  .max(253, 'Domain too long')
  .regex(
    /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+$/,
    'Invalid domain format'
  )
  .transform((val) => val.toLowerCase().trim());

/**
 * URL schema with protocol validation
 */
export const urlSchema = z
  .string()
  .url('Invalid URL format')
  .refine((url) => {
    const lower = url.toLowerCase();
    return lower.startsWith('https://') || lower.startsWith('http://');
  }, 'URL must use http or https protocol')
  .refine((url) => {
    const lower = url.toLowerCase();
    const dangerous = ['javascript:', 'data:', 'vbscript:', 'file:'];
    return !dangerous.some((d) => lower.includes(d));
  }, 'URL contains dangerous protocol');

/**
 * Secure webhook URL schema (HTTPS only, no SSRF)
 */
export const webhookUrlSchema = z
  .string()
  .url('Invalid URL format')
  .refine((url) => url.toLowerCase().startsWith('https://'), 'Webhook URL must use HTTPS')
  .refine((url) => {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      const blocked = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254'];
      const privateRanges = ['192.168.', '10.', '172.16.', '172.17.', '172.18.'];
      if (blocked.includes(hostname)) return false;
      if (privateRanges.some((r) => hostname.startsWith(r))) return false;
      return true;
    } catch {
      return false;
    }
  }, 'Webhook URL cannot point to internal addresses');

/**
 * UUID schema
 */
export const uuidSchema = z.string().uuid('Invalid UUID format');

/**
 * Tenant ID schema (supports org_xxx, personal_xxx formats)
 */
export const tenantIdSchema = z
  .string()
  .min(1, 'Tenant ID is required')
  .max(255, 'Tenant ID too long')
  .refine((id) => !id.includes('<') && !id.includes('>'), 'Invalid characters in tenant ID');

/**
 * Pagination schema
 */
export const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce
    .number()
    .int()
    .min(1)
    .default(20)
    .transform((val) => Math.min(val, 100)),
});

// ============================================================================
// Threat Schemas
// ============================================================================

/**
 * Threat status enum
 */
export const threatStatusSchema = z.enum([
  'detected',
  'quarantined',
  'released',
  'deleted',
  'false_positive',
  'pending_review',
]);

/**
 * Threat verdict enum
 */
export const threatVerdictSchema = z.enum(['pass', 'quarantine', 'block', 'review']);

/**
 * Get threats query parameters
 */
export const getThreatsQuerySchema = paginationSchema.extend({
  status: threatStatusSchema.optional(),
  verdict: threatVerdictSchema.optional(),
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
  search: z.string().max(200).optional(),
});

/**
 * Update threat status
 */
export const updateThreatSchema = z.object({
  status: threatStatusSchema,
  reason: z.string().max(500).optional(),
});

/**
 * Threat action (release, delete, etc.)
 */
export const threatActionSchema = z.object({
  action: z.enum(['release', 'delete', 'mark_false_positive', 'block_sender']),
  threatId: uuidSchema,
  reason: z.string().max(500).optional(),
});

// ============================================================================
// Policy Schemas
// ============================================================================

/**
 * Policy rule action
 */
export const policyActionSchema = z.enum([
  'allow',
  'block',
  'quarantine',
  'flag',
  'notify',
]);

/**
 * Policy rule condition
 */
export const policyConditionSchema = z.object({
  field: z.enum([
    'sender_domain',
    'sender_email',
    'subject',
    'attachment_type',
    'attachment_size',
    'link_count',
    'external_links',
    'threat_score',
  ]),
  operator: z.enum(['equals', 'contains', 'starts_with', 'ends_with', 'greater_than', 'less_than', 'regex']),
  value: z.union([z.string().max(500), z.number()]),
});

/**
 * Policy rule
 */
export const policyRuleSchema = z.object({
  id: z.string().optional(),
  name: z.string().min(1).max(100),
  conditions: z.array(policyConditionSchema).min(1).max(10),
  action: policyActionSchema,
  priority: z.number().int().min(0).max(1000).default(100),
  enabled: z.boolean().default(true),
});

/**
 * Create policy request
 */
export const createPolicySchema = z.object({
  name: z.string().min(1, 'Policy name is required').max(100),
  description: z.string().max(500).optional(),
  rules: z.array(policyRuleSchema).min(1, 'At least one rule is required').max(50),
  scope: z.enum(['all', 'inbound', 'outbound']).default('all'),
  status: z.enum(['active', 'draft', 'disabled']).default('draft'),
});

/**
 * Update policy request
 */
export const updatePolicySchema = createPolicySchema.partial();

// ============================================================================
// Integration Schemas
// ============================================================================

/**
 * Integration type enum
 */
export const integrationTypeSchema = z.enum(['gmail', 'o365']);

/**
 * Create integration (connect email provider)
 */
export const createIntegrationSchema = z.object({
  type: integrationTypeSchema,
  email: emailSchema.optional(),
  config: z
    .object({
      syncEnabled: z.boolean().default(true),
      autoRemediate: z.boolean().default(false),
      notifyOnThreat: z.boolean().default(true),
    })
    .optional(),
});

/**
 * Update integration config
 */
export const updateIntegrationSchema = z.object({
  config: z.object({
    syncEnabled: z.boolean().optional(),
    autoRemediate: z.boolean().optional(),
    notifyOnThreat: z.boolean().optional(),
  }),
});

// ============================================================================
// Webhook Schemas
// ============================================================================

/**
 * Create webhook subscription
 */
export const createWebhookSchema = z.object({
  url: webhookUrlSchema,
  events: z.array(z.enum(['threat.detected', 'threat.quarantined', 'threat.released', 'sync.completed'])).min(1),
  secret: z.string().min(16).max(128).optional(),
  enabled: z.boolean().default(true),
});

/**
 * Update webhook
 */
export const updateWebhookSchema = createWebhookSchema.partial();

// ============================================================================
// List Entry Schemas (Allow/Block lists)
// ============================================================================

/**
 * List type enum
 */
export const listTypeSchema = z.enum(['allow', 'block']);

/**
 * List entry type enum
 */
export const listEntryTypeSchema = z.enum(['email', 'domain', 'ip']);

/**
 * Create list entry
 */
export const createListEntrySchema = z.object({
  listType: listTypeSchema,
  entryType: listEntryTypeSchema,
  value: z.string().min(1).max(255),
  reason: z.string().max(500).optional(),
  expiresAt: z.coerce.date().optional(),
});

/**
 * Batch create list entries
 */
export const batchCreateListEntriesSchema = z.object({
  listType: listTypeSchema,
  entryType: listEntryTypeSchema,
  values: z.array(z.string().min(1).max(255)).min(1).max(100),
  reason: z.string().max(500).optional(),
});

// ============================================================================
// Notification Schemas
// ============================================================================

/**
 * Notification preferences
 */
export const notificationPreferencesSchema = z.object({
  emailOnThreat: z.boolean().default(true),
  emailOnQuarantine: z.boolean().default(true),
  emailDigest: z.enum(['never', 'daily', 'weekly']).default('daily'),
  slackWebhook: webhookUrlSchema.optional().nullable(),
});

// ============================================================================
// Feedback Schemas
// ============================================================================

/**
 * Submit threat feedback (for ML training)
 */
export const submitFeedbackSchema = z.object({
  threatId: uuidSchema,
  feedback: z.enum(['correct', 'false_positive', 'missed_threat']),
  notes: z.string().max(1000).optional(),
});

// ============================================================================
// Search Schema
// ============================================================================

/**
 * Global search query
 */
export const searchQuerySchema = z.object({
  q: z.string().min(1).max(200),
  type: z.enum(['threats', 'emails', 'policies', 'all']).default('all'),
  ...paginationSchema.shape,
});

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Validate request body against a schema
 * @throws ValidationError with details if invalid
 */
export function validateBody<T extends z.ZodSchema>(
  schema: T,
  body: unknown
): z.infer<T> {
  const result = schema.safeParse(body);

  if (!result.success) {
    const errors = result.error.errors.map((e) => ({
      field: e.path.join('.'),
      message: e.message,
    }));

    throw new ValidationError('Validation failed', errors);
  }

  return result.data;
}

/**
 * Custom validation error for API responses
 */
export class ValidationError extends Error {
  errors: Array<{ field: string; message: string }>;
  statusCode = 400;

  constructor(message: string, errors: Array<{ field: string; message: string }>) {
    super(message);
    this.name = 'ValidationError';
    this.errors = errors;
  }

  toJSON() {
    return {
      error: this.message,
      details: this.errors,
    };
  }
}

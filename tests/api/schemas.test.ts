/**
 * API Schema Validation Tests
 * TDD tests for Zod-based API request validation
 */

import { describe, it, expect } from 'vitest';
import {
  emailSchema,
  domainSchema,
  urlSchema,
  webhookUrlSchema,
  tenantIdSchema,
  paginationSchema,
  threatStatusSchema,
  getThreatsQuerySchema,
  updateThreatSchema,
  threatActionSchema,
  createPolicySchema,
  policyRuleSchema,
  createIntegrationSchema,
  createWebhookSchema,
  createListEntrySchema,
  batchCreateListEntriesSchema,
  submitFeedbackSchema,
  searchQuerySchema,
  validateBody,
  ValidationError,
} from '@/lib/api/schemas';

describe('API Schema Validation', () => {
  describe('Base Schemas', () => {
    describe('emailSchema', () => {
      it('should accept valid emails', () => {
        expect(emailSchema.parse('user@example.com')).toBe('user@example.com');
        expect(emailSchema.parse('User@Example.COM')).toBe('user@example.com'); // lowercase
        expect(emailSchema.parse('  user@example.com  ')).toBe('user@example.com'); // trim
      });

      it('should reject invalid emails', () => {
        expect(() => emailSchema.parse('notanemail')).toThrow();
        expect(() => emailSchema.parse('')).toThrow();
        expect(() => emailSchema.parse('@example.com')).toThrow();
      });

      it('should reject emails exceeding max length', () => {
        const longEmail = 'a'.repeat(250) + '@example.com';
        expect(() => emailSchema.parse(longEmail)).toThrow();
      });
    });

    describe('domainSchema', () => {
      it('should accept valid domains', () => {
        expect(domainSchema.parse('example.com')).toBe('example.com');
        expect(domainSchema.parse('sub.example.com')).toBe('sub.example.com');
        expect(domainSchema.parse('EXAMPLE.COM')).toBe('example.com'); // lowercase
      });

      it('should reject invalid domains', () => {
        expect(() => domainSchema.parse('')).toThrow();
        expect(() => domainSchema.parse('notadomain')).toThrow();
        expect(() => domainSchema.parse('-example.com')).toThrow();
      });
    });

    describe('urlSchema', () => {
      it('should accept valid URLs', () => {
        expect(urlSchema.parse('https://example.com')).toBe('https://example.com');
        expect(urlSchema.parse('http://example.com/path')).toBe('http://example.com/path');
      });

      it('should reject dangerous URLs', () => {
        expect(() => urlSchema.parse('javascript:alert(1)')).toThrow();
        expect(() => urlSchema.parse('data:text/html,<script>')).toThrow();
        expect(() => urlSchema.parse('file:///etc/passwd')).toThrow();
      });

      it('should reject non-http protocols', () => {
        expect(() => urlSchema.parse('ftp://example.com')).toThrow();
      });
    });

    describe('webhookUrlSchema', () => {
      it('should accept HTTPS URLs', () => {
        expect(webhookUrlSchema.parse('https://example.com/webhook')).toBe('https://example.com/webhook');
      });

      it('should reject HTTP URLs', () => {
        expect(() => webhookUrlSchema.parse('http://example.com/webhook')).toThrow();
      });

      it('should reject localhost and internal IPs', () => {
        expect(() => webhookUrlSchema.parse('https://localhost/webhook')).toThrow();
        expect(() => webhookUrlSchema.parse('https://127.0.0.1/webhook')).toThrow();
        expect(() => webhookUrlSchema.parse('https://192.168.1.1/webhook')).toThrow();
        expect(() => webhookUrlSchema.parse('https://169.254.169.254/webhook')).toThrow();
      });
    });

    describe('tenantIdSchema', () => {
      it('should accept valid tenant IDs', () => {
        expect(tenantIdSchema.parse('org_abc123')).toBe('org_abc123');
        expect(tenantIdSchema.parse('personal_user123')).toBe('personal_user123');
      });

      it('should reject invalid characters', () => {
        expect(() => tenantIdSchema.parse('tenant<script>')).toThrow();
        expect(() => tenantIdSchema.parse('tenant>xss')).toThrow();
      });
    });

    describe('paginationSchema', () => {
      it('should parse valid pagination params', () => {
        const result = paginationSchema.parse({ page: 2, limit: 50 });
        expect(result.page).toBe(2);
        expect(result.limit).toBe(50);
      });

      it('should use defaults for missing values', () => {
        const result = paginationSchema.parse({});
        expect(result.page).toBe(1);
        expect(result.limit).toBe(20);
      });

      it('should coerce string values', () => {
        const result = paginationSchema.parse({ page: '3', limit: '25' });
        expect(result.page).toBe(3);
        expect(result.limit).toBe(25);
      });

      it('should enforce maximum limit', () => {
        const result = paginationSchema.parse({ limit: 500 });
        expect(result.limit).toBe(100); // capped at max
      });

      it('should enforce minimum values', () => {
        expect(() => paginationSchema.parse({ page: 0 })).toThrow();
        expect(() => paginationSchema.parse({ limit: 0 })).toThrow();
      });
    });
  });

  describe('Threat Schemas', () => {
    describe('threatStatusSchema', () => {
      it('should accept valid statuses', () => {
        const validStatuses = ['detected', 'quarantined', 'released', 'deleted', 'false_positive', 'pending_review'];
        for (const status of validStatuses) {
          expect(threatStatusSchema.parse(status)).toBe(status);
        }
      });

      it('should reject invalid statuses', () => {
        expect(() => threatStatusSchema.parse('invalid')).toThrow();
      });
    });

    describe('getThreatsQuerySchema', () => {
      it('should parse valid query params', () => {
        const result = getThreatsQuerySchema.parse({
          page: 1,
          limit: 10,
          status: 'quarantined',
          search: 'phishing',
        });

        expect(result.page).toBe(1);
        expect(result.status).toBe('quarantined');
        expect(result.search).toBe('phishing');
      });

      it('should parse date filters', () => {
        const result = getThreatsQuerySchema.parse({
          from: '2024-01-01',
          to: '2024-12-31',
        });

        expect(result.from).toBeInstanceOf(Date);
        expect(result.to).toBeInstanceOf(Date);
      });
    });

    describe('updateThreatSchema', () => {
      it('should validate status update', () => {
        const result = updateThreatSchema.parse({
          status: 'released',
          reason: 'False positive confirmed',
        });

        expect(result.status).toBe('released');
        expect(result.reason).toBe('False positive confirmed');
      });

      it('should reject invalid status', () => {
        expect(() => updateThreatSchema.parse({ status: 'invalid' })).toThrow();
      });
    });

    describe('threatActionSchema', () => {
      it('should validate threat actions', () => {
        const result = threatActionSchema.parse({
          action: 'release',
          threatId: '550e8400-e29b-41d4-a716-446655440000',
          reason: 'User requested',
        });

        expect(result.action).toBe('release');
      });

      it('should require valid UUID', () => {
        expect(() =>
          threatActionSchema.parse({
            action: 'release',
            threatId: 'not-a-uuid',
          })
        ).toThrow();
      });
    });
  });

  describe('Policy Schemas', () => {
    describe('policyRuleSchema', () => {
      it('should validate a policy rule', () => {
        const rule = policyRuleSchema.parse({
          name: 'Block phishing domains',
          conditions: [
            { field: 'sender_domain', operator: 'contains', value: 'phishing' },
          ],
          action: 'block',
        });

        expect(rule.name).toBe('Block phishing domains');
        expect(rule.action).toBe('block');
        expect(rule.enabled).toBe(true); // default
      });

      it('should require at least one condition', () => {
        expect(() =>
          policyRuleSchema.parse({
            name: 'Empty rule',
            conditions: [],
            action: 'block',
          })
        ).toThrow();
      });
    });

    describe('createPolicySchema', () => {
      it('should validate a complete policy', () => {
        const policy = createPolicySchema.parse({
          name: 'Anti-phishing policy',
          description: 'Blocks known phishing domains',
          rules: [
            {
              name: 'Block suspicious',
              conditions: [{ field: 'threat_score', operator: 'greater_than', value: 80 }],
              action: 'quarantine',
            },
          ],
          scope: 'inbound',
          status: 'active',
        });

        expect(policy.name).toBe('Anti-phishing policy');
        expect(policy.rules).toHaveLength(1);
      });

      it('should require at least one rule', () => {
        expect(() =>
          createPolicySchema.parse({
            name: 'Empty policy',
            rules: [],
          })
        ).toThrow();
      });

      it('should reject names exceeding max length', () => {
        expect(() =>
          createPolicySchema.parse({
            name: 'a'.repeat(101),
            rules: [
              {
                name: 'Rule',
                conditions: [{ field: 'sender_email', operator: 'equals', value: 'x' }],
                action: 'block',
              },
            ],
          })
        ).toThrow();
      });
    });
  });

  describe('Integration Schemas', () => {
    describe('createIntegrationSchema', () => {
      it('should validate integration creation', () => {
        const result = createIntegrationSchema.parse({
          type: 'gmail',
          email: 'user@gmail.com',
          config: {
            syncEnabled: true,
            autoRemediate: false,
          },
        });

        expect(result.type).toBe('gmail');
        expect(result.config?.syncEnabled).toBe(true);
      });

      it('should reject invalid integration type', () => {
        expect(() =>
          createIntegrationSchema.parse({
            type: 'invalid',
          })
        ).toThrow();
      });
    });
  });

  describe('Webhook Schemas', () => {
    describe('createWebhookSchema', () => {
      it('should validate webhook creation', () => {
        const result = createWebhookSchema.parse({
          url: 'https://example.com/webhook',
          events: ['threat.detected', 'threat.quarantined'],
          secret: 'my-secret-key-1234567890',
        });

        expect(result.url).toBe('https://example.com/webhook');
        expect(result.events).toHaveLength(2);
      });

      it('should require at least one event', () => {
        expect(() =>
          createWebhookSchema.parse({
            url: 'https://example.com/webhook',
            events: [],
          })
        ).toThrow();
      });

      it('should reject HTTP webhook URLs', () => {
        expect(() =>
          createWebhookSchema.parse({
            url: 'http://example.com/webhook',
            events: ['threat.detected'],
          })
        ).toThrow();
      });
    });
  });

  describe('List Entry Schemas', () => {
    describe('createListEntrySchema', () => {
      it('should validate list entry creation', () => {
        const result = createListEntrySchema.parse({
          listType: 'block',
          entryType: 'domain',
          value: 'malicious.com',
          reason: 'Known phishing domain',
        });

        expect(result.listType).toBe('block');
        expect(result.value).toBe('malicious.com');
      });
    });

    describe('batchCreateListEntriesSchema', () => {
      it('should validate batch creation', () => {
        const result = batchCreateListEntriesSchema.parse({
          listType: 'allow',
          entryType: 'email',
          values: ['safe@example.com', 'trusted@example.com'],
        });

        expect(result.values).toHaveLength(2);
      });

      it('should enforce max batch size', () => {
        expect(() =>
          batchCreateListEntriesSchema.parse({
            listType: 'block',
            entryType: 'domain',
            values: Array(101).fill('domain.com'),
          })
        ).toThrow();
      });
    });
  });

  describe('Feedback Schema', () => {
    describe('submitFeedbackSchema', () => {
      it('should validate feedback submission', () => {
        const result = submitFeedbackSchema.parse({
          threatId: '550e8400-e29b-41d4-a716-446655440000',
          feedback: 'false_positive',
          notes: 'This is a legitimate marketing email',
        });

        expect(result.feedback).toBe('false_positive');
      });

      it('should reject invalid feedback type', () => {
        expect(() =>
          submitFeedbackSchema.parse({
            threatId: '550e8400-e29b-41d4-a716-446655440000',
            feedback: 'invalid',
          })
        ).toThrow();
      });
    });
  });

  describe('Search Schema', () => {
    describe('searchQuerySchema', () => {
      it('should validate search query', () => {
        const result = searchQuerySchema.parse({
          q: 'phishing attack',
          type: 'threats',
          page: 1,
          limit: 20,
        });

        expect(result.q).toBe('phishing attack');
        expect(result.type).toBe('threats');
      });

      it('should require non-empty query', () => {
        expect(() => searchQuerySchema.parse({ q: '' })).toThrow();
      });

      it('should enforce max query length', () => {
        expect(() => searchQuerySchema.parse({ q: 'a'.repeat(201) })).toThrow();
      });
    });
  });

  describe('validateBody helper', () => {
    it('should return parsed data for valid input', () => {
      const result = validateBody(emailSchema, 'user@example.com');
      expect(result).toBe('user@example.com');
    });

    it('should throw ValidationError for invalid input', () => {
      expect(() => validateBody(emailSchema, 'invalid')).toThrow(ValidationError);
    });

    it('should include field-level error details', () => {
      try {
        validateBody(createPolicySchema, { name: '', rules: [] });
      } catch (error) {
        expect(error).toBeInstanceOf(ValidationError);
        const validationError = error as ValidationError;
        expect(validationError.errors.length).toBeGreaterThan(0);
        expect(validationError.errors[0]).toHaveProperty('field');
        expect(validationError.errors[0]).toHaveProperty('message');
      }
    });

    it('should serialize to JSON format', () => {
      const error = new ValidationError('Test error', [
        { field: 'email', message: 'Invalid email' },
      ]);

      const json = error.toJSON();
      expect(json.error).toBe('Test error');
      expect(json.details).toHaveLength(1);
    });
  });
});

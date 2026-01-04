/**
 * Policy Types
 * Defines the structure for detection policies and rules
 */

// Policy status
export type PolicyStatus = 'active' | 'inactive' | 'draft';

// Policy priority (higher = evaluated first)
export type PolicyPriority = 'low' | 'medium' | 'high' | 'critical';

// Actions that can be taken when a policy matches
export type PolicyAction =
  | 'allow'      // Skip detection, deliver email
  | 'block'      // Reject email immediately
  | 'quarantine' // Move to quarantine for review
  | 'tag'        // Deliver but add warning tag
  | 'log'        // Just log, no action
  | 'notify';    // Log and send notification

// Condition operators
export type ConditionOperator =
  | 'equals'
  | 'not_equals'
  | 'contains'
  | 'not_contains'
  | 'starts_with'
  | 'ends_with'
  | 'matches_regex'
  | 'in_list'
  | 'not_in_list'
  | 'greater_than'
  | 'less_than'
  | 'between';

// Fields that can be used in conditions
export type ConditionField =
  | 'sender_email'
  | 'sender_domain'
  | 'sender_name'
  | 'recipient_email'
  | 'recipient_domain'
  | 'subject'
  | 'body_text'
  | 'body_html'
  | 'attachment_name'
  | 'attachment_type'
  | 'attachment_count'
  | 'has_attachments'
  | 'has_links'
  | 'link_domain'
  | 'ip_address'
  | 'country'
  | 'spf_result'
  | 'dkim_result'
  | 'dmarc_result'
  | 'threat_score'
  | 'header';

// A single condition in a rule
export interface PolicyCondition {
  id: string;
  field: ConditionField;
  operator: ConditionOperator;
  value: string | number | boolean | string[];
  headerName?: string; // For 'header' field type
}

// Logical grouping of conditions
export type ConditionLogic = 'and' | 'or';

// A rule consists of conditions and an action
export interface PolicyRule {
  id: string;
  name: string;
  description?: string;
  conditions: PolicyCondition[];
  conditionLogic: ConditionLogic;
  action: PolicyAction;
  actionParams?: {
    tagText?: string;        // For 'tag' action
    notifyEmails?: string[]; // For 'notify' action
    quarantineReason?: string;
    blockReason?: string;
  };
  enabled: boolean;
  order: number;
}

// A complete policy
export interface Policy {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  type: PolicyType;
  status: PolicyStatus;
  priority: PolicyPriority;
  rules: PolicyRule[];
  // Scope - which emails this policy applies to
  scope?: {
    integrationTypes?: ('o365' | 'gmail' | 'smtp')[];
    directions?: ('inbound' | 'outbound' | 'internal')[];
  };
  // Metadata
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
  updatedBy?: string;
}

// Policy types for different use cases
export type PolicyType =
  | 'detection'     // Affects threat detection
  | 'allowlist'     // Sender/domain allowlists
  | 'blocklist'     // Sender/domain blocklists
  | 'content'       // Content filtering rules
  | 'attachment'    // Attachment policies
  | 'dlp'           // Data loss prevention
  | 'custom';       // Custom user-defined

// Allowlist/Blocklist entry
export interface ListEntry {
  id: string;
  tenantId: string;
  listType: 'allowlist' | 'blocklist';
  entryType: 'email' | 'domain' | 'ip' | 'url';
  value: string;
  reason?: string;
  expiresAt?: Date;
  createdAt: Date;
  createdBy: string;
}

// Policy evaluation result
export interface PolicyEvaluationResult {
  matched: boolean;
  policyId?: string;
  policyName?: string;
  ruleId?: string;
  ruleName?: string;
  action?: PolicyAction;
  actionParams?: PolicyRule['actionParams'];
  reason?: string;
}

// Default policies for new tenants
export const DEFAULT_POLICIES: Omit<Policy, 'id' | 'tenantId' | 'createdAt' | 'updatedAt' | 'createdBy'>[] = [
  {
    name: 'Block Known Malicious Senders',
    description: 'Automatically block emails from known malicious domains',
    type: 'blocklist',
    status: 'active',
    priority: 'critical',
    rules: [
      {
        id: 'rule-block-malicious',
        name: 'Block malicious domains',
        conditions: [
          {
            id: 'cond-1',
            field: 'sender_domain',
            operator: 'in_list',
            value: ['malware.com', 'phishing-site.net'], // Will be populated from threat intel
          },
        ],
        conditionLogic: 'and',
        action: 'block',
        actionParams: {
          blockReason: 'Sender domain is on known malicious list',
        },
        enabled: true,
        order: 1,
      },
    ],
  },
  {
    name: 'Quarantine High-Risk Attachments',
    description: 'Quarantine emails with potentially dangerous attachment types',
    type: 'attachment',
    status: 'active',
    priority: 'high',
    rules: [
      {
        id: 'rule-dangerous-attachments',
        name: 'Dangerous attachment types',
        conditions: [
          {
            id: 'cond-1',
            field: 'attachment_type',
            operator: 'in_list',
            value: [
              'application/x-msdownload',
              'application/x-executable',
              'application/x-msdos-program',
              'application/vnd.microsoft.portable-executable',
              'application/x-sh',
              'application/x-csh',
              'application/x-bat',
              'application/x-powershell',
            ],
          },
        ],
        conditionLogic: 'and',
        action: 'quarantine',
        actionParams: {
          quarantineReason: 'Email contains potentially dangerous attachment type',
        },
        enabled: true,
        order: 1,
      },
    ],
  },
  {
    name: 'Tag External Emails',
    description: 'Add warning tag to emails from external senders',
    type: 'content',
    status: 'inactive', // Disabled by default
    priority: 'low',
    rules: [
      {
        id: 'rule-external-tag',
        name: 'Tag external emails',
        conditions: [
          {
            id: 'cond-1',
            field: 'sender_domain',
            operator: 'not_equals',
            value: '', // Will be set to tenant's domain
          },
        ],
        conditionLogic: 'and',
        action: 'tag',
        actionParams: {
          tagText: '[EXTERNAL] ',
        },
        enabled: true,
        order: 1,
      },
    ],
  },
];

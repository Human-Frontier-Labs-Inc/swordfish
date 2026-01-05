/**
 * Security Validation Module
 *
 * Input validation, sanitization, and security controls
 */

export class ValidationError extends Error {
  details: Record<string, unknown>;

  constructor(message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = 'ValidationError';
    this.details = details;
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      details: this.details,
    };
  }
}

// Email validation regex (RFC 5322 compliant subset)
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

// Dangerous characters that shouldn't appear in emails
const DANGEROUS_CHARS = /[<>'";&]/;

/**
 * Validate email address format
 */
export function validateEmail(email: string): boolean {
  if (!email || typeof email !== 'string') return false;
  if (email.length > 254) return false; // RFC limit
  if (DANGEROUS_CHARS.test(email)) return false;
  return EMAIL_REGEX.test(email);
}

// Domain validation regex
const DOMAIN_REGEX = /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+$/;

/**
 * Validate domain format
 */
export function validateDomain(domain: string): boolean {
  if (!domain || typeof domain !== 'string') return false;
  if (domain.length > 253) return false;
  if (domain.includes('..')) return false;
  return DOMAIN_REGEX.test(domain);
}

// SSRF-risky hostnames
const SSRF_BLOCKLIST = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '[::1]',
  '169.254.169.254', // AWS metadata
  '192.168.',
  '10.',
  '172.16.',
  '172.17.',
  '172.18.',
  '172.19.',
  '172.20.',
  '172.21.',
  '172.22.',
  '172.23.',
  '172.24.',
  '172.25.',
  '172.26.',
  '172.27.',
  '172.28.',
  '172.29.',
  '172.30.',
  '172.31.',
];

// Dangerous URL schemes
const DANGEROUS_SCHEMES = ['javascript:', 'data:', 'vbscript:', 'file:'];

interface UrlValidationOptions {
  blockSSRF?: boolean;
}

/**
 * Validate URL format and safety
 */
export function validateUrl(url: string, options: UrlValidationOptions = {}): boolean {
  if (!url || typeof url !== 'string') return false;

  // Check for dangerous schemes
  const lowerUrl = url.toLowerCase();
  for (const scheme of DANGEROUS_SCHEMES) {
    if (lowerUrl.startsWith(scheme)) return false;
  }

  // Must be http or https
  if (!lowerUrl.startsWith('http://') && !lowerUrl.startsWith('https://')) {
    return false;
  }

  try {
    const parsed = new URL(url);

    // SSRF protection
    if (options.blockSSRF) {
      const hostname = parsed.hostname.toLowerCase();
      for (const blocked of SSRF_BLOCKLIST) {
        if (hostname === blocked || hostname.startsWith(blocked)) {
          return false;
        }
      }
    }

    return true;
  } catch {
    return false;
  }
}

// API key format regex
const API_KEY_REGEX = /^(sk|pk)_(live|test)_[a-zA-Z0-9]{10,}$/;

/**
 * Validate API key format
 */
export function validateApiKey(key: string): boolean {
  if (!key || typeof key !== 'string') return false;
  return API_KEY_REGEX.test(key);
}

// Tenant ID format regex
const TENANT_ID_REGEX = /^(tenant|org|user)_[a-zA-Z0-9]{4,}$/;

/**
 * Validate tenant ID format
 */
export function validateTenantId(id: string): boolean {
  if (!id || typeof id !== 'string') return false;
  if (id.includes('<') || id.includes('>') || id.includes('..')) return false;
  return TENANT_ID_REGEX.test(id);
}

interface PaginationParams {
  page: number;
  limit: number;
}

const MAX_LIMIT = 100;

/**
 * Validate and normalize pagination parameters
 */
export function validatePagination(params: PaginationParams): PaginationParams {
  const page = Math.max(1, Math.floor(params.page) || 1);
  const limit = Math.max(1, Math.floor(params.limit) || 1);
  return {
    page,
    limit: Math.min(MAX_LIMIT, limit),
  };
}

// Dangerous HTML tags
const DANGEROUS_TAGS = [
  'script', 'iframe', 'object', 'embed', 'form', 'input',
  'button', 'select', 'textarea', 'style', 'link', 'meta',
  'base', 'applet', 'frame', 'frameset', 'layer',
];

// Dangerous attributes
const DANGEROUS_ATTRS = [
  'onclick', 'ondblclick', 'onmousedown', 'onmouseup', 'onmouseover',
  'onmousemove', 'onmouseout', 'onkeypress', 'onkeydown', 'onkeyup',
  'onfocus', 'onblur', 'onchange', 'onsubmit', 'onreset', 'onselect',
  'onerror', 'onload', 'onunload', 'onabort', 'onresize', 'onscroll',
  'href', 'src', 'action', 'formaction', 'data',
];

interface HtmlSanitizationOptions {
  decodeEntities?: boolean;
}

/**
 * Sanitize HTML to prevent XSS
 */
export function sanitizeHtml(input: string, options: HtmlSanitizationOptions = {}): string {
  if (!input) return '';

  let html = input;

  // Decode entities if requested (to catch encoded XSS)
  if (options.decodeEntities) {
    html = decodeHtmlEntities(html);
    html = decodeURIComponentSafe(html);
  }

  // Remove dangerous tags
  for (const tag of DANGEROUS_TAGS) {
    const tagRegex = new RegExp(`<${tag}[^>]*>.*?</${tag}>|<${tag}[^>]*/>|<${tag}[^>]*>`, 'gis');
    html = html.replace(tagRegex, '');
  }

  // Remove dangerous attributes
  for (const attr of DANGEROUS_ATTRS) {
    const attrRegex = new RegExp(`\\s*${attr}\\s*=\\s*["'][^"']*["']|\\s*${attr}\\s*=\\s*[^\\s>]+`, 'gi');
    html = html.replace(attrRegex, '');
  }

  // Remove javascript: and data: URLs
  html = html.replace(/javascript:[^"']*/gi, '');
  html = html.replace(/data:[^"']*/gi, '');

  return html;
}

function decodeHtmlEntities(html: string): string {
  const entities: Record<string, string> = {
    '&lt;': '<',
    '&gt;': '>',
    '&amp;': '&',
    '&quot;': '"',
    '&#60;': '<',
    '&#62;': '>',
    '&#38;': '&',
    '&#34;': '"',
  };

  let result = html;
  for (const [entity, char] of Object.entries(entities)) {
    result = result.replace(new RegExp(entity, 'g'), char);
  }
  return result;
}

function decodeURIComponentSafe(str: string): string {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}

interface InputSanitizationOptions {
  maxLength?: number;
}

/**
 * Sanitize general input
 */
export function sanitizeInput(
  input: unknown,
  options: InputSanitizationOptions = {}
): unknown {
  if (typeof input === 'string') {
    let result = input.trim();
    // Remove null bytes
    result = result.replace(/\x00/g, '');
    // Limit length
    if (options.maxLength && result.length > options.maxLength) {
      result = result.slice(0, options.maxLength);
    }
    return result;
  }

  if (Array.isArray(input)) {
    return input.map(item => sanitizeInput(item, options));
  }

  if (input && typeof input === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input)) {
      result[key] = sanitizeInput(value, options);
    }
    return result;
  }

  return input;
}

// SQL dangerous characters
const SQL_DANGEROUS = /[';\-]/g;

/**
 * Escape string for SQL (use parameterized queries instead when possible)
 */
export function escapeForSql(input: string): string {
  return input.replace(SQL_DANGEROUS, '');
}

interface WebhookValidationOptions {
  maxSize?: number;
}

/**
 * Validate webhook payload structure
 */
export function validateWebhookPayload(
  payload: unknown,
  type: 'o365' | 'gmail',
  options: WebhookValidationOptions = {}
): boolean {
  if (!payload || typeof payload !== 'object') return false;

  // Check size limit
  if (options.maxSize) {
    const size = JSON.stringify(payload).length;
    if (size > options.maxSize) {
      throw new ValidationError('Payload exceeds size limit', {
        maxSize: options.maxSize,
        actualSize: size,
      });
    }
  }

  const p = payload as Record<string, unknown>;

  if (type === 'o365') {
    // O365 webhook structure
    if (!Array.isArray(p.value)) return false;
    if (p.value.length === 0) return true; // Empty array is valid
    const first = p.value[0] as Record<string, unknown>;
    return 'subscriptionId' in first || 'changeType' in first;
  }

  if (type === 'gmail') {
    // Gmail Pub/Sub structure
    if (!p.message || typeof p.message !== 'object') return false;
    const msg = p.message as Record<string, unknown>;
    return 'data' in msg || 'messageId' in msg;
  }

  return false;
}

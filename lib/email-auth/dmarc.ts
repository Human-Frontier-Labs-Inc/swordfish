/**
 * DMARC (Domain-based Message Authentication, Reporting & Conformance) Evaluator
 *
 * Evaluates DMARC policies based on SPF and DKIM results as defined in RFC 7489
 */

import type {
  DNSResolver,
  DMARCRecord,
  DMARCPolicy,
  DMARCResult,
  DMARCAlignment,
  DMARCEvaluationResult,
  SPFResult,
  DKIMValidationResult,
} from './types';

// Common second-level TLDs (for organizational domain extraction)
const SECOND_LEVEL_TLDS = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'ad.jp', 'ed.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
  'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx',
  'co.za', 'net.za', 'org.za', 'gov.za', 'ac.za',
]);

export interface DMARCEvaluationInput {
  headerFrom: string;
  mailFrom: string;
  spfResult: SPFResult;
  dkimResults: DKIMValidationResult[];
}

export class DMARCEvaluator {
  private resolver: DNSResolver;

  constructor(resolver: DNSResolver) {
    this.resolver = resolver;
  }

  /**
   * Get DMARC record for a domain
   */
  async getRecord(domain: string): Promise<DMARCRecord | null> {
    const dmarcDomain = `_dmarc.${domain}`;

    let txtRecords: string[];
    try {
      txtRecords = await this.resolver.resolveTxt(dmarcDomain);
    } catch {
      // DNS lookup failed - treat as no record
      return null;
    }

    // Find DMARC-like records (start with v=)
    const dmarcLikeRecords = txtRecords.filter(r => r.startsWith('v='));

    if (dmarcLikeRecords.length === 0) {
      // Try organizational domain if this is a subdomain
      const orgDomain = this.getOrganizationalDomain(domain);
      if (orgDomain !== domain) {
        return this.getRecord(orgDomain);
      }
      return null;
    }

    // Check for valid DMARC1 records
    const dmarcRecords = txtRecords.filter(r => r.startsWith('v=DMARC1'));

    if (dmarcRecords.length === 0 && dmarcLikeRecords.length > 0) {
      // Found a version tag but not DMARC1 - invalid version
      throw new Error('Invalid DMARC version: must be DMARC1');
    }

    if (dmarcRecords.length === 0) {
      // Try organizational domain if this is a subdomain
      const orgDomain = this.getOrganizationalDomain(domain);
      if (orgDomain !== domain) {
        return this.getRecord(orgDomain);
      }
      return null;
    }

    // Multiple DMARC records is an error, but we'll use the first one
    const record = dmarcRecords[0];
    return this.parseRecord(record);
  }

  /**
   * Parse a DMARC record string
   */
  parseRecord(record: string): DMARCRecord {
    const tags = this.parseTags(record);

    // Validate version
    if (tags['v'] !== 'DMARC1') {
      throw new Error('Invalid DMARC version: must be DMARC1');
    }

    // Validate policy (required)
    if (!tags['p']) {
      throw new Error('Missing required policy (p=) tag');
    }

    const policy = this.parsePolicy(tags['p']);
    const subdomainPolicy = tags['sp'] ? this.parsePolicy(tags['sp']) : undefined;

    // Parse alignment modes
    const adkim = this.parseAlignment(tags['adkim']);
    const aspf = this.parseAlignment(tags['aspf']);

    // Parse percentage (default 100)
    const percentage = tags['pct'] ? parseInt(tags['pct'], 10) : 100;

    // Parse report URIs
    const ruaAddresses = tags['rua'] ? tags['rua'].split(',').map(a => a.trim()) : undefined;
    const rufAddresses = tags['ruf'] ? tags['ruf'].split(',').map(a => a.trim()) : undefined;

    // Parse report interval (default 86400 seconds = 1 day)
    const reportInterval = tags['ri'] ? parseInt(tags['ri'], 10) : 86400;

    return {
      version: 'DMARC1',
      policy,
      subdomainPolicy,
      percentage,
      ruaAddresses,
      rufAddresses,
      adkim,
      aspf,
      reportFormat: tags['rf'],
      reportInterval,
      failureOptions: tags['fo'],
      raw: record,
    };
  }

  /**
   * Parse tag=value pairs from DMARC record
   */
  private parseTags(record: string): Record<string, string> {
    const tags: Record<string, string> = {};

    const parts = record.split(';');

    for (const part of parts) {
      const trimmed = part.trim();
      if (!trimmed) continue;

      const eqIndex = trimmed.indexOf('=');
      if (eqIndex > 0) {
        const key = trimmed.substring(0, eqIndex).trim().toLowerCase();
        const value = trimmed.substring(eqIndex + 1).trim();
        tags[key] = value;
      }
    }

    return tags;
  }

  /**
   * Parse policy value
   */
  private parsePolicy(value: string): DMARCPolicy {
    switch (value.toLowerCase()) {
      case 'none': return 'none';
      case 'quarantine': return 'quarantine';
      case 'reject': return 'reject';
      default: return 'none';
    }
  }

  /**
   * Parse alignment mode
   */
  private parseAlignment(value?: string): DMARCAlignment {
    if (!value) return 'relaxed';

    switch (value.toLowerCase()) {
      case 's': return 'strict';
      case 'r': return 'relaxed';
      default: return 'relaxed';
    }
  }

  /**
   * Check SPF alignment
   */
  checkSPFAlignment(
    headerFrom: string,
    mailFrom: string,
    mode: DMARCAlignment
  ): boolean {
    const headerDomain = this.extractDomain(headerFrom);
    const mailFromDomain = this.extractDomain(mailFrom);

    if (mode === 'strict') {
      return headerDomain.toLowerCase() === mailFromDomain.toLowerCase();
    }

    // Relaxed: organizational domains must match
    const headerOrgDomain = this.getOrganizationalDomain(headerDomain);
    const mailFromOrgDomain = this.getOrganizationalDomain(mailFromDomain);

    return headerOrgDomain.toLowerCase() === mailFromOrgDomain.toLowerCase();
  }

  /**
   * Check DKIM alignment
   */
  checkDKIMAlignment(
    headerFrom: string,
    dkimDomain: string,
    mode: DMARCAlignment
  ): boolean {
    const headerDomain = this.extractDomain(headerFrom);

    if (mode === 'strict') {
      return headerDomain.toLowerCase() === dkimDomain.toLowerCase();
    }

    // Relaxed: organizational domains must match
    const headerOrgDomain = this.getOrganizationalDomain(headerDomain);
    const dkimOrgDomain = this.getOrganizationalDomain(dkimDomain);

    return headerOrgDomain.toLowerCase() === dkimOrgDomain.toLowerCase();
  }

  /**
   * Check if any DKIM signature passes and aligns
   */
  checkAnyDKIMAlignment(
    headerFrom: string,
    dkimResults: DKIMValidationResult[],
    mode: DMARCAlignment
  ): boolean {
    for (const result of dkimResults) {
      if (result.result === 'pass') {
        if (this.checkDKIMAlignment(headerFrom, result.domain, mode)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Extract domain from email address
   */
  private extractDomain(email: string): string {
    // Handle "Name <email@domain>" format
    const match = email.match(/<([^>]+)>/);
    const address = match ? match[1] : email;

    // Extract domain part
    const atIndex = address.lastIndexOf('@');
    if (atIndex > 0) {
      return address.substring(atIndex + 1);
    }

    return address;
  }

  /**
   * Get organizational domain from a domain name
   * This is a simplified implementation - production should use Public Suffix List
   */
  getOrganizationalDomain(domain: string): string {
    const parts = domain.toLowerCase().split('.');

    if (parts.length <= 2) {
      return domain;
    }

    // Check for common second-level TLDs
    const lastTwo = parts.slice(-2).join('.');
    if (SECOND_LEVEL_TLDS.has(lastTwo)) {
      return parts.slice(-3).join('.');
    }

    return parts.slice(-2).join('.');
  }

  /**
   * Evaluate DMARC policy for an email
   */
  async evaluate(input: DMARCEvaluationInput): Promise<DMARCEvaluationResult> {
    const headerDomain = this.extractDomain(input.headerFrom);
    const orgDomain = this.getOrganizationalDomain(headerDomain);

    // Get DMARC record
    const record = await this.getRecord(headerDomain);

    // No DMARC record
    if (!record) {
      return {
        result: 'none',
        domain: headerDomain,
        policy: 'none',
        appliedPolicy: 'none',
        spfAlignment: false,
        dkimAlignment: false,
        spfResult: input.spfResult,
        dkimResults: input.dkimResults,
      };
    }

    // Determine which policy to apply
    const isSubdomain = headerDomain !== orgDomain;
    let appliedPolicy = record.policy;

    if (isSubdomain && record.subdomainPolicy) {
      appliedPolicy = record.subdomainPolicy;
    }

    // Check SPF alignment
    const spfAligned =
      input.spfResult === 'pass' &&
      this.checkSPFAlignment(input.headerFrom, input.mailFrom, record.aspf!);

    // Check DKIM alignment
    const dkimAligned = this.checkAnyDKIMAlignment(
      input.headerFrom,
      input.dkimResults,
      record.adkim!
    );

    // DMARC passes if either SPF or DKIM passes AND aligns
    const dmarcPass = spfAligned || dkimAligned;

    // Apply percentage
    let finalPolicy = appliedPolicy;
    if (!dmarcPass && record.percentage !== undefined && record.percentage < 100) {
      // Generate a random number to determine if policy applies
      // For pct=0, always use none
      if (record.percentage === 0) {
        finalPolicy = 'none';
      } else {
        // In production, this would be a consistent hash of message ID
        // For simplicity, we apply the policy as specified
        // The percentage indicates what fraction of failing messages get the policy
      }
    }

    return {
      result: dmarcPass ? 'pass' : 'fail',
      domain: headerDomain,
      policy: record.policy,
      appliedPolicy: finalPolicy,
      spfAlignment: spfAligned,
      dkimAlignment: dkimAligned,
      spfResult: input.spfResult,
      dkimResults: input.dkimResults,
      percentage: record.percentage,
      record,
    };
  }
}

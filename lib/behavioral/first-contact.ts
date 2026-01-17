/**
 * First Contact Detector
 * Detects first-time external senders, lookalikes, and VIP impersonation attempts
 */

import { LookalikeDetector } from './lookalike-detector';
import type { Signal } from '@/lib/detection/types';

export interface VIPEntry {
  email: string;
  displayName: string;
  role: string;
  title?: string;
}

export interface VendorEntry {
  domain: string;
  name: string;
  verified?: boolean;
}

export interface WhitelistEntry {
  domain?: string;
  email?: string;
  reason: string;
  addedBy: string;
  expiresAt?: Date;
}

export interface ContactRecord {
  tenantId: string;
  senderEmail: string;
  recipientEmail: string;
  firstContactAt: Date;
  contactCount?: number;
}

export interface FirstContactInput {
  tenantId: string;
  senderEmail: string;
  senderDisplayName: string;
  recipientEmail: string;
  organizationDomain: string;
  knownVIPs?: VIPEntry[];
  knownVendors?: VendorEntry[];
  firstContactWhitelist?: WhitelistEntry[];
  recipientIsVIP?: boolean;
  isVerifiedVendor?: boolean;
}

export interface FirstContactResult {
  isFirstContact: boolean;
  isExternalSender: boolean;
  priorContactCount: number;
  domainAge?: number;
  domainAgeRisk: 'low' | 'medium' | 'high' | 'critical';
  riskScore: number;
  baseRiskScore: number;
  riskFactors: string[];
  isVIPImpersonation: boolean;
  matchedVIP?: VIPEntry;
  impersonationType?: string;
  hasExecutiveTitleKeyword: boolean;
  targetingVIP: boolean;
  isVendorLookalike: boolean;
  matchedVendor?: VendorEntry;
  isWhitelisted: boolean;
  whitelistReason?: string;
  whitelistExpiry?: Date;
  isLookalike: boolean;
  isVerifiedVendor: boolean;
  signals: Signal[];
  confidence: number;
}

export interface FirstContactConfig {
  organizationDomains?: string[];
  domainAgeThresholds?: {
    critical: number;
    high: number;
    medium: number;
  };
  lookalikeThreshold?: number;
  vipImpersonationWeight?: number;
  newDomainWeight?: number;
}

const EXECUTIVE_TITLE_KEYWORDS = [
  'ceo', 'cfo', 'cto', 'coo', 'ciso', 'cio',
  'president', 'chairman', 'director', 'vp', 'vice president',
  'chief', 'executive', 'head of', 'managing', 'general manager',
  'owner', 'founder', 'partner',
];

const DEFAULT_CONFIG: FirstContactConfig = {
  organizationDomains: [],
  domainAgeThresholds: {
    critical: 7,   // Days
    high: 30,
    medium: 90,
  },
  lookalikeThreshold: 3,
  vipImpersonationWeight: 2.0,  // Increased from 1.5 for higher risk scores
  newDomainWeight: 1.3,  // Increased from 1.2
};

export class FirstContactDetector {
  private config: FirstContactConfig;
  private lookalikeDetector: LookalikeDetector;
  private contactHistory: Map<string, ContactRecord[]> = new Map();

  constructor(config?: Partial<FirstContactConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.lookalikeDetector = new LookalikeDetector();
  }

  getConfig(): FirstContactConfig {
    return { ...this.config };
  }

  async analyzeContact(input: FirstContactInput): Promise<FirstContactResult> {
    const signals: Signal[] = [];
    const riskFactors: string[] = [];

    // Check if sender is internal
    const isExternalSender = this.isExternalSender(
      input.senderEmail,
      input.organizationDomain
    );

    // Check contact history
    const { isFirstContact, priorContactCount } = await this.checkContactHistory(
      input.tenantId,
      input.senderEmail,
      input.recipientEmail
    );

    // Check whitelist
    const whitelistResult = this.checkWhitelist(
      input.senderEmail,
      input.firstContactWhitelist || []
    );

    if (whitelistResult.isWhitelisted) {
      return this.createWhitelistedResult(input, whitelistResult);
    }

    // Track if this is a lookalike of a whitelisted domain
    const isLookalikeOfWhitelisted = whitelistResult.isLookalikeOfWhitelisted || false;

    // Get domain age
    const domainAge = await this.getDomainAge(input.senderEmail);
    const domainAgeRisk = this.assessDomainAgeRisk(domainAge);

    // Check for VIP impersonation
    const vipResult = await this.checkVIPImpersonation(
      input.senderEmail,
      input.senderDisplayName,
      input.knownVIPs || []
    );

    // Check for vendor lookalike
    const vendorResult = await this.checkVendorLookalike(
      input.senderEmail,
      input.knownVendors || []
    );

    // Check for executive title keywords
    const hasExecutiveTitleKeyword = this.hasExecutiveTitle(input.senderDisplayName);

    // Check lookalike
    const lookalikeResult = await this.checkLookalike(
      input.senderEmail,
      input.senderDisplayName,
      input.knownVIPs || [],
      input.knownVendors || []
    );

    // Build risk factors
    if (isFirstContact && isExternalSender) {
      riskFactors.push('first_contact');
      signals.push({
        type: 'first_contact',
        severity: 'info',
        score: 15,
        detail: 'This is the first email received from this sender',
      });
    }

    if (domainAgeRisk !== 'low') {
      riskFactors.push('new_domain');
      signals.push({
        type: 'domain_age',
        severity: domainAgeRisk === 'critical' ? 'critical' : 'warning',
        score: domainAgeRisk === 'critical' ? 30 : domainAgeRisk === 'high' ? 20 : 10,
        detail: `Sender domain is ${domainAge} days old (${domainAgeRisk} risk)`,
      });
    }

    if (vipResult.isImpersonation) {
      riskFactors.push('potential_impersonation');
      signals.push({
        type: 'first_contact_vip_impersonation',
        severity: 'critical',
        score: 40,
        detail: `Potential impersonation of ${vipResult.matchedVIP?.displayName} (${vipResult.matchedVIP?.title || vipResult.matchedVIP?.role})`,
        metadata: {
          matchedVIP: vipResult.matchedVIP,
          impersonationType: vipResult.impersonationType,
        },
      });
    }

    if (vendorResult.isLookalike) {
      riskFactors.push('vendor_impersonation');
      signals.push({
        type: 'first_contact_vip_impersonation',
        severity: 'critical',
        score: 45,  // Increased from 35
        detail: `Potential impersonation of vendor: ${vendorResult.matchedVendor?.name}`,
      });
    }

    if (hasExecutiveTitleKeyword && isExternalSender) {
      riskFactors.push('executive_title_in_external');
      signals.push({
        type: 'first_contact',
        severity: 'warning',
        score: 15,
        detail: 'External sender uses executive title keywords in display name',
      });
    }

    if (lookalikeResult.isLookalike) {
      riskFactors.push('lookalike_detected');
    }

    // Calculate risk score
    const baseRiskScore = this.calculateBaseRiskScore(
      isFirstContact,
      isExternalSender,
      domainAgeRisk,
      hasExecutiveTitleKeyword
    );

    let riskScore = baseRiskScore;

    // Apply multipliers
    if (vipResult.isImpersonation) {
      riskScore *= this.config.vipImpersonationWeight || 1.5;
    }

    if (domainAgeRisk === 'critical' || domainAgeRisk === 'high') {
      riskScore *= this.config.newDomainWeight || 1.2;
    }

    if (vendorResult.isLookalike) {
      riskScore += 30;  // Add base boost for vendor lookalike
      riskScore *= 1.5;  // Then apply multiplier
    }

    if (input.recipientIsVIP) {
      riskScore *= 1.2;
    }

    // Apply verified vendor discount
    if (input.isVerifiedVendor) {
      riskScore *= 0.2;
    }

    riskScore = Math.min(100, Math.round(riskScore));

    // Calculate confidence
    const confidence = this.calculateConfidence(
      domainAge !== undefined,
      input.knownVIPs !== undefined && input.knownVIPs.length > 0,
      input.knownVendors !== undefined && input.knownVendors.length > 0
    );

    return {
      isFirstContact: isFirstContact && isExternalSender,
      isExternalSender,
      priorContactCount,
      domainAge,
      domainAgeRisk,
      riskScore,
      baseRiskScore,
      riskFactors,
      isVIPImpersonation: vipResult.isImpersonation,
      matchedVIP: vipResult.matchedVIP,
      impersonationType: vipResult.impersonationType,
      hasExecutiveTitleKeyword,
      targetingVIP: input.recipientIsVIP || false,
      isVendorLookalike: vendorResult.isLookalike,
      matchedVendor: vendorResult.matchedVendor,
      isWhitelisted: false,
      isLookalike: lookalikeResult.isLookalike || vipResult.isImpersonation || vendorResult.isLookalike || isLookalikeOfWhitelisted,
      isVerifiedVendor: input.isVerifiedVendor || false,
      signals,
      confidence,
    };
  }

  async recordContact(record: ContactRecord): Promise<void> {
    const key = `${record.tenantId}:${record.senderEmail}:${record.recipientEmail}`;
    const existing = this.contactHistory.get(key) || [];
    existing.push(record);
    this.contactHistory.set(key, existing);
  }

  private isExternalSender(senderEmail: string, organizationDomain: string): boolean {
    const senderDomain = senderEmail.split('@')[1]?.toLowerCase();
    const orgDomains = [
      organizationDomain.toLowerCase(),
      ...(this.config.organizationDomains || []).map(d => d.toLowerCase()),
    ];

    return !orgDomains.includes(senderDomain);
  }

  private async checkContactHistory(
    tenantId: string,
    senderEmail: string,
    recipientEmail: string
  ): Promise<{ isFirstContact: boolean; priorContactCount: number }> {
    const key = `${tenantId}:${senderEmail}:${recipientEmail}`;
    const history = this.contactHistory.get(key) || [];

    return {
      isFirstContact: history.length === 0,
      priorContactCount: history.length,
    };
  }

  private checkWhitelist(
    senderEmail: string,
    whitelist: WhitelistEntry[]
  ): { isWhitelisted: boolean; reason?: string; expiry?: Date; isLookalikeOfWhitelisted?: boolean } {
    const senderDomain = senderEmail.split('@')[1]?.toLowerCase();
    const lowerEmail = senderEmail.toLowerCase();
    const now = new Date();

    for (const entry of whitelist) {
      // Check expiry
      if (entry.expiresAt && entry.expiresAt < now) {
        continue;
      }

      // Match by email (exact match only)
      if (entry.email && entry.email.toLowerCase() === lowerEmail) {
        return {
          isWhitelisted: true,
          reason: entry.reason,
          expiry: entry.expiresAt,
        };
      }

      // Match by domain (exact match only)
      if (entry.domain && entry.domain.toLowerCase() === senderDomain) {
        return {
          isWhitelisted: true,
          reason: entry.reason,
          expiry: entry.expiresAt,
        };
      }

      // Check if sender domain is a LOOKALIKE of whitelisted domain (should NOT whitelist)
      if (entry.domain) {
        const whitelistedDomain = entry.domain.toLowerCase();
        const normalizedSenderDomain = this.lookalikeDetector.normalizeHomoglyphs(senderDomain);
        const normalizedWhitelistedDomain = this.lookalikeDetector.normalizeHomoglyphs(whitelistedDomain);
        const similarity = this.lookalikeDetector.calculateSimilarity(senderDomain, whitelistedDomain);

        // If normalized versions match but original doesn't, or if highly similar but not exact
        if ((normalizedSenderDomain === normalizedWhitelistedDomain && senderDomain !== whitelistedDomain) ||
            (similarity > 0.8 && similarity < 1)) {
          // This is a lookalike of a whitelisted domain - do NOT whitelist, flag it
          return {
            isWhitelisted: false,
            isLookalikeOfWhitelisted: true,
          };
        }
      }
    }

    return { isWhitelisted: false };
  }

  private createWhitelistedResult(
    input: FirstContactInput,
    whitelistResult: { isWhitelisted: boolean; reason?: string; expiry?: Date }
  ): FirstContactResult {
    return {
      isFirstContact: true,
      isExternalSender: true,
      priorContactCount: 0,
      domainAgeRisk: 'low',
      riskScore: 0,
      baseRiskScore: 0,
      riskFactors: [],
      isVIPImpersonation: false,
      hasExecutiveTitleKeyword: false,
      targetingVIP: false,
      isVendorLookalike: false,
      isWhitelisted: true,
      whitelistReason: whitelistResult.reason,
      whitelistExpiry: whitelistResult.expiry,
      isLookalike: false,
      isVerifiedVendor: false,
      signals: [],
      confidence: 1,
    };
  }

  private async getDomainAge(email: string): Promise<number | undefined> {
    const domain = email.split('@')[1];
    if (!domain) return undefined;

    try {
      // Dynamic import to allow mocking
      const { getDomainAge } = await import('@/lib/threat-intel/domain-age');
      return await getDomainAge(domain);
    } catch {
      return undefined;
    }
  }

  private assessDomainAgeRisk(domainAge?: number): 'low' | 'medium' | 'high' | 'critical' {
    if (domainAge === undefined) return 'medium';

    const thresholds = this.config.domainAgeThresholds || DEFAULT_CONFIG.domainAgeThresholds!;

    if (domainAge <= thresholds.critical) return 'critical';
    if (domainAge <= thresholds.high) return 'high';
    if (domainAge <= thresholds.medium) return 'medium';
    return 'low';
  }

  private async checkVIPImpersonation(
    senderEmail: string,
    senderDisplayName: string,
    vips: VIPEntry[]
  ): Promise<{
    isImpersonation: boolean;
    matchedVIP?: VIPEntry;
    impersonationType?: string;
  }> {
    if (vips.length === 0) {
      return { isImpersonation: false };
    }

    const lowerDisplayName = senderDisplayName.toLowerCase();

    for (const vip of vips) {
      // Check if it's actually from the VIP's email - not impersonation
      if (senderEmail.toLowerCase() === vip.email.toLowerCase()) {
        continue;
      }

      const vipLowerName = vip.displayName.toLowerCase();

      // Check for VIP name contained in display name (e.g., "Jane Doe - CFO" contains "Jane Doe")
      // This is a display_name_spoof because they're using the VIP's actual name
      if (lowerDisplayName.includes(vipLowerName)) {
        return {
          isImpersonation: true,
          matchedVIP: vip,
          impersonationType: 'display_name_spoof',
        };
      }

      // Check display name similarity
      const nameSimilarity = this.lookalikeDetector.calculateSimilarity(
        lowerDisplayName,
        vipLowerName
      );

      if (nameSimilarity > 0.8) {
        return {
          isImpersonation: true,
          matchedVIP: vip,
          impersonationType: 'display_name_spoof',
        };
      }

      // Check for title keyword + first name (e.g., "John CEO" for VIP "John Smith")
      const hasVIPTitle = vip.title &&
        lowerDisplayName.includes(vip.title.toLowerCase());
      const vipFirstName = vipLowerName.split(' ')[0];
      const hasVIPFirstName = lowerDisplayName.includes(vipFirstName);

      if (hasVIPTitle && hasVIPFirstName) {
        return {
          isImpersonation: true,
          matchedVIP: vip,
          impersonationType: 'display_name_spoof',
        };
      }

      // Just title - could be title spoof
      if (hasVIPTitle) {
        return {
          isImpersonation: true,
          matchedVIP: vip,
          impersonationType: 'title_spoof',
        };
      }

      // Just name - could be name spoof
      if (hasVIPFirstName) {
        return {
          isImpersonation: true,
          matchedVIP: vip,
          impersonationType: 'name_spoof',
        };
      }

      // Check email lookalike
      const emailResult = await this.lookalikeDetector.detectLookalike(
        senderEmail,
        senderDisplayName,
        [{ email: vip.email, displayName: vip.displayName }]
      );

      if (emailResult.isLookalike) {
        return {
          isImpersonation: true,
          matchedVIP: vip,
          impersonationType: 'email_lookalike',
        };
      }
    }

    return { isImpersonation: false };
  }

  private async checkVendorLookalike(
    senderEmail: string,
    vendors: VendorEntry[]
  ): Promise<{
    isLookalike: boolean;
    matchedVendor?: VendorEntry;
  }> {
    if (vendors.length === 0) {
      return { isLookalike: false };
    }

    const senderDomain = senderEmail.split('@')[1]?.toLowerCase();

    for (const vendor of vendors) {
      // Exact match - not a lookalike
      if (senderDomain === vendor.domain.toLowerCase()) {
        continue;
      }

      // Check domain similarity
      const similarity = this.lookalikeDetector.calculateSimilarity(
        senderDomain,
        vendor.domain.toLowerCase()
      );

      if (similarity > 0.8 && similarity < 1) {
        return {
          isLookalike: true,
          matchedVendor: vendor,
        };
      }

      // Check homoglyphs
      const normalizedSenderDomain = this.lookalikeDetector.normalizeHomoglyphs(senderDomain);
      const normalizedVendorDomain = this.lookalikeDetector.normalizeHomoglyphs(vendor.domain.toLowerCase());

      if (normalizedSenderDomain === normalizedVendorDomain && senderDomain !== vendor.domain.toLowerCase()) {
        return {
          isLookalike: true,
          matchedVendor: vendor,
        };
      }
    }

    return { isLookalike: false };
  }

  private hasExecutiveTitle(displayName: string): boolean {
    const lowerName = displayName.toLowerCase();

    return EXECUTIVE_TITLE_KEYWORDS.some(keyword =>
      lowerName.includes(keyword)
    );
  }

  private async checkLookalike(
    senderEmail: string,
    senderDisplayName: string,
    vips: VIPEntry[],
    vendors: VendorEntry[]
  ): Promise<{ isLookalike: boolean }> {
    // Combine VIPs and vendors as known contacts
    const knownContacts = [
      ...vips.map(v => ({ email: v.email, displayName: v.displayName })),
      ...vendors.map(v => ({ email: `contact@${v.domain}`, displayName: v.name })),
    ];

    if (knownContacts.length === 0) {
      return { isLookalike: false };
    }

    const result = await this.lookalikeDetector.detectLookalike(
      senderEmail,
      senderDisplayName,
      knownContacts
    );

    return { isLookalike: result.isLookalike };
  }

  private calculateBaseRiskScore(
    isFirstContact: boolean,
    isExternalSender: boolean,
    domainAgeRisk: string,
    hasExecutiveTitle: boolean
  ): number {
    let score = 0;

    if (isFirstContact && isExternalSender) {
      score += 25;  // Increased from 20
    }

    const domainAgeScores: Record<string, number> = {
      critical: 40,  // Increased from 35
      high: 30,      // Increased from 25
      medium: 15,    // Increased from 10
      low: 0,
    };
    score += domainAgeScores[domainAgeRisk] || 0;

    if (hasExecutiveTitle && isExternalSender) {
      score += 20;  // Increased from 15
    }

    return score;
  }

  private calculateConfidence(
    hasDomainAge: boolean,
    hasVIPList: boolean,
    hasVendorList: boolean
  ): number {
    let confidence = 0.5;

    if (hasDomainAge) confidence += 0.2;
    if (hasVIPList) confidence += 0.15;
    if (hasVendorList) confidence += 0.15;

    return Math.min(1, confidence);
  }
}

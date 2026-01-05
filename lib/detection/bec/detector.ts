/**
 * BEC Detection Engine
 * Main orchestrator for Business Email Compromise detection
 */

import {
  checkBECPatterns,
  extractAmounts,
  assessAmountRisk,
  detectCompoundAttack,
  type PatternMatch,
} from './patterns';
import {
  detectImpersonation,
  calculateImpersonationRisk,
  type ImpersonationResult,
  type ImpersonationSignal,
} from './impersonation';
import { getVIPList, type VIPEntry } from './vip-list';

export interface BECDetectionResult {
  isBEC: boolean;
  confidence: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  signals: BECSignal[];
  patterns: PatternMatch[];
  impersonation: ImpersonationResult | null;
  financialRisk: FinancialRisk;
  summary: string;
}

export interface BECSignal {
  type: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  evidence: string;
}

export interface FinancialRisk {
  hasFinancialRequest: boolean;
  amounts: Array<{ amount: number; original: string }>;
  maxAmount: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface EmailData {
  subject: string;
  body: string;
  senderEmail: string;
  senderDisplayName: string;
  replyTo?: string;
  headers?: Record<string, string>;
}

/**
 * Main BEC detection function
 */
export async function detectBEC(
  email: EmailData,
  tenantId: string,
  organizationDomain?: string
): Promise<BECDetectionResult> {
  const signals: BECSignal[] = [];

  // 1. Check BEC patterns in content
  const patternMatches = checkBECPatterns(email.subject, email.body);

  for (const match of patternMatches) {
    signals.push({
      type: match.pattern.id,
      category: match.pattern.category,
      severity: match.pattern.severity,
      description: match.pattern.description,
      evidence: match.matches.map(m => `"${m.matchedText}" in ${m.location}`).join(', '),
    });
  }

  // 2. Check for impersonation
  const impersonation = await detectImpersonation(
    tenantId,
    email.senderEmail,
    email.senderDisplayName,
    email.replyTo,
    organizationDomain
  );

  if (impersonation.isImpersonation) {
    for (const signal of impersonation.signals) {
      signals.push({
        type: signal.type,
        category: 'impersonation',
        severity: signal.severity,
        description: signal.detail,
        evidence: `Sender: ${email.senderDisplayName} <${email.senderEmail}>`,
      });
    }
  }

  // 3. Extract and assess financial amounts
  const amounts = extractAmounts(`${email.subject} ${email.body}`);
  const amountRisk = assessAmountRisk(amounts);

  const financialRisk: FinancialRisk = {
    hasFinancialRequest: amounts.length > 0 && patternMatches.some(
      m => ['wire_fraud', 'gift_card', 'invoice_fraud'].includes(m.pattern.category)
    ),
    amounts: amounts.map(a => ({ amount: a.amount, original: a.original })),
    maxAmount: amountRisk.maxAmount,
    riskLevel: amountRisk.riskLevel,
  };

  if (financialRisk.hasFinancialRequest && financialRisk.maxAmount > 0) {
    signals.push({
      type: 'financial_amount',
      category: 'financial_request',
      severity: amountRisk.riskLevel,
      description: `Financial amount detected: ${formatCurrency(financialRisk.maxAmount)}`,
      evidence: amounts.map(a => a.original).join(', '),
    });
  }

  // 4. Check for compound attacks
  const compoundAttack = detectCompoundAttack(patternMatches);

  if (compoundAttack.isCompoundAttack) {
    signals.push({
      type: 'compound_attack',
      category: 'multi_vector',
      severity: compoundAttack.severity,
      description: 'Multiple BEC attack vectors detected',
      evidence: compoundAttack.explanation,
    });
  }

  // 5. Calculate overall confidence and risk
  const { confidence, riskLevel, isBEC } = calculateOverallRisk(
    signals,
    patternMatches,
    impersonation,
    financialRisk,
    compoundAttack.isCompoundAttack
  );

  // 6. Generate summary
  const summary = generateSummary(
    isBEC,
    signals,
    impersonation,
    financialRisk
  );

  return {
    isBEC,
    confidence,
    riskLevel,
    signals,
    patterns: patternMatches,
    impersonation,
    financialRisk,
    summary,
  };
}

/**
 * Calculate overall BEC risk
 */
function calculateOverallRisk(
  signals: BECSignal[],
  patterns: PatternMatch[],
  impersonation: ImpersonationResult | null,
  financialRisk: FinancialRisk,
  isCompoundAttack: boolean
): {
  confidence: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  isBEC: boolean;
} {
  let score = 0;

  // Pattern score (max 0.4)
  const patternScore = Math.min(
    patterns.reduce((sum, p) => sum + p.score * 0.15, 0),
    0.4
  );
  score += patternScore;

  // Impersonation score (max 0.4)
  if (impersonation?.isImpersonation) {
    const impScore = calculateImpersonationRisk(impersonation);
    score += impScore.score * 0.4;
  }

  // Financial risk score (max 0.2)
  if (financialRisk.hasFinancialRequest) {
    const riskMultiplier: Record<string, number> = {
      critical: 1.0,
      high: 0.7,
      medium: 0.4,
      low: 0.2,
    };
    score += 0.2 * (riskMultiplier[financialRisk.riskLevel] || 0);
  }

  // Compound attack bonus
  if (isCompoundAttack) {
    score = Math.min(score + 0.15, 1.0);
  }

  // Critical signals override
  const hasCritical = signals.some(s => s.severity === 'critical');
  if (hasCritical) {
    score = Math.max(score, 0.8);
  }

  // Determine risk level
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  if (score >= 0.8 || hasCritical) {
    riskLevel = 'critical';
  } else if (score >= 0.5) {
    riskLevel = 'high';
  } else if (score >= 0.3) {
    riskLevel = 'medium';
  }

  // Determine if BEC
  const isBEC = score >= 0.5 ||
    (impersonation?.isImpersonation && financialRisk.hasFinancialRequest) ||
    hasCritical;

  return {
    confidence: score,
    riskLevel,
    isBEC,
  };
}

/**
 * Generate human-readable summary
 */
function generateSummary(
  isBEC: boolean,
  signals: BECSignal[],
  impersonation: ImpersonationResult | null,
  financialRisk: FinancialRisk
): string {
  if (!isBEC && signals.length === 0) {
    return 'No BEC indicators detected';
  }

  const parts: string[] = [];

  // Impersonation summary
  if (impersonation?.isImpersonation) {
    if (impersonation.matchedVIP) {
      parts.push(`Possible impersonation of ${impersonation.matchedVIP.displayName} (${impersonation.matchedVIP.role})`);
    } else {
      parts.push('Executive impersonation attempt detected');
    }
  }

  // Financial summary
  if (financialRisk.hasFinancialRequest && financialRisk.maxAmount > 0) {
    parts.push(`Financial request for ${formatCurrency(financialRisk.maxAmount)}`);
  }

  // Pattern summary
  const categories = [...new Set(signals.map(s => s.category))];
  const categoryNames: Record<string, string> = {
    wire_fraud: 'wire transfer request',
    gift_card: 'gift card scam',
    invoice_fraud: 'invoice fraud',
    payroll_diversion: 'payroll diversion',
    urgency_pressure: 'urgency tactics',
    executive_spoof: 'authority manipulation',
    impersonation: 'identity spoofing',
  };

  const patternParts = categories
    .filter(c => c !== 'impersonation' && categoryNames[c])
    .map(c => categoryNames[c]);

  if (patternParts.length > 0) {
    parts.push(`Detected: ${patternParts.join(', ')}`);
  }

  if (parts.length === 0) {
    return 'Suspicious patterns detected';
  }

  return parts.join('. ');
}

/**
 * Format currency for display
 */
function formatCurrency(amount: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 0,
    maximumFractionDigits: 0,
  }).format(amount);
}

/**
 * Quick BEC check (lightweight, no DB calls)
 */
export function quickBECCheck(subject: string, body: string): {
  isSuspicious: boolean;
  topPatterns: string[];
  urgencyLevel: 'low' | 'medium' | 'high';
} {
  const patterns = checkBECPatterns(subject, body);
  const amounts = extractAmounts(`${subject} ${body}`);

  const isSuspicious = patterns.length >= 2 ||
    patterns.some(p => p.pattern.severity === 'critical') ||
    (patterns.length > 0 && amounts.length > 0);

  const topPatterns = patterns
    .slice(0, 3)
    .map(p => p.pattern.name);

  // Check urgency
  const urgencyPattern = patterns.find(p => p.pattern.id === 'urgency_pressure');
  let urgencyLevel: 'low' | 'medium' | 'high' = 'low';
  if (urgencyPattern) {
    urgencyLevel = urgencyPattern.score > 0.5 ? 'high' : 'medium';
  }

  return {
    isSuspicious,
    topPatterns,
    urgencyLevel,
  };
}

/**
 * Get BEC risk factors for a tenant
 */
export async function getTenantBECRiskFactors(tenantId: string): Promise<{
  hasVIPList: boolean;
  vipCount: number;
  highRiskRoles: string[];
}> {
  const vips = await getVIPList(tenantId);

  const highRiskRoles = ['executive', 'finance'];
  const hasHighRiskVIPs = vips.filter(v =>
    highRiskRoles.includes(v.role)
  );

  return {
    hasVIPList: vips.length > 0,
    vipCount: vips.length,
    highRiskRoles: [...new Set(hasHighRiskVIPs.map(v => v.role))],
  };
}

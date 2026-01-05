/**
 * BEC Attack Pattern Detection
 * Detects common Business Email Compromise patterns
 */

export interface BECPattern {
  id: string;
  name: string;
  description: string;
  category: BECCategory;
  severity: 'low' | 'medium' | 'high' | 'critical';
  indicators: PatternIndicator[];
}

export type BECCategory =
  | 'wire_fraud'           // Wire transfer requests
  | 'invoice_fraud'        // Fake/modified invoices
  | 'gift_card'            // Gift card scams
  | 'payroll_diversion'    // W-2/payroll fraud
  | 'vendor_impersonation' // Vendor account changes
  | 'executive_spoof'      // CEO/CFO impersonation
  | 'urgency_pressure'     // Urgent action requests
  | 'credential_theft';    // Account compromise attempts

export interface PatternIndicator {
  type: 'keyword' | 'phrase' | 'regex' | 'amount' | 'combination';
  pattern: string | RegExp;
  weight: number;
  context?: 'subject' | 'body' | 'both';
}

export interface PatternMatch {
  pattern: BECPattern;
  matches: Array<{
    indicator: PatternIndicator;
    matchedText: string;
    location: 'subject' | 'body';
  }>;
  score: number;
}

// Wire transfer fraud patterns
const WIRE_FRAUD_KEYWORDS = [
  'wire transfer', 'wire payment', 'wire funds',
  'bank transfer', 'bank wire', 'transfer funds',
  'send payment', 'payment instruction', 'payment details',
  'banking information', 'bank account', 'routing number',
  'swift code', 'iban', 'aba number',
  'account number', 'beneficiary',
];

// Gift card fraud patterns
const GIFT_CARD_KEYWORDS = [
  'gift card', 'gift cards', 'itunes card', 'itunes cards',
  'google play card', 'google play cards', 'google play',
  'amazon card', 'amazon cards', 'amazon gift',
  'steam card', 'steam cards', 'visa gift', 'visa cards',
  'prepaid card', 'prepaid cards', 'buy cards', 'purchase cards',
  'scratch off', 'redemption code', 'card numbers', 'pin numbers',
];

// Invoice fraud patterns
const INVOICE_FRAUD_KEYWORDS = [
  'updated invoice', 'revised invoice', 'new invoice',
  'banking changed', 'account changed', 'payment method changed',
  'vendor change', 'supplier change', 'new bank details',
  'payment redirect', 'updated payment',
];

// Payroll diversion patterns
const PAYROLL_DIVERSION_KEYWORDS = [
  'direct deposit', 'change my direct deposit', 'update payroll',
  'w-2', 'w2 form', 'tax form', 'employee tax',
  'payroll change', 'salary deposit', 'pay stub',
];

// Urgency indicators
const URGENCY_KEYWORDS = [
  'urgent', 'urgently', 'asap', 'immediately', 'right away',
  'time sensitive', 'critical', 'important', 'priority',
  'today', 'now', 'before end of day', 'before close',
  'deadline', 'must be done', 'need this done',
  "don't delay", 'cannot wait', "can't wait",
];

// Secrecy indicators (red flag when combined with financial)
const SECRECY_KEYWORDS = [
  'confidential', 'keep this between us', 'private matter',
  "don't tell anyone", 'just between us', 'secret',
  "don't mention", 'discreet', 'quietly',
  "don't involve", 'bypass', 'skip the usual',
];

// Authority/pressure indicators
const AUTHORITY_KEYWORDS = [
  'i need you to', "i'm asking you", 'can you handle',
  'take care of this', 'personal favor', 'trust you',
  'count on you', 'rely on you', 'need your help',
  "i'm in a meeting", 'traveling', 'out of office',
  "can't call", "can't talk", 'email only',
];

// Amount patterns
const AMOUNT_PATTERNS = [
  /\$\s*[\d,]+(?:\.\d{2})?/g,                    // $1,000.00
  /\d+(?:,\d{3})*(?:\.\d{2})?\s*(?:usd|dollars?)/gi, // 1000 USD
  /(?:usd|dollars?)\s*\d+(?:,\d{3})*(?:\.\d{2})?/gi, // USD 1000
];

/**
 * BEC Pattern Library
 */
export const BEC_PATTERNS: BECPattern[] = [
  {
    id: 'wire_transfer_request',
    name: 'Wire Transfer Request',
    description: 'Request to initiate or redirect wire transfer',
    category: 'wire_fraud',
    severity: 'critical',
    indicators: [
      ...WIRE_FRAUD_KEYWORDS.map(k => ({
        type: 'keyword' as const,
        pattern: k,
        weight: 0.3,
        context: 'both' as const,
      })),
      {
        type: 'regex',
        pattern: /(?:wire|transfer|send)\s+(?:the\s+)?(?:funds?|money|payment)/i,
        weight: 0.4,
        context: 'both',
      },
    ],
  },
  {
    id: 'gift_card_scam',
    name: 'Gift Card Scam',
    description: 'Request to purchase gift cards',
    category: 'gift_card',
    severity: 'high',
    indicators: [
      ...GIFT_CARD_KEYWORDS.map(k => ({
        type: 'keyword' as const,
        pattern: k,
        weight: 0.35,
        context: 'both' as const,
      })),
      {
        type: 'regex',
        pattern: /(?:buy|purchase|get)\s+(?:some\s+)?(?:\d+\s+)?gift\s*cards?/i,
        weight: 0.5,
        context: 'both',
      },
    ],
  },
  {
    id: 'invoice_fraud',
    name: 'Invoice/Payment Fraud',
    description: 'Attempt to redirect invoice payments',
    category: 'invoice_fraud',
    severity: 'critical',
    indicators: [
      ...INVOICE_FRAUD_KEYWORDS.map(k => ({
        type: 'keyword' as const,
        pattern: k,
        weight: 0.3,
        context: 'both' as const,
      })),
      {
        type: 'regex',
        pattern: /(?:our|my)\s+(?:bank(?:ing)?|account)\s+(?:details?|info(?:rmation)?)\s+(?:has|have)\s+changed/i,
        weight: 0.5,
        context: 'both',
      },
    ],
  },
  {
    id: 'payroll_diversion',
    name: 'Payroll Diversion',
    description: 'Attempt to redirect payroll or obtain tax info',
    category: 'payroll_diversion',
    severity: 'high',
    indicators: [
      ...PAYROLL_DIVERSION_KEYWORDS.map(k => ({
        type: 'keyword' as const,
        pattern: k,
        weight: 0.3,
        context: 'both' as const,
      })),
      {
        type: 'regex',
        pattern: /(?:change|update)\s+(?:my\s+)?direct\s+deposit/i,
        weight: 0.5,
        context: 'both',
      },
    ],
  },
  {
    id: 'urgency_pressure',
    name: 'Urgency & Pressure',
    description: 'High-pressure tactics to rush decision',
    category: 'urgency_pressure',
    severity: 'medium',
    indicators: [
      ...URGENCY_KEYWORDS.map(k => ({
        type: 'keyword' as const,
        pattern: k,
        weight: 0.2,
        context: 'both' as const,
      })),
      {
        type: 'regex',
        pattern: /(?:need|must|have to)\s+(?:be\s+)?(?:done|completed?|sent)\s+(?:by\s+)?(?:today|now|immediately)/i,
        weight: 0.3,
        context: 'both',
      },
    ],
  },
  {
    id: 'secrecy_request',
    name: 'Secrecy Request',
    description: 'Request to keep transaction confidential',
    category: 'executive_spoof',
    severity: 'high',
    indicators: [
      ...SECRECY_KEYWORDS.map(k => ({
        type: 'keyword' as const,
        pattern: k,
        weight: 0.25,
        context: 'both' as const,
      })),
      {
        type: 'regex',
        pattern: /(?:keep|this)\s+(?:is\s+)?(?:between\s+us|confidential|private)/i,
        weight: 0.4,
        context: 'both',
      },
    ],
  },
  {
    id: 'authority_manipulation',
    name: 'Authority Manipulation',
    description: 'Using authority/trust to pressure action',
    category: 'executive_spoof',
    severity: 'medium',
    indicators: [
      ...AUTHORITY_KEYWORDS.map(k => ({
        type: 'keyword' as const,
        pattern: k,
        weight: 0.2,
        context: 'both' as const,
      })),
    ],
  },
];

/**
 * Check text against BEC patterns
 */
export function checkBECPatterns(
  subject: string,
  body: string
): PatternMatch[] {
  const matches: PatternMatch[] = [];
  const normalizedSubject = subject.toLowerCase();
  const normalizedBody = body.toLowerCase();

  for (const pattern of BEC_PATTERNS) {
    const patternMatches: PatternMatch['matches'] = [];
    let totalScore = 0;

    for (const indicator of pattern.indicators) {
      const textsToCheck: Array<{ text: string; location: 'subject' | 'body' }> = [];

      if (indicator.context === 'subject' || indicator.context === 'both') {
        textsToCheck.push({ text: normalizedSubject, location: 'subject' });
      }
      if (indicator.context === 'body' || indicator.context === 'both') {
        textsToCheck.push({ text: normalizedBody, location: 'body' });
      }

      for (const { text, location } of textsToCheck) {
        let matched = false;
        let matchedText = '';

        if (indicator.type === 'keyword' || indicator.type === 'phrase') {
          const searchTerm = indicator.pattern.toString().toLowerCase();
          if (text.includes(searchTerm)) {
            matched = true;
            matchedText = searchTerm;
          }
        } else if (indicator.type === 'regex' && indicator.pattern instanceof RegExp) {
          const regex = new RegExp(indicator.pattern.source, indicator.pattern.flags);
          const match = text.match(regex);
          if (match) {
            matched = true;
            matchedText = match[0];
          }
        }

        if (matched) {
          patternMatches.push({
            indicator,
            matchedText,
            location,
          });
          totalScore += indicator.weight;
        }
      }
    }

    if (patternMatches.length > 0) {
      matches.push({
        pattern,
        matches: patternMatches,
        score: Math.min(totalScore, 1.0),
      });
    }
  }

  // Sort by score descending
  return matches.sort((a, b) => b.score - a.score);
}

/**
 * Extract monetary amounts from text
 */
export function extractAmounts(text: string): Array<{
  amount: number;
  original: string;
  position: number;
}> {
  const amounts: Array<{ amount: number; original: string; position: number }> = [];

  for (const pattern of AMOUNT_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match;

    while ((match = regex.exec(text)) !== null) {
      const original = match[0];
      // Parse the numeric value
      const numericString = original.replace(/[^0-9.]/g, '');
      const amount = parseFloat(numericString);

      if (!isNaN(amount) && amount > 0) {
        amounts.push({
          amount,
          original,
          position: match.index,
        });
      }
    }
  }

  return amounts;
}

/**
 * Check for high-risk amount thresholds
 */
export function assessAmountRisk(amounts: Array<{ amount: number }>): {
  hasHighRiskAmount: boolean;
  maxAmount: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
} {
  if (amounts.length === 0) {
    return { hasHighRiskAmount: false, maxAmount: 0, riskLevel: 'low' };
  }

  const maxAmount = Math.max(...amounts.map(a => a.amount));

  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';

  if (maxAmount >= 100000) {
    riskLevel = 'critical';
  } else if (maxAmount >= 25000) {
    riskLevel = 'high';
  } else if (maxAmount >= 5000) {
    riskLevel = 'medium';
  }

  return {
    hasHighRiskAmount: maxAmount >= 5000,
    maxAmount,
    riskLevel,
  };
}

/**
 * Detect compound BEC attack (multiple patterns combined)
 */
export function detectCompoundAttack(matches: PatternMatch[]): {
  isCompoundAttack: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  explanation: string;
} {
  if (matches.length < 2) {
    return {
      isCompoundAttack: false,
      severity: 'low',
      explanation: 'Single pattern or no patterns detected',
    };
  }

  const categories = new Set(matches.map(m => m.pattern.category));

  // Critical combinations
  const criticalCombos = [
    ['wire_fraud', 'urgency_pressure'],
    ['wire_fraud', 'executive_spoof'],
    ['gift_card', 'executive_spoof'],
    ['invoice_fraud', 'urgency_pressure'],
  ];

  for (const combo of criticalCombos) {
    if (combo.every(c => categories.has(c as BECCategory))) {
      return {
        isCompoundAttack: true,
        severity: 'critical',
        explanation: `Critical combination detected: ${combo.join(' + ')}`,
      };
    }
  }

  // High-risk: financial pattern + pressure
  const financialCategories: BECCategory[] = ['wire_fraud', 'gift_card', 'invoice_fraud', 'payroll_diversion'];
  const pressureCategories: BECCategory[] = ['urgency_pressure', 'executive_spoof'];

  const hasFinancial = financialCategories.some(c => categories.has(c));
  const hasPressure = pressureCategories.some(c => categories.has(c));

  if (hasFinancial && hasPressure) {
    return {
      isCompoundAttack: true,
      severity: 'high',
      explanation: 'Financial request combined with pressure tactics',
    };
  }

  // Medium: multiple patterns
  if (matches.length >= 3) {
    return {
      isCompoundAttack: true,
      severity: 'medium',
      explanation: `Multiple BEC indicators detected (${matches.length} patterns)`,
    };
  }

  return {
    isCompoundAttack: false,
    severity: 'low',
    explanation: 'Patterns detected but not in high-risk combination',
  };
}

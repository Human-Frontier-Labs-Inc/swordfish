/**
 * BEC Detection Engine Tests
 * Tests for Business Email Compromise detection
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  checkBECPatterns,
  extractAmounts,
  assessAmountRisk,
  detectCompoundAttack,
  type PatternMatch,
} from '@/lib/detection/bec/patterns';
import { quickBECCheck } from '@/lib/detection/bec/detector';

// Mock the VIP list functions
vi.mock('@/lib/detection/bec/vip-list', () => ({
  getVIPList: vi.fn().mockResolvedValue([
    {
      id: 'vip-1',
      tenantId: 'test-tenant',
      email: 'john.smith@company.com',
      displayName: 'John Smith',
      title: 'CEO',
      role: 'executive',
      aliases: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      id: 'vip-2',
      tenantId: 'test-tenant',
      email: 'jane.doe@company.com',
      displayName: 'Jane Doe',
      title: 'CFO',
      role: 'finance',
      aliases: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ]),
  findVIPByEmail: vi.fn().mockResolvedValue(null),
  findVIPByDisplayName: vi.fn().mockResolvedValue([]),
  checkVIPImpersonation: vi.fn().mockResolvedValue({
    isImpersonation: false,
    confidence: 0,
  }),
}));

describe('BEC Pattern Detection', () => {
  describe('Wire Transfer Fraud', () => {
    it('should detect wire transfer requests', () => {
      const subject = 'Urgent: Wire Transfer Needed';
      const body = 'Please wire transfer $50,000 to the following account. This is urgent and needs to be done today.';

      const matches = checkBECPatterns(subject, body);

      expect(matches.length).toBeGreaterThan(0);
      expect(matches.some(m => m.pattern.category === 'wire_fraud')).toBe(true);
    });

    it('should detect bank account change requests', () => {
      const subject = 'Updated Banking Information';
      const body = 'Our banking information has changed. Please use the new account number for all future payments.';

      const matches = checkBECPatterns(subject, body);

      expect(matches.some(m => m.pattern.id === 'invoice_fraud')).toBe(true);
    });

    it('should detect SWIFT/routing number requests', () => {
      const subject = 'Payment Details';
      const body = 'Please send the payment to this SWIFT code: ABCD1234. Routing number: 123456789.';

      const matches = checkBECPatterns(subject, body);

      expect(matches.some(m => m.pattern.category === 'wire_fraud')).toBe(true);
    });
  });

  describe('Gift Card Scams', () => {
    it('should detect gift card purchase requests', () => {
      const subject = 'Quick Favor';
      const body = 'I need you to buy 5 iTunes gift cards for $500 each. Please send me the redemption codes.';

      const matches = checkBECPatterns(subject, body);

      expect(matches.some(m => m.pattern.category === 'gift_card')).toBe(true);
    });

    it('should detect various gift card types', () => {
      const testCases = [
        'Buy some Google Play cards',
        'Purchase Amazon gift cards',
        'Get Steam cards for the team',
        'Need prepaid Visa cards',
      ];

      for (const body of testCases) {
        const matches = checkBECPatterns('Request', body);
        expect(matches.some(m => m.pattern.category === 'gift_card')).toBe(true);
      }
    });

    it('should detect scratch off / PIN requests', () => {
      const subject = 'Cards received?';
      const body = 'Once you have the cards, scratch off the back and send me the pin numbers and card numbers.';

      const matches = checkBECPatterns(subject, body);

      expect(matches.some(m => m.pattern.category === 'gift_card')).toBe(true);
    });
  });

  describe('Invoice Fraud', () => {
    it('should detect invoice payment redirect attempts', () => {
      const subject = 'Updated Invoice';
      const body = 'Please note our bank details have changed. Use the updated payment method for this invoice.';

      const matches = checkBECPatterns(subject, body);

      expect(matches.some(m => m.pattern.category === 'invoice_fraud')).toBe(true);
    });

    it('should detect vendor change notifications', () => {
      const subject = 'Vendor Information Update';
      const body = 'We have a new bank details for vendor payments. Please redirect all payments to the new account.';

      const matches = checkBECPatterns(subject, body);

      expect(matches.some(m => m.pattern.category === 'invoice_fraud')).toBe(true);
    });
  });

  describe('Payroll Diversion', () => {
    it('should detect direct deposit change requests', () => {
      const subject = 'Direct Deposit Update';
      const body = 'Hi HR, I need to change my direct deposit information. Please update my payroll to the new account.';

      const matches = checkBECPatterns(subject, body);

      expect(matches.some(m => m.pattern.category === 'payroll_diversion')).toBe(true);
    });

    it('should detect W-2 / tax form requests', () => {
      const subject = 'W2 Forms Needed';
      const body = 'Please send me all employee W-2 forms and tax information for the audit.';

      const matches = checkBECPatterns(subject, body);

      expect(matches.some(m => m.pattern.category === 'payroll_diversion')).toBe(true);
    });
  });

  describe('Urgency & Pressure Tactics', () => {
    it('should detect urgent language', () => {
      const subject = 'URGENT - Action Required Immediately';
      const body = 'This must be done ASAP. Cannot wait. Need this completed today before close of business.';

      const matches = checkBECPatterns(subject, body);

      expect(matches.some(m => m.pattern.category === 'urgency_pressure')).toBe(true);
    });

    it('should detect deadline pressure', () => {
      const subject = 'Time Sensitive Matter';
      const body = 'This is critical and time sensitive. Must be done now, deadline is in 1 hour.';

      const matches = checkBECPatterns(subject, body);

      expect(matches.some(m => m.pattern.category === 'urgency_pressure')).toBe(true);
    });
  });

  describe('Executive Impersonation / Authority', () => {
    it('should detect secrecy requests', () => {
      const subject = 'Confidential Request';
      const body = 'This is a private matter. Keep this between us and dont tell anyone about this transaction.';

      const matches = checkBECPatterns(subject, body);

      expect(matches.some(m => m.pattern.category === 'executive_spoof')).toBe(true);
    });

    it('should detect authority manipulation', () => {
      const subject = 'Personal Favor';
      const body = 'I need you to handle this for me. Im in a meeting and cant call. Trust you to take care of this.';

      const matches = checkBECPatterns(subject, body);

      expect(matches.some(m => m.pattern.category === 'executive_spoof')).toBe(true);
    });
  });
});

describe('Amount Extraction', () => {
  it('should extract USD amounts with $ symbol', () => {
    const text = 'Please wire $50,000 to the account. Additional payment of $1,234.56 needed.';

    const amounts = extractAmounts(text);

    expect(amounts.length).toBe(2);
    expect(amounts[0].amount).toBe(50000);
    expect(amounts[1].amount).toBe(1234.56);
  });

  it('should extract amounts with USD suffix', () => {
    const text = 'Transfer 25000 USD to complete the transaction.';

    const amounts = extractAmounts(text);

    expect(amounts.length).toBeGreaterThan(0);
    expect(amounts[0].amount).toBe(25000);
  });

  it('should extract amounts with dollar suffix', () => {
    const text = 'The total is 10,000 dollars.';

    const amounts = extractAmounts(text);

    expect(amounts.length).toBeGreaterThan(0);
    expect(amounts[0].amount).toBe(10000);
  });

  it('should handle amounts in both subject and body', () => {
    const text = 'Invoice for $5,000 - Payment of $3,000 due immediately';

    const amounts = extractAmounts(text);

    expect(amounts.length).toBe(2);
  });

  it('should return empty array for no amounts', () => {
    const text = 'Please review the attached document.';

    const amounts = extractAmounts(text);

    expect(amounts.length).toBe(0);
  });
});

describe('Amount Risk Assessment', () => {
  it('should classify critical risk for amounts >= $100,000', () => {
    const amounts = [{ amount: 150000 }];

    const risk = assessAmountRisk(amounts);

    expect(risk.riskLevel).toBe('critical');
    expect(risk.hasHighRiskAmount).toBe(true);
    expect(risk.maxAmount).toBe(150000);
  });

  it('should classify high risk for amounts >= $25,000', () => {
    const amounts = [{ amount: 50000 }];

    const risk = assessAmountRisk(amounts);

    expect(risk.riskLevel).toBe('high');
    expect(risk.hasHighRiskAmount).toBe(true);
  });

  it('should classify medium risk for amounts >= $5,000', () => {
    const amounts = [{ amount: 10000 }];

    const risk = assessAmountRisk(amounts);

    expect(risk.riskLevel).toBe('medium');
    expect(risk.hasHighRiskAmount).toBe(true);
  });

  it('should classify low risk for amounts < $5,000', () => {
    const amounts = [{ amount: 1000 }];

    const risk = assessAmountRisk(amounts);

    expect(risk.riskLevel).toBe('low');
    expect(risk.hasHighRiskAmount).toBe(false);
  });

  it('should use maximum amount for risk assessment', () => {
    const amounts = [{ amount: 1000 }, { amount: 50000 }, { amount: 500 }];

    const risk = assessAmountRisk(amounts);

    expect(risk.maxAmount).toBe(50000);
    expect(risk.riskLevel).toBe('high');
  });

  it('should handle empty amounts', () => {
    const amounts: Array<{ amount: number }> = [];

    const risk = assessAmountRisk(amounts);

    expect(risk.riskLevel).toBe('low');
    expect(risk.hasHighRiskAmount).toBe(false);
    expect(risk.maxAmount).toBe(0);
  });
});

describe('Compound Attack Detection', () => {
  it('should detect critical wire fraud + urgency combination', () => {
    const matches: PatternMatch[] = [
      {
        pattern: { id: 'wire_transfer', name: 'Wire Transfer', description: '', category: 'wire_fraud', severity: 'critical', indicators: [] },
        matches: [],
        score: 0.5,
      },
      {
        pattern: { id: 'urgency', name: 'Urgency', description: '', category: 'urgency_pressure', severity: 'medium', indicators: [] },
        matches: [],
        score: 0.3,
      },
    ];

    const result = detectCompoundAttack(matches);

    expect(result.isCompoundAttack).toBe(true);
    expect(result.severity).toBe('critical');
  });

  it('should detect critical wire fraud + executive spoof combination', () => {
    const matches: PatternMatch[] = [
      {
        pattern: { id: 'wire_transfer', name: 'Wire Transfer', description: '', category: 'wire_fraud', severity: 'critical', indicators: [] },
        matches: [],
        score: 0.5,
      },
      {
        pattern: { id: 'authority', name: 'Authority', description: '', category: 'executive_spoof', severity: 'medium', indicators: [] },
        matches: [],
        score: 0.3,
      },
    ];

    const result = detectCompoundAttack(matches);

    expect(result.isCompoundAttack).toBe(true);
    expect(result.severity).toBe('critical');
  });

  it('should detect high risk financial + pressure combination', () => {
    const matches: PatternMatch[] = [
      {
        pattern: { id: 'gift_card', name: 'Gift Card', description: '', category: 'gift_card', severity: 'high', indicators: [] },
        matches: [],
        score: 0.4,
      },
      {
        pattern: { id: 'secrecy', name: 'Secrecy', description: '', category: 'executive_spoof', severity: 'high', indicators: [] },
        matches: [],
        score: 0.3,
      },
    ];

    const result = detectCompoundAttack(matches);

    expect(result.isCompoundAttack).toBe(true);
    expect(['critical', 'high']).toContain(result.severity);
  });

  it('should detect medium severity for 3+ patterns', () => {
    const matches: PatternMatch[] = [
      {
        pattern: { id: 'p1', name: 'P1', description: '', category: 'credential_theft', severity: 'low', indicators: [] },
        matches: [],
        score: 0.2,
      },
      {
        pattern: { id: 'p2', name: 'P2', description: '', category: 'credential_theft', severity: 'low', indicators: [] },
        matches: [],
        score: 0.2,
      },
      {
        pattern: { id: 'p3', name: 'P3', description: '', category: 'credential_theft', severity: 'low', indicators: [] },
        matches: [],
        score: 0.2,
      },
    ];

    const result = detectCompoundAttack(matches);

    expect(result.isCompoundAttack).toBe(true);
    expect(result.severity).toBe('medium');
  });

  it('should not flag single pattern as compound', () => {
    const matches: PatternMatch[] = [
      {
        pattern: { id: 'wire_transfer', name: 'Wire Transfer', description: '', category: 'wire_fraud', severity: 'critical', indicators: [] },
        matches: [],
        score: 0.5,
      },
    ];

    const result = detectCompoundAttack(matches);

    expect(result.isCompoundAttack).toBe(false);
  });

  it('should handle empty matches', () => {
    const result = detectCompoundAttack([]);

    expect(result.isCompoundAttack).toBe(false);
    expect(result.severity).toBe('low');
  });
});

describe('Quick BEC Check', () => {
  it('should identify suspicious emails with multiple patterns', () => {
    const subject = 'Urgent Wire Transfer';
    const body = 'Please wire $50,000 immediately. This is confidential.';

    const result = quickBECCheck(subject, body);

    expect(result.isSuspicious).toBe(true);
    expect(result.topPatterns.length).toBeGreaterThan(0);
  });

  it('should detect high urgency level', () => {
    const subject = 'URGENT - IMMEDIATE ACTION REQUIRED';
    const body = 'This must be done NOW. Cannot wait. ASAP please.';

    const result = quickBECCheck(subject, body);

    expect(['medium', 'high']).toContain(result.urgencyLevel);
  });

  it('should flag pattern + amount combination as suspicious', () => {
    const subject = 'Invoice';
    const body = 'Please pay this invoice for $25,000 using wire transfer.';

    const result = quickBECCheck(subject, body);

    expect(result.isSuspicious).toBe(true);
  });

  it('should not flag clean emails as suspicious', () => {
    const subject = 'Weekly Team Meeting';
    const body = 'Reminder: Our weekly team meeting is scheduled for tomorrow at 2pm.';

    const result = quickBECCheck(subject, body);

    expect(result.isSuspicious).toBe(false);
    expect(result.topPatterns.length).toBe(0);
  });

  it('should return top 3 patterns max', () => {
    const subject = 'Urgent Wire Gift Card Invoice';
    const body = 'Wire transfer $50,000. Buy gift cards. Updated invoice. Direct deposit change. Confidential.';

    const result = quickBECCheck(subject, body);

    expect(result.topPatterns.length).toBeLessThanOrEqual(3);
  });
});

describe('BEC Detection Edge Cases', () => {
  it('should handle empty strings', () => {
    const matches = checkBECPatterns('', '');

    expect(matches).toEqual([]);
  });

  it('should be case insensitive', () => {
    const lowerMatches = checkBECPatterns('wire transfer needed', 'please send payment');
    const upperMatches = checkBECPatterns('WIRE TRANSFER NEEDED', 'PLEASE SEND PAYMENT');

    expect(lowerMatches.length).toBe(upperMatches.length);
  });

  it('should handle special characters in text', () => {
    const subject = 'Urgent!!! Wire $$$ Now!!!';
    const body = 'Please wire $50,000.00 ASAP!!! @#$%^&*()';

    // Should not throw
    const matches = checkBECPatterns(subject, body);
    expect(Array.isArray(matches)).toBe(true);
  });

  it('should handle very long text', () => {
    const longBody = 'wire transfer '.repeat(1000);

    const matches = checkBECPatterns('Test', longBody);

    expect(Array.isArray(matches)).toBe(true);
  });

  it('should handle unicode characters', () => {
    const subject = 'Urg€nt Wïre Trαnsfer';
    const body = 'Please send pαyment immediately.';

    // Should not throw
    const matches = checkBECPatterns(subject, body);
    expect(Array.isArray(matches)).toBe(true);
  });
});

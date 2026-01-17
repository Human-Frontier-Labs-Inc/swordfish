/**
 * Email Classification Tests
 *
 * Tests for the email type classification system that runs
 * BEFORE threat detection to provide context-aware scoring.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  classifyEmailType,
  explainClassification,
  type EmailType,
  type EmailClassification,
} from '@/lib/detection/classifier';
import {
  detectMarketingSignals,
  shouldReduceThreatScore,
  type MarketingSignals,
} from '@/lib/detection/classifier/marketing-signals';
import {
  lookupSender,
  isLegitimateReplyTo,
  getAllKnownSenders,
  getSendersByCategory,
  SenderCategory,
  type SenderInfo,
} from '@/lib/detection/classifier/sender-registry';
import type { ParsedEmail } from '@/lib/detection/types';

// Helper to create test emails
function createTestEmail(overrides: Partial<ParsedEmail> = {}): ParsedEmail {
  return {
    messageId: 'test-message-id',
    subject: 'Test Subject',
    from: {
      address: 'sender@example.com',
      displayName: 'Test Sender',
      domain: 'example.com',
    },
    to: [{
      address: 'recipient@company.com',
      displayName: 'Recipient',
      domain: 'company.com',
    }],
    date: new Date(),
    headers: {},
    body: {
      text: 'Test email body',
      html: '<p>Test email body</p>',
    },
    attachments: [],
    rawHeaders: '',
    ...overrides,
  };
}

describe('Email Classification', () => {
  console.log('Test suite starting...');

  describe('Marketing Signals Detection', () => {
    it('should detect unsubscribe links', () => {
      const email = createTestEmail({
        body: {
          text: 'Click here to unsubscribe from our newsletter',
          html: '<a href="https://example.com/unsubscribe">Unsubscribe</a>',
        },
      });

      const signals = detectMarketingSignals(email);

      expect(signals.hasUnsubscribeLink).toBe(true);
      expect(signals.signals).toContain('unsubscribe_link');
    });

    it('should detect List-Unsubscribe header', () => {
      const email = createTestEmail({
        headers: {
          'list-unsubscribe': '<mailto:unsubscribe@example.com>',
        },
      });

      const signals = detectMarketingSignals(email);

      expect(signals.hasUnsubscribeHeader).toBe(true);
      expect(signals.signals).toContain('unsubscribe_header');
    });

    it('should detect view in browser links', () => {
      const email = createTestEmail({
        body: {
          text: 'View this email in your browser',
          html: '<a href="https://example.com/view">View in browser</a>',
        },
      });

      const signals = detectMarketingSignals(email);

      expect(signals.hasViewInBrowserLink).toBe(true);
    });

    it('should detect tracking pixels', () => {
      const email = createTestEmail({
        body: {
          text: '',
          html: '<img src="https://tracking.example.com/pixel.gif" width="1" height="1">',
        },
      });

      const signals = detectMarketingSignals(email);

      expect(signals.hasTrackingPixels).toBe(true);
    });

    it('should detect social media links', () => {
      const email = createTestEmail({
        body: {
          text: 'Follow us on Facebook and Twitter',
          html: '<a href="https://facebook.com/company">Facebook</a>',
        },
      });

      const signals = detectMarketingSignals(email);

      expect(signals.hasSocialLinks).toBe(true);
    });

    it('should detect promotional subject lines', () => {
      const email = createTestEmail({
        subject: '50% OFF - Limited Time Flash Sale!',
        body: { text: '', html: '' },
      });

      const signals = detectMarketingSignals(email);

      expect(signals.hasPromoLanguage).toBe(true);
    });

    it('should detect discount offers', () => {
      const email = createTestEmail({
        body: {
          text: 'Use code SAVE20 for 20% off your order! Free shipping included.',
          html: '',
        },
      });

      const signals = detectMarketingSignals(email);

      expect(signals.hasDiscountOffer).toBe(true);
    });

    it('should detect bulk mail headers', () => {
      const email = createTestEmail({
        headers: {
          'x-mailchimp': 'campaign-12345',
          'precedence': 'bulk',
        },
      });

      const signals = detectMarketingSignals(email);

      expect(signals.hasBulkMailHeaders).toBe(true);
    });

    it('should detect marketing footer patterns', () => {
      const email = createTestEmail({
        body: {
          text: '© 2025 Company Inc. All rights reserved. Privacy Policy | Terms of Service | Contact Us',
          html: '',
        },
      });

      const signals = detectMarketingSignals(email);

      expect(signals.hasMarketingFooter).toBe(true);
    });

    it('should classify as marketing with multiple signals', () => {
      const email = createTestEmail({
        subject: 'Your Weekly Newsletter - New Arrivals Inside!',
        headers: {
          'list-unsubscribe': '<mailto:unsub@newsletter.com>',
        },
        body: {
          text: 'Check out our new collection! Click to unsubscribe. © 2025 Shop Inc. Privacy Policy.',
          html: '<img src="https://track.example.com/open" width="1" height="1">',
        },
      });

      const signals = detectMarketingSignals(email);

      expect(signals.isMarketing).toBe(true);
      expect(signals.confidence).toBeGreaterThan(0.5);
      expect(signals.signalCount).toBeGreaterThanOrEqual(3);
    });

    it('should not classify personal emails as marketing', () => {
      const email = createTestEmail({
        subject: 'Re: Meeting tomorrow',
        body: {
          text: 'Hi John, looking forward to our meeting tomorrow. Let me know if 2pm works.',
          html: '',
        },
      });

      const signals = detectMarketingSignals(email);

      expect(signals.isMarketing).toBe(false);
      expect(signals.signalCount).toBe(0);
    });
  });

  describe('Known Sender Registry', () => {
    it('should recognize Amazon as a retail sender', async () => {
      const sender = await lookupSender('orders@amazon.com', 'amazon.com');

      expect(sender).not.toBeNull();
      expect(sender?.name).toBe('Amazon');
      expect(sender?.category).toBe(SenderCategory.RETAIL);
    });

    it('should recognize email subdomains of known senders', async () => {
      const sender = await lookupSender('noreply@email.amazon.com', 'email.amazon.com');

      expect(sender).not.toBeNull();
      expect(sender?.name).toBe('Amazon');
    });

    it('should recognize The Fresh Market', async () => {
      const sender = await lookupSender('freshideas@thefreshmarketmail.com', 'thefreshmarketmail.com');

      expect(sender).not.toBeNull();
      expect(sender?.name).toBe('The Fresh Market');
      expect(sender?.category).toBe(SenderCategory.RETAIL);
    });

    it('should recognize Humble Bundle', async () => {
      const sender = await lookupSender('contact@mailer.humblebundle.com', 'mailer.humblebundle.com');

      expect(sender).not.toBeNull();
      expect(sender?.name).toBe('Humble Bundle');
    });

    it('should recognize PayPal as transactional', async () => {
      const sender = await lookupSender('service@paypal.com', 'paypal.com');

      expect(sender).not.toBeNull();
      expect(sender?.category).toBe(SenderCategory.TRANSACTIONAL);
    });

    it('should recognize GitHub as SaaS', async () => {
      const sender = await lookupSender('noreply@github.com', 'github.com');

      expect(sender).not.toBeNull();
      expect(sender?.category).toBe(SenderCategory.SAAS);
    });

    it('should recognize Mailchimp as marketing platform', async () => {
      const sender = await lookupSender('noreply@mail.mailchimp.com', 'mail.mailchimp.com');

      expect(sender).not.toBeNull();
      expect(sender?.category).toBe(SenderCategory.MARKETING);
    });

    it('should return null for unknown senders', async () => {
      const sender = await lookupSender('unknown@randomdomain.xyz', 'randomdomain.xyz');

      expect(sender).toBeNull();
    });

    it('should validate legitimate reply-to domains', async () => {
      const sender = await lookupSender('noreply@ebay.com', 'ebay.com');

      expect(sender).not.toBeNull();
      expect(isLegitimateReplyTo(sender, 'reply.ebay.com')).toBe(true);
      expect(isLegitimateReplyTo(sender, 'phishing.evil.com')).toBe(false);
    });

    it('should get all known senders', () => {
      const allSenders = getAllKnownSenders();

      expect(allSenders.length).toBeGreaterThan(50);
    });

    it('should filter senders by category', () => {
      const retailers = getSendersByCategory(SenderCategory.RETAIL);
      const financial = getSendersByCategory(SenderCategory.FINANCIAL);

      expect(retailers.length).toBeGreaterThan(10);
      expect(financial.length).toBeGreaterThan(5);

      retailers.forEach((s) => expect(s.category).toBe(SenderCategory.RETAIL));
      financial.forEach((s) => expect(s.category).toBe(SenderCategory.FINANCIAL));
    });
  });

  describe('Email Type Classification', () => {
    it('should classify Amazon emails as marketing from known sender', async () => {
      const email = createTestEmail({
        from: {
          address: 'store-news@amazon.com',
          displayName: 'Amazon.com',
          domain: 'amazon.com',
        },
        subject: 'New deals just for you',
        body: {
          text: 'Check out these exclusive offers. Unsubscribe at any time.',
          html: '',
        },
        headers: {
          'list-unsubscribe': '<mailto:unsub@amazon.com>',
        },
      });

      const classification = await classifyEmailType(email);

      expect(classification.type).toBe('marketing');
      expect(classification.isKnownSender).toBe(true);
      expect(classification.senderInfo?.name).toBe('Amazon');
      expect(classification.threatScoreModifier).toBeLessThan(0.5);
      expect(classification.skipGiftCardDetection).toBe(true);
    });

    it('should classify PayPal receipts as transactional', async () => {
      const email = createTestEmail({
        from: {
          address: 'service@paypal.com',
          displayName: 'PayPal',
          domain: 'paypal.com',
        },
        subject: 'Receipt for your payment',
        body: {
          text: 'You sent a payment of $50.00 to Example Store.',
          html: '',
        },
      });

      const classification = await classifyEmailType(email);

      expect(classification.type).toBe('transactional');
      expect(classification.isKnownSender).toBe(true);
      expect(classification.skipBECDetection).toBe(true);
    });

    it('should classify GitHub notifications as automated', async () => {
      const email = createTestEmail({
        from: {
          address: 'notifications@github.com',
          displayName: 'GitHub',
          domain: 'github.com',
        },
        subject: '[repo-name] New pull request: Fix typo in readme',
        body: {
          text: 'A new pull request has been opened.',
          html: '',
        },
      });

      const classification = await classifyEmailType(email);

      expect(classification.type).toBe('automated');
      expect(classification.isKnownSender).toBe(true);
    });

    it('should classify unknown sender with marketing signals as marketing', async () => {
      const email = createTestEmail({
        from: {
          address: 'newsletter@someshop.com',
          displayName: 'Some Shop',
          domain: 'someshop.com',
        },
        subject: '20% OFF Everything - This Weekend Only!',
        headers: {
          'list-unsubscribe': '<mailto:unsub@someshop.com>',
          'x-campaign': 'weekend-sale',
        },
        body: {
          text: 'Shop now and save! Free shipping on orders over $50. Unsubscribe here. © 2025 Some Shop. Privacy Policy.',
          html: '<img src="https://track.someshop.com/open" width="1" height="1">',
        },
      });

      const classification = await classifyEmailType(email);

      expect(classification.type).toBe('marketing');
      expect(classification.isKnownSender).toBe(false);
      expect(classification.isLikelyMarketing).toBe(true);
      expect(classification.threatScoreModifier).toBeLessThan(0.6);
    });

    it('should classify direct personal emails correctly', async () => {
      const email = createTestEmail({
        from: {
          address: 'john.doe@company.com',
          displayName: 'John Doe',
          domain: 'company.com',
        },
        subject: 'Re: Project update',
        body: {
          text: 'Hi Sarah, thanks for the update. Can you send me the latest report? Best, John',
          html: '',
        },
      });

      const classification = await classifyEmailType(email);

      expect(classification.type).toBe('personal');
      expect(classification.threatScoreModifier).toBe(1.0);
      expect(classification.skipBECDetection).toBe(false);
    });

    it('should correctly set skipGiftCardDetection for retail emails', async () => {
      const email = createTestEmail({
        from: {
          address: 'deals@target.com',
          displayName: 'Target',
          domain: 'target.com',
        },
        subject: 'Gift Cards for Every Occasion',
        body: {
          text: 'Buy gift cards today! Perfect for birthdays, holidays, and more.',
          html: '',
        },
      });

      const classification = await classifyEmailType(email);

      expect(classification.skipGiftCardDetection).toBe(true);
      expect(classification.senderInfo?.category).toBe(SenderCategory.RETAIL);
    });

    it('should NOT skip gift card detection for personal emails', async () => {
      const email = createTestEmail({
        from: {
          address: 'ceo@somecompany.com',
          displayName: 'CEO',
          domain: 'somecompany.com',
        },
        subject: 'Urgent: Need gift cards',
        body: {
          text: 'Please purchase $500 in iTunes gift cards immediately.',
          html: '',
        },
      });

      const classification = await classifyEmailType(email);

      expect(classification.skipGiftCardDetection).toBe(false);
      expect(classification.threatScoreModifier).toBe(1.0);
    });
  });

  describe('Threat Score Modifier', () => {
    it('should reduce score by 70% for known retail senders', async () => {
      const email = createTestEmail({
        from: {
          address: 'deals@bestbuy.com',
          displayName: 'Best Buy',
          domain: 'bestbuy.com',
        },
        subject: 'Flash Sale!',
        body: { text: '', html: '' },
      });

      const classification = await classifyEmailType(email);

      expect(classification.threatScoreModifier).toBe(0.3);
    });

    it('should reduce score by 60% for marketing with 4+ signals', async () => {
      const email = createTestEmail({
        from: {
          address: 'news@unknownshop.com',
          displayName: 'Unknown Shop',
          domain: 'unknownshop.com',
        },
        subject: '50% OFF Sale!',
        headers: {
          'list-unsubscribe': '<mailto:unsub@unknownshop.com>',
          'x-campaign': 'sale',
        },
        body: {
          text: 'Shop now! Free shipping. Unsubscribe. © 2025 Unknown Shop. Follow us on Facebook.',
          html: '<img width="1" height="1" src="https://track.unknownshop.com/pixel">',
        },
      });

      const classification = await classifyEmailType(email);

      // Should have 4+ signals: unsubscribe_link, unsubscribe_header, promo_subject, promo_body, social_links, tracking_pixels, marketing_footer
      expect(classification.marketingSignals.signalCount).toBeGreaterThanOrEqual(4);
      expect(classification.threatScoreModifier).toBeLessThanOrEqual(0.4);
    });

    it('should not reduce score for personal emails', async () => {
      const email = createTestEmail({
        from: {
          address: 'someone@unknown.com',
          displayName: 'Someone',
          domain: 'unknown.com',
        },
        subject: 'Quick question',
        body: {
          text: 'Hi, can you help me with something?',
          html: '',
        },
      });

      const classification = await classifyEmailType(email);

      expect(classification.threatScoreModifier).toBe(1.0);
    });
  });

  describe('Classification Explanation', () => {
    it('should generate human-readable explanation', async () => {
      const email = createTestEmail({
        from: {
          address: 'deals@amazon.com',
          displayName: 'Amazon',
          domain: 'amazon.com',
        },
        subject: 'Your order has shipped',
        headers: {
          'list-unsubscribe': '<mailto:unsub@amazon.com>',
        },
        body: { text: '', html: '' },
      });

      const classification = await classifyEmailType(email);
      const explanation = explainClassification(classification);

      expect(explanation).toContain('marketing');
      expect(explanation).toContain('Amazon');
    });
  });

  describe('Edge Cases', () => {
    it('should handle emails with no body', async () => {
      const email = createTestEmail({
        body: { text: '', html: '' },
      });

      const classification = await classifyEmailType(email);

      expect(classification.type).toBeDefined();
    });

    it('should handle emails with no subject', async () => {
      const email = createTestEmail({
        subject: '',
      });

      const classification = await classifyEmailType(email);

      expect(classification.type).toBeDefined();
    });

    it('should handle emails with missing from address', async () => {
      const email = createTestEmail({
        from: {
          address: '',
          displayName: '',
          domain: '',
        },
      });

      const classification = await classifyEmailType(email);

      expect(classification.type).toBe('unknown');
    });

    it('should handle emails with special characters in sender domain', async () => {
      const email = createTestEmail({
        from: {
          address: 'test@sub.domain-with-hyphens.co.uk',
          displayName: 'Test',
          domain: 'sub.domain-with-hyphens.co.uk',
        },
      });

      const classification = await classifyEmailType(email);

      expect(classification).toBeDefined();
    });
  });

  describe('Shoulde Reduce Threat Score', () => {
    it('should return true for emails with unsubscribe header', () => {
      const signals: MarketingSignals = {
        isMarketing: true,
        confidence: 0.7,
        signalCount: 2,
        signals: ['unsubscribe_header', 'promo_subject'],
        hasUnsubscribeLink: false,
        hasUnsubscribeHeader: true,
        hasViewInBrowserLink: false,
        hasTrackingPixels: false,
        hasSocialLinks: false,
        hasPromoLanguage: true,
        hasDiscountOffer: false,
        hasBulkMailHeaders: false,
        hasMarketingFooter: false,
        hasCompanyLogo: false,
      };

      expect(shouldReduceThreatScore(signals)).toBe(true);
    });

    it('should return true for high signal count', () => {
      const signals: MarketingSignals = {
        isMarketing: true,
        confidence: 0.8,
        signalCount: 5,
        signals: ['unsubscribe_link', 'promo_subject', 'social_links', 'tracking_pixels', 'marketing_footer'],
        hasUnsubscribeLink: true,
        hasUnsubscribeHeader: false,
        hasViewInBrowserLink: false,
        hasTrackingPixels: true,
        hasSocialLinks: true,
        hasPromoLanguage: true,
        hasDiscountOffer: false,
        hasBulkMailHeaders: false,
        hasMarketingFooter: true,
        hasCompanyLogo: false,
      };

      expect(shouldReduceThreatScore(signals)).toBe(true);
    });

    it('should return false for low confidence marketing', () => {
      const signals: MarketingSignals = {
        isMarketing: true,
        confidence: 0.4,
        signalCount: 2,
        signals: ['promo_subject', 'social_links'],
        hasUnsubscribeLink: false,
        hasUnsubscribeHeader: false,
        hasViewInBrowserLink: false,
        hasTrackingPixels: false,
        hasSocialLinks: true,
        hasPromoLanguage: true,
        hasDiscountOffer: false,
        hasBulkMailHeaders: false,
        hasMarketingFooter: false,
        hasCompanyLogo: false,
      };

      expect(shouldReduceThreatScore(signals)).toBe(false);
    });
  });

  console.log('Test suite complete.');
});

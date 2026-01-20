/**
 * Marketing Email Signal Detection
 *
 * Detects signals that indicate an email is marketing/promotional
 * rather than personal communication or a threat.
 */

import type { ParsedEmail } from '../types';

/**
 * Marketing signals found in email
 */
export interface MarketingSignals {
  isMarketing: boolean;
  confidence: number;
  signalCount: number;
  signals: string[];

  // Specific indicators
  hasUnsubscribeLink: boolean;
  hasUnsubscribeHeader: boolean;
  hasViewInBrowserLink: boolean;
  hasTrackingPixels: boolean;
  hasSocialLinks: boolean;
  hasPromoLanguage: boolean;
  hasDiscountOffer: boolean;
  hasBulkMailHeaders: boolean;
  hasMarketingFooter: boolean;
  hasCompanyLogo: boolean;
}

/**
 * Marketing subject line patterns
 */
const MARKETING_SUBJECT_PATTERNS = [
  // Sales/Promotions
  /\b(\d+%?\s*off|sale|deal|discount|save|promo|coupon|offer)\b/i,
  /\b(free shipping|clearance|limited time|flash sale|black friday|cyber monday)\b/i,
  /\b(today only|ends? (today|soon|tonight)|last chance|final hours)\b/i,

  // Newsletters
  /\b(newsletter|weekly|monthly|digest|roundup|recap|update)\b/i,
  /\b(news|announcement|introducing|new arrival|just (dropped|arrived|launched))\b/i,

  // Engagement
  /\b(don't miss|check out|discover|explore|shop now|browse)\b/i,
  /\b(top picks|trending|best seller|popular|featured|recommended)\b/i,

  // Seasonal
  /\b(holiday|christmas|thanksgiving|valentine|easter|halloween|summer|winter|spring|fall)\b/i,
  /\b(gift guide|gift ideas|perfect gift)\b/i,
];

/**
 * Marketing body patterns
 */
const MARKETING_BODY_PATTERNS = [
  // Standard marketing footer elements
  /unsubscribe|opt[- ]?out|email preferences|manage (your )?subscriptions?/i,
  /view (this email )?in (your )?browser|view online|web version/i,
  /update (your )?preferences|email settings/i,

  // Legal/compliance
  /©\s*\d{4}|copyright|all rights reserved/i,
  /privacy policy|terms (of service|and conditions)|contact us/i,
  /this (email|message) was sent (to|by)/i,
  /you (are )?receiv(e|ing) this (email|message) because/i,

  // Social media links
  /follow us on|connect with us|find us on/i,
  /(facebook|twitter|instagram|linkedin|youtube|pinterest|tiktok)\.com/i,

  // Marketing language
  /shop now|buy now|order now|get (it|yours) now/i,
  /limited (time|stock|availability)|while supplies last|selling fast/i,
  /exclusive (offer|deal|access|preview)|vip|members? only/i,
  /free (gift|sample|trial)|bonus|reward/i,

  // Product marketing
  /new collection|new season|new style|just in|back in stock/i,
  /best seller|customer favorite|top rated/i,
];

/**
 * Headers that indicate bulk/marketing mail
 */
const BULK_MAIL_HEADERS = [
  'list-unsubscribe',
  'list-unsubscribe-post',
  'x-mailer',
  'x-campaign',
  'x-mailgun',
  'x-sendgrid',
  'x-mailchimp',
  'x-mc-user',
  'x-ses-outgoing',
  'precedence', // bulk, list
  'x-auto-response-suppress',
  'feedback-id',
];

/**
 * Detect marketing signals in an email
 */
export function detectMarketingSignals(email: ParsedEmail): MarketingSignals {
  const signals: string[] = [];
  const subject = email.subject || '';
  const bodyText = email.body.text || '';
  const bodyHtml = email.body.html || '';
  const combinedBody = bodyText + bodyHtml;
  const lowerBody = combinedBody.toLowerCase();
  const headers = email.headers || {};

  // Check for unsubscribe link
  const hasUnsubscribeLink = /unsubscribe|opt[- ]?out/i.test(lowerBody);
  if (hasUnsubscribeLink) signals.push('unsubscribe_link');

  // Check for List-Unsubscribe header
  const hasUnsubscribeHeader = 'list-unsubscribe' in headers ||
    'List-Unsubscribe' in headers;
  if (hasUnsubscribeHeader) signals.push('unsubscribe_header');

  // Check for view in browser link
  const hasViewInBrowserLink = /view (this email |online |in (your )?browser)/i.test(lowerBody);
  if (hasViewInBrowserLink) signals.push('view_in_browser');

  // Check for tracking pixels (1x1 images, common tracking domains)
  const hasTrackingPixels = /(width|height)=["']?1["']?/i.test(bodyHtml) ||
    /tracking|pixel|beacon|open\.(mailchimp|sendgrid|hubspot)/i.test(bodyHtml);
  if (hasTrackingPixels) signals.push('tracking_pixels');

  // Check for social media links
  const hasSocialLinks = /(facebook|twitter|instagram|linkedin|youtube|pinterest|tiktok)\.com/i.test(lowerBody);
  if (hasSocialLinks) signals.push('social_links');

  // Check for promotional language in subject
  const hasPromoSubject = MARKETING_SUBJECT_PATTERNS.some(p => p.test(subject));
  if (hasPromoSubject) signals.push('promo_subject');

  // Check for promotional language in body
  const hasPromoBody = MARKETING_BODY_PATTERNS.some(p => p.test(combinedBody));
  if (hasPromoBody) signals.push('promo_body');

  // Check for discount offers
  const hasDiscountOffer = /\b\d+%?\s*(off|discount|save)/i.test(combinedBody) ||
    /\$\d+\s*(off|savings?)/i.test(combinedBody) ||
    /free\s+shipping/i.test(combinedBody);
  if (hasDiscountOffer) signals.push('discount_offer');

  // Check for bulk mail headers
  const hasBulkMailHeaders = BULK_MAIL_HEADERS.some(h =>
    h in headers || h.toLowerCase() in headers
  );
  if (hasBulkMailHeaders) signals.push('bulk_headers');

  // Check for marketing footer (copyright, address, etc.)
  const hasMarketingFooter = /©\s*\d{4}|copyright|\d{5}(-\d{4})?/i.test(lowerBody) && // copyright or ZIP
    /privacy|terms|contact/i.test(lowerBody);
  if (hasMarketingFooter) signals.push('marketing_footer');

  // Check for company logo (img early in HTML)
  const hasCompanyLogo = /<img[^>]*(logo|header|banner)/i.test(bodyHtml.slice(0, 2000));
  if (hasCompanyLogo) signals.push('company_logo');

  // Calculate confidence based on signal count
  const signalCount = signals.length;
  let confidence = 0;

  // Weight certain signals more heavily
  if (hasUnsubscribeLink || hasUnsubscribeHeader) confidence += 0.25;
  if (hasViewInBrowserLink) confidence += 0.15;
  if (hasPromoSubject) confidence += 0.15;
  if (hasDiscountOffer) confidence += 0.10;
  if (hasBulkMailHeaders) confidence += 0.15;
  if (hasMarketingFooter) confidence += 0.10;
  if (hasSocialLinks) confidence += 0.05;
  if (hasTrackingPixels) confidence += 0.05;

  // Cap at 0.95
  confidence = Math.min(0.95, confidence);

  // Is marketing if confidence > 0.5 OR has unsubscribe + 2 other signals
  const isMarketing = confidence >= 0.5 ||
    (hasUnsubscribeLink && signalCount >= 3);

  return {
    isMarketing,
    confidence,
    signalCount,
    signals,
    hasUnsubscribeLink,
    hasUnsubscribeHeader,
    hasViewInBrowserLink,
    hasTrackingPixels,
    hasSocialLinks,
    hasPromoLanguage: hasPromoSubject || hasPromoBody,
    hasDiscountOffer,
    hasBulkMailHeaders,
    hasMarketingFooter,
    hasCompanyLogo,
  };
}

/**
 * Check if marketing signals should reduce threat score
 */
export function shouldReduceThreatScore(signals: MarketingSignals): boolean {
  // Strong marketing indicators
  if (signals.hasUnsubscribeHeader) return true;
  if (signals.hasUnsubscribeLink && signals.hasMarketingFooter) return true;
  if (signals.signalCount >= 4) return true;

  return signals.isMarketing && signals.confidence >= 0.6;
}

/**
 * Known Sender Registry
 *
 * Database of known legitimate senders categorized by type.
 * This is used to identify marketing, transactional, and trusted senders
 * BEFORE threat detection runs.
 */

/**
 * Sender categories for classification
 */
export enum SenderCategory {
  RETAIL = 'retail',           // Amazon, Best Buy, Target, etc.
  ECOMMERCE = 'ecommerce',     // Shopify stores, eBay, Etsy
  MARKETING = 'marketing',     // Marketing platforms, newsletters
  TRANSACTIONAL = 'transactional', // Payment processors, shipping
  FINANCIAL = 'financial',     // Banks, credit cards, payroll
  SAAS = 'saas',              // SaaS notifications, dev tools
  SOCIAL = 'social',          // Social media notifications
  AUTOMATED = 'automated',     // System notifications, alerts
  TRUSTED = 'trusted',        // Known business partners (tenant-specific)
  UNKNOWN = 'unknown',
}

/**
 * Sender information from registry
 */
export interface SenderInfo {
  domain: string;
  name: string;
  category: SenderCategory;
  subDomains?: string[];      // e.g., email.amazon.com, notifications.amazon.com
  alternateFroms?: string[];   // Common from addresses
  replyToDomains?: string[];   // Known reply-to domains (don't flag mismatch)
  trustedSince?: Date;
  notes?: string;
}

/**
 * Known legitimate sender domains
 * This is a curated list - can be extended via tenant configuration
 */
const KNOWN_SENDERS: SenderInfo[] = [
  // RETAIL - Major retailers
  {
    domain: 'amazon.com',
    name: 'Amazon',
    category: SenderCategory.RETAIL,
    subDomains: ['email.amazon.com', 'amazon.com', 'a]mazon.co.uk', 'amazon.de', 'amazon.ca'],
    alternateFroms: ['auto-confirm@amazon.com', 'shipment-tracking@amazon.com', 'store-news@amazon.com'],
  },
  {
    domain: 'bestbuy.com',
    name: 'Best Buy',
    category: SenderCategory.RETAIL,
    subDomains: ['email.bestbuy.com', 'emailinfo.bestbuy.com'],
    alternateFroms: ['BestBuyInfo@emailinfo.bestbuy.com'],
  },
  {
    domain: 'target.com',
    name: 'Target',
    category: SenderCategory.RETAIL,
    subDomains: ['email.target.com', 'target.narvar.com'],
  },
  {
    domain: 'walmart.com',
    name: 'Walmart',
    category: SenderCategory.RETAIL,
    subDomains: ['email.walmart.com', 'walmart-email.narvar.com'],
  },
  {
    domain: 'costco.com',
    name: 'Costco',
    category: SenderCategory.RETAIL,
    subDomains: ['costco.narvar.com', 'email.costco.com'],
  },
  {
    domain: 'homedepot.com',
    name: 'Home Depot',
    category: SenderCategory.RETAIL,
    subDomains: ['homedepot.narvar.com'],
  },
  {
    domain: 'lowes.com',
    name: "Lowe's",
    category: SenderCategory.RETAIL,
  },
  {
    domain: 'macys.com',
    name: "Macy's",
    category: SenderCategory.RETAIL,
    subDomains: ['email.macys.com', 'e.macys.com'],
  },
  {
    domain: 'nordstrom.com',
    name: 'Nordstrom',
    category: SenderCategory.RETAIL,
  },
  {
    domain: 'kohls.com',
    name: "Kohl's",
    category: SenderCategory.RETAIL,
  },
  {
    domain: 'thefreshmarket.com',
    name: 'The Fresh Market',
    category: SenderCategory.RETAIL,
    subDomains: ['thefreshmarketmail.com', 'email.thefreshmarket.com'],
    alternateFroms: ['freshideas@thefreshmarketmail.com'],
  },
  {
    domain: 'wholefoods.com',
    name: 'Whole Foods',
    category: SenderCategory.RETAIL,
    subDomains: ['wholefoodsmarket.com'],
  },
  {
    domain: 'traderjoes.com',
    name: "Trader Joe's",
    category: SenderCategory.RETAIL,
  },

  // ECOMMERCE - Online marketplaces
  {
    domain: 'ebay.com',
    name: 'eBay',
    category: SenderCategory.ECOMMERCE,
    subDomains: ['ebay.com', 'reply.ebay.com', 'srn.ebay.com'],
    replyToDomains: ['reply.ebay.com'],
  },
  {
    domain: 'etsy.com',
    name: 'Etsy',
    category: SenderCategory.ECOMMERCE,
    subDomains: ['mail.etsy.com', 'transaction.etsy.com'],
  },
  {
    domain: 'shopify.com',
    name: 'Shopify',
    category: SenderCategory.ECOMMERCE,
    subDomains: ['email.shopify.com', 'shops.shopify.com'],
  },
  {
    domain: 'aliexpress.com',
    name: 'AliExpress',
    category: SenderCategory.ECOMMERCE,
  },

  // FOOD DELIVERY
  {
    domain: 'uber.com',
    name: 'Uber/Uber Eats',
    category: SenderCategory.RETAIL,
    subDomains: ['ubereats.com', 'uber.com'],
    alternateFroms: ['ubereats@uber.com'],
    replyToDomains: ['replies.uber.com'],
  },
  {
    domain: 'doordash.com',
    name: 'DoorDash',
    category: SenderCategory.RETAIL,
    subDomains: ['email.doordash.com', 'doordash-email.com'],
  },
  {
    domain: 'grubhub.com',
    name: 'Grubhub',
    category: SenderCategory.RETAIL,
  },
  {
    domain: 'instacart.com',
    name: 'Instacart',
    category: SenderCategory.RETAIL,
  },

  // GAMING/ENTERTAINMENT
  {
    domain: 'humblebundle.com',
    name: 'Humble Bundle',
    category: SenderCategory.RETAIL,
    subDomains: ['mailer.humblebundle.com', 'mail.humblebundle.com'],
    replyToDomains: ['humblebundle.com', 'mailer.humblebundle.com'],
    alternateFroms: ['contact@mailer.humblebundle.com'],
  },
  {
    domain: 'steampowered.com',
    name: 'Steam',
    category: SenderCategory.RETAIL,
    subDomains: ['store.steampowered.com'],
  },
  {
    domain: 'epicgames.com',
    name: 'Epic Games',
    category: SenderCategory.RETAIL,
  },
  {
    domain: 'playstation.com',
    name: 'PlayStation',
    category: SenderCategory.RETAIL,
    subDomains: ['email.playstation.com'],
  },
  {
    domain: 'xbox.com',
    name: 'Xbox',
    category: SenderCategory.RETAIL,
  },
  {
    domain: 'nintendo.com',
    name: 'Nintendo',
    category: SenderCategory.RETAIL,
  },

  // MARKETING PLATFORMS
  {
    domain: 'mailchimp.com',
    name: 'Mailchimp',
    category: SenderCategory.MARKETING,
    subDomains: ['mail.mailchimp.com', 'mailchi.mp'],
  },
  {
    domain: 'sendgrid.net',
    name: 'SendGrid',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'constantcontact.com',
    name: 'Constant Contact',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'hubspot.com',
    name: 'HubSpot',
    category: SenderCategory.MARKETING,
    subDomains: ['hs-email.hubspot.com', 'email.hubspot.com'],
  },
  {
    domain: 'klaviyo.com',
    name: 'Klaviyo',
    category: SenderCategory.MARKETING,
  },

  // TRANSACTIONAL - Payment/Shipping
  {
    domain: 'paypal.com',
    name: 'PayPal',
    category: SenderCategory.TRANSACTIONAL,
    subDomains: ['paypal.com', 'e.paypal.com'],
  },
  {
    domain: 'stripe.com',
    name: 'Stripe',
    category: SenderCategory.TRANSACTIONAL,
    subDomains: ['email.stripe.com'],
  },
  {
    domain: 'square.com',
    name: 'Square',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'venmo.com',
    name: 'Venmo',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'ups.com',
    name: 'UPS',
    category: SenderCategory.TRANSACTIONAL,
    subDomains: ['ups.com', 'email.ups.com'],
  },
  {
    domain: 'fedex.com',
    name: 'FedEx',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'usps.com',
    name: 'USPS',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'narvar.com',
    name: 'Narvar (Shipping Tracker)',
    category: SenderCategory.TRANSACTIONAL,
  },

  // FINANCIAL
  {
    domain: 'chase.com',
    name: 'Chase Bank',
    category: SenderCategory.FINANCIAL,
  },
  {
    domain: 'bankofamerica.com',
    name: 'Bank of America',
    category: SenderCategory.FINANCIAL,
  },
  {
    domain: 'wellsfargo.com',
    name: 'Wells Fargo',
    category: SenderCategory.FINANCIAL,
  },
  {
    domain: 'citi.com',
    name: 'Citi',
    category: SenderCategory.FINANCIAL,
  },
  {
    domain: 'capitalone.com',
    name: 'Capital One',
    category: SenderCategory.FINANCIAL,
  },
  {
    domain: 'americanexpress.com',
    name: 'American Express',
    category: SenderCategory.FINANCIAL,
  },
  {
    domain: 'discover.com',
    name: 'Discover',
    category: SenderCategory.FINANCIAL,
  },

  // SAAS/DEV TOOLS
  {
    domain: 'github.com',
    name: 'GitHub',
    category: SenderCategory.SAAS,
    subDomains: ['notifications@github.com', 'noreply@github.com'],
  },
  {
    domain: 'gitlab.com',
    name: 'GitLab',
    category: SenderCategory.SAAS,
  },
  {
    domain: 'atlassian.com',
    name: 'Atlassian (Jira/Confluence)',
    category: SenderCategory.SAAS,
    subDomains: ['atlassian.net', 'jira.com'],
  },
  {
    domain: 'slack.com',
    name: 'Slack',
    category: SenderCategory.SAAS,
    subDomains: ['slackbot.com', 'email.slack.com'],
  },
  {
    domain: 'zoom.us',
    name: 'Zoom',
    category: SenderCategory.SAAS,
  },
  {
    domain: 'notion.so',
    name: 'Notion',
    category: SenderCategory.SAAS,
  },
  {
    domain: 'figma.com',
    name: 'Figma',
    category: SenderCategory.SAAS,
  },
  {
    domain: 'vercel.com',
    name: 'Vercel',
    category: SenderCategory.SAAS,
  },
  {
    domain: 'netlify.com',
    name: 'Netlify',
    category: SenderCategory.SAAS,
  },
  {
    domain: 'heroku.com',
    name: 'Heroku',
    category: SenderCategory.SAAS,
  },
  {
    domain: 'aws.amazon.com',
    name: 'AWS',
    category: SenderCategory.SAAS,
    subDomains: ['amazonses.com', 'amazonaws.com'],
  },
  {
    domain: 'google.com',
    name: 'Google',
    category: SenderCategory.SAAS,
    subDomains: ['googlemail.com', 'google.com', 'youtube.com', 'accounts.google.com'],
  },
  {
    domain: 'microsoft.com',
    name: 'Microsoft',
    category: SenderCategory.SAAS,
    subDomains: ['outlook.com', 'office.com', 'live.com', 'azure.com'],
  },
  {
    domain: 'apple.com',
    name: 'Apple',
    category: SenderCategory.SAAS,
    subDomains: ['icloud.com', 'me.com', 'apple.com'],
  },
  {
    domain: 'dropbox.com',
    name: 'Dropbox',
    category: SenderCategory.SAAS,
  },

  // SOCIAL MEDIA
  {
    domain: 'linkedin.com',
    name: 'LinkedIn',
    category: SenderCategory.SOCIAL,
  },
  {
    domain: 'twitter.com',
    name: 'Twitter/X',
    category: SenderCategory.SOCIAL,
    subDomains: ['x.com'],
  },
  {
    domain: 'facebook.com',
    name: 'Facebook/Meta',
    category: SenderCategory.SOCIAL,
    subDomains: ['facebookmail.com', 'meta.com', 'instagram.com'],
  },
  {
    domain: 'tiktok.com',
    name: 'TikTok',
    category: SenderCategory.SOCIAL,
  },

  // NEWSLETTERS & FINANCIAL NEWS
  {
    domain: 'morningbrew.com',
    name: 'Morning Brew',
    category: SenderCategory.MARKETING,
    subDomains: ['email.morningbrew.com', 'newsletters.morningbrew.com'],
  },
  {
    domain: 'themorningbrew.com',
    name: 'Morning Brew',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'substack.com',
    name: 'Substack',
    category: SenderCategory.MARKETING,
    subDomains: ['email.substack.com'],
  },
  {
    domain: 'beehiiv.com',
    name: 'Beehiiv',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'convertkit.com',
    name: 'ConvertKit',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'techcrunch.com',
    name: 'TechCrunch',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'theinformation.com',
    name: 'The Information',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'axios.com',
    name: 'Axios',
    category: SenderCategory.MARKETING,
    subDomains: ['email.axios.com'],
  },
  {
    domain: 'wsj.com',
    name: 'Wall Street Journal',
    category: SenderCategory.MARKETING,
    subDomains: ['email.wsj.com', 'newsletters.wsj.com'],
  },
  {
    domain: 'nytimes.com',
    name: 'New York Times',
    category: SenderCategory.MARKETING,
    subDomains: ['email.nytimes.com', 'newsletters.nytimes.com'],
  },
  {
    domain: 'bloomberg.com',
    name: 'Bloomberg',
    category: SenderCategory.MARKETING,
    subDomains: ['email.bloomberg.com'],
  },
  {
    domain: 'reuters.com',
    name: 'Reuters',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'cnbc.com',
    name: 'CNBC',
    category: SenderCategory.MARKETING,
    subDomains: ['email.cnbc.com'],
  },
  {
    domain: 'marketwatch.com',
    name: 'MarketWatch',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'fool.com',
    name: 'Motley Fool',
    category: SenderCategory.MARKETING,
    subDomains: ['email.fool.com'],
  },
  {
    domain: 'investopedia.com',
    name: 'Investopedia',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'seekingalpha.com',
    name: 'Seeking Alpha',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'barrons.com',
    name: "Barron's",
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'fortune.com',
    name: 'Fortune',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'forbes.com',
    name: 'Forbes',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'medium.com',
    name: 'Medium',
    category: SenderCategory.MARKETING,
    subDomains: ['email.medium.com'],
  },
  {
    domain: 'wired.com',
    name: 'Wired',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'theverge.com',
    name: 'The Verge',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'arstechnica.com',
    name: 'Ars Technica',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'engadget.com',
    name: 'Engadget',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'cnet.com',
    name: 'CNET',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'zdnet.com',
    name: 'ZDNet',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'techpoint.africa',
    name: 'TechPoint Africa',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'techcabal.com',
    name: 'TechCabal',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'thedailybeast.com',
    name: 'The Daily Beast',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'politico.com',
    name: 'Politico',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'thehill.com',
    name: 'The Hill',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'vox.com',
    name: 'Vox',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'washingtonpost.com',
    name: 'Washington Post',
    category: SenderCategory.MARKETING,
    subDomains: ['email.washingtonpost.com'],
  },
  {
    domain: 'latimes.com',
    name: 'Los Angeles Times',
    category: SenderCategory.MARKETING,
  },
  {
    domain: 'usatoday.com',
    name: 'USA Today',
    category: SenderCategory.MARKETING,
  },

  // GOVERNMENT DOMAINS
  {
    domain: 'irs.gov',
    name: 'Internal Revenue Service',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'ssa.gov',
    name: 'Social Security Administration',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'state.gov',
    name: 'US State Department',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'treasury.gov',
    name: 'US Treasury',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'dol.gov',
    name: 'Department of Labor',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'dhs.gov',
    name: 'Department of Homeland Security',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'fbi.gov',
    name: 'FBI',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'cdc.gov',
    name: 'CDC',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'nih.gov',
    name: 'National Institutes of Health',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'fda.gov',
    name: 'FDA',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'cms.gov',
    name: 'CMS (Medicare/Medicaid)',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'usa.gov',
    name: 'USA.gov',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'benefits.gov',
    name: 'Benefits.gov',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'sec.gov',
    name: 'SEC',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'ftc.gov',
    name: 'FTC',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'federalreserve.gov',
    name: 'Federal Reserve',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'doi.gov',
    name: 'Department of Interior',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'epa.gov',
    name: 'EPA',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'ed.gov',
    name: 'Department of Education',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'hud.gov',
    name: 'HUD',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'va.gov',
    name: 'Veterans Affairs',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'sba.gov',
    name: 'Small Business Administration',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'gsa.gov',
    name: 'General Services Administration',
    category: SenderCategory.TRANSACTIONAL,
  },

  // STATE GOVERNMENT (Common patterns)
  {
    domain: 'nc.gov',
    name: 'North Carolina Government',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'ca.gov',
    name: 'California Government',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'ny.gov',
    name: 'New York Government',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'tx.gov',
    name: 'Texas Government',
    category: SenderCategory.TRANSACTIONAL,
  },
  {
    domain: 'fl.gov',
    name: 'Florida Government',
    category: SenderCategory.TRANSACTIONAL,
  },
];

/**
 * Build domain lookup index for fast searching
 */
const domainIndex = new Map<string, SenderInfo>();
const subDomainIndex = new Map<string, SenderInfo>();

// Initialize indexes
for (const sender of KNOWN_SENDERS) {
  domainIndex.set(sender.domain.toLowerCase(), sender);

  if (sender.subDomains) {
    for (const subDomain of sender.subDomains) {
      subDomainIndex.set(subDomain.toLowerCase(), sender);
    }
  }
}

/**
 * Look up a sender in the registry
 */
export async function lookupSender(
  email: string,
  domain: string
): Promise<SenderInfo | null> {
  const lowerDomain = domain.toLowerCase();

  // Direct domain match
  if (domainIndex.has(lowerDomain)) {
    return domainIndex.get(lowerDomain)!;
  }

  // Subdomain match
  if (subDomainIndex.has(lowerDomain)) {
    return subDomainIndex.get(lowerDomain)!;
  }

  // Try parent domain (e.g., email.amazon.com → amazon.com)
  const parts = lowerDomain.split('.');
  if (parts.length > 2) {
    const parentDomain = parts.slice(-2).join('.');
    if (domainIndex.has(parentDomain)) {
      return domainIndex.get(parentDomain)!;
    }
  }

  // Auto-recognize .gov domains as government senders
  // This catches all government domains not explicitly listed
  if (lowerDomain.endsWith('.gov') || lowerDomain.endsWith('.gov.uk') || lowerDomain.endsWith('.gc.ca')) {
    return {
      domain: lowerDomain,
      name: `Government Domain (${lowerDomain})`,
      category: SenderCategory.TRANSACTIONAL,
      notes: 'Auto-recognized government domain',
    };
  }

  // Auto-recognize .edu domains as educational institutions
  if (lowerDomain.endsWith('.edu') || lowerDomain.endsWith('.ac.uk')) {
    return {
      domain: lowerDomain,
      name: `Educational Institution (${lowerDomain})`,
      category: SenderCategory.TRANSACTIONAL,
      notes: 'Auto-recognized educational domain',
    };
  }

  // TODO: Check tenant-specific trusted senders from database

  return null;
}

/**
 * Check if a reply-to domain is legitimate for a sender
 */
export function isLegitimateReplyTo(
  senderInfo: SenderInfo | null,
  replyToDomain: string
): boolean {
  if (!senderInfo) return false;

  const lowerReplyTo = replyToDomain.toLowerCase();

  // Same as sender domain
  if (lowerReplyTo === senderInfo.domain.toLowerCase()) {
    return true;
  }

  // Matches subdomain
  if (senderInfo.subDomains?.some(d => d.toLowerCase() === lowerReplyTo)) {
    return true;
  }

  // Matches known reply-to domain
  if (senderInfo.replyToDomains?.some(d => d.toLowerCase() === lowerReplyTo)) {
    return true;
  }

  return false;
}

/**
 * Get all known senders (for admin display)
 */
export function getAllKnownSenders(): SenderInfo[] {
  return [...KNOWN_SENDERS];
}

/**
 * Get senders by category
 */
export function getSendersByCategory(category: SenderCategory): SenderInfo[] {
  return KNOWN_SENDERS.filter(s => s.category === category);
}

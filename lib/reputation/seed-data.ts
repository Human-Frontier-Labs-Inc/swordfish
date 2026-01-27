/**
 * Seed data for sender_reputation table
 * Phase 1: Known Sender Reputation System
 *
 * Trust Score Guidelines:
 * - 95-100: Highly trusted (major tech companies, financial institutions)
 * - 85-94: Trusted (established marketing platforms, verified services)
 * - 75-84: Generally safe (newsletters, community platforms)
 * - 60-74: Low trust (promotional, less established)
 * - 0-59: Unknown/suspicious
 */

export interface SenderReputationSeed {
  domain: string;
  display_name: string;
  category: 'trusted' | 'marketing' | 'transactional' | 'suspicious' | 'unknown';
  trust_score: number;
  known_tracking_domains: string[];
  email_types: string[];
}

export const TRUSTED_SENDERS: SenderReputationSeed[] = [
  // Major Tech Companies (95-100)
  {
    domain: 'google.com',
    display_name: 'Google',
    category: 'transactional',
    trust_score: 100,
    known_tracking_domains: ['google.com', 'gstatic.com'],
    email_types: ['security', 'notification', 'marketing']
  },
  {
    domain: 'apple.com',
    display_name: 'Apple',
    category: 'transactional',
    trust_score: 100,
    known_tracking_domains: ['apple.com', 'icloud.com'],
    email_types: ['security', 'notification', 'receipt']
  },
  {
    domain: 'microsoft.com',
    display_name: 'Microsoft',
    category: 'transactional',
    trust_score: 100,
    known_tracking_domains: ['microsoft.com', 'office.com', 'outlook.com'],
    email_types: ['security', 'notification', 'marketing']
  },
  {
    domain: 'amazon.com',
    display_name: 'Amazon',
    category: 'transactional',
    trust_score: 98,
    known_tracking_domains: ['amazon.com', 'amazonses.com'],
    email_types: ['order', 'notification', 'marketing']
  },
  {
    domain: 'github.com',
    display_name: 'GitHub',
    category: 'transactional',
    trust_score: 98,
    known_tracking_domains: ['github.com'],
    email_types: ['notification', 'security', 'marketing']
  },

  // Financial & Payment (95-100)
  {
    domain: 'stripe.com',
    display_name: 'Stripe',
    category: 'transactional',
    trust_score: 99,
    known_tracking_domains: ['stripe.com'],
    email_types: ['payment', 'receipt', 'notification']
  },
  {
    domain: 'paypal.com',
    display_name: 'PayPal',
    category: 'transactional',
    trust_score: 98,
    known_tracking_domains: ['paypal.com'],
    email_types: ['payment', 'receipt', 'notification']
  },
  {
    domain: 'square.com',
    display_name: 'Square',
    category: 'transactional',
    trust_score: 97,
    known_tracking_domains: ['square.com', 'squareup.com'],
    email_types: ['payment', 'receipt', 'notification']
  },

  // Social Networks & Community (85-94)
  {
    domain: 'linkedin.com',
    display_name: 'LinkedIn',
    category: 'marketing',
    trust_score: 90,
    known_tracking_domains: ['linkedin.com', 'licdn.com'],
    email_types: ['notification', 'digest', 'marketing']
  },
  {
    domain: 'twitter.com',
    display_name: 'Twitter',
    category: 'marketing',
    trust_score: 88,
    known_tracking_domains: ['twitter.com', 't.co'],
    email_types: ['notification', 'digest', 'marketing']
  },
  {
    domain: 'facebook.com',
    display_name: 'Facebook',
    category: 'marketing',
    trust_score: 87,
    known_tracking_domains: ['facebook.com', 'fb.com'],
    email_types: ['notification', 'digest', 'marketing']
  },
  {
    domain: 'instagram.com',
    display_name: 'Instagram',
    category: 'marketing',
    trust_score: 87,
    known_tracking_domains: ['instagram.com'],
    email_types: ['notification', 'digest', 'marketing']
  },
  {
    domain: 'quora.com',
    display_name: 'Quora',
    category: 'marketing',
    trust_score: 85,
    known_tracking_domains: ['quora.com', 'links.quora.com'],
    email_types: ['digest', 'notification', 'marketing']
  },
  {
    domain: 'reddit.com',
    display_name: 'Reddit',
    category: 'marketing',
    trust_score: 85,
    known_tracking_domains: ['reddit.com', 'redd.it'],
    email_types: ['digest', 'notification', 'marketing']
  },
  {
    domain: 'stackoverflow.com',
    display_name: 'Stack Overflow',
    category: 'marketing',
    trust_score: 90,
    known_tracking_domains: ['stackoverflow.com', 'stackexchange.com'],
    email_types: ['digest', 'notification']
  },
  {
    domain: 'medium.com',
    display_name: 'Medium',
    category: 'marketing',
    trust_score: 85,
    known_tracking_domains: ['medium.com'],
    email_types: ['digest', 'notification', 'marketing']
  },
  {
    domain: 'substack.com',
    display_name: 'Substack',
    category: 'marketing',
    trust_score: 88,
    known_tracking_domains: ['substack.com'],
    email_types: ['newsletter', 'digest']
  },

  // Developer Tools & Services (90-95)
  {
    domain: 'gitlab.com',
    display_name: 'GitLab',
    category: 'transactional',
    trust_score: 95,
    known_tracking_domains: ['gitlab.com'],
    email_types: ['notification', 'security']
  },
  {
    domain: 'bitbucket.org',
    display_name: 'Bitbucket',
    category: 'transactional',
    trust_score: 93,
    known_tracking_domains: ['bitbucket.org'],
    email_types: ['notification', 'security']
  },
  {
    domain: 'atlassian.com',
    display_name: 'Atlassian',
    category: 'transactional',
    trust_score: 94,
    known_tracking_domains: ['atlassian.com', 'atlassian.net'],
    email_types: ['notification', 'marketing']
  },
  {
    domain: 'slack.com',
    display_name: 'Slack',
    category: 'transactional',
    trust_score: 96,
    known_tracking_domains: ['slack.com'],
    email_types: ['notification', 'digest']
  },
  {
    domain: 'notion.so',
    display_name: 'Notion',
    category: 'transactional',
    trust_score: 93,
    known_tracking_domains: ['notion.so'],
    email_types: ['notification', 'digest']
  },
  {
    domain: 'figma.com',
    display_name: 'Figma',
    category: 'transactional',
    trust_score: 93,
    known_tracking_domains: ['figma.com'],
    email_types: ['notification', 'collaboration']
  },
  {
    domain: 'vercel.com',
    display_name: 'Vercel',
    category: 'transactional',
    trust_score: 94,
    known_tracking_domains: ['vercel.com'],
    email_types: ['deployment', 'notification']
  },
  {
    domain: 'netlify.com',
    display_name: 'Netlify',
    category: 'transactional',
    trust_score: 93,
    known_tracking_domains: ['netlify.com'],
    email_types: ['deployment', 'notification']
  },
  {
    domain: 'heroku.com',
    display_name: 'Heroku',
    category: 'transactional',
    trust_score: 93,
    known_tracking_domains: ['heroku.com'],
    email_types: ['deployment', 'notification']
  },

  // Cloud Providers (95-100)
  {
    domain: 'aws.amazon.com',
    display_name: 'Amazon Web Services',
    category: 'transactional',
    trust_score: 99,
    known_tracking_domains: ['aws.amazon.com', 'amazonaws.com'],
    email_types: ['billing', 'notification', 'security']
  },
  {
    domain: 'cloud.google.com',
    display_name: 'Google Cloud',
    category: 'transactional',
    trust_score: 99,
    known_tracking_domains: ['cloud.google.com', 'google.com'],
    email_types: ['billing', 'notification', 'security']
  },
  {
    domain: 'azure.microsoft.com',
    display_name: 'Microsoft Azure',
    category: 'transactional',
    trust_score: 99,
    known_tracking_domains: ['azure.microsoft.com', 'microsoft.com'],
    email_types: ['billing', 'notification', 'security']
  },
  {
    domain: 'digitalocean.com',
    display_name: 'DigitalOcean',
    category: 'transactional',
    trust_score: 95,
    known_tracking_domains: ['digitalocean.com'],
    email_types: ['billing', 'notification']
  },

  // Email Services & Marketing Platforms (75-90)
  {
    domain: 'sendgrid.com',
    display_name: 'SendGrid',
    category: 'transactional',
    trust_score: 90,
    known_tracking_domains: ['sendgrid.com', 'sendgrid.net'],
    email_types: ['transactional']
  },
  {
    domain: 'mailchimp.com',
    display_name: 'Mailchimp',
    category: 'marketing',
    trust_score: 85,
    known_tracking_domains: ['mailchimp.com', 'list-manage.com'],
    email_types: ['marketing', 'newsletter']
  },
  {
    domain: 'constantcontact.com',
    display_name: 'Constant Contact',
    category: 'marketing',
    trust_score: 82,
    known_tracking_domains: ['constantcontact.com'],
    email_types: ['marketing', 'newsletter']
  },
  {
    domain: 'hubspot.com',
    display_name: 'HubSpot',
    category: 'marketing',
    trust_score: 87,
    known_tracking_domains: ['hubspot.com', 'hs-sites.com'],
    email_types: ['marketing', 'transactional']
  },
  {
    domain: 'intercom.com',
    display_name: 'Intercom',
    category: 'transactional',
    trust_score: 88,
    known_tracking_domains: ['intercom.com', 'intercom.io'],
    email_types: ['notification', 'support']
  },

  // E-commerce & Retail (85-95)
  {
    domain: 'shopify.com',
    display_name: 'Shopify',
    category: 'transactional',
    trust_score: 93,
    known_tracking_domains: ['shopify.com'],
    email_types: ['order', 'notification', 'marketing']
  },
  {
    domain: 'ebay.com',
    display_name: 'eBay',
    category: 'transactional',
    trust_score: 90,
    known_tracking_domains: ['ebay.com'],
    email_types: ['order', 'notification', 'marketing']
  },
  {
    domain: 'etsy.com',
    display_name: 'Etsy',
    category: 'transactional',
    trust_score: 88,
    known_tracking_domains: ['etsy.com'],
    email_types: ['order', 'notification', 'marketing']
  },

  // Productivity & Collaboration (90-95)
  {
    domain: 'zoom.us',
    display_name: 'Zoom',
    category: 'transactional',
    trust_score: 94,
    known_tracking_domains: ['zoom.us'],
    email_types: ['meeting', 'notification']
  },
  {
    domain: 'dropbox.com',
    display_name: 'Dropbox',
    category: 'transactional',
    trust_score: 92,
    known_tracking_domains: ['dropbox.com'],
    email_types: ['notification', 'sharing']
  },
  {
    domain: 'box.com',
    display_name: 'Box',
    category: 'transactional',
    trust_score: 91,
    known_tracking_domains: ['box.com'],
    email_types: ['notification', 'sharing']
  },
  {
    domain: 'asana.com',
    display_name: 'Asana',
    category: 'transactional',
    trust_score: 90,
    known_tracking_domains: ['asana.com'],
    email_types: ['notification', 'task']
  },
  {
    domain: 'trello.com',
    display_name: 'Trello',
    category: 'transactional',
    trust_score: 90,
    known_tracking_domains: ['trello.com'],
    email_types: ['notification', 'task']
  },
  {
    domain: 'monday.com',
    display_name: 'Monday.com',
    category: 'transactional',
    trust_score: 89,
    known_tracking_domains: ['monday.com'],
    email_types: ['notification', 'task']
  },
  {
    domain: 'airtable.com',
    display_name: 'Airtable',
    category: 'transactional',
    trust_score: 90,
    known_tracking_domains: ['airtable.com'],
    email_types: ['notification', 'collaboration']
  },

  // News & Media (80-90)
  {
    domain: 'nytimes.com',
    display_name: 'The New York Times',
    category: 'marketing',
    trust_score: 88,
    known_tracking_domains: ['nytimes.com'],
    email_types: ['newsletter', 'marketing']
  },
  {
    domain: 'wsj.com',
    display_name: 'The Wall Street Journal',
    category: 'marketing',
    trust_score: 88,
    known_tracking_domains: ['wsj.com'],
    email_types: ['newsletter', 'marketing']
  },
  {
    domain: 'bloomberg.com',
    display_name: 'Bloomberg',
    category: 'marketing',
    trust_score: 87,
    known_tracking_domains: ['bloomberg.com'],
    email_types: ['newsletter', 'marketing']
  },
  {
    domain: 'techcrunch.com',
    display_name: 'TechCrunch',
    category: 'marketing',
    trust_score: 85,
    known_tracking_domains: ['techcrunch.com'],
    email_types: ['newsletter', 'marketing']
  },
  {
    domain: 'theverge.com',
    display_name: 'The Verge',
    category: 'marketing',
    trust_score: 85,
    known_tracking_domains: ['theverge.com'],
    email_types: ['newsletter', 'marketing']
  },

  // Education & Learning (85-95)
  {
    domain: 'coursera.org',
    display_name: 'Coursera',
    category: 'marketing',
    trust_score: 88,
    known_tracking_domains: ['coursera.org'],
    email_types: ['course', 'notification', 'marketing']
  },
  {
    domain: 'udemy.com',
    display_name: 'Udemy',
    category: 'marketing',
    trust_score: 85,
    known_tracking_domains: ['udemy.com'],
    email_types: ['course', 'notification', 'marketing']
  },
  {
    domain: 'khanacademy.org',
    display_name: 'Khan Academy',
    category: 'marketing',
    trust_score: 90,
    known_tracking_domains: ['khanacademy.org'],
    email_types: ['notification', 'progress']
  },

  // Travel & Hospitality (85-92)
  {
    domain: 'airbnb.com',
    display_name: 'Airbnb',
    category: 'transactional',
    trust_score: 90,
    known_tracking_domains: ['airbnb.com'],
    email_types: ['booking', 'notification', 'marketing']
  },
  {
    domain: 'booking.com',
    display_name: 'Booking.com',
    category: 'transactional',
    trust_score: 88,
    known_tracking_domains: ['booking.com'],
    email_types: ['booking', 'notification', 'marketing']
  },
  {
    domain: 'expedia.com',
    display_name: 'Expedia',
    category: 'transactional',
    trust_score: 87,
    known_tracking_domains: ['expedia.com'],
    email_types: ['booking', 'notification', 'marketing']
  },
  {
    domain: 'uber.com',
    display_name: 'Uber',
    category: 'transactional',
    trust_score: 89,
    known_tracking_domains: ['uber.com'],
    email_types: ['receipt', 'notification']
  },

  // Health & Fitness (80-88)
  {
    domain: 'fitbit.com',
    display_name: 'Fitbit',
    category: 'marketing',
    trust_score: 85,
    known_tracking_domains: ['fitbit.com'],
    email_types: ['notification', 'progress', 'marketing']
  },
  {
    domain: 'myfitnesspal.com',
    display_name: 'MyFitnessPal',
    category: 'marketing',
    trust_score: 83,
    known_tracking_domains: ['myfitnesspal.com'],
    email_types: ['notification', 'progress', 'marketing']
  },

  // Banking & Finance (95-100)
  {
    domain: 'chase.com',
    display_name: 'Chase',
    category: 'transactional',
    trust_score: 98,
    known_tracking_domains: ['chase.com'],
    email_types: ['statement', 'security', 'notification']
  },
  {
    domain: 'bankofamerica.com',
    display_name: 'Bank of America',
    category: 'transactional',
    trust_score: 98,
    known_tracking_domains: ['bankofamerica.com'],
    email_types: ['statement', 'security', 'notification']
  },
  {
    domain: 'wellsfargo.com',
    display_name: 'Wells Fargo',
    category: 'transactional',
    trust_score: 97,
    known_tracking_domains: ['wellsfargo.com'],
    email_types: ['statement', 'security', 'notification']
  },
  {
    domain: 'americanexpress.com',
    display_name: 'American Express',
    category: 'transactional',
    trust_score: 98,
    known_tracking_domains: ['americanexpress.com'],
    email_types: ['statement', 'security', 'notification']
  },

  // Security & Identity (95-100)
  {
    domain: '1password.com',
    display_name: '1Password',
    category: 'transactional',
    trust_score: 96,
    known_tracking_domains: ['1password.com'],
    email_types: ['security', 'notification']
  },
  {
    domain: 'lastpass.com',
    display_name: 'LastPass',
    category: 'transactional',
    trust_score: 94,
    known_tracking_domains: ['lastpass.com'],
    email_types: ['security', 'notification']
  },
  {
    domain: 'okta.com',
    display_name: 'Okta',
    category: 'transactional',
    trust_score: 96,
    known_tracking_domains: ['okta.com'],
    email_types: ['security', 'notification']
  },
  {
    domain: 'auth0.com',
    display_name: 'Auth0',
    category: 'transactional',
    trust_score: 95,
    known_tracking_domains: ['auth0.com'],
    email_types: ['security', 'notification']
  },

  // Open Source & Community (85-92)
  {
    domain: 'npmjs.com',
    display_name: 'npm',
    category: 'transactional',
    trust_score: 92,
    known_tracking_domains: ['npmjs.com'],
    email_types: ['security', 'notification']
  },
  {
    domain: 'pypi.org',
    display_name: 'PyPI',
    category: 'transactional',
    trust_score: 91,
    known_tracking_domains: ['pypi.org'],
    email_types: ['security', 'notification']
  },
  {
    domain: 'rubygems.org',
    display_name: 'RubyGems',
    category: 'transactional',
    trust_score: 90,
    known_tracking_domains: ['rubygems.org'],
    email_types: ['security', 'notification']
  },
  {
    domain: 'docker.com',
    display_name: 'Docker',
    category: 'transactional',
    trust_score: 93,
    known_tracking_domains: ['docker.com'],
    email_types: ['security', 'notification', 'marketing']
  },

  // Analytics & Monitoring (90-95)
  {
    domain: 'analytics.google.com',
    display_name: 'Google Analytics',
    category: 'transactional',
    trust_score: 95,
    known_tracking_domains: ['google.com'],
    email_types: ['report', 'notification']
  },
  {
    domain: 'segment.com',
    display_name: 'Segment',
    category: 'transactional',
    trust_score: 91,
    known_tracking_domains: ['segment.com'],
    email_types: ['notification', 'report']
  },
  {
    domain: 'sentry.io',
    display_name: 'Sentry',
    category: 'transactional',
    trust_score: 92,
    known_tracking_domains: ['sentry.io'],
    email_types: ['error', 'notification']
  },
  {
    domain: 'datadog.com',
    display_name: 'Datadog',
    category: 'transactional',
    trust_score: 93,
    known_tracking_domains: ['datadog.com'],
    email_types: ['alert', 'notification']
  },

  // Design & Creative (88-93)
  {
    domain: 'adobe.com',
    display_name: 'Adobe',
    category: 'transactional',
    trust_score: 93,
    known_tracking_domains: ['adobe.com'],
    email_types: ['notification', 'marketing']
  },
  {
    domain: 'canva.com',
    display_name: 'Canva',
    category: 'transactional',
    trust_score: 88,
    known_tracking_domains: ['canva.com'],
    email_types: ['notification', 'marketing']
  },

  // CRM & Sales (85-92)
  {
    domain: 'salesforce.com',
    display_name: 'Salesforce',
    category: 'transactional',
    trust_score: 94,
    known_tracking_domains: ['salesforce.com'],
    email_types: ['notification', 'report']
  },
  {
    domain: 'zendesk.com',
    display_name: 'Zendesk',
    category: 'transactional',
    trust_score: 90,
    known_tracking_domains: ['zendesk.com'],
    email_types: ['support', 'notification']
  },
  {
    domain: 'freshdesk.com',
    display_name: 'Freshdesk',
    category: 'transactional',
    trust_score: 87,
    known_tracking_domains: ['freshdesk.com'],
    email_types: ['support', 'notification']
  },

  // Documentation & Knowledge Base (85-92)
  {
    domain: 'readthedocs.org',
    display_name: 'Read the Docs',
    category: 'transactional',
    trust_score: 88,
    known_tracking_domains: ['readthedocs.org'],
    email_types: ['notification']
  },
  {
    domain: 'gitbook.com',
    display_name: 'GitBook',
    category: 'transactional',
    trust_score: 87,
    known_tracking_domains: ['gitbook.com'],
    email_types: ['notification', 'collaboration']
  },

  // Miscellaneous Trusted Services (80-90)
  {
    domain: 'twilio.com',
    display_name: 'Twilio',
    category: 'transactional',
    trust_score: 93,
    known_tracking_domains: ['twilio.com'],
    email_types: ['notification', 'billing']
  },
  {
    domain: 'calendly.com',
    display_name: 'Calendly',
    category: 'transactional',
    trust_score: 88,
    known_tracking_domains: ['calendly.com'],
    email_types: ['meeting', 'notification']
  },
  {
    domain: 'typeform.com',
    display_name: 'Typeform',
    category: 'transactional',
    trust_score: 86,
    known_tracking_domains: ['typeform.com'],
    email_types: ['response', 'notification']
  },
  {
    domain: 'surveymonkey.com',
    display_name: 'SurveyMonkey',
    category: 'transactional',
    trust_score: 85,
    known_tracking_domains: ['surveymonkey.com'],
    email_types: ['response', 'notification']
  },
];

/**
 * Get trust modifier for scoring adjustment
 * - 90-100: 0.3 (70% reduction for highly trusted)
 * - 80-89: 0.5 (50% reduction for trusted)
 * - 70-79: 0.7 (30% reduction)
 * - <70: 1.0 (no reduction)
 */
export function getTrustModifier(trustScore: number): number {
  if (trustScore >= 90) return 0.3;
  if (trustScore >= 80) return 0.5;
  if (trustScore >= 70) return 0.7;
  return 1.0;
}

/**
 * Calculate expected score reduction for a sender
 */
export function calculateScoreReduction(originalScore: number, trustScore: number): {
  originalScore: number;
  modifier: number;
  adjustedScore: number;
  reduction: number;
  reductionPercent: number;
} {
  const modifier = getTrustModifier(trustScore);
  const adjustedScore = originalScore * modifier;
  const reduction = originalScore - adjustedScore;
  const reductionPercent = (reduction / originalScore) * 100;

  return {
    originalScore,
    modifier,
    adjustedScore,
    reduction,
    reductionPercent,
  };
}

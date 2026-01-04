/**
 * Test Email Fixtures
 * Sample emails for testing detection pipeline
 */

import type { ParsedEmail, EmailAddress } from '@/lib/detection/types';

// Helper to create EmailAddress objects
function emailAddr(address: string, displayName?: string): EmailAddress {
  return {
    address,
    displayName,
    domain: address.split('@')[1] || '',
  };
}

/**
 * Clean legitimate business email
 */
export const legitimateBusinessEmail: ParsedEmail = {
  messageId: 'test-legit-001@example.com',
  from: emailAddr('john.smith@acmecorp.com', 'John Smith'),
  to: [emailAddr('recipient@company.com')],
  cc: [],
  subject: 'Q4 Budget Review Meeting',
  date: new Date(),
  body: {
    text: `Hi Team,

I wanted to schedule a meeting to review our Q4 budget allocations. Please let me know your availability for next Tuesday or Wednesday.

Key agenda items:
- Review current spending
- Discuss proposed allocations for next quarter
- Address any department-specific concerns

Best regards,
John Smith
Finance Director
ACME Corp`,
    html: undefined,
  },
  headers: {
    'message-id': '<test-legit-001@example.com>',
    'from': 'John Smith <john.smith@acmecorp.com>',
    'date': new Date().toISOString(),
  },
  rawHeaders: '',
  attachments: [],
};

/**
 * Obvious phishing email
 */
export const obviousPhishingEmail: ParsedEmail = {
  messageId: 'test-phish-001@malicious.tk',
  from: emailAddr('security@micros0ft-support.tk', 'Microsoft Security'),
  to: [emailAddr('victim@company.com')],
  cc: [],
  subject: 'URGENT: Your Account Will Be Suspended!!!',
  date: new Date(),
  body: {
    text: `URGENT SECURITY ALERT!!!

Your Microsoft account has been compromised! You must verify your identity within 24 hours or your account will be PERMANENTLY SUSPENDED!

Click here IMMEDIATELY to verify your account:
http://bit.ly/3xFakeLink

Enter your password and credit card information to confirm your identity.

This is your FINAL WARNING!

Microsoft Security Team`,
    html: `<html>
<body style="font-family: Arial;">
<h1 style="color: red;">URGENT SECURITY ALERT!!!</h1>
<p>Your Microsoft account has been compromised! You must verify your identity within 24 hours or your account will be <b>PERMANENTLY SUSPENDED</b>!</p>
<p><a href="http://bit.ly/3xFakeLink">Click here IMMEDIATELY to verify your account</a></p>
<p>Enter your password and credit card information to confirm your identity.</p>
<p style="color: red; font-weight: bold;">This is your FINAL WARNING!</p>
<p>Microsoft Security Team</p>
</body>
</html>`,
  },
  headers: {
    'message-id': '<test-phish-001@malicious.tk>',
    'from': 'Microsoft Security <security@micros0ft-support.tk>',
    'date': new Date().toISOString(),
  },
  rawHeaders: '',
  attachments: [],
};

/**
 * Business Email Compromise (BEC) attempt
 */
export const becEmail: ParsedEmail = {
  messageId: 'test-bec-001@gmail.com',
  from: emailAddr('ceo.company@gmail.com', 'John CEO'),
  to: [emailAddr('finance@company.com')],
  cc: [],
  subject: 'Urgent Wire Transfer Needed',
  date: new Date(),
  body: {
    text: `Hi,

I need you to process an urgent wire transfer today. I'm in a meeting and can't call right now.

Please wire $45,000 to:
Bank: First National Bank
Account: 1234567890
Routing: 987654321

This is confidential - don't discuss with anyone else. Just get it done ASAP.

Thanks,
John (CEO)

Sent from my iPhone`,
    html: undefined,
  },
  headers: {
    'message-id': '<test-bec-001@gmail.com>',
    'from': 'John CEO <ceo.company@gmail.com>',
    'date': new Date().toISOString(),
  },
  rawHeaders: '',
  attachments: [],
};

/**
 * Spam email
 */
export const spamEmail: ParsedEmail = {
  messageId: 'test-spam-001@marketing.net',
  from: emailAddr('deals@amazing-offers-now.net', 'Amazing Deals'),
  to: [emailAddr('recipient@company.com')],
  cc: [],
  subject: 'FREE iPhone 15 - CLICK NOW - Limited Time Offer!!!',
  date: new Date(),
  body: {
    text: `CONGRATULATIONS!!!

You have been SPECIALLY SELECTED to receive a FREE iPhone 15 Pro Max!!!

This is NOT a joke! You are one of only 100 lucky winners!

CLICK HERE NOW to claim your FREE prize:
http://free-iphone-giveaway.xyz/claim?id=12345

This offer expires in 24 HOURS so ACT NOW!!!

Don't miss this AMAZING opportunity!

To unsubscribe, reply with STOP (but why would you want to miss FREE stuff?)`,
    html: undefined,
  },
  headers: {
    'message-id': '<test-spam-001@marketing.net>',
    'from': 'Amazing Deals <deals@amazing-offers-now.net>',
    'date': new Date().toISOString(),
  },
  rawHeaders: '',
  attachments: [],
};

/**
 * Email with malicious attachment
 */
export const malwareEmail: ParsedEmail = {
  messageId: 'test-malware-001@unknown.com',
  from: emailAddr('documents@invoice-delivery.com', 'Billing'),
  to: [emailAddr('recipient@company.com')],
  cc: [],
  subject: 'Invoice #INV-2024-0892 Attached',
  date: new Date(),
  body: {
    text: `Dear Customer,

Please find attached your invoice for recent services.

Payment is due within 30 days.

Best regards,
Billing Department`,
    html: undefined,
  },
  headers: {
    'message-id': '<test-malware-001@unknown.com>',
    'from': 'Billing <documents@invoice-delivery.com>',
    'date': new Date().toISOString(),
  },
  rawHeaders: '',
  attachments: [
    {
      filename: 'Invoice_2024_0892.exe',
      contentType: 'application/x-msdownload',
      size: 245760,
    },
  ],
};

/**
 * Suspicious but not clearly malicious email
 */
export const suspiciousEmail: ParsedEmail = {
  messageId: 'test-suspicious-001@newdomain.com',
  from: emailAddr('support@customer-service-help.com', 'Customer Support'),
  to: [emailAddr('recipient@company.com')],
  cc: [],
  subject: 'Action Required: Verify Your Account',
  date: new Date(),
  body: {
    text: `Hello,

We noticed some unusual activity on your account. For your security, please verify your account information by clicking the link below:

https://customer-service-help.com/verify?token=abc123

If you did not request this, please ignore this email.

Thank you,
Customer Support`,
    html: undefined,
  },
  headers: {
    'message-id': '<test-suspicious-001@newdomain.com>',
    'from': 'Customer Support <support@customer-service-help.com>',
    'date': new Date().toISOString(),
  },
  rawHeaders: '',
  attachments: [],
};

/**
 * Email from known trusted sender (for allowlist testing)
 */
export const trustedSenderEmail: ParsedEmail = {
  messageId: 'test-trusted-001@google.com',
  from: emailAddr('noreply@google.com', 'Google'),
  to: [emailAddr('recipient@company.com')],
  cc: [],
  subject: 'Security Alert: New Sign-in',
  date: new Date(),
  body: {
    text: `A new sign-in to your Google Account was detected.

Device: MacBook Pro
Location: San Francisco, CA
Time: Just now

If this was you, you can ignore this message. If not, please review your account security.

- The Google Accounts Team`,
    html: undefined,
  },
  headers: {
    'message-id': '<test-trusted-001@google.com>',
    'from': 'Google <noreply@google.com>',
    'date': new Date().toISOString(),
  },
  rawHeaders: '',
  attachments: [],
};

/**
 * Create email with custom properties
 */
export function createTestEmail(overrides: Partial<ParsedEmail>): ParsedEmail {
  return {
    messageId: `test-${Date.now()}@test.com`,
    from: emailAddr('sender@test.com'),
    to: [emailAddr('recipient@test.com')],
    cc: [],
    subject: 'Test Email',
    date: new Date(),
    body: {
      text: 'This is a test email.',
      html: undefined,
    },
    headers: {
      'message-id': `<test-${Date.now()}@test.com>`,
      'date': new Date().toISOString(),
    },
    rawHeaders: '',
    attachments: [],
    ...overrides,
  };
}

/**
 * Collection of all test emails by category
 */
export const testEmails = {
  legitimate: legitimateBusinessEmail,
  phishing: obviousPhishingEmail,
  bec: becEmail,
  spam: spamEmail,
  malware: malwareEmail,
  suspicious: suspiciousEmail,
  trusted: trustedSenderEmail,
};

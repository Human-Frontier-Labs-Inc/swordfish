/**
 * Feature Extractor Tests
 *
 * Tests for the ML feature extraction module that extracts comprehensive
 * features from emails for phishing detection.
 */

import {
  FeatureExtractor,
  extractFeatures,
  extractHeaderFeatures,
  extractContentFeatures,
  extractAttachmentFeatures,
  featuresToVector,
  featuresToPredictorFormat,
  getFeatureNames,
  getFeatureSchema,
  RawEmail,
  EmailFeatures,
  ExtractionContext,
} from '@/lib/ml/feature-extractor';

describe('FeatureExtractor', () => {
  let extractor: FeatureExtractor;

  beforeEach(() => {
    extractor = new FeatureExtractor();
  });

  describe('extractFeatures', () => {
    const mockEmail: RawEmail = {
      messageId: '<test-123@example.com>',
      from: {
        address: 'sender@example.com',
        displayName: 'Test Sender',
      },
      to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
      subject: 'Test Email Subject',
      date: new Date('2024-01-15T10:30:00Z'),
      headers: {
        'authentication-results': 'spf=pass dkim=pass dmarc=pass',
        'from': 'Test Sender <sender@example.com>',
        'message-id': '<test-123@example.com>',
        'date': 'Mon, 15 Jan 2024 10:30:00 +0000',
      },
      body: {
        text: 'This is a test email body.',
        html: '<html><body><p>This is a test email body.</p></body></html>',
      },
      attachments: [],
    };

    it('should extract all feature categories', async () => {
      const features = await extractor.extractFeatures(mockEmail, 'test-tenant');

      expect(features).toBeDefined();
      expect(features.header).toBeDefined();
      expect(features.content).toBeDefined();
      expect(features.sender).toBeDefined();
      expect(features.url).toBeDefined();
      expect(features.attachment).toBeDefined();
      expect(features.behavioral).toBeDefined();
      expect(features.metadata).toBeDefined();
    });

    it('should include metadata with extraction time', async () => {
      const features = await extractor.extractFeatures(mockEmail, 'test-tenant');

      expect(features.metadata.extractedAt).toBeInstanceOf(Date);
      expect(features.metadata.extractionTimeMs).toBeGreaterThanOrEqual(0);
      expect(features.metadata.featureVersion).toBe('1.0.0');
    });

    it('should work with ExtractionContext', async () => {
      const context: ExtractionContext = {
        tenantId: 'test-tenant',
        skipAsync: true,
        skipDomainAge: true,
        skipThreatIntel: true,
        skipBehavioral: true,
      };

      const features = await extractor.extractFeatures(mockEmail, context);
      expect(features).toBeDefined();
      expect(features.header.spfPassed).toBe(true);
    });
  });

  describe('extractHeaderFeatures', () => {
    it('should parse SPF pass result', () => {
      const headers = {
        'authentication-results': 'spf=pass smtp.mailfrom=example.com',
      };

      const features = extractor.extractHeaderFeatures(headers);
      expect(features.spfResult).toBe('pass');
      expect(features.spfPassed).toBe(true);
    });

    it('should parse SPF fail result', () => {
      const headers = {
        'authentication-results': 'spf=fail smtp.mailfrom=example.com',
      };

      const features = extractor.extractHeaderFeatures(headers);
      expect(features.spfResult).toBe('fail');
      expect(features.spfPassed).toBe(false);
    });

    it('should parse DKIM and DMARC results', () => {
      const headers = {
        'authentication-results': 'spf=pass dkim=pass dmarc=pass',
      };

      const features = extractor.extractHeaderFeatures(headers);
      expect(features.dkimPassed).toBe(true);
      expect(features.dmarcPassed).toBe(true);
      expect(features.authenticationScore).toBe(100);
    });

    it('should calculate authentication score correctly', () => {
      const headers = {
        'authentication-results': 'spf=pass dkim=fail dmarc=none',
      };

      const features = extractor.extractHeaderFeatures(headers);
      // SPF pass = 30, DKIM fail = 0, DMARC none = 0
      expect(features.authenticationScore).toBe(30);
    });

    it('should detect reply-to mismatch', () => {
      const headers = {
        'from': 'sender@example.com',
        'reply-to': 'different@other.com',
        'authentication-results': '',
      };

      const features = extractor.extractHeaderFeatures(headers);
      expect(features.replyToMismatch).toBe(true);
      expect(features.replyToDomainMismatch).toBe(true);
    });

    it('should detect missing message ID', () => {
      const features = extractor.extractHeaderFeatures({});
      expect(features.missingMessageId).toBe(true);
    });

    it('should detect suspicious mailer', () => {
      const headers = {
        'x-mailer': 'PHPMailer/5.2.9',
        'authentication-results': '',
      };

      const features = extractor.extractHeaderFeatures(headers);
      expect(features.suspiciousMailer).toBe(true);
    });
  });

  describe('extractContentFeatures', () => {
    it('should detect urgency words', () => {
      const body = 'URGENT: Your account will be suspended immediately if you do not act now!';
      const features = extractor.extractContentFeatures(body, undefined, 'Urgent Action Required');

      expect(features.urgencyWordCount).toBeGreaterThan(0);
      expect(features.hasUrgencyIndicator).toBe(true);
      expect(features.subjectHasUrgency).toBe(true);
    });

    it('should detect financial terminology', () => {
      const body = 'Please complete the wire transfer and update your bank account details.';
      const features = extractor.extractContentFeatures(body);

      expect(features.financialTermCount).toBeGreaterThan(0);
      expect(features.hasFinancialRequest).toBe(true);
    });

    it('should detect credential requests', () => {
      const body = 'Please enter password and verify credentials to avoid account suspension. Enter your SSN.';
      const features = extractor.extractContentFeatures(body);

      expect(features.credentialRequestCount).toBeGreaterThan(0);
      expect(features.hasCredentialRequest).toBe(true);
    });

    it('should calculate sentiment score', () => {
      const negativeBody = 'Your account will be suspended and terminated due to unauthorized access.';
      const positiveBody = 'Thank you for your business! We appreciate your continued support.';

      const negativeFeatures = extractor.extractContentFeatures(negativeBody);
      const positiveFeatures = extractor.extractContentFeatures(positiveBody);

      expect(negativeFeatures.sentimentScore).toBeLessThan(positiveFeatures.sentimentScore);
    });

    it('should detect threat language', () => {
      const body = 'Failure to comply will result in legal action and prosecution.';
      const features = extractor.extractContentFeatures(body);

      expect(features.threatLanguageScore).toBeGreaterThan(0);
      expect(features.hasThreateningLanguage).toBe(true);
    });

    it('should detect excessive punctuation in subject', () => {
      const features = extractor.extractContentFeatures('', undefined, 'IMPORTANT!!!');
      expect(features.subjectExcessivePunctuation).toBe(true);
    });

    it('should detect all caps subject', () => {
      const features = extractor.extractContentFeatures('', undefined, 'URGENT NOTICE');
      expect(features.subjectAllCaps).toBe(true);
    });
  });

  describe('extractAttachmentFeatures', () => {
    it('should detect executable attachments', () => {
      const attachments = [
        { filename: 'document.exe', contentType: 'application/x-msdownload', size: 1024 },
      ];

      const features = extractor.extractAttachmentFeatures(attachments);
      expect(features.hasExecutable).toBe(true);
      expect(features.executableCount).toBe(1);
      expect(features.riskScore).toBeGreaterThanOrEqual(50);
    });

    it('should detect macro-enabled documents', () => {
      const attachments = [
        { filename: 'document.docm', contentType: 'application/vnd.ms-word.document.macroEnabled.12', size: 2048 },
      ];

      const features = extractor.extractAttachmentFeatures(attachments);
      expect(features.hasMacros).toBe(true);
      expect(features.macroEnabledCount).toBe(1);
    });

    it('should detect double extensions', () => {
      // Double extension detection checks if a dangerous extension is hidden in the middle
      // e.g., document.exe.txt (where .exe is the second-to-last extension)
      const attachments = [
        { filename: 'document.exe.txt', contentType: 'text/plain', size: 512 },
      ];

      const features = extractor.extractAttachmentFeatures(attachments);
      expect(features.hasDoubleExtension).toBe(true);
    });

    it('should calculate total size', () => {
      const attachments = [
        { filename: 'file1.pdf', contentType: 'application/pdf', size: 1000 },
        { filename: 'file2.pdf', contentType: 'application/pdf', size: 2000 },
      ];

      const features = extractor.extractAttachmentFeatures(attachments);
      expect(features.fileCount).toBe(2);
      expect(features.totalSize).toBe(3000);
      expect(features.avgSize).toBe(1500);
    });

    it('should return safe risk level for clean attachments', () => {
      const attachments = [
        { filename: 'document.pdf', contentType: 'application/pdf', size: 1024 },
      ];

      const features = extractor.extractAttachmentFeatures(attachments);
      expect(features.riskLevel).toBe('safe');
    });
  });

  describe('batchExtract', () => {
    it('should process multiple emails', async () => {
      const emails: RawEmail[] = [
        {
          messageId: '<test-1@example.com>',
          from: { address: 'sender1@example.com' },
          to: [{ address: 'recipient@company.com' }],
          subject: 'Email 1',
          date: new Date(),
          headers: {},
          body: { text: 'Body 1' },
          attachments: [],
        },
        {
          messageId: '<test-2@example.com>',
          from: { address: 'sender2@example.com' },
          to: [{ address: 'recipient@company.com' }],
          subject: 'Email 2',
          date: new Date(),
          headers: {},
          body: { text: 'Body 2' },
          attachments: [],
        },
      ];

      const context: ExtractionContext = {
        tenantId: 'test-tenant',
        skipAsync: true,
      };

      const results = await extractor.batchExtract(emails, context);

      expect(results).toHaveLength(2);
      expect(results[0].metadata).toBeDefined();
      expect(results[1].metadata).toBeDefined();
    });
  });

  describe('getFeatureSchema', () => {
    it('should return valid schema', () => {
      const schema = extractor.getFeatureSchema();

      expect(schema.version).toBe('1.0.0');
      expect(schema.totalFeatures).toBe(84);
      expect(schema.categories.header).toBeDefined();
      expect(schema.categories.content).toBeDefined();
      expect(schema.categories.sender).toBeDefined();
      expect(schema.categories.url).toBeDefined();
      expect(schema.categories.attachment).toBeDefined();
      expect(schema.categories.behavioral).toBeDefined();
    });

    it('should have proper field definitions', () => {
      const schema = extractor.getFeatureSchema();

      for (const field of schema.categories.header) {
        expect(field.name).toBeDefined();
        expect(field.type).toBeDefined();
        expect(field.description).toBeDefined();
        expect(field.importance).toBeDefined();
        expect(field.category).toBe('header');
      }
    });
  });
});

describe('Feature Conversion Functions', () => {
  describe('featuresToVector', () => {
    it('should convert features to numeric vector', async () => {
      const extractor = new FeatureExtractor();
      const email: RawEmail = {
        messageId: '<test@example.com>',
        from: { address: 'sender@example.com' },
        to: [{ address: 'recipient@company.com' }],
        subject: 'Test',
        date: new Date(),
        headers: { 'authentication-results': 'spf=pass dkim=pass dmarc=pass' },
        body: { text: 'Test body' },
        attachments: [],
      };

      const features = await extractor.extractFeatures(email, { tenantId: 'test', skipAsync: true });
      const vector = featuresToVector(features);

      expect(Array.isArray(vector)).toBe(true);
      expect(vector.length).toBe(84);
      expect(vector.every(v => typeof v === 'number')).toBe(true);
    });
  });

  describe('getFeatureNames', () => {
    it('should return feature names matching vector length', () => {
      const names = getFeatureNames();
      expect(names.length).toBe(84);
      expect(names[0]).toBe('header_spf_passed');
    });
  });

  describe('featuresToPredictorFormat', () => {
    it('should convert to predictor format', async () => {
      const extractor = new FeatureExtractor();
      const email: RawEmail = {
        messageId: '<test@example.com>',
        from: { address: 'sender@example.com' },
        to: [{ address: 'recipient@company.com' }],
        subject: 'Test',
        date: new Date(),
        headers: { 'authentication-results': 'spf=pass dkim=pass dmarc=pass' },
        body: { text: 'Test body' },
        attachments: [],
      };

      const features = await extractor.extractFeatures(email, { tenantId: 'test', skipAsync: true });
      const predictorFeatures = featuresToPredictorFormat(features);

      expect(predictorFeatures.headerFeatures).toBeDefined();
      expect(predictorFeatures.contentFeatures).toBeDefined();
      expect(predictorFeatures.senderFeatures).toBeDefined();
      expect(predictorFeatures.urlFeatures).toBeDefined();
      expect(predictorFeatures.attachmentFeatures).toBeDefined();
      expect(predictorFeatures.behavioralFeatures).toBeDefined();

      // Check specific conversions
      expect(predictorFeatures.headerFeatures.spfScore).toBe(1);
      expect(predictorFeatures.headerFeatures.dkimScore).toBe(1);
      expect(predictorFeatures.headerFeatures.dmarcScore).toBe(1);
    });
  });

  describe('getFeatureSchema', () => {
    it('should match extractor schema', () => {
      const extractor = new FeatureExtractor();
      const schema1 = getFeatureSchema();
      const schema2 = extractor.getFeatureSchema();

      expect(schema1.version).toBe(schema2.version);
      expect(schema1.totalFeatures).toBe(schema2.totalFeatures);
    });
  });
});

describe('NLP Pattern Detection', () => {
  let extractor: FeatureExtractor;

  beforeEach(() => {
    extractor = new FeatureExtractor();
  });

  describe('Urgency Detection', () => {
    const urgencyPhrases = [
      'urgent action required',
      'respond immediately',
      'your account will be suspended',
      'verify immediately',
      'act now',
      'limited time',
      'expires today',
      'within 24 hours',
      "before it's too late",
    ];

    it.each(urgencyPhrases)('should detect urgency phrase: %s', (phrase) => {
      const features = extractor.extractContentFeatures(phrase);
      expect(features.urgencyWordCount).toBeGreaterThan(0);
    });
  });

  describe('Threat Detection', () => {
    const threatPhrases = [
      'your account will be suspended',
      'unauthorized access detected',
      'legal action will be taken',
      'fraud alert',
      'violation of terms',
    ];

    it.each(threatPhrases)('should detect threat phrase: %s', (phrase) => {
      const features = extractor.extractContentFeatures(phrase);
      expect(features.threatLanguageScore).toBeGreaterThan(0);
    });
  });

  describe('Financial Request Detection', () => {
    const financialPhrases = [
      'wire transfer',
      'bank account details',
      'gift card',
      'bitcoin payment',
      'routing number',
      'payroll update',
    ];

    it.each(financialPhrases)('should detect financial phrase: %s', (phrase) => {
      const features = extractor.extractContentFeatures(phrase);
      expect(features.financialTermCount).toBeGreaterThan(0);
    });
  });

  describe('Credential Request Detection', () => {
    const credentialPhrases = [
      'enter password',
      'verify credentials',
      'login required',
      'verify account',
      'social security',
      'ssn',
    ];

    it.each(credentialPhrases)('should detect credential phrase: %s', (phrase) => {
      const features = extractor.extractContentFeatures(phrase);
      expect(features.credentialRequestCount).toBeGreaterThan(0);
    });
  });
});

describe('URL Feature Extraction', () => {
  let extractor: FeatureExtractor;

  beforeEach(() => {
    extractor = new FeatureExtractor();
  });

  it('should detect URL shorteners', async () => {
    const email: RawEmail = {
      messageId: '<test@example.com>',
      from: { address: 'sender@example.com' },
      to: [{ address: 'recipient@company.com' }],
      subject: 'Test',
      date: new Date(),
      headers: {},
      body: { text: 'Click here: https://bit.ly/abc123 or https://tinyurl.com/xyz' },
      attachments: [],
    };

    const features = await extractor.extractFeatures(email, { tenantId: 'test', skipAsync: true });
    expect(features.url.urlShortenerCount).toBeGreaterThan(0);
    expect(features.url.shortenerDomains.length).toBeGreaterThan(0);
  });

  it('should detect IP-based URLs', async () => {
    const email: RawEmail = {
      messageId: '<test@example.com>',
      from: { address: 'sender@example.com' },
      to: [{ address: 'recipient@company.com' }],
      subject: 'Test',
      date: new Date(),
      headers: {},
      body: { text: 'Click here: http://192.168.1.1/login' },
      attachments: [],
    };

    const features = await extractor.extractFeatures(email, { tenantId: 'test', skipAsync: true });
    expect(features.url.hasIPAddressUrl).toBe(true);
    expect(features.url.ipAddressUrls.length).toBeGreaterThan(0);
  });

  it('should detect suspicious TLDs', async () => {
    const email: RawEmail = {
      messageId: '<test@example.com>',
      from: { address: 'sender@example.com' },
      to: [{ address: 'recipient@company.com' }],
      subject: 'Test',
      date: new Date(),
      headers: {},
      body: { text: 'Click here: https://secure-login.tk/verify' },
      attachments: [],
    };

    const features = await extractor.extractFeatures(email, { tenantId: 'test', skipAsync: true });
    expect(features.url.suspiciousTldCount).toBeGreaterThan(0);
    expect(features.url.suspiciousTlds).toContain('tk');
  });
});

describe('Sender Feature Extraction', () => {
  let extractor: FeatureExtractor;

  beforeEach(() => {
    extractor = new FeatureExtractor();
  });

  it('should detect free email providers', async () => {
    const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];

    for (const provider of freeProviders) {
      const email: RawEmail = {
        messageId: '<test@example.com>',
        from: { address: `sender@${provider}` },
        to: [{ address: 'recipient@company.com' }],
        subject: 'Test',
        date: new Date(),
        headers: {},
        body: { text: 'Test' },
        attachments: [],
      };

      const features = await extractor.extractFeatures(email, { tenantId: 'test', skipAsync: true });
      expect(features.sender.isFreeEmailProvider).toBe(true);
      expect(features.sender.freeEmailProvider).toBe(provider);
    }
  });

  it('should detect disposable email providers', async () => {
    const email: RawEmail = {
      messageId: '<test@example.com>',
      from: { address: 'sender@tempmail.com' },
      to: [{ address: 'recipient@company.com' }],
      subject: 'Test',
      date: new Date(),
      headers: {},
      body: { text: 'Test' },
      attachments: [],
    };

    const features = await extractor.extractFeatures(email, { tenantId: 'test', skipAsync: true });
    expect(features.sender.isDisposableEmail).toBe(true);
  });
});

describe('Behavioral Feature Extraction', () => {
  let extractor: FeatureExtractor;

  beforeEach(() => {
    extractor = new FeatureExtractor();
  });

  it('should detect unusual send time (weekend)', async () => {
    // Create a date that's on a weekend (Saturday)
    const saturday = new Date('2024-01-13T14:00:00Z'); // January 13, 2024 is a Saturday

    const email: RawEmail = {
      messageId: '<test@example.com>',
      from: { address: 'sender@example.com' },
      to: [{ address: 'recipient@company.com' }],
      subject: 'Test',
      date: saturday,
      headers: {},
      body: { text: 'Test' },
      attachments: [],
    };

    const features = await extractor.extractFeatures(email, { tenantId: 'test', skipAsync: true });
    expect(features.behavioral.isWeekend).toBe(true);
  });

  it('should detect unusual send time (outside business hours)', async () => {
    // Create a date at 2 AM on a weekday
    const lateNight = new Date('2024-01-15T02:00:00Z'); // Monday at 2 AM UTC

    const email: RawEmail = {
      messageId: '<test@example.com>',
      from: { address: 'sender@example.com' },
      to: [{ address: 'recipient@company.com' }],
      subject: 'Test',
      date: lateNight,
      headers: {},
      body: { text: 'Test' },
      attachments: [],
    };

    const features = await extractor.extractFeatures(email, { tenantId: 'test', skipAsync: true });
    expect(features.behavioral.sendTimeAnomalyScore).toBeGreaterThan(0);
  });
});

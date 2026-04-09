/**
 * Email Analysis API Tests
 * Tests for POST /api/analyze endpoint
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { NextRequest } from 'next/server';

// Mock Clerk auth
vi.mock('@clerk/nextjs/server', () => ({
  auth: vi.fn(),
}));

// Mock rate limiting
vi.mock('@/lib/api/rate-limit', () => ({
  rateLimit: vi.fn().mockReturnValue({ success: true, remaining: 9 }),
}));

// Mock detection pipeline
vi.mock('@/lib/detection/pipeline', () => ({
  analyzeEmail: vi.fn(),
  quickCheck: vi.fn(),
}));

// Mock parser
vi.mock('@/lib/detection/parser', () => ({
  parseEmail: vi.fn(),
  parseGraphEmail: vi.fn(),
  parseGmailEmail: vi.fn(),
}));

import { auth } from '@clerk/nextjs/server';
import { analyzeEmail, quickCheck } from '@/lib/detection/pipeline';
import { parseEmail, parseGraphEmail, parseGmailEmail } from '@/lib/detection/parser';
import { rateLimit } from '@/lib/api/rate-limit';
import { POST } from '@/app/api/analyze/route';

describe('POST /api/analyze', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Re-establish rate limit mock after clearAllMocks
    (rateLimit as ReturnType<typeof vi.fn>).mockReturnValue({ success: true, remaining: 9 });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const mockParsedEmail = {
    messageId: 'test-msg-123',
    subject: 'Test Email',
    from: { address: 'sender@test.com', domain: 'test.com' },
    to: [{ address: 'recipient@company.com', domain: 'company.com' }],
    date: new Date(),
    headers: {},
    body: { text: 'Test body' },
    attachments: [],
    rawHeaders: '',
  };

  const mockVerdict = {
    messageId: 'test-msg-123',
    tenantId: 'org_123',
    verdict: 'pass' as const,
    overallScore: 15,
    confidence: 0.9,
    signals: [],
    layerResults: [],
    processingTimeMs: 100,
    analyzedAt: new Date(),
  };

  describe('Authentication', () => {
    it('should return 401 when not authenticated', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: null, orgId: null });

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ parsed: mockParsedEmail }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(401);
      const data = await response.json();
      expect(data.error).toBe('Unauthorized');
    });

    it('should accept authenticated requests', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(mockVerdict);

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ parsed: mockParsedEmail }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
    });
  });

  describe('Input Validation', () => {
    beforeEach(() => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
    });

    it('should return 400 when no email data provided', async () => {
      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({}),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(400);
      const data = await response.json();
      expect(data.error).toContain('No email data provided');
    });

    it('should accept pre-parsed email format', async () => {
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(mockVerdict);

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ parsed: mockParsedEmail }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      expect(analyzeEmail).toHaveBeenCalled();
      const callArgs = (analyzeEmail as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(callArgs[1]).toBe('org_123');
    });

    it('should accept raw MIME format', async () => {
      const rawMime = 'From: sender@test.com\nTo: recipient@test.com\nSubject: Test\n\nBody';
      (parseEmail as ReturnType<typeof vi.fn>).mockReturnValue(mockParsedEmail);
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(mockVerdict);

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ rawMime }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      expect(parseEmail).toHaveBeenCalledWith(rawMime);
    });

    it('should accept Microsoft Graph format', async () => {
      const graphMessage = { id: 'graph-123', subject: 'Test' };
      (parseGraphEmail as ReturnType<typeof vi.fn>).mockReturnValue(mockParsedEmail);
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(mockVerdict);

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ graphMessage }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      expect(parseGraphEmail).toHaveBeenCalledWith(graphMessage);
    });

    it('should accept Gmail format', async () => {
      const gmailMessage = { id: 'gmail-123', payload: { headers: [] } };
      (parseGmailEmail as ReturnType<typeof vi.fn>).mockReturnValue(mockParsedEmail);
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(mockVerdict);

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ gmailMessage }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      expect(parseGmailEmail).toHaveBeenCalledWith(gmailMessage);
    });
  });

  describe('Quick Check Mode', () => {
    beforeEach(() => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
    });

    it('should return quick check result when conclusive', async () => {
      (quickCheck as ReturnType<typeof vi.fn>).mockResolvedValue('pass');

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ parsed: mockParsedEmail, quickCheckOnly: true }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.quickCheck).toBe(true);
      expect(data.verdict).toBe('pass');
      expect(analyzeEmail).not.toHaveBeenCalled();
    });

    it('should indicate full analysis needed when quick check inconclusive', async () => {
      (quickCheck as ReturnType<typeof vi.fn>).mockResolvedValue(null);

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ parsed: mockParsedEmail, quickCheckOnly: true }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.quickCheck).toBe(true);
      expect(data.needsFullAnalysis).toBe(true);
    });
  });

  describe('Full Analysis', () => {
    beforeEach(() => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
    });

    it('should return complete verdict for full analysis', async () => {
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(mockVerdict);

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ parsed: mockParsedEmail }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.verdict).toBe('pass');
      expect(data.score).toBe(15); // API returns 'score' not 'overallScore'
      expect(data.confidence).toBe(0.9);
    });

    it('should use personal tenant ID when no org', async () => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_456', orgId: null });
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(mockVerdict);

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ parsed: mockParsedEmail }),
        headers: { 'Content-Type': 'application/json' },
      });

      await POST(request);

      expect(analyzeEmail).toHaveBeenCalled();
      const callArgs = (analyzeEmail as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(callArgs[1]).toBe('personal_user_456');
    });

    it('should skip LLM when requested', async () => {
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(mockVerdict);

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ parsed: mockParsedEmail, skipLLM: true }),
        headers: { 'Content-Type': 'application/json' },
      });

      await POST(request);

      expect(analyzeEmail).toHaveBeenCalled();
      const callArgs = (analyzeEmail as ReturnType<typeof vi.fn>).mock.calls[0];
      const config = callArgs[2];
      expect(config.invokeLlmConfidenceRange).toEqual([1, 1]); // Never trigger LLM
    });
  });

  describe('Verdict Types', () => {
    beforeEach(() => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
    });

    it('should return suspicious verdict for medium threats', async () => {
      const suspiciousVerdict = { ...mockVerdict, verdict: 'suspicious' as const, overallScore: 55 };
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(suspiciousVerdict);

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ parsed: mockParsedEmail }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.verdict).toBe('suspicious');
    });

    it('should return quarantine verdict for high threats', async () => {
      const quarantineVerdict = { ...mockVerdict, verdict: 'quarantine' as const, overallScore: 75 };
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(quarantineVerdict);

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ parsed: mockParsedEmail }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.verdict).toBe('quarantine');
    });

    it('should return block verdict for critical threats', async () => {
      const blockVerdict = { ...mockVerdict, verdict: 'block' as const, overallScore: 95 };
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValue(blockVerdict);

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ parsed: mockParsedEmail }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.verdict).toBe('block');
    });
  });

  describe('Error Handling', () => {
    beforeEach(() => {
      (auth as ReturnType<typeof vi.fn>).mockResolvedValue({ userId: 'user_123', orgId: 'org_123' });
    });

    it('should handle analysis errors gracefully', async () => {
      (analyzeEmail as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Analysis failed'));

      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ parsed: mockParsedEmail }),
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(500);
      const data = await response.json();
      expect(data.error).toBeDefined();
    });

    it('should handle invalid JSON gracefully', async () => {
      const request = new NextRequest('http://localhost/api/analyze', {
        method: 'POST',
        body: 'not valid json',
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await POST(request);

      expect(response.status).toBe(500);
    });
  });
});

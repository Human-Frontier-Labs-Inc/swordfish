/**
 * QR Code Detection Tests - Phase 1
 *
 * TDD tests for QR code detection ("Quishing" attacks)
 * Tests attachment detection, inline images, and URL analysis
 */

import { describe, it, expect } from 'vitest';
import {
  detectQRCodes,
  analyzeQRUrls,
  getQRRiskSummary,
  type QRCodeDetection,
  type QRSignal,
} from '@/lib/detection/qr-detector';

describe('QR Code Detection - Quishing Prevention', () => {
  describe('Attachment Detection', () => {
    it('should detect QR code patterns in image filenames', () => {
      const attachments = [
        { filename: 'qr-code.png', mimeType: 'image/png', size: 15000 },
      ];

      const result = detectQRCodes(attachments);

      expect(result.found).toBe(true);
      expect(result.count).toBe(1);
      expect(result.sources[0].type).toBe('attachment');
      expect(result.signals.length).toBeGreaterThan(0);
    });

    it('should detect scan-me named images', () => {
      const attachments = [
        { filename: 'scan-me.jpg', mimeType: 'image/jpeg', size: 20000 },
      ];

      const result = detectQRCodes(attachments);

      expect(result.found).toBe(true);
      expect(result.sources[0].filename).toBe('scan-me.jpg');
    });

    it('should detect payment QR codes', () => {
      const attachments = [
        { filename: 'payment-qr.png', mimeType: 'image/png', size: 12000 },
      ];

      const result = detectQRCodes(attachments);

      expect(result.found).toBe(true);
      expect(result.signals.some(s => s.type === 'qr_code_present')).toBe(true);
    });

    it('should detect SVG files as potential QR codes', () => {
      const attachments = [
        { filename: 'image.svg', mimeType: 'image/svg+xml', size: 5000 },
      ];

      const result = detectQRCodes(attachments);

      expect(result.found).toBe(true);
      expect(result.signals.some(s => s.detail.includes('SVG'))).toBe(true);
    });

    it('should detect small image files as potential QR codes', () => {
      const attachments = [
        { filename: 'image.png', mimeType: 'image/png', size: 25000 },
      ];

      const result = detectQRCodes(attachments);

      expect(result.found).toBe(true);
      expect(result.signals.some(s => s.detail.includes('Small image'))).toBe(true);
    });

    it('should NOT flag large images as QR codes', () => {
      const attachments = [
        { filename: 'photo.jpg', mimeType: 'image/jpeg', size: 2000000 }, // 2MB
      ];

      const result = detectQRCodes(attachments);

      expect(result.found).toBe(false);
    });

    it('should NOT flag non-image attachments', () => {
      const attachments = [
        { filename: 'document.pdf', mimeType: 'application/pdf', size: 50000 },
        { filename: 'report.docx', mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', size: 100000 },
      ];

      const result = detectQRCodes(attachments);

      expect(result.found).toBe(false);
    });
  });

  describe('Inline Image Detection', () => {
    it('should detect base64-encoded inline images in HTML', () => {
      const html = `
        <html>
          <body>
            <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==" />
          </body>
        </html>
      `;

      const result = detectQRCodes([], html);

      expect(result.found).toBe(true);
      expect(result.sources[0].type).toBe('inline');
      expect(result.signals.some(s => s.type === 'qr_inline_hidden')).toBe(true);
    });

    it('should detect multiple inline images', () => {
      const html = `
        <html>
          <body>
            <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==" />
            <img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAn/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBEQCEAwEPwAB//9k=" />
          </body>
        </html>
      `;

      const result = detectQRCodes([], html);

      expect(result.found).toBe(true);
      expect(result.count).toBe(2);
    });

    it('should NOT flag very large inline images', () => {
      // Create a large base64 string (simulating a large image)
      const largeBase64 = 'A'.repeat(200000); // ~150KB decoded
      const html = `<img src="data:image/png;base64,${largeBase64}" />`;

      const result = detectQRCodes([], html);

      expect(result.found).toBe(false);
    });
  });

  describe('Embedded Image References', () => {
    it('should detect QR-named image references in HTML', () => {
      const html = `
        <html>
          <body>
            <img src="https://example.com/qr-code-payment.png" />
          </body>
        </html>
      `;

      const result = detectQRCodes([], html);

      expect(result.found).toBe(true);
      expect(result.sources[0].type).toBe('html_embedded');
      expect(result.sources[0].filename).toBe('https://example.com/qr-code-payment.png');
    });

    it('should detect scan-to-pay image references', () => {
      const html = `<img src="https://cdn.example.com/scan-to-pay.jpg" />`;

      const result = detectQRCodes([], html);

      expect(result.found).toBe(true);
      expect(result.signals.some(s => s.type === 'qr_code_present')).toBe(true);
    });

    it('should NOT flag regular image references', () => {
      const html = `
        <html>
          <body>
            <img src="https://example.com/logo.png" />
            <img src="https://example.com/banner.jpg" />
          </body>
        </html>
      `;

      const result = detectQRCodes([], html);

      expect(result.found).toBe(false);
    });
  });

  describe('Multiple QR Code Detection', () => {
    it('should flag multiple QR codes as higher risk', () => {
      const attachments = [
        { filename: 'qr1.png', mimeType: 'image/png', size: 15000 },
        { filename: 'qr2.png', mimeType: 'image/png', size: 15000 },
      ];

      const result = detectQRCodes(attachments);

      expect(result.found).toBe(true);
      expect(result.count).toBe(2);
      expect(result.signals.some(s => s.type === 'qr_multiple')).toBe(true);
      expect(result.riskScore).toBeGreaterThan(8); // Higher risk for multiple QR codes
    });
  });

  describe('URL Analysis from QR Codes', () => {
    it('should flag shortened URLs as suspicious', () => {
      const urls = ['https://bit.ly/abc123'];
      const signals = analyzeQRUrls(urls);

      expect(signals.length).toBeGreaterThan(0);
      expect(signals[0].type).toBe('qr_url_shortened');
      expect(signals[0].severity).toBe('warning');
    });

    it('should flag tinyurl as suspicious', () => {
      const urls = ['https://tinyurl.com/xyz789'];
      const signals = analyzeQRUrls(urls);

      expect(signals.some(s => s.type === 'qr_url_shortened')).toBe(true);
    });

    it('should flag IP-based URLs as critical', () => {
      const urls = ['http://192.168.1.1/login'];
      const signals = analyzeQRUrls(urls);

      expect(signals.some(s => s.type === 'qr_url_suspicious')).toBe(true);
      expect(signals.some(s => s.severity === 'critical')).toBe(true);
    });

    it('should flag credential-related URLs as suspicious', () => {
      const urls = [
        'https://example.com/login',
        'https://example.com/verify-account',
        'https://example.com/confirm-payment',
      ];

      for (const url of urls) {
        const signals = analyzeQRUrls([url]);
        expect(signals.some(s => s.type === 'qr_url_suspicious')).toBe(true);
      }
    });

    it('should flag high-risk TLDs', () => {
      const urls = [
        'https://example.ru/payment',
        'https://example.tk/download',
        'https://example.ml/verify',
      ];

      for (const url of urls) {
        const signals = analyzeQRUrls([url]);
        expect(signals.some(s => s.type === 'qr_url_suspicious')).toBe(true);
      }
    });

    it('should return empty for legitimate URLs', () => {
      const urls = ['https://example.com/products', 'https://company.com/about'];
      const signals = analyzeQRUrls(urls);

      expect(signals.length).toBe(0);
    });
  });

  describe('Risk Scoring', () => {
    it('should calculate risk score based on signals', () => {
      const attachments = [
        { filename: 'qr-code.png', mimeType: 'image/png', size: 15000 },
      ];

      const result = detectQRCodes(attachments);

      expect(result.riskScore).toBeGreaterThan(0);
      expect(result.riskScore).toBeLessThanOrEqual(10);
    });

    it('should cap risk score at 10', () => {
      const attachments = [
        { filename: 'qr1.png', mimeType: 'image/png', size: 15000 },
        { filename: 'qr2.png', mimeType: 'image/png', size: 15000 },
        { filename: 'qr3.png', mimeType: 'image/png', size: 15000 },
      ];

      const result = detectQRCodes(attachments);

      expect(result.riskScore).toBe(10);
    });

    it('should return zero risk for no QR codes', () => {
      const attachments = [
        { filename: 'document.pdf', mimeType: 'application/pdf', size: 50000 },
      ];

      const result = detectQRCodes(attachments);

      expect(result.riskScore).toBe(0);
    });
  });

  describe('Risk Summary', () => {
    it('should return "No QR codes detected" for clean emails', () => {
      const detection: QRCodeDetection = {
        found: false,
        count: 0,
        sources: [],
        extractedUrls: [],
        riskScore: 0,
        signals: [],
      };

      const summary = getQRRiskSummary(detection);

      expect(summary).toBe('No QR codes detected');
    });

    it('should return LOW risk summary for single QR code', () => {
      const detection: QRCodeDetection = {
        found: true,
        count: 1,
        sources: [{ type: 'attachment', filename: 'qr.png', mimeType: 'image/png', size: 15000 }],
        extractedUrls: [],
        riskScore: 3,
        signals: [],
      };

      const summary = getQRRiskSummary(detection);

      expect(summary).toContain('1 potential QR code');
      expect(summary).toContain('LOW');
    });

    it('should return MEDIUM risk summary for moderate score', () => {
      const detection: QRCodeDetection = {
        found: true,
        count: 2,
        sources: [],
        extractedUrls: [],
        riskScore: 5,
        signals: [],
      };

      const summary = getQRRiskSummary(detection);

      expect(summary).toContain('MEDIUM');
    });

    it('should return HIGH risk summary for high score', () => {
      const detection: QRCodeDetection = {
        found: true,
        count: 3,
        sources: [],
        extractedUrls: [],
        riskScore: 8,
        signals: [],
      };

      const summary = getQRRiskSummary(detection);

      expect(summary).toContain('HIGH');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty inputs gracefully', () => {
      const result = detectQRCodes([]);

      expect(result.found).toBe(false);
      expect(result.count).toBe(0);
      expect(result.riskScore).toBe(0);
    });

    it('should handle undefined HTML content', () => {
      const result = detectQRCodes([], undefined);

      expect(result.found).toBe(false);
    });

    it('should handle attachments with missing properties', () => {
      const attachments = [
        { filename: 'qr.png', mimeType: 'image/png', size: 15000 },
        { filename: '', mimeType: 'image/png', size: 0 },
      ];

      // Should not throw
      const result = detectQRCodes(attachments);
      expect(Array.isArray(result.sources)).toBe(true);
    });

    it('should handle malformed HTML', () => {
      const malformedHtml = '<img src="data:image/png;base64,abc" <broken>';

      // Should not throw
      const result = detectQRCodes([], malformedHtml);
      expect(Array.isArray(result.sources)).toBe(true);
    });

    it('should handle very long URLs in analysis', () => {
      const longUrl = 'https://example.com/' + 'a'.repeat(2000);
      const signals = analyzeQRUrls([longUrl]);

      // Should not throw
      expect(Array.isArray(signals)).toBe(true);
    });
  });

  describe('Combined Detection', () => {
    it('should detect QR codes from multiple sources in one email', () => {
      const attachments = [
        { filename: 'qrcode.png', mimeType: 'image/png', size: 15000 },
      ];
      const html = `
        <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==" />
        <img src="https://example.com/scan-me.png" />
      `;

      const result = detectQRCodes(attachments, html);

      expect(result.found).toBe(true);
      expect(result.count).toBe(3); // 1 attachment + 1 inline + 1 embedded
      expect(result.signals.some(s => s.type === 'qr_multiple')).toBe(true);
    });
  });
});

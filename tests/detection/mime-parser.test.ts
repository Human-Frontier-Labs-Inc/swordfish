/**
 * MIME Parser Tests
 * Tests for email attachment parsing from raw MIME format
 */

import { describe, it, expect } from 'vitest';
import { parseEmail } from '@/lib/detection/parser';

describe('MIME Parser - Attachment Extraction', () => {
  describe('Simple Emails (Non-multipart)', () => {
    it('should parse simple text email', () => {
      // Note: Raw MIME format - headers must be on single lines
      const rawEmail = [
        'From: sender@test.com',
        'To: recipient@test.com',
        'Subject: Simple text email',
        'Content-Type: text/plain; charset=utf-8',
        '',
        'This is a simple text email body.'
      ].join('\r\n');

      const parsed = parseEmail(rawEmail);

      expect(parsed.from.address).toBe('sender@test.com');
      expect(parsed.subject).toBe('Simple text email');
      expect(parsed.body.text).toContain('simple text email body');
      expect(parsed.attachments).toHaveLength(0);
    });

    it('should parse simple HTML email', () => {
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: HTML email
Content-Type: text/html; charset=utf-8

<html><body><h1>Hello!</h1></body></html>`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.body.html).toContain('<h1>Hello!</h1>');
      expect(parsed.attachments).toHaveLength(0);
    });
  });

  describe('Multipart Emails', () => {
    it('should parse multipart/alternative email (text + html)', () => {
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Multipart alternative
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset=utf-8

Plain text version

--boundary123
Content-Type: text/html; charset=utf-8

<html><body>HTML version</body></html>

--boundary123--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.body.text).toContain('Plain text version');
      expect(parsed.body.html).toContain('HTML version');
      expect(parsed.attachments).toHaveLength(0);
    });

    it('should parse multipart/mixed email with text attachment', () => {
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Email with attachment
Content-Type: multipart/mixed; boundary="mixed-boundary"

--mixed-boundary
Content-Type: text/plain; charset=utf-8

Email body text.

--mixed-boundary
Content-Type: text/plain; name="document.txt"
Content-Disposition: attachment; filename="document.txt"

This is the attachment content.

--mixed-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.body.text).toContain('Email body text');
      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].filename).toBe('document.txt');
      expect(parsed.attachments[0].contentType).toBe('text/plain');
    });

    it('should parse email with base64 encoded attachment', () => {
      const base64Content = Buffer.from('Hello, World!').toString('base64');
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Base64 attachment
Content-Type: multipart/mixed; boundary="b64-boundary"

--b64-boundary
Content-Type: text/plain

Email body.

--b64-boundary
Content-Type: application/octet-stream; name="test.bin"
Content-Disposition: attachment; filename="test.bin"
Content-Transfer-Encoding: base64

${base64Content}

--b64-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].filename).toBe('test.bin');
      expect(parsed.attachments[0].content?.toString('utf-8')).toBe('Hello, World!');
    });

    it('should parse email with quoted-printable encoded content', () => {
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Quoted-printable test
Content-Type: multipart/mixed; boundary="qp-boundary"

--qp-boundary
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Hello=20World!=0D=0AThis is a test.

--qp-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.body.text).toContain('Hello World!');
      expect(parsed.body.text).toContain('This is a test.');
    });
  });

  describe('Attachment Types', () => {
    it('should detect executable attachments', () => {
      const base64Content = Buffer.from('MZ...').toString('base64');
      const rawEmail = `From: attacker@malicious.com
To: victim@company.com
Subject: Important document
Content-Type: multipart/mixed; boundary="exe-boundary"

--exe-boundary
Content-Type: text/plain

Please review the attached document.

--exe-boundary
Content-Type: application/x-msdownload; name="invoice.exe"
Content-Disposition: attachment; filename="invoice.exe"
Content-Transfer-Encoding: base64

${base64Content}

--exe-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].filename).toBe('invoice.exe');
      expect(parsed.attachments[0].contentType).toBe('application/x-msdownload');
    });

    it('should detect PDF attachments', () => {
      const base64Content = Buffer.from('%PDF-1.4...').toString('base64');
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: PDF document
Content-Type: multipart/mixed; boundary="pdf-boundary"

--pdf-boundary
Content-Type: text/plain

Please find attached PDF.

--pdf-boundary
Content-Type: application/pdf; name="report.pdf"
Content-Disposition: attachment; filename="report.pdf"
Content-Transfer-Encoding: base64

${base64Content}

--pdf-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].filename).toBe('report.pdf');
      expect(parsed.attachments[0].contentType).toBe('application/pdf');
    });

    it('should detect Office document attachments', () => {
      const base64Content = Buffer.from('PK...').toString('base64');
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Office document
Content-Type: multipart/mixed; boundary="office-boundary"

--office-boundary
Content-Type: text/plain

Please review the spreadsheet.

--office-boundary
Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
Content-Disposition: attachment; filename="data.xlsx"
Content-Transfer-Encoding: base64

${base64Content}

--office-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].filename).toBe('data.xlsx');
      expect(parsed.attachments[0].contentType).toContain('spreadsheetml');
    });

    it('should detect image attachments', () => {
      const base64Content = Buffer.from('GIF89a...').toString('base64');
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Image attachment
Content-Type: multipart/mixed; boundary="img-boundary"

--img-boundary
Content-Type: text/plain

See attached image.

--img-boundary
Content-Type: image/gif; name="photo.gif"
Content-Disposition: attachment; filename="photo.gif"
Content-Transfer-Encoding: base64

${base64Content}

--img-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].filename).toBe('photo.gif');
      expect(parsed.attachments[0].contentType).toBe('image/gif');
    });

    it('should detect archive attachments', () => {
      const base64Content = Buffer.from('PK...').toString('base64');
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Archive attachment
Content-Type: multipart/mixed; boundary="zip-boundary"

--zip-boundary
Content-Type: text/plain

Files attached.

--zip-boundary
Content-Type: application/zip; name="files.zip"
Content-Disposition: attachment; filename="files.zip"
Content-Transfer-Encoding: base64

${base64Content}

--zip-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].filename).toBe('files.zip');
      expect(parsed.attachments[0].contentType).toBe('application/zip');
    });
  });

  describe('Multiple Attachments', () => {
    it('should parse email with multiple attachments', () => {
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Multiple attachments
Content-Type: multipart/mixed; boundary="multi-boundary"

--multi-boundary
Content-Type: text/plain

Email with multiple files.

--multi-boundary
Content-Type: text/plain; name="file1.txt"
Content-Disposition: attachment; filename="file1.txt"

Content of file 1.

--multi-boundary
Content-Type: text/plain; name="file2.txt"
Content-Disposition: attachment; filename="file2.txt"

Content of file 2.

--multi-boundary
Content-Type: text/plain; name="file3.txt"
Content-Disposition: attachment; filename="file3.txt"

Content of file 3.

--multi-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.attachments).toHaveLength(3);
      expect(parsed.attachments[0].filename).toBe('file1.txt');
      expect(parsed.attachments[1].filename).toBe('file2.txt');
      expect(parsed.attachments[2].filename).toBe('file3.txt');
    });
  });

  describe('Nested Multipart', () => {
    it('should parse nested multipart/alternative inside multipart/mixed', () => {
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Nested multipart
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/plain

Plain text body.

--inner
Content-Type: text/html

<html><body>HTML body.</body></html>

--inner--

--outer
Content-Type: text/plain; name="attachment.txt"
Content-Disposition: attachment; filename="attachment.txt"

Attachment content.

--outer--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.body.text).toContain('Plain text body');
      expect(parsed.body.html).toContain('HTML body');
      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].filename).toBe('attachment.txt');
    });
  });

  describe('Filename Handling', () => {
    it('should handle encoded filenames', () => {
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Encoded filename
Content-Type: multipart/mixed; boundary="enc-boundary"

--enc-boundary
Content-Type: text/plain

Email body.

--enc-boundary
Content-Type: application/pdf
Content-Disposition: attachment; filename*=utf-8''report%20%282024%29.pdf

PDF content.

--enc-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].filename).toBe('report (2024).pdf');
    });

    it('should extract filename from Content-Type if not in Content-Disposition', () => {
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Filename in content-type
Content-Type: multipart/mixed; boundary="ct-boundary"

--ct-boundary
Content-Type: text/plain

Email body.

--ct-boundary
Content-Type: application/pdf; name="document.pdf"

PDF content.

--ct-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].filename).toBe('document.pdf');
    });
  });

  describe('Inline Attachments', () => {
    it('should detect inline images', () => {
      const base64Content = Buffer.from('PNG...').toString('base64');
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Email with inline image
Content-Type: multipart/related; boundary="related-boundary"

--related-boundary
Content-Type: text/html

<html><body><img src="cid:image001"></body></html>

--related-boundary
Content-Type: image/png; name="logo.png"
Content-ID: <image001>
Content-Disposition: inline; filename="logo.png"
Content-Transfer-Encoding: base64

${base64Content}

--related-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.body.html).toContain('<img src="cid:image001">');
      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].filename).toBe('logo.png');
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing boundary gracefully', () => {
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Missing boundary
Content-Type: multipart/mixed

This is the body without proper multipart structure.`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.body.text).toBeDefined();
      expect(parsed.attachments).toHaveLength(0);
    });

    it('should handle empty attachments section', () => {
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Empty boundary sections
Content-Type: multipart/mixed; boundary="empty-boundary"

--empty-boundary
Content-Type: text/plain

Body text.

--empty-boundary
--empty-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.body.text).toContain('Body text');
      expect(parsed.attachments).toHaveLength(0);
    });

    it('should handle malformed base64 gracefully', () => {
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Malformed base64
Content-Type: multipart/mixed; boundary="bad-b64"

--bad-b64
Content-Type: text/plain

Body.

--bad-b64
Content-Type: application/octet-stream; name="file.bin"
Content-Disposition: attachment; filename="file.bin"
Content-Transfer-Encoding: base64

This is not valid base64!!!

--bad-b64--`;

      const parsed = parseEmail(rawEmail);

      // Should not crash, may have the attachment with raw content
      expect(parsed.body.text).toContain('Body');
      expect(parsed.attachments.length).toBeGreaterThanOrEqual(0);
    });

    it('should handle CRLF and LF line endings', () => {
      const rawEmail = `From: sender@test.com\r\nTo: recipient@test.com\r\nSubject: CRLF test\r\nContent-Type: multipart/mixed; boundary="crlf-boundary"\r\n\r\n--crlf-boundary\r\nContent-Type: text/plain\r\n\r\nBody with CRLF.\r\n\r\n--crlf-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.subject).toBe('CRLF test');
      expect(parsed.body.text).toContain('Body with CRLF');
    });

    it('should handle quoted boundary values', () => {
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Quoted boundary
Content-Type: multipart/mixed; boundary="----=_Part_123_456.789"

------=_Part_123_456.789
Content-Type: text/plain

Body content.

------=_Part_123_456.789--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.body.text).toContain('Body content');
    });
  });

  describe('Attachment Size', () => {
    it('should report correct attachment size', () => {
      const content = 'A'.repeat(1000);
      const base64Content = Buffer.from(content).toString('base64');
      const rawEmail = `From: sender@test.com
To: recipient@test.com
Subject: Size test
Content-Type: multipart/mixed; boundary="size-boundary"

--size-boundary
Content-Type: text/plain

Body.

--size-boundary
Content-Type: application/octet-stream; name="data.bin"
Content-Disposition: attachment; filename="data.bin"
Content-Transfer-Encoding: base64

${base64Content}

--size-boundary--`;

      const parsed = parseEmail(rawEmail);

      expect(parsed.attachments).toHaveLength(1);
      expect(parsed.attachments[0].size).toBe(1000);
    });
  });
});

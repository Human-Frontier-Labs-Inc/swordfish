/**
 * Phase 3: Enhanced Sandbox Layer Tests (+4 points)
 *
 * TDD tests for integrating AttachmentAnalyzer and SandboxService
 * into the detection pipeline for comprehensive attachment analysis.
 *
 * Current State: Pipeline only checks file extensions
 * Target: Deep file analysis with magic bytes, macros, archives, and sandbox
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ParsedEmail, Attachment, Signal } from '@/lib/detection/types';

// Mock the attachment analyzer
vi.mock('@/lib/detection/attachment-analyzer', () => ({
  attachmentAnalyzer: {
    analyzeAttachment: vi.fn(),
  },
  analyzeAttachment: vi.fn(),
}));

// Mock the sandbox service
vi.mock('@/lib/threat-intel/sandbox', () => ({
  sandboxService: {
    scanAttachments: vi.fn(),
    checkHash: vi.fn(),
  },
}));

// Import after mocking
import { attachmentAnalyzer, analyzeAttachment } from '@/lib/detection/attachment-analyzer';
import { sandboxService } from '@/lib/threat-intel/sandbox';
import {
  runEnhancedSandboxAnalysis,
  analyzeAttachmentDeep,
  type EnhancedSandboxResult,
} from '@/lib/detection/sandbox-layer';

describe('Phase 3: Enhanced Sandbox Layer (+4 points)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Magic Bytes Detection', () => {
    it('should detect executable disguised as PDF', async () => {
      // PE executable with .pdf extension
      const fakeBuffer = Buffer.from([0x4D, 0x5A, 0x90, 0x00]); // MZ header

      const attachment: Attachment = {
        filename: 'invoice.pdf',
        contentType: 'application/pdf',
        size: 4096,
        content: fakeBuffer,
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'invoice.pdf',
        detectedType: {
          extension: 'exe',
          mimeType: 'application/x-executable',
          category: 'executable',
          confidence: 0.95,
        },
        declaredType: {
          extension: 'pdf',
          mimeType: 'application/pdf',
        },
        extensionMismatch: true,
        isExecutable: true,
        hasMacros: false,
        isPasswordProtected: false,
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'critical',
        riskScore: 95,
        riskFactors: ['Extension mismatch: executable disguised as PDF'],
      });

      const result = await analyzeAttachmentDeep(attachment);

      expect(result.signals).toContainEqual(
        expect.objectContaining({
          type: 'executable',
          severity: 'critical',
          detail: expect.stringContaining('mismatch'),
        })
      );
      expect(result.riskScore).toBeGreaterThanOrEqual(40);
    });

    it('should detect script disguised as image', async () => {
      // JavaScript content with .jpg extension
      const jsBuffer = Buffer.from('#!/usr/bin/env node\nconsole.log("pwned");');

      const attachment: Attachment = {
        filename: 'photo.jpg',
        contentType: 'image/jpeg',
        size: jsBuffer.length,
        content: jsBuffer,
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'photo.jpg',
        detectedType: {
          extension: 'js',
          mimeType: 'application/javascript',
          category: 'script',
          confidence: 0.85,
        },
        declaredType: {
          extension: 'jpg',
          mimeType: 'image/jpeg',
        },
        extensionMismatch: true,
        isExecutable: false,
        hasMacros: false,
        isPasswordProtected: false,
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'high',
        riskScore: 75,
        riskFactors: ['Script disguised as image'],
      });

      const result = await analyzeAttachmentDeep(attachment);

      expect(result.typeMismatch).toBe(true);
      expect(result.riskScore).toBeGreaterThanOrEqual(35);
    });

    it('should pass clean PDF with valid magic bytes', async () => {
      // Valid PDF header
      const pdfBuffer = Buffer.from('%PDF-1.4\n');

      const attachment: Attachment = {
        filename: 'report.pdf',
        contentType: 'application/pdf',
        size: pdfBuffer.length,
        content: pdfBuffer,
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'report.pdf',
        detectedType: {
          extension: 'pdf',
          mimeType: 'application/pdf',
          category: 'document',
          confidence: 0.99,
        },
        declaredType: {
          extension: 'pdf',
          mimeType: 'application/pdf',
        },
        extensionMismatch: false,
        isExecutable: false,
        hasMacros: false,
        isPasswordProtected: false,
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'safe',
        riskScore: 0,
        riskFactors: [],
      });

      const result = await analyzeAttachmentDeep(attachment);

      expect(result.typeMismatch).toBe(false);
      expect(result.riskScore).toBeLessThan(10);
    });
  });

  describe('Macro Detection', () => {
    it('should detect macros in Office documents', async () => {
      const attachment: Attachment = {
        filename: 'quarterly_report.xlsm',
        contentType: 'application/vnd.ms-excel.sheet.macroEnabled.12',
        size: 50000,
        content: Buffer.alloc(50000),
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'quarterly_report.xlsm',
        detectedType: {
          extension: 'xlsm',
          mimeType: 'application/vnd.ms-excel.sheet.macroEnabled.12',
          category: 'office',
          confidence: 0.95,
        },
        declaredType: {
          extension: 'xlsm',
          mimeType: 'application/vnd.ms-excel.sheet.macroEnabled.12',
        },
        extensionMismatch: false,
        isExecutable: false,
        hasMacros: true,
        isPasswordProtected: false,
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'high',
        riskScore: 65,
        riskFactors: ['Document contains macros', 'Macros with suspicious keywords: Shell, WScript'],
        macroInfo: {
          hasMacros: true,
          macroCount: 3,
          suspiciousKeywords: ['Shell', 'WScript'],
          autoExecute: true,
        },
      });

      const result = await analyzeAttachmentDeep(attachment);

      expect(result.hasMacros).toBe(true);
      expect(result.signals).toContainEqual(
        expect.objectContaining({
          type: 'macro_enabled',
        })
      );
    });

    it('should flag suspicious VBA keywords', async () => {
      const attachment: Attachment = {
        filename: 'document.docm',
        contentType: 'application/vnd.ms-word.document.macroEnabled.12',
        size: 30000,
        content: Buffer.alloc(30000),
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'document.docm',
        detectedType: {
          extension: 'docm',
          mimeType: 'application/vnd.ms-word.document.macroEnabled.12',
          category: 'office',
          confidence: 0.95,
        },
        declaredType: {
          extension: 'docm',
          mimeType: 'application/vnd.ms-word.document.macroEnabled.12',
        },
        extensionMismatch: false,
        isExecutable: false,
        hasMacros: true,
        isPasswordProtected: false,
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'critical',
        riskScore: 85,
        riskFactors: ['Macros with suspicious keywords: PowerShell, DownloadString, CreateObject, Shell'],
        macroInfo: {
          hasMacros: true,
          macroCount: 5,
          suspiciousKeywords: ['PowerShell', 'DownloadString', 'CreateObject', 'Shell'],
          autoExecute: true,
        },
      });

      const result = await analyzeAttachmentDeep(attachment);

      expect(result.riskScore).toBeGreaterThanOrEqual(50);
      expect(result.signals).toContainEqual(
        expect.objectContaining({
          severity: 'critical',
        })
      );
    });
  });

  describe('Archive Analysis', () => {
    it('should detect executable inside archive', async () => {
      const attachment: Attachment = {
        filename: 'documents.zip',
        contentType: 'application/zip',
        size: 100000,
        content: Buffer.alloc(100000),
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'documents.zip',
        detectedType: {
          extension: 'zip',
          mimeType: 'application/zip',
          category: 'archive',
          confidence: 0.99,
        },
        declaredType: {
          extension: 'zip',
          mimeType: 'application/zip',
        },
        extensionMismatch: false,
        isExecutable: false,
        hasMacros: false,
        isPasswordProtected: false,
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'critical',
        riskScore: 80,
        riskFactors: ['Archive contains executable'],
        archiveContents: {
          format: 'zip',
          totalEntries: 2,
          totalSize: 51000,
          compressedSize: 40000,
          isEncrypted: false,
          isPasswordProtected: false,
          entries: [
            { path: 'readme.txt', filename: 'readme.txt', size: 1000, compressedSize: 800, isDirectory: false, isEncrypted: false, extension: '.txt', isDangerous: false, isNested: false },
            { path: 'setup.exe', filename: 'setup.exe', size: 50000, compressedSize: 39200, isDirectory: false, isEncrypted: false, extension: '.exe', isDangerous: true, isNested: false },
          ],
          dangerousFiles: ['setup.exe'],
          nestedArchives: [],
          maxDepth: 1,
        },
      });

      const result = await analyzeAttachmentDeep(attachment);

      expect(result.archiveContents?.containsExecutable).toBe(true);
      expect(result.riskScore).toBeGreaterThanOrEqual(40);
    });

    it('should detect password-protected archive', async () => {
      const attachment: Attachment = {
        filename: 'secure.zip',
        contentType: 'application/zip',
        size: 50000,
        content: Buffer.alloc(50000),
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'secure.zip',
        detectedType: {
          extension: 'zip',
          mimeType: 'application/zip',
          category: 'archive',
          confidence: 0.99,
        },
        declaredType: {
          extension: 'zip',
          mimeType: 'application/zip',
        },
        extensionMismatch: false,
        isExecutable: false,
        hasMacros: false,
        isPasswordProtected: true,
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'high',
        riskScore: 60,
        riskFactors: ['Password-protected archive'],
        archiveContents: {
          format: 'zip',
          totalEntries: 0,
          totalSize: 0,
          compressedSize: 0,
          isEncrypted: true,
          isPasswordProtected: true,
          entries: [],
          dangerousFiles: [],
          nestedArchives: [],
          maxDepth: 0,
        },
      });

      const result = await analyzeAttachmentDeep(attachment);

      expect(result.isEncrypted).toBe(true);
      expect(result.signals).toContainEqual(
        expect.objectContaining({
          type: 'password_protected_archive',
        })
      );
    });

    it('should detect nested archives (archive bomb prevention)', async () => {
      const attachment: Attachment = {
        filename: 'files.zip',
        contentType: 'application/zip',
        size: 200000,
        content: Buffer.alloc(200000),
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'files.zip',
        detectedType: {
          extension: 'zip',
          mimeType: 'application/zip',
          category: 'archive',
          confidence: 0.99,
        },
        declaredType: {
          extension: 'zip',
          mimeType: 'application/zip',
        },
        extensionMismatch: false,
        isExecutable: false,
        hasMacros: false,
        isPasswordProtected: false,
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'medium',
        riskScore: 45,
        riskFactors: ['Deeply nested archive'],
        archiveContents: {
          format: 'zip',
          totalEntries: 1,
          totalSize: 100000,
          compressedSize: 80000,
          isEncrypted: false,
          isPasswordProtected: false,
          entries: [
            { path: 'level1.zip', filename: 'level1.zip', size: 100000, compressedSize: 80000, isDirectory: false, isEncrypted: false, extension: '.zip', isDangerous: false, isNested: true },
          ],
          dangerousFiles: [],
          nestedArchives: ['level1.zip'],
          maxDepth: 3, // 3 levels deep
        },
      });

      const result = await analyzeAttachmentDeep(attachment);

      expect(result.archiveContents?.nestingLevel).toBeGreaterThanOrEqual(3);
    });
  });

  describe('Double Extension Detection', () => {
    it('should detect invoice.pdf.exe pattern', async () => {
      const attachment: Attachment = {
        filename: 'invoice.pdf.exe',
        contentType: 'application/octet-stream',
        size: 5000,
        content: Buffer.from([0x4D, 0x5A]), // MZ header
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'invoice.pdf.exe',
        detectedType: {
          extension: 'exe',
          mimeType: 'application/x-executable',
          category: 'executable',
          confidence: 0.99,
        },
        declaredType: {
          extension: 'exe',
          mimeType: 'application/octet-stream',
        },
        extensionMismatch: false,
        isExecutable: true,
        hasMacros: false,
        isPasswordProtected: false,
        hasDoubleExtension: true,
        hasRtlOverride: false,
        riskLevel: 'critical',
        riskScore: 90,
        riskFactors: ['Double extension detected: pdf.exe', 'Executable file'],
      });

      const result = await analyzeAttachmentDeep(attachment);

      expect(result.hasDoubleExtension).toBe(true);
      expect(result.riskScore).toBeGreaterThanOrEqual(50);
    });

    it('should detect document.doc.js pattern', async () => {
      const attachment: Attachment = {
        filename: 'document.doc.js',
        contentType: 'application/javascript',
        size: 2000,
        content: Buffer.from('eval(malicious);'),
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'document.doc.js',
        detectedType: {
          extension: 'js',
          mimeType: 'application/javascript',
          category: 'script',
          confidence: 0.95,
        },
        declaredType: {
          extension: 'js',
          mimeType: 'application/javascript',
        },
        extensionMismatch: false,
        isExecutable: false,
        hasMacros: false,
        isPasswordProtected: false,
        hasDoubleExtension: true,
        hasRtlOverride: false,
        riskLevel: 'critical',
        riskScore: 85,
        riskFactors: ['Double extension: doc.js'],
      });

      const result = await analyzeAttachmentDeep(attachment);

      expect(result.hasDoubleExtension).toBe(true);
    });
  });

  describe('RTL Override Detection', () => {
    it('should detect RTL override filename spoofing', async () => {
      // filename: "invoice\u202Eexe.pdf" appears as "invoicefdp.exe"
      const attachment: Attachment = {
        filename: 'invoice\u202Eexe.pdf',
        contentType: 'application/octet-stream',
        size: 5000,
        content: Buffer.from([0x4D, 0x5A]), // MZ header
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'invoice\u202Eexe.pdf',
        detectedType: {
          extension: 'exe',
          mimeType: 'application/x-executable',
          category: 'executable',
          confidence: 0.95,
        },
        declaredType: {
          extension: 'pdf',
          mimeType: 'application/octet-stream',
        },
        extensionMismatch: true,
        isExecutable: true,
        hasMacros: false,
        isPasswordProtected: false,
        hasDoubleExtension: false,
        hasRtlOverride: true,
        riskLevel: 'critical',
        riskScore: 95,
        riskFactors: ['RTL override character detected'],
      });

      const result = await analyzeAttachmentDeep(attachment);

      expect(result.hasRtlOverride).toBe(true);
      expect(result.riskScore).toBeGreaterThanOrEqual(50);
    });
  });

  describe('Sandbox Integration', () => {
    it('should check file hash against known malware', async () => {
      const attachment: Attachment = {
        filename: 'update.exe',
        contentType: 'application/x-executable',
        size: 10000,
        content: Buffer.alloc(10000),
        hash: 'abc123def456',
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'update.exe',
        detectedType: {
          extension: 'exe',
          mimeType: 'application/x-executable',
          category: 'executable',
          confidence: 0.99,
        },
        declaredType: {
          extension: 'exe',
          mimeType: 'application/x-executable',
        },
        extensionMismatch: false,
        isExecutable: true,
        hasMacros: false,
        isPasswordProtected: false,
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'high',
        riskScore: 50,
        riskFactors: [],
      });

      vi.mocked(sandboxService.checkHash).mockResolvedValue({
        found: true,
        verdict: 'malicious',
        malwareFamily: 'Emotet',
        firstSeen: new Date('2024-01-15'),
        lastSeen: new Date('2024-01-20'),
        sources: ['VirusTotal', 'HybridAnalysis'],
      });

      const result = await analyzeAttachmentDeep(attachment, { checkSandbox: true });

      expect(result.sandboxResult?.verdict).toBe('malicious');
      expect(result.signals).toContainEqual(
        expect.objectContaining({
          type: 'attachment_malware',
          severity: 'critical',
        })
      );
    });

    it('should return clean result for unknown hash', async () => {
      const attachment: Attachment = {
        filename: 'legitimate.exe',
        contentType: 'application/x-executable',
        size: 10000,
        content: Buffer.alloc(10000),
        hash: 'clean123hash',
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'legitimate.exe',
        fileSize: 10000,
        fileType: { extension: 'exe', mimeType: 'application/x-executable', category: 'executable', confidence: 0.99 },
        isDangerous: false,
        isExecutable: true,
        isScript: false,
        isArchive: false,
        isOfficeDocument: false,
        hasMacros: false,
        macros: [],
        suspiciousMacros: false,
        hasNestedArchives: false,
        isPasswordProtected: false,
        extractedUrls: [],
        hasDoubleExtension: false,
        hasRtlOverride: false,
        fileSizeAnomaly: false,
        extensionMismatch: false,
        riskLevel: 'medium',
        riskScore: 30,
        riskFactors: [],
        analysisTimeMs: 50,
        analysisTimestamp: new Date(),
      });

      vi.mocked(sandboxService.checkHash).mockResolvedValue({
        found: false,
        verdict: 'unknown',
      });

      const result = await analyzeAttachmentDeep(attachment, { checkSandbox: true });

      expect(result.sandboxResult?.verdict).toBe('unknown');
      expect(result.signals.filter(s => s.type === 'attachment_malware')).toHaveLength(0);
    });
  });

  describe('Enhanced Sandbox Layer Integration', () => {
    it('should analyze all attachments in email', async () => {
      const email: ParsedEmail = {
        messageId: 'test-123',
        subject: 'Test email',
        from: { address: 'sender@example.com', domain: 'example.com' },
        to: [{ address: 'recipient@company.com', domain: 'company.com' }],
        date: new Date(),
        headers: {},
        body: { text: 'Test body' },
        attachments: [
          { filename: 'report.pdf', contentType: 'application/pdf', size: 5000 },
          { filename: 'data.xlsx', contentType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', size: 10000 },
        ],
        rawHeaders: '',
      };

      vi.mocked(analyzeAttachment).mockImplementation(async (_buffer, filename) => ({
        filename,
        fileSize: 5000,
        fileType: { extension: filename.split('.').pop() || '', mimeType: 'application/octet-stream', category: 'document', confidence: 0.9 },
        isDangerous: false,
        isExecutable: false,
        isScript: false,
        isArchive: false,
        isOfficeDocument: true,
        hasMacros: false,
        macros: [],
        suspiciousMacros: false,
        hasNestedArchives: false,
        isPasswordProtected: false,
        extractedUrls: [],
        hasDoubleExtension: false,
        hasRtlOverride: false,
        fileSizeAnomaly: false,
        extensionMismatch: false,
        riskLevel: 'safe',
        riskScore: 0,
        riskFactors: [],
        analysisTimeMs: 30,
        analysisTimestamp: new Date(),
      }));

      const result = await runEnhancedSandboxAnalysis(email, 'tenant-123');

      expect(result.layer).toBe('sandbox');
      expect(result.attachmentsAnalyzed).toBe(2);
    });

    it('should aggregate risk from multiple dangerous attachments', async () => {
      const email: ParsedEmail = {
        messageId: 'test-456',
        subject: 'Urgent - Multiple files',
        from: { address: 'sender@malicious.com', domain: 'malicious.com' },
        to: [{ address: 'victim@company.com', domain: 'company.com' }],
        date: new Date(),
        headers: {},
        body: { text: 'Please review attached files urgently' },
        attachments: [
          { filename: 'invoice.pdf.exe', contentType: 'application/octet-stream', size: 5000, content: Buffer.from([0x4D, 0x5A]) },
          { filename: 'payment.docm', contentType: 'application/vnd.ms-word.document.macroEnabled.12', size: 30000 },
        ],
        rawHeaders: '',
      };

      vi.mocked(analyzeAttachment)
        .mockResolvedValueOnce({
          filename: 'invoice.pdf.exe',
          fileSize: 5000,
          fileType: { extension: 'exe', mimeType: 'application/x-executable', category: 'executable', confidence: 0.99 },
          isDangerous: true,
          isExecutable: true,
          isScript: false,
          isArchive: false,
          isOfficeDocument: false,
          hasMacros: false,
          macros: [],
          suspiciousMacros: false,
          hasNestedArchives: false,
          isPasswordProtected: false,
          extractedUrls: [],
          hasDoubleExtension: true,
          hasRtlOverride: false,
          fileSizeAnomaly: false,
          extensionMismatch: false,
          riskLevel: 'critical',
          riskScore: 90,
          riskFactors: ['Double extension executable detected'],
          analysisTimeMs: 45,
          analysisTimestamp: new Date(),
        })
        .mockResolvedValueOnce({
          filename: 'payment.docm',
          fileSize: 30000,
          fileType: { extension: 'docm', mimeType: 'application/vnd.ms-word.document.macroEnabled.12', category: 'office', confidence: 0.95 },
          isDangerous: true,
          isExecutable: false,
          isScript: false,
          isArchive: false,
          isOfficeDocument: true,
          hasMacros: true,
          macros: [{ name: 'AutoOpen', type: 'auto', isSuspicious: true, code: '' }],
          suspiciousMacros: true,
          hasNestedArchives: false,
          isPasswordProtected: false,
          extractedUrls: [],
          hasDoubleExtension: false,
          hasRtlOverride: false,
          fileSizeAnomaly: false,
          extensionMismatch: false,
          riskLevel: 'high',
          riskScore: 70,
          riskFactors: ['Macro-enabled document with suspicious macros'],
          analysisTimeMs: 60,
          analysisTimestamp: new Date(),
        });

      const result = await runEnhancedSandboxAnalysis(email, 'tenant-123');

      expect(result.score).toBeGreaterThanOrEqual(50);
      expect(result.signals.length).toBeGreaterThanOrEqual(2);
      expect(result.signals.some(s => s.severity === 'critical')).toBe(true);
    });

    it('should skip sandbox for emails without attachments', async () => {
      const email: ParsedEmail = {
        messageId: 'test-789',
        subject: 'Plain text email',
        from: { address: 'sender@example.com', domain: 'example.com' },
        to: [{ address: 'recipient@company.com', domain: 'company.com' }],
        date: new Date(),
        headers: {},
        body: { text: 'Just a plain text email with no attachments' },
        attachments: [],
        rawHeaders: '',
      };

      const result = await runEnhancedSandboxAnalysis(email, 'tenant-123');

      expect(result.skipped).toBe(true);
      expect(result.skipReason).toContain('No attachments');
      expect(result.score).toBe(0);
    });

    it('should respect tenant configuration for sandbox analysis', async () => {
      const email: ParsedEmail = {
        messageId: 'test-config',
        subject: 'Config test',
        from: { address: 'sender@example.com', domain: 'example.com' },
        to: [{ address: 'recipient@company.com', domain: 'company.com' }],
        date: new Date(),
        headers: {},
        body: { text: 'Test' },
        attachments: [
          { filename: 'file.pdf', contentType: 'application/pdf', size: 5000 },
        ],
        rawHeaders: '',
      };

      // When sandbox is disabled for tenant
      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'file.pdf',
        fileSize: 5000,
        fileType: { extension: 'pdf', mimeType: 'application/pdf', category: 'document', confidence: 0.99 },
        isDangerous: false,
        isExecutable: false,
        isScript: false,
        isArchive: false,
        isOfficeDocument: false,
        hasMacros: false,
        macros: [],
        suspiciousMacros: false,
        hasNestedArchives: false,
        isPasswordProtected: false,
        extractedUrls: [],
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'safe',
        riskScore: 0,
        signals: [],
      });

      const result = await runEnhancedSandboxAnalysis(email, 'tenant-no-sandbox', {
        skipDynamicAnalysis: true,
      });

      // Should still do static analysis
      expect(result.attachmentsAnalyzed).toBe(1);
      expect(sandboxService.scanAttachments).not.toHaveBeenCalled();
    });
  });

  describe('Pipeline Integration', () => {
    it('should convert attachment analysis results to pipeline signals', async () => {
      const email: ParsedEmail = {
        messageId: 'signal-test',
        subject: 'Signal conversion test',
        from: { address: 'sender@example.com', domain: 'example.com' },
        to: [{ address: 'recipient@company.com', domain: 'company.com' }],
        date: new Date(),
        headers: {},
        body: { text: 'Test' },
        attachments: [
          { filename: 'malware.exe', contentType: 'application/x-executable', size: 5000 },
        ],
        rawHeaders: '',
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'malware.exe',
        detectedType: { extension: 'exe', mimeType: 'application/x-executable', category: 'executable', confidence: 0.99 },
        declaredType: { extension: 'exe', mimeType: 'application/x-executable' },
        typeMismatch: false,
        isExecutable: true,
        hasMacros: false,
        isEncrypted: false,
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'critical',
        riskScore: 80,
        signals: [
          { type: 'executable', severity: 'critical', detail: 'Executable file detected' },
        ],
      });

      vi.mocked(sandboxService.checkHash).mockResolvedValue({
        found: true,
        verdict: 'malicious',
        malwareFamily: 'Trojan.Generic',
        sources: ['VirusTotal'],
      });

      const result = await runEnhancedSandboxAnalysis(email, 'tenant-123', {
        checkSandbox: true,
      });

      // Should have properly typed signals for pipeline
      for (const signal of result.signals) {
        expect(signal).toHaveProperty('type');
        expect(signal).toHaveProperty('severity');
        expect(signal).toHaveProperty('score');
        expect(signal).toHaveProperty('detail');
        expect(['info', 'warning', 'critical']).toContain(signal.severity);
      }
    });

    it('should calculate layer confidence based on analysis depth', async () => {
      const email: ParsedEmail = {
        messageId: 'confidence-test',
        subject: 'Confidence test',
        from: { address: 'sender@example.com', domain: 'example.com' },
        to: [{ address: 'recipient@company.com', domain: 'company.com' }],
        date: new Date(),
        headers: {},
        body: { text: 'Test' },
        attachments: [
          { filename: 'file.pdf', contentType: 'application/pdf', size: 5000, content: Buffer.from('%PDF-1.4') },
        ],
        rawHeaders: '',
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'file.pdf',
        detectedType: { extension: 'pdf', mimeType: 'application/pdf', category: 'document', confidence: 0.99 },
        declaredType: { extension: 'pdf', mimeType: 'application/pdf' },
        typeMismatch: false,
        isExecutable: false,
        hasMacros: false,
        isEncrypted: false,
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'safe',
        riskScore: 0,
        signals: [],
      });

      // With buffer content - higher confidence
      const resultWithContent = await runEnhancedSandboxAnalysis(email, 'tenant-123');
      expect(resultWithContent.confidence).toBeGreaterThanOrEqual(0.8);

      // Without buffer content - lower confidence (extension only)
      email.attachments[0].content = undefined;
      const resultWithoutContent = await runEnhancedSandboxAnalysis(email, 'tenant-123');
      expect(resultWithoutContent.confidence).toBeLessThan(resultWithContent.confidence);
    });
  });

  describe('Edge Cases', () => {
    it('should handle attachments without content buffer', async () => {
      const attachment: Attachment = {
        filename: 'large-file.zip',
        contentType: 'application/zip',
        size: 50000000, // 50MB - content not loaded
        // No content buffer
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'large-file.zip',
        detectedType: { extension: 'zip', mimeType: 'application/zip', category: 'archive', confidence: 0.7 },
        declaredType: { extension: 'zip', mimeType: 'application/zip' },
        typeMismatch: false,
        isExecutable: false,
        hasMacros: false,
        isEncrypted: false,
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'medium',
        riskScore: 20,
        signals: [
          { type: 'dangerous_attachment', severity: 'info', detail: 'Archive file - contents not analyzed' },
        ],
      });

      const result = await analyzeAttachmentDeep(attachment);

      // Should still provide risk assessment based on extension/metadata
      expect(result).toBeDefined();
      expect(result.riskLevel).toBe('medium');
    });

    it('should handle analysis errors gracefully', async () => {
      const email: ParsedEmail = {
        messageId: 'error-test',
        subject: 'Error test',
        from: { address: 'sender@example.com', domain: 'example.com' },
        to: [{ address: 'recipient@company.com', domain: 'company.com' }],
        date: new Date(),
        headers: {},
        body: { text: 'Test' },
        attachments: [
          { filename: 'corrupt.pdf', contentType: 'application/pdf', size: 5000, content: Buffer.from('not a pdf') },
        ],
        rawHeaders: '',
      };

      vi.mocked(analyzeAttachment).mockRejectedValue(new Error('Parse error'));

      const result = await runEnhancedSandboxAnalysis(email, 'tenant-123');

      // Should not throw, but mark as error
      expect(result.skipped).toBe(true);
      expect(result.skipReason).toContain('error');
    });

    it('should handle zero-byte attachments', async () => {
      const attachment: Attachment = {
        filename: 'empty.exe',
        contentType: 'application/x-executable',
        size: 0,
        content: Buffer.alloc(0),
      };

      vi.mocked(analyzeAttachment).mockResolvedValue({
        filename: 'empty.exe',
        detectedType: { extension: 'exe', mimeType: 'application/x-executable', category: 'executable', confidence: 0.5 },
        declaredType: { extension: 'exe', mimeType: 'application/x-executable' },
        typeMismatch: false,
        isExecutable: true,
        hasMacros: false,
        isEncrypted: false,
        hasDoubleExtension: false,
        hasRtlOverride: false,
        riskLevel: 'low',
        riskScore: 10,
        signals: [],
      });

      const result = await analyzeAttachmentDeep(attachment);

      expect(result).toBeDefined();
    });
  });
});

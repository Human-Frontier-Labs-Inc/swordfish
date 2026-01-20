/**
 * Attachment Analysis Tests
 * Phase 5.4: Deep Attachment Analysis
 *
 * Tests for file type detection, macro detection, archive inspection,
 * and risk scoring for email attachments.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  AttachmentAnalyzer,
  analyzeAttachment,
  detectFileType,
  extractMacros,
  extractUrls,
  inspectArchive,
  calculateRiskScore,
  type AttachmentAnalysis,
  type FileTypeResult,
  type MacroInfo,
  type ArchiveContents,
} from '@/lib/detection/attachment-analyzer';
import {
  FILE_SIGNATURES,
  DANGEROUS_EXTENSIONS,
  isDangerousExtension,
  isScriptExtension,
  isExecutableExtension,
  isArchiveExtension,
  isOfficeExtension,
  hasDoubleExtension,
  hasRtlOverride,
  getAllExtensions,
  matchMagicBytes,
  detectFileTypeFromBuffer,
} from '@/lib/detection/file-signatures';

describe('File Signatures Module', () => {
  describe('Magic Bytes Matching', () => {
    it('should match ZIP magic bytes', () => {
      const zipBuffer = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x00, 0x00]);
      const zipSignature = FILE_SIGNATURES.find(s => s.type === 'zip');
      expect(zipSignature).toBeDefined();
      expect(matchMagicBytes(zipBuffer, zipSignature!)).toBe(true);
    });

    it('should match PDF magic bytes', () => {
      const pdfBuffer = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E]);
      const pdfSignature = FILE_SIGNATURES.find(s => s.type === 'pdf');
      expect(pdfSignature).toBeDefined();
      expect(matchMagicBytes(pdfBuffer, pdfSignature!)).toBe(true);
    });

    it('should match EXE magic bytes (MZ header)', () => {
      const exeBuffer = Buffer.from([0x4D, 0x5A, 0x90, 0x00]);
      const exeSignature = FILE_SIGNATURES.find(s => s.type === 'exe');
      expect(exeSignature).toBeDefined();
      expect(matchMagicBytes(exeBuffer, exeSignature!)).toBe(true);
    });

    it('should match RAR magic bytes', () => {
      const rarBuffer = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]);
      const rarSignature = FILE_SIGNATURES.find(s => s.type === 'rar');
      expect(rarSignature).toBeDefined();
      expect(matchMagicBytes(rarBuffer, rarSignature!)).toBe(true);
    });

    it('should match 7z magic bytes', () => {
      const sevenZBuffer = Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
      const sevenZSignature = FILE_SIGNATURES.find(s => s.type === '7z');
      expect(sevenZSignature).toBeDefined();
      expect(matchMagicBytes(sevenZBuffer, sevenZSignature!)).toBe(true);
    });

    it('should match PNG magic bytes', () => {
      const pngBuffer = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
      const pngSignature = FILE_SIGNATURES.find(s => s.type === 'png');
      expect(pngSignature).toBeDefined();
      expect(matchMagicBytes(pngBuffer, pngSignature!)).toBe(true);
    });

    it('should match JPEG magic bytes', () => {
      const jpegBuffer = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]);
      const jpegSignature = FILE_SIGNATURES.find(s => s.type === 'jpeg');
      expect(jpegSignature).toBeDefined();
      expect(matchMagicBytes(jpegBuffer, jpegSignature!)).toBe(true);
    });

    it('should match OLE compound file magic bytes', () => {
      const oleBuffer = Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
      const oleSignature = FILE_SIGNATURES.find(s => s.type === 'ole_compound');
      expect(oleSignature).toBeDefined();
      expect(matchMagicBytes(oleBuffer, oleSignature!)).toBe(true);
    });

    it('should not match with insufficient buffer length', () => {
      const shortBuffer = Buffer.from([0x50, 0x4B]);
      const zipSignature = FILE_SIGNATURES.find(s => s.type === 'zip');
      expect(matchMagicBytes(shortBuffer, zipSignature!)).toBe(false);
    });
  });

  describe('File Type Detection from Buffer', () => {
    it('should detect ZIP file type', () => {
      const zipBuffer = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00]);
      const result = detectFileTypeFromBuffer(zipBuffer);
      expect(result).toBeDefined();
      expect(result?.type).toBe('zip');
      expect(result?.category).toBe('archive');
    });

    it('should detect PDF file type', () => {
      const pdfBuffer = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34]);
      const result = detectFileTypeFromBuffer(pdfBuffer);
      expect(result).toBeDefined();
      expect(result?.type).toBe('pdf');
      expect(result?.category).toBe('document');
    });

    it('should detect executable file type', () => {
      const exeBuffer = Buffer.from([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
      const result = detectFileTypeFromBuffer(exeBuffer);
      expect(result).toBeDefined();
      expect(['exe', 'dll']).toContain(result?.type);
      expect(result?.category).toBe('executable');
    });

    it('should detect ELF executable', () => {
      const elfBuffer = Buffer.from([0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]);
      const result = detectFileTypeFromBuffer(elfBuffer);
      expect(result).toBeDefined();
      expect(result?.type).toBe('elf');
      expect(result?.category).toBe('executable');
    });

    it('should return null for unknown file type', () => {
      const unknownBuffer = Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
      const result = detectFileTypeFromBuffer(unknownBuffer);
      expect(result).toBeNull();
    });
  });

  describe('Extension Checks', () => {
    it('should identify dangerous extensions', () => {
      expect(isDangerousExtension('malware.exe')).toBe(true);
      expect(isDangerousExtension('script.ps1')).toBe(true);
      expect(isDangerousExtension('macro.docm')).toBe(true);
      expect(isDangerousExtension('installer.msi')).toBe(true);
      expect(isDangerousExtension('batch.bat')).toBe(true);
      expect(isDangerousExtension('safe.pdf')).toBe(false);
      expect(isDangerousExtension('image.jpg')).toBe(false);
    });

    it('should identify script extensions', () => {
      expect(isScriptExtension('script.js')).toBe(true);
      expect(isScriptExtension('script.vbs')).toBe(true);
      expect(isScriptExtension('script.ps1')).toBe(true);
      expect(isScriptExtension('script.bat')).toBe(true);
      expect(isScriptExtension('script.py')).toBe(true);
      expect(isScriptExtension('document.docx')).toBe(false);
    });

    it('should identify executable extensions', () => {
      expect(isExecutableExtension('program.exe')).toBe(true);
      expect(isExecutableExtension('library.dll')).toBe(true);
      expect(isExecutableExtension('screensaver.scr')).toBe(true);
      expect(isExecutableExtension('java.jar')).toBe(true);
      expect(isExecutableExtension('text.txt')).toBe(false);
    });

    it('should identify archive extensions', () => {
      expect(isArchiveExtension('archive.zip')).toBe(true);
      expect(isArchiveExtension('archive.rar')).toBe(true);
      expect(isArchiveExtension('archive.7z')).toBe(true);
      expect(isArchiveExtension('archive.tar')).toBe(true);
      expect(isArchiveExtension('document.docx')).toBe(false);
    });

    it('should identify Office extensions', () => {
      expect(isOfficeExtension('document.docx')).toBe(true);
      expect(isOfficeExtension('spreadsheet.xlsx')).toBe(true);
      expect(isOfficeExtension('presentation.pptx')).toBe(true);
      expect(isOfficeExtension('macro.docm')).toBe(true);
      expect(isOfficeExtension('image.png')).toBe(false);
    });
  });

  describe('Double Extension Detection', () => {
    it('should detect invoice.pdf.exe as double extension', () => {
      expect(hasDoubleExtension('invoice.pdf.exe')).toBe(true);
    });

    it('should detect document.docx.scr as double extension', () => {
      expect(hasDoubleExtension('document.docx.scr')).toBe(true);
    });

    it('should detect photo.jpg.exe as double extension', () => {
      expect(hasDoubleExtension('photo.jpg.exe')).toBe(true);
    });

    it('should not flag normal files', () => {
      expect(hasDoubleExtension('document.pdf')).toBe(false);
      expect(hasDoubleExtension('image.jpg')).toBe(false);
      expect(hasDoubleExtension('program.exe')).toBe(false);
    });

    it('should get all extensions from filename', () => {
      expect(getAllExtensions('invoice.pdf.exe')).toEqual(['.pdf', '.exe']);
      expect(getAllExtensions('file.tar.gz')).toEqual(['.tar', '.gz']);
      expect(getAllExtensions('document.docx')).toEqual(['.docx']);
    });
  });

  describe('RTL Override Detection', () => {
    it('should detect RTL override character', () => {
      const rtlFilename = 'document\u202Etxt.exe';
      expect(hasRtlOverride(rtlFilename)).toBe(true);
    });

    it('should detect other dangerous Unicode characters', () => {
      expect(hasRtlOverride('file\u202Dname.exe')).toBe(true);
      expect(hasRtlOverride('file\u200Ename.exe')).toBe(true);
    });

    it('should not flag normal filenames', () => {
      expect(hasRtlOverride('normal-file.pdf')).toBe(false);
      expect(hasRtlOverride('document_v2.docx')).toBe(false);
    });
  });
});

describe('AttachmentAnalyzer Class', () => {
  let analyzer: AttachmentAnalyzer;

  beforeEach(() => {
    analyzer = new AttachmentAnalyzer();
  });

  describe('detectFileType', () => {
    it('should detect PDF files', () => {
      const pdfBuffer = Buffer.concat([
        Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E]),
        Buffer.alloc(100),
      ]);
      const result = analyzer.detectFileType(pdfBuffer);
      expect(result.detected).toBe(true);
      expect(result.type).toBe('pdf');
      expect(result.category).toBe('document');
    });

    it('should detect Office documents (OOXML)', () => {
      // Create a minimal ZIP structure that looks like a docx
      const zipBuffer = createMinimalZipBuffer('word/document.xml');
      const result = analyzer.detectFileType(zipBuffer);
      expect(result.detected).toBe(true);
      expect(['zip', 'docx', 'xlsx', 'pptx']).toContain(result.type);
    });

    it('should detect executables', () => {
      const exeBuffer = Buffer.concat([
        Buffer.from([0x4D, 0x5A]),
        Buffer.alloc(100),
      ]);
      const result = analyzer.detectFileType(exeBuffer);
      expect(result.detected).toBe(true);
      expect(result.category).toBe('executable');
    });

    it('should return unknown for empty buffer', () => {
      const result = analyzer.detectFileType(Buffer.alloc(0));
      expect(result.detected).toBe(false);
      expect(result.type).toBe('empty');
    });

    it('should detect text files', () => {
      const textBuffer = Buffer.from('This is a plain text file with normal ASCII characters.\n');
      const result = analyzer.detectFileType(textBuffer);
      expect(result.detected).toBe(true);
      expect(result.type).toBe('text');
    });
  });

  describe('extractMacros', () => {
    it('should detect VBA project in OLE compound file', () => {
      // Create buffer with OLE signature and VBA indicator
      const oleBuffer = Buffer.concat([
        Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
        Buffer.alloc(100),
        Buffer.from('vbaProject.bin'),
        Buffer.alloc(100),
      ]);
      const macros = analyzer.extractMacros(oleBuffer);
      expect(macros.length).toBeGreaterThan(0);
    });

    it('should detect suspicious VBA keywords', () => {
      const oleBuffer = Buffer.concat([
        Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
        Buffer.alloc(50),
        Buffer.from('vbaProject.bin'),
        Buffer.alloc(50),
        Buffer.from('Shell'),
        Buffer.from('CreateObject'),
        Buffer.from('WScript.Shell'),
        Buffer.alloc(50),
      ]);
      const macros = analyzer.extractMacros(oleBuffer);
      expect(macros.length).toBeGreaterThan(0);
      expect(macros[0].suspicious).toBe(true);
      expect(macros[0].suspiciousKeywords.length).toBeGreaterThan(0);
    });

    it('should return empty array for files without macros', () => {
      const pdfBuffer = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E]);
      const macros = analyzer.extractMacros(pdfBuffer);
      expect(macros).toEqual([]);
    });
  });

  describe('extractUrls', () => {
    it('should extract HTTP URLs from buffer', () => {
      const buffer = Buffer.from('Visit http://example.com and https://test.com/path for more info');
      const urls = analyzer.extractUrls(buffer);
      expect(urls).toContain('http://example.com');
      expect(urls).toContain('https://test.com/path');
    });

    it('should extract multiple URLs', () => {
      const buffer = Buffer.from(`
        Link 1: https://malicious.com/phish
        Link 2: http://evil.org/download.exe
        Link 3: https://suspicious.net/redirect?url=http://bad.com
      `);
      const urls = analyzer.extractUrls(buffer);
      expect(urls.length).toBeGreaterThanOrEqual(3);
    });

    it('should deduplicate URLs', () => {
      const buffer = Buffer.from('https://example.com https://example.com https://example.com');
      const urls = analyzer.extractUrls(buffer);
      expect(urls.filter(u => u === 'https://example.com').length).toBe(1);
    });

    it('should return empty array when no URLs found', () => {
      const buffer = Buffer.from('This is plain text with no URLs');
      const urls = analyzer.extractUrls(buffer);
      expect(urls).toEqual([]);
    });

    it('should clean trailing punctuation from URLs', () => {
      const buffer = Buffer.from('Check https://example.com/path. Also see https://test.org!');
      const urls = analyzer.extractUrls(buffer);
      expect(urls).toContain('https://example.com/path');
      expect(urls).toContain('https://test.org');
    });
  });

  describe('inspectArchive', () => {
    it('should inspect ZIP archive contents', () => {
      const zipBuffer = createMinimalZipBuffer('test.txt');
      const contents = analyzer.inspectArchive(zipBuffer);
      expect(contents.format).toBe('zip');
      expect(contents.entries.length).toBeGreaterThan(0);
    });

    it('should detect dangerous files in archives', () => {
      const zipBuffer = createMinimalZipBuffer('malware.exe');
      const contents = analyzer.inspectArchive(zipBuffer);
      expect(contents.dangerousFiles.length).toBeGreaterThan(0);
      expect(contents.dangerousFiles[0]).toBe('malware.exe');
    });

    it('should detect nested archives', () => {
      const zipBuffer = createMinimalZipBuffer('nested.zip');
      const contents = analyzer.inspectArchive(zipBuffer);
      expect(contents.nestedArchives.length).toBeGreaterThan(0);
    });

    it('should detect encrypted entries', () => {
      const encryptedZipBuffer = createEncryptedZipBuffer('secret.txt');
      const contents = analyzer.inspectArchive(encryptedZipBuffer);
      expect(contents.isEncrypted).toBe(true);
    });

    it('should handle RAR archives', () => {
      const rarBuffer = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]);
      const contents = analyzer.inspectArchive(rarBuffer);
      expect(contents.format).toBe('rar');
    });

    it('should handle 7z archives', () => {
      const sevenZBuffer = Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
      const contents = analyzer.inspectArchive(sevenZBuffer);
      expect(contents.format).toBe('7z');
    });
  });

  describe('analyzeAttachment', () => {
    it('should analyze a safe PDF attachment', async () => {
      const pdfBuffer = Buffer.concat([
        Buffer.from('%PDF-1.4\n'),
        Buffer.alloc(100),
      ]);
      const analysis = await analyzer.analyzeAttachment(pdfBuffer, 'document.pdf');

      expect(analysis.filename).toBe('document.pdf');
      expect(analysis.fileType.type).toBe('pdf');
      expect(analysis.isDangerous).toBe(false);
      expect(analysis.riskLevel).toBe('safe');
    });

    it('should flag executable attachments as high risk', async () => {
      const exeBuffer = Buffer.concat([
        Buffer.from([0x4D, 0x5A]),
        Buffer.alloc(100),
      ]);
      const analysis = await analyzer.analyzeAttachment(exeBuffer, 'program.exe');

      expect(analysis.isExecutable).toBe(true);
      expect(analysis.isDangerous).toBe(true);
      expect(analysis.riskScore).toBeGreaterThanOrEqual(50);
      expect(['high', 'critical']).toContain(analysis.riskLevel);
    });

    it('should flag script attachments', async () => {
      const scriptBuffer = Buffer.from('#!/bin/bash\nrm -rf /\n');
      const analysis = await analyzer.analyzeAttachment(scriptBuffer, 'script.sh');

      expect(analysis.isScript).toBe(true);
      expect(analysis.isDangerous).toBe(true);
      expect(analysis.riskScore).toBeGreaterThan(20);
    });

    it('should detect double extension attacks', async () => {
      const exeBuffer = Buffer.concat([
        Buffer.from([0x4D, 0x5A]),
        Buffer.alloc(100),
      ]);
      const analysis = await analyzer.analyzeAttachment(exeBuffer, 'invoice.pdf.exe');

      expect(analysis.hasDoubleExtension).toBe(true);
      expect(analysis.riskFactors).toContain('double_extension');
      expect(analysis.riskScore).toBeGreaterThanOrEqual(40);
    });

    it('should detect RTL override attacks', async () => {
      const exeBuffer = Buffer.concat([
        Buffer.from([0x4D, 0x5A]),
        Buffer.alloc(100),
      ]);
      const analysis = await analyzer.analyzeAttachment(exeBuffer, 'document\u202Etxt.exe');

      expect(analysis.hasRtlOverride).toBe(true);
      expect(analysis.riskFactors).toContain('rtl_override_character');
    });

    it('should detect password-protected archives', async () => {
      const encryptedZipBuffer = createEncryptedZipBuffer('secret.txt');
      const analysis = await analyzer.analyzeAttachment(encryptedZipBuffer, 'archive.zip');

      expect(analysis.isPasswordProtected).toBe(true);
      expect(analysis.riskFactors).toContain('password_protected');
    });

    it('should extract URLs from documents', async () => {
      const docBuffer = Buffer.from('Visit https://phishing-site.com for more info');
      const analysis = await analyzer.analyzeAttachment(docBuffer, 'document.txt');

      expect(analysis.extractedUrls.length).toBeGreaterThan(0);
      expect(analysis.extractedUrls).toContain('https://phishing-site.com');
    });

    it('should detect macros in Office documents', async () => {
      const oleBuffer = Buffer.concat([
        Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
        Buffer.alloc(100),
        Buffer.from('vbaProject.bin'),
        Buffer.alloc(100),
      ]);
      const analysis = await analyzer.analyzeAttachment(oleBuffer, 'document.doc');

      expect(analysis.hasMacros).toBe(true);
      expect(analysis.riskFactors).toContain('contains_macros');
    });

    it('should detect suspicious macros', async () => {
      const oleBuffer = Buffer.concat([
        Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
        Buffer.alloc(50),
        Buffer.from('vbaProject.bin'),
        Buffer.alloc(50),
        Buffer.from('Shell'),
        Buffer.from('CreateObject'),
        Buffer.alloc(50),
      ]);
      const analysis = await analyzer.analyzeAttachment(oleBuffer, 'malicious.docm');

      expect(analysis.suspiciousMacros).toBe(true);
      expect(analysis.riskFactors).toContain('suspicious_macros');
      expect(analysis.riskScore).toBeGreaterThanOrEqual(50);
    });

    it('should include analysis metadata', async () => {
      const buffer = Buffer.from('test content');
      const analysis = await analyzer.analyzeAttachment(buffer, 'test.txt');

      expect(analysis.analysisTimeMs).toBeGreaterThanOrEqual(0);
      expect(analysis.analysisTimestamp).toBeInstanceOf(Date);
      expect(analysis.fileSize).toBe(buffer.length);
    });
  });

  describe('calculateRiskScore', () => {
    it('should return 0 for safe files', () => {
      const analysis: AttachmentAnalysis = createMockAnalysis({
        isDangerous: false,
        isExecutable: false,
        isScript: false,
        hasMacros: false,
        hasDoubleExtension: false,
        hasRtlOverride: false,
      });
      const score = analyzer.calculateRiskScore(analysis);
      expect(score).toBeLessThan(20);
    });

    it('should return high score for executables', () => {
      const analysis: AttachmentAnalysis = createMockAnalysis({
        isExecutable: true,
        isDangerous: true,
      });
      const score = analyzer.calculateRiskScore(analysis);
      expect(score).toBeGreaterThanOrEqual(50);
    });

    it('should return high score for double extension', () => {
      const analysis: AttachmentAnalysis = createMockAnalysis({
        hasDoubleExtension: true,
      });
      const score = analyzer.calculateRiskScore(analysis);
      expect(score).toBeGreaterThanOrEqual(40);
    });

    it('should return high score for suspicious macros', () => {
      const analysis: AttachmentAnalysis = createMockAnalysis({
        hasMacros: true,
        suspiciousMacros: true,
      });
      const score = analyzer.calculateRiskScore(analysis);
      expect(score).toBeGreaterThanOrEqual(50);
    });

    it('should cap score at 100', () => {
      const analysis: AttachmentAnalysis = createMockAnalysis({
        isExecutable: true,
        isDangerous: true,
        isScript: true,
        hasMacros: true,
        suspiciousMacros: true,
        hasDoubleExtension: true,
        hasRtlOverride: true,
        isPasswordProtected: true,
        hasNestedArchives: true,
      });
      const score = analyzer.calculateRiskScore(analysis);
      expect(score).toBeLessThanOrEqual(100);
    });

    it('should add score for many URLs', () => {
      const analysis: AttachmentAnalysis = createMockAnalysis({
        extractedUrls: Array(25).fill('https://example.com'),
      });
      const score = analyzer.calculateRiskScore(analysis);
      expect(score).toBeGreaterThan(0);
    });
  });
});

describe('Convenience Functions', () => {
  it('analyzeAttachment should work correctly', async () => {
    const buffer = Buffer.from('%PDF-1.4\n');
    const result = await analyzeAttachment(buffer, 'test.pdf');
    expect(result.filename).toBe('test.pdf');
  });

  it('detectFileType should work correctly', () => {
    const buffer = Buffer.from([0x25, 0x50, 0x44, 0x46]);
    const result = detectFileType(buffer);
    expect(result.type).toBe('pdf');
  });

  it('extractMacros should work correctly', () => {
    const buffer = Buffer.from('no macros here');
    const result = extractMacros(buffer);
    expect(result).toEqual([]);
  });

  it('extractUrls should work correctly', () => {
    const buffer = Buffer.from('Visit https://example.com');
    const result = extractUrls(buffer);
    expect(result).toContain('https://example.com');
  });

  it('inspectArchive should work correctly', () => {
    const zipBuffer = createMinimalZipBuffer('test.txt');
    const result = inspectArchive(zipBuffer);
    expect(result.format).toBe('zip');
  });

  it('calculateRiskScore should work correctly', () => {
    const analysis = createMockAnalysis({ isDangerous: true });
    const score = calculateRiskScore(analysis);
    expect(score).toBeGreaterThan(0);
  });
});

// Helper functions for creating test data

function createMinimalZipBuffer(filename: string): Buffer {
  // Create a minimal valid ZIP file structure
  const filenameBuffer = Buffer.from(filename, 'utf8');
  const content = Buffer.from('test content');

  // Local file header
  const localHeader = Buffer.alloc(30 + filenameBuffer.length + content.length);
  let offset = 0;

  // Local file header signature
  localHeader.writeUInt32LE(0x04034B50, offset); offset += 4;
  // Version needed
  localHeader.writeUInt16LE(20, offset); offset += 2;
  // Flags
  localHeader.writeUInt16LE(0, offset); offset += 2;
  // Compression
  localHeader.writeUInt16LE(0, offset); offset += 2;
  // Mod time
  localHeader.writeUInt16LE(0, offset); offset += 2;
  // Mod date
  localHeader.writeUInt16LE(0, offset); offset += 2;
  // CRC32
  localHeader.writeUInt32LE(0, offset); offset += 4;
  // Compressed size
  localHeader.writeUInt32LE(content.length, offset); offset += 4;
  // Uncompressed size
  localHeader.writeUInt32LE(content.length, offset); offset += 4;
  // Filename length
  localHeader.writeUInt16LE(filenameBuffer.length, offset); offset += 2;
  // Extra field length
  localHeader.writeUInt16LE(0, offset); offset += 2;
  // Filename
  filenameBuffer.copy(localHeader, offset); offset += filenameBuffer.length;
  // File content
  content.copy(localHeader, offset); offset += content.length;

  const localHeaderEnd = offset;

  // Central directory header
  const centralDir = Buffer.alloc(46 + filenameBuffer.length);
  offset = 0;

  // Central directory signature
  centralDir.writeUInt32LE(0x02014B50, offset); offset += 4;
  // Version made by
  centralDir.writeUInt16LE(20, offset); offset += 2;
  // Version needed
  centralDir.writeUInt16LE(20, offset); offset += 2;
  // Flags
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // Compression
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // Mod time
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // Mod date
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // CRC32
  centralDir.writeUInt32LE(0, offset); offset += 4;
  // Compressed size
  centralDir.writeUInt32LE(content.length, offset); offset += 4;
  // Uncompressed size
  centralDir.writeUInt32LE(content.length, offset); offset += 4;
  // Filename length
  centralDir.writeUInt16LE(filenameBuffer.length, offset); offset += 2;
  // Extra field length
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // Comment length
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // Disk start
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // Internal attributes
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // External attributes
  centralDir.writeUInt32LE(0, offset); offset += 4;
  // Local header offset
  centralDir.writeUInt32LE(0, offset); offset += 4;
  // Filename
  filenameBuffer.copy(centralDir, offset);

  // End of central directory
  const eocd = Buffer.alloc(22);
  offset = 0;

  // EOCD signature
  eocd.writeUInt32LE(0x06054B50, offset); offset += 4;
  // Disk number
  eocd.writeUInt16LE(0, offset); offset += 2;
  // Disk with CD
  eocd.writeUInt16LE(0, offset); offset += 2;
  // Entries on disk
  eocd.writeUInt16LE(1, offset); offset += 2;
  // Total entries
  eocd.writeUInt16LE(1, offset); offset += 2;
  // CD size
  eocd.writeUInt32LE(centralDir.length, offset); offset += 4;
  // CD offset
  eocd.writeUInt32LE(localHeaderEnd, offset); offset += 4;
  // Comment length
  eocd.writeUInt16LE(0, offset);

  return Buffer.concat([localHeader.slice(0, localHeaderEnd), centralDir, eocd]);
}

function createEncryptedZipBuffer(filename: string): Buffer {
  // Create a ZIP with encryption flag set
  const filenameBuffer = Buffer.from(filename, 'utf8');
  const content = Buffer.from('encrypted content');

  // Local file header with encryption flag
  const localHeader = Buffer.alloc(30 + filenameBuffer.length + content.length);
  let offset = 0;

  // Local file header signature
  localHeader.writeUInt32LE(0x04034B50, offset); offset += 4;
  // Version needed
  localHeader.writeUInt16LE(20, offset); offset += 2;
  // Flags - bit 0 set for encryption
  localHeader.writeUInt16LE(0x01, offset); offset += 2;
  // Compression
  localHeader.writeUInt16LE(0, offset); offset += 2;
  // Mod time
  localHeader.writeUInt16LE(0, offset); offset += 2;
  // Mod date
  localHeader.writeUInt16LE(0, offset); offset += 2;
  // CRC32
  localHeader.writeUInt32LE(0, offset); offset += 4;
  // Compressed size
  localHeader.writeUInt32LE(content.length, offset); offset += 4;
  // Uncompressed size
  localHeader.writeUInt32LE(content.length, offset); offset += 4;
  // Filename length
  localHeader.writeUInt16LE(filenameBuffer.length, offset); offset += 2;
  // Extra field length
  localHeader.writeUInt16LE(0, offset); offset += 2;
  // Filename
  filenameBuffer.copy(localHeader, offset); offset += filenameBuffer.length;
  // File content
  content.copy(localHeader, offset); offset += content.length;

  const localHeaderEnd = offset;

  // Central directory header with encryption flag
  const centralDir = Buffer.alloc(46 + filenameBuffer.length);
  offset = 0;

  // Central directory signature
  centralDir.writeUInt32LE(0x02014B50, offset); offset += 4;
  // Version made by
  centralDir.writeUInt16LE(20, offset); offset += 2;
  // Version needed
  centralDir.writeUInt16LE(20, offset); offset += 2;
  // Flags - bit 0 set for encryption
  centralDir.writeUInt16LE(0x01, offset); offset += 2;
  // Compression
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // Mod time
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // Mod date
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // CRC32
  centralDir.writeUInt32LE(0, offset); offset += 4;
  // Compressed size
  centralDir.writeUInt32LE(content.length, offset); offset += 4;
  // Uncompressed size
  centralDir.writeUInt32LE(content.length, offset); offset += 4;
  // Filename length
  centralDir.writeUInt16LE(filenameBuffer.length, offset); offset += 2;
  // Extra field length
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // Comment length
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // Disk start
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // Internal attributes
  centralDir.writeUInt16LE(0, offset); offset += 2;
  // External attributes
  centralDir.writeUInt32LE(0, offset); offset += 4;
  // Local header offset
  centralDir.writeUInt32LE(0, offset); offset += 4;
  // Filename
  filenameBuffer.copy(centralDir, offset);

  // End of central directory
  const eocd = Buffer.alloc(22);
  offset = 0;

  // EOCD signature
  eocd.writeUInt32LE(0x06054B50, offset); offset += 4;
  // Disk number
  eocd.writeUInt16LE(0, offset); offset += 2;
  // Disk with CD
  eocd.writeUInt16LE(0, offset); offset += 2;
  // Entries on disk
  eocd.writeUInt16LE(1, offset); offset += 2;
  // Total entries
  eocd.writeUInt16LE(1, offset); offset += 2;
  // CD size
  eocd.writeUInt32LE(centralDir.length, offset); offset += 4;
  // CD offset
  eocd.writeUInt32LE(localHeaderEnd, offset); offset += 4;
  // Comment length
  eocd.writeUInt16LE(0, offset);

  return Buffer.concat([localHeader.slice(0, localHeaderEnd), centralDir, eocd]);
}

function createMockAnalysis(overrides: Partial<AttachmentAnalysis> = {}): AttachmentAnalysis {
  return {
    filename: 'test.txt',
    fileSize: 100,
    fileType: {
      detected: true,
      type: 'text',
      extension: '.txt',
      mimeType: 'text/plain',
      category: 'other',
      description: 'Text file',
      confidence: 0.8,
      magicBytesMatch: false,
      extensionMatch: true,
      mismatch: false,
    },
    isDangerous: false,
    isExecutable: false,
    isScript: false,
    isArchive: false,
    isOfficeDocument: false,
    hasMacros: false,
    macros: [],
    suspiciousMacros: false,
    archiveContents: undefined,
    hasNestedArchives: false,
    isPasswordProtected: false,
    extractedUrls: [],
    hasDoubleExtension: false,
    hasRtlOverride: false,
    realExtension: undefined,
    fileSizeAnomaly: false,
    extensionMismatch: false,
    riskScore: 0,
    riskLevel: 'safe',
    riskFactors: [],
    analysisTimeMs: 0,
    analysisTimestamp: new Date(),
    ...overrides,
  };
}

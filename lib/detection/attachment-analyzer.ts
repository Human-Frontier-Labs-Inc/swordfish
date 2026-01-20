/**
 * Attachment Analyzer - Deep file analysis for phishing detection
 * Phase 5.4: Deep Attachment Analysis
 */

import {
  FILE_SIGNATURES,
  DANGEROUS_EXTENSIONS,
  VBA_INDICATORS,
  SUSPICIOUS_VBA_KEYWORDS,
  ARCHIVE_EXTENSIONS,
  matchMagicBytes,
  detectFileTypeFromBuffer,
  isDangerousExtension,
  isScriptExtension,
  isExecutableExtension,
  isArchiveExtension,
  isOfficeExtension,
  getExtension,
  getAllExtensions,
  hasDoubleExtension,
  hasRtlOverride,
  getRealExtension,
  type FileSignature,
} from './file-signatures';

/**
 * Result from file type detection
 */
export interface FileTypeResult {
  detected: boolean;
  type: string;
  extension: string;
  mimeType: string;
  category: 'document' | 'archive' | 'executable' | 'script' | 'image' | 'media' | 'other' | 'unknown';
  description: string;
  confidence: number; // 0-1
  magicBytesMatch: boolean;
  extensionMatch: boolean;
  mismatch: boolean; // True if magic bytes don't match extension
}

/**
 * Information about extracted macros
 */
export interface MacroInfo {
  name: string;
  type: 'auto_exec' | 'user_form' | 'module' | 'class' | 'unknown';
  suspicious: boolean;
  suspiciousKeywords: string[];
  codeSnippet?: string;
}

/**
 * Archive content information
 */
export interface ArchiveEntry {
  path: string;
  filename: string;
  size: number;
  compressedSize: number;
  isDirectory: boolean;
  isEncrypted: boolean;
  extension: string;
  isDangerous: boolean;
  isNested: boolean; // Is this another archive?
}

/**
 * Archive inspection result
 */
export interface ArchiveContents {
  format: string;
  totalEntries: number;
  totalSize: number;
  compressedSize: number;
  isEncrypted: boolean;
  isPasswordProtected: boolean;
  entries: ArchiveEntry[];
  dangerousFiles: string[];
  nestedArchives: string[];
  maxDepth: number;
}

/**
 * Complete attachment analysis result
 */
export interface AttachmentAnalysis {
  filename: string;
  fileSize: number;
  fileType: FileTypeResult;

  // Security checks
  isDangerous: boolean;
  isExecutable: boolean;
  isScript: boolean;
  isArchive: boolean;
  isOfficeDocument: boolean;

  // Macro analysis
  hasMacros: boolean;
  macros: MacroInfo[];
  suspiciousMacros: boolean;

  // Archive analysis
  archiveContents?: ArchiveContents;
  hasNestedArchives: boolean;

  // Password protection
  isPasswordProtected: boolean;

  // URL extraction
  extractedUrls: string[];

  // Spoofing detection
  hasDoubleExtension: boolean;
  hasRtlOverride: boolean;
  realExtension?: string;

  // File anomalies
  fileSizeAnomaly: boolean;
  extensionMismatch: boolean;

  // Risk assessment
  riskScore: number; // 0-100
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  riskFactors: string[];

  // Processing metadata
  analysisTimeMs: number;
  analysisTimestamp: Date;
}

/**
 * ZIP local file header structure
 */
interface ZipLocalHeader {
  signature: number;
  version: number;
  flags: number;
  compression: number;
  modTime: number;
  modDate: number;
  crc32: number;
  compressedSize: number;
  uncompressedSize: number;
  filenameLength: number;
  extraLength: number;
}

/**
 * ZIP central directory entry
 */
interface ZipCentralEntry {
  signature: number;
  versionMade: number;
  versionNeeded: number;
  flags: number;
  compression: number;
  modTime: number;
  modDate: number;
  crc32: number;
  compressedSize: number;
  uncompressedSize: number;
  filenameLength: number;
  extraLength: number;
  commentLength: number;
  diskStart: number;
  internalAttr: number;
  externalAttr: number;
  localHeaderOffset: number;
  filename: string;
}

/**
 * Attachment Analyzer class for deep file analysis
 */
export class AttachmentAnalyzer {
  /**
   * Analyze an attachment buffer
   */
  async analyzeAttachment(
    buffer: Buffer,
    filename: string
  ): Promise<AttachmentAnalysis> {
    const startTime = Date.now();
    const riskFactors: string[] = [];

    // Detect file type
    const fileType = this.detectFileType(buffer);

    // Basic security checks
    const isDangerous = isDangerousExtension(filename);
    const isExecutable = isExecutableExtension(filename) || fileType.category === 'executable';
    const isScript = isScriptExtension(filename) || fileType.category === 'script';
    const isArchive = isArchiveExtension(filename) || fileType.category === 'archive';
    const isOfficeDocument = isOfficeExtension(filename) || fileType.category === 'document';

    // Spoofing detection
    const doubleExtension = hasDoubleExtension(filename);
    const rtlOverride = hasRtlOverride(filename);
    const realExtension = rtlOverride ? getRealExtension(filename) : undefined;

    // Extension mismatch detection
    const extensionMismatch = this.detectExtensionMismatch(buffer, filename, fileType);

    // Macro analysis
    let macros: MacroInfo[] = [];
    let hasMacros = false;
    let suspiciousMacros = false;

    if (isOfficeDocument || fileType.type === 'ole_compound' ||
        fileType.type === 'docx' || fileType.type === 'xlsx' || fileType.type === 'pptx') {
      macros = this.extractMacros(buffer);
      hasMacros = macros.length > 0;
      suspiciousMacros = macros.some(m => m.suspicious);
    }

    // URL extraction
    const extractedUrls = this.extractUrls(buffer);

    // Archive inspection
    let archiveContents: ArchiveContents | undefined;
    let hasNestedArchives = false;

    if (isArchive || fileType.category === 'archive') {
      archiveContents = this.inspectArchive(buffer);
      hasNestedArchives = archiveContents.nestedArchives.length > 0;
    }

    // Password protection detection
    const isPasswordProtected = this.detectPasswordProtection(buffer, fileType);

    // File size anomaly detection
    const fileSizeAnomaly = this.detectFileSizeAnomaly(buffer.length, fileType);

    // Build risk factors
    if (isDangerous) riskFactors.push('dangerous_extension');
    if (isExecutable) riskFactors.push('executable_file');
    if (isScript) riskFactors.push('script_file');
    if (doubleExtension) riskFactors.push('double_extension');
    if (rtlOverride) riskFactors.push('rtl_override_character');
    if (extensionMismatch) riskFactors.push('extension_mismatch');
    if (hasMacros) riskFactors.push('contains_macros');
    if (suspiciousMacros) riskFactors.push('suspicious_macros');
    if (isPasswordProtected) riskFactors.push('password_protected');
    if (hasNestedArchives) riskFactors.push('nested_archives');
    if (fileSizeAnomaly) riskFactors.push('file_size_anomaly');
    if (archiveContents?.dangerousFiles.length) riskFactors.push('dangerous_files_in_archive');
    if (extractedUrls.length > 10) riskFactors.push('excessive_urls');

    // Build analysis result
    const analysis: AttachmentAnalysis = {
      filename,
      fileSize: buffer.length,
      fileType,
      isDangerous,
      isExecutable,
      isScript,
      isArchive,
      isOfficeDocument,
      hasMacros,
      macros,
      suspiciousMacros,
      archiveContents,
      hasNestedArchives,
      isPasswordProtected,
      extractedUrls,
      hasDoubleExtension: doubleExtension,
      hasRtlOverride: rtlOverride,
      realExtension,
      fileSizeAnomaly,
      extensionMismatch,
      riskScore: 0,
      riskLevel: 'safe',
      riskFactors,
      analysisTimeMs: 0,
      analysisTimestamp: new Date(),
    };

    // Calculate risk score
    analysis.riskScore = this.calculateRiskScore(analysis);
    analysis.riskLevel = this.getRiskLevel(analysis.riskScore);
    analysis.analysisTimeMs = Date.now() - startTime;

    return analysis;
  }

  /**
   * Detect file type from buffer using magic bytes
   */
  detectFileType(buffer: Buffer): FileTypeResult {
    if (buffer.length === 0) {
      return {
        detected: false,
        type: 'empty',
        extension: '',
        mimeType: 'application/octet-stream',
        category: 'unknown',
        description: 'Empty file',
        confidence: 0,
        magicBytesMatch: false,
        extensionMatch: false,
        mismatch: false,
      };
    }

    const signature = detectFileTypeFromBuffer(buffer);

    if (signature) {
      // For OOXML files (docx, xlsx, pptx), we need deeper inspection
      // because they all use ZIP magic bytes
      if (signature.magicBytes[0] === 0x50 && signature.magicBytes[1] === 0x4B) {
        const ooxmlType = this.detectOOXMLType(buffer);
        if (ooxmlType) {
          return {
            detected: true,
            type: ooxmlType.type,
            extension: ooxmlType.extension,
            mimeType: ooxmlType.mimeType,
            category: 'document',
            description: ooxmlType.description,
            confidence: 0.95,
            magicBytesMatch: true,
            extensionMatch: true,
            mismatch: false,
          };
        }
      }

      return {
        detected: true,
        type: signature.type,
        extension: signature.extension,
        mimeType: signature.mimeType,
        category: signature.category,
        description: signature.description,
        confidence: 0.9,
        magicBytesMatch: true,
        extensionMatch: true,
        mismatch: false,
      };
    }

    // Check if it looks like text/script
    if (this.isLikelyTextFile(buffer)) {
      return {
        detected: true,
        type: 'text',
        extension: '.txt',
        mimeType: 'text/plain',
        category: 'other',
        description: 'Text file',
        confidence: 0.6,
        magicBytesMatch: false,
        extensionMatch: false,
        mismatch: false,
      };
    }

    return {
      detected: false,
      type: 'unknown',
      extension: '',
      mimeType: 'application/octet-stream',
      category: 'unknown',
      description: 'Unknown file type',
      confidence: 0,
      magicBytesMatch: false,
      extensionMatch: false,
      mismatch: false,
    };
  }

  /**
   * Detect OOXML document type by inspecting ZIP contents
   */
  private detectOOXMLType(buffer: Buffer): { type: string; extension: string; mimeType: string; description: string } | null {
    try {
      const contents = this.inspectArchive(buffer);

      for (const entry of contents.entries) {
        const path = entry.path.toLowerCase();

        if (path.includes('[content_types].xml') || path.includes('_rels')) {
          // Look for specific content types
          if (path.includes('word/')) {
            return {
              type: 'docx',
              extension: '.docx',
              mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
              description: 'Microsoft Word Document',
            };
          }
          if (path.includes('xl/')) {
            return {
              type: 'xlsx',
              extension: '.xlsx',
              mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
              description: 'Microsoft Excel Spreadsheet',
            };
          }
          if (path.includes('ppt/')) {
            return {
              type: 'pptx',
              extension: '.pptx',
              mimeType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
              description: 'Microsoft PowerPoint Presentation',
            };
          }
        }

        // Check for document.xml which indicates Word
        if (path === 'word/document.xml') {
          return {
            type: 'docx',
            extension: '.docx',
            mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            description: 'Microsoft Word Document',
          };
        }

        // Check for workbook.xml which indicates Excel
        if (path === 'xl/workbook.xml') {
          return {
            type: 'xlsx',
            extension: '.xlsx',
            mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            description: 'Microsoft Excel Spreadsheet',
          };
        }

        // Check for presentation.xml which indicates PowerPoint
        if (path === 'ppt/presentation.xml') {
          return {
            type: 'pptx',
            extension: '.pptx',
            mimeType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            description: 'Microsoft PowerPoint Presentation',
          };
        }
      }
    } catch {
      // Not a valid ZIP/OOXML
    }

    return null;
  }

  /**
   * Check if buffer appears to be text
   */
  private isLikelyTextFile(buffer: Buffer): boolean {
    // Check first 1KB for text characteristics
    const checkLength = Math.min(buffer.length, 1024);
    let textChars = 0;

    for (let i = 0; i < checkLength; i++) {
      const byte = buffer[i];
      // Common text characters: printable ASCII, newlines, tabs
      if ((byte >= 0x20 && byte <= 0x7E) || byte === 0x09 || byte === 0x0A || byte === 0x0D) {
        textChars++;
      }
    }

    return textChars / checkLength > 0.8;
  }

  /**
   * Extract macros from Office documents
   */
  extractMacros(buffer: Buffer): MacroInfo[] {
    const macros: MacroInfo[] = [];

    // Check for OLE compound file (legacy Office)
    const oleSignature = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    const isOle = buffer.length >= oleSignature.length &&
      oleSignature.every((byte, i) => buffer[i] === byte);

    if (isOle) {
      // Search for VBA indicators in the binary
      const bufferStr = buffer.toString('binary');

      for (const indicator of VBA_INDICATORS) {
        if (bufferStr.includes(indicator)) {
          const suspicious = this.checkForSuspiciousVBA(buffer);
          macros.push({
            name: indicator,
            type: this.getMacroType(indicator),
            suspicious: suspicious.isSuspicious,
            suspiciousKeywords: suspicious.keywords,
            codeSnippet: undefined,
          });
          break; // Found VBA, no need to check all indicators
        }
      }
    }

    // Check for OOXML (modern Office)
    const zipSignature = [0x50, 0x4B, 0x03, 0x04];
    const isZip = buffer.length >= zipSignature.length &&
      zipSignature.every((byte, i) => buffer[i] === byte);

    if (isZip) {
      try {
        const contents = this.inspectArchive(buffer);

        for (const entry of contents.entries) {
          const path = entry.path.toLowerCase();

          // Check for VBA project in OOXML
          if (path.includes('vbaproject.bin') || path.includes('vba')) {
            const suspicious = this.checkForSuspiciousVBA(buffer);
            macros.push({
              name: entry.filename,
              type: 'module',
              suspicious: suspicious.isSuspicious,
              suspiciousKeywords: suspicious.keywords,
              codeSnippet: undefined,
            });
          }
        }
      } catch {
        // Not a valid archive
      }
    }

    return macros;
  }

  /**
   * Get macro type from name
   */
  private getMacroType(name: string): 'auto_exec' | 'user_form' | 'module' | 'class' | 'unknown' {
    const autoExecIndicators = ['Auto_Open', 'AutoOpen', 'Auto_Close', 'AutoClose',
                                'AutoExec', 'Document_Open', 'Workbook_Open'];

    if (autoExecIndicators.some(ind => name.includes(ind))) {
      return 'auto_exec';
    }
    if (name.toLowerCase().includes('form')) {
      return 'user_form';
    }
    if (name.toLowerCase().includes('class')) {
      return 'class';
    }
    if (name.toLowerCase().includes('module')) {
      return 'module';
    }
    return 'unknown';
  }

  /**
   * Check for suspicious VBA patterns
   */
  private checkForSuspiciousVBA(buffer: Buffer): { isSuspicious: boolean; keywords: string[] } {
    const bufferStr = buffer.toString('binary');
    const foundKeywords: string[] = [];

    for (const keyword of SUSPICIOUS_VBA_KEYWORDS) {
      if (bufferStr.toLowerCase().includes(keyword.toLowerCase())) {
        foundKeywords.push(keyword);
      }
    }

    return {
      isSuspicious: foundKeywords.length > 0,
      keywords: foundKeywords,
    };
  }

  /**
   * Extract URLs from document content
   */
  extractUrls(buffer: Buffer): string[] {
    const urls: string[] = [];

    // Convert buffer to string for URL extraction
    const text = buffer.toString('utf8');

    // URL regex pattern
    const urlPattern = /https?:\/\/[^\s<>"')\]]+/gi;
    const matches = text.match(urlPattern);

    if (matches) {
      // Deduplicate and clean URLs
      const seen = new Set<string>();
      for (const url of matches) {
        // Clean trailing punctuation
        const cleanUrl = url.replace(/[.,;:!?)]+$/, '');
        if (!seen.has(cleanUrl)) {
          seen.add(cleanUrl);
          urls.push(cleanUrl);
        }
      }
    }

    return urls;
  }

  /**
   * Inspect archive contents
   */
  inspectArchive(buffer: Buffer): ArchiveContents {
    // Check for ZIP format
    const zipSignature = [0x50, 0x4B, 0x03, 0x04];
    const isZip = buffer.length >= zipSignature.length &&
      zipSignature.every((byte, i) => buffer[i] === byte);

    if (isZip) {
      return this.inspectZipArchive(buffer);
    }

    // Check for RAR format
    const rarSignature = [0x52, 0x61, 0x72, 0x21];
    const isRar = buffer.length >= rarSignature.length &&
      rarSignature.every((byte, i) => buffer[i] === byte);

    if (isRar) {
      return this.createEmptyArchiveContents('rar', 'RAR archive inspection not fully implemented');
    }

    // Check for 7z format
    const sevenZSignature = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    const is7z = buffer.length >= sevenZSignature.length &&
      sevenZSignature.every((byte, i) => buffer[i] === byte);

    if (is7z) {
      return this.createEmptyArchiveContents('7z', '7-Zip archive inspection not fully implemented');
    }

    return this.createEmptyArchiveContents('unknown', 'Unknown archive format');
  }

  /**
   * Inspect ZIP archive contents
   */
  private inspectZipArchive(buffer: Buffer): ArchiveContents {
    const entries: ArchiveEntry[] = [];
    const dangerousFiles: string[] = [];
    const nestedArchives: string[] = [];
    let totalSize = 0;
    let compressedSize = 0;
    let isEncrypted = false;
    let maxDepth = 0;

    try {
      // Parse ZIP central directory
      const centralEntries = this.parseZipCentralDirectory(buffer);

      for (const entry of centralEntries) {
        const extension = getExtension(entry.filename);
        const pathDepth = entry.filename.split('/').length - 1;
        maxDepth = Math.max(maxDepth, pathDepth);

        const isDangerous = isDangerousExtension(entry.filename);
        const isNested = ARCHIVE_EXTENSIONS.some(ext =>
          entry.filename.toLowerCase().endsWith(ext)
        );

        // Check encryption flag
        if (entry.flags & 0x01) {
          isEncrypted = true;
        }

        const archiveEntry: ArchiveEntry = {
          path: entry.filename,
          filename: entry.filename.split('/').pop() || entry.filename,
          size: entry.uncompressedSize,
          compressedSize: entry.compressedSize,
          isDirectory: entry.filename.endsWith('/'),
          isEncrypted: (entry.flags & 0x01) !== 0,
          extension,
          isDangerous,
          isNested,
        };

        entries.push(archiveEntry);
        totalSize += entry.uncompressedSize;
        compressedSize += entry.compressedSize;

        if (isDangerous) {
          dangerousFiles.push(entry.filename);
        }
        if (isNested) {
          nestedArchives.push(entry.filename);
        }
      }
    } catch {
      // Malformed ZIP or parsing error
    }

    return {
      format: 'zip',
      totalEntries: entries.length,
      totalSize,
      compressedSize,
      isEncrypted,
      isPasswordProtected: isEncrypted,
      entries,
      dangerousFiles,
      nestedArchives,
      maxDepth,
    };
  }

  /**
   * Parse ZIP central directory
   */
  private parseZipCentralDirectory(buffer: Buffer): ZipCentralEntry[] {
    const entries: ZipCentralEntry[] = [];

    // Find End of Central Directory
    let eocdOffset = -1;
    const eocdSignature = 0x06054B50;

    for (let i = buffer.length - 22; i >= 0; i--) {
      if (buffer.readUInt32LE(i) === eocdSignature) {
        eocdOffset = i;
        break;
      }
    }

    if (eocdOffset === -1) {
      return entries;
    }

    // Read EOCD
    const centralDirOffset = buffer.readUInt32LE(eocdOffset + 16);
    const centralDirSize = buffer.readUInt32LE(eocdOffset + 12);
    const entryCount = buffer.readUInt16LE(eocdOffset + 10);

    // Parse central directory entries
    let offset = centralDirOffset;
    const centralSignature = 0x02014B50;

    for (let i = 0; i < entryCount && offset < buffer.length; i++) {
      if (buffer.readUInt32LE(offset) !== centralSignature) {
        break;
      }

      const filenameLength = buffer.readUInt16LE(offset + 28);
      const extraLength = buffer.readUInt16LE(offset + 30);
      const commentLength = buffer.readUInt16LE(offset + 32);

      const entry: ZipCentralEntry = {
        signature: buffer.readUInt32LE(offset),
        versionMade: buffer.readUInt16LE(offset + 4),
        versionNeeded: buffer.readUInt16LE(offset + 6),
        flags: buffer.readUInt16LE(offset + 8),
        compression: buffer.readUInt16LE(offset + 10),
        modTime: buffer.readUInt16LE(offset + 12),
        modDate: buffer.readUInt16LE(offset + 14),
        crc32: buffer.readUInt32LE(offset + 16),
        compressedSize: buffer.readUInt32LE(offset + 20),
        uncompressedSize: buffer.readUInt32LE(offset + 24),
        filenameLength,
        extraLength,
        commentLength,
        diskStart: buffer.readUInt16LE(offset + 34),
        internalAttr: buffer.readUInt16LE(offset + 36),
        externalAttr: buffer.readUInt32LE(offset + 38),
        localHeaderOffset: buffer.readUInt32LE(offset + 42),
        filename: buffer.toString('utf8', offset + 46, offset + 46 + filenameLength),
      };

      entries.push(entry);
      offset += 46 + filenameLength + extraLength + commentLength;
    }

    return entries;
  }

  /**
   * Create empty archive contents for unsupported formats
   */
  private createEmptyArchiveContents(format: string, _note?: string): ArchiveContents {
    return {
      format,
      totalEntries: 0,
      totalSize: 0,
      compressedSize: 0,
      isEncrypted: false,
      isPasswordProtected: false,
      entries: [],
      dangerousFiles: [],
      nestedArchives: [],
      maxDepth: 0,
    };
  }

  /**
   * Detect password protection
   */
  private detectPasswordProtection(buffer: Buffer, fileType: FileTypeResult): boolean {
    // Check ZIP encryption flag
    if (fileType.type === 'zip' || fileType.category === 'archive') {
      const contents = this.inspectArchive(buffer);
      return contents.isPasswordProtected;
    }

    // Check PDF encryption
    if (fileType.type === 'pdf') {
      const text = buffer.toString('binary');
      return text.includes('/Encrypt') || text.includes('/Standard');
    }

    // Check OLE compound file encryption
    if (fileType.type === 'ole_compound') {
      const text = buffer.toString('binary');
      return text.includes('EncryptedPackage') || text.includes('StrongEncryptionDataSpace');
    }

    return false;
  }

  /**
   * Detect file size anomalies
   */
  private detectFileSizeAnomaly(size: number, fileType: FileTypeResult): boolean {
    // Very small executable (likely dropper/stub)
    if (fileType.category === 'executable' && size < 4096) {
      return true;
    }

    // Very large image (possible embedded payload)
    if (fileType.category === 'image' && size > 50 * 1024 * 1024) {
      return true;
    }

    // Empty archive
    if (fileType.category === 'archive' && size < 50) {
      return true;
    }

    // Suspiciously small document
    if (fileType.category === 'document' && size < 100) {
      return true;
    }

    return false;
  }

  /**
   * Detect extension mismatch
   */
  private detectExtensionMismatch(buffer: Buffer, filename: string, fileType: FileTypeResult): boolean {
    if (!fileType.detected) {
      return false;
    }

    const declaredExt = getExtension(filename).toLowerCase();
    const detectedExt = fileType.extension.toLowerCase();

    // If we detected a specific type, check if extension matches
    if (detectedExt && declaredExt) {
      // Allow some equivalent extensions
      const equivalents: Record<string, string[]> = {
        '.jpg': ['.jpeg'],
        '.jpeg': ['.jpg'],
        '.htm': ['.html'],
        '.html': ['.htm'],
        '.tgz': ['.tar.gz'],
        '.docx': ['.docm', '.dotx', '.dotm'],
        '.xlsx': ['.xlsm', '.xltx', '.xltm'],
        '.pptx': ['.pptm', '.potx', '.potm'],
      };

      if (declaredExt !== detectedExt) {
        const allowed = equivalents[detectedExt] || [];
        if (!allowed.includes(declaredExt)) {
          // Special case: ZIP-based formats (docx, xlsx, pptx) all have ZIP magic bytes
          // Don't flag mismatch for these
          if (fileType.type === 'zip' || fileType.type === 'docx' ||
              fileType.type === 'xlsx' || fileType.type === 'pptx') {
            return false;
          }
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Calculate overall risk score
   */
  calculateRiskScore(analysis: AttachmentAnalysis): number {
    let score = 0;

    // Base risk by file type
    if (analysis.isExecutable) score += 50;
    if (analysis.isScript) score += 40;
    if (analysis.isDangerous) score += 30;

    // Macro risks
    if (analysis.hasMacros) score += 20;
    if (analysis.suspiciousMacros) score += 35;

    // Spoofing risks
    if (analysis.hasDoubleExtension) score += 40;
    if (analysis.hasRtlOverride) score += 45;
    if (analysis.extensionMismatch) score += 25;

    // Archive risks
    if (analysis.hasNestedArchives) score += 15;
    if (analysis.archiveContents?.dangerousFiles.length) {
      score += Math.min(30, analysis.archiveContents.dangerousFiles.length * 10);
    }

    // Password protection (often used to evade scanning)
    if (analysis.isPasswordProtected) score += 20;

    // File anomalies
    if (analysis.fileSizeAnomaly) score += 10;

    // URL density (many URLs in a document is suspicious)
    if (analysis.extractedUrls.length > 20) score += 15;
    else if (analysis.extractedUrls.length > 10) score += 10;
    else if (analysis.extractedUrls.length > 5) score += 5;

    // Cap at 100
    return Math.min(100, score);
  }

  /**
   * Get risk level from score
   */
  private getRiskLevel(score: number): 'safe' | 'low' | 'medium' | 'high' | 'critical' {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'safe';
  }
}

// Export singleton instance
export const attachmentAnalyzer = new AttachmentAnalyzer();

// Export convenience functions
export async function analyzeAttachment(
  buffer: Buffer,
  filename: string
): Promise<AttachmentAnalysis> {
  return attachmentAnalyzer.analyzeAttachment(buffer, filename);
}

export function detectFileType(buffer: Buffer): FileTypeResult {
  return attachmentAnalyzer.detectFileType(buffer);
}

export function extractMacros(buffer: Buffer): MacroInfo[] {
  return attachmentAnalyzer.extractMacros(buffer);
}

export function extractUrls(buffer: Buffer): string[] {
  return attachmentAnalyzer.extractUrls(buffer);
}

export function inspectArchive(buffer: Buffer): ArchiveContents {
  return attachmentAnalyzer.inspectArchive(buffer);
}

export function calculateRiskScore(analysis: AttachmentAnalysis): number {
  return attachmentAnalyzer.calculateRiskScore(analysis);
}

/**
 * File Signatures - Magic byte signatures for file type detection
 * Phase 5.4: Deep Attachment Analysis
 */

export interface FileSignature {
  type: string;
  extension: string;
  mimeType: string;
  magicBytes: number[];
  offset: number;
  description: string;
  category: 'document' | 'archive' | 'executable' | 'script' | 'image' | 'media' | 'other';
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Magic byte signatures for common file types
 * These are the first bytes of a file that identify its format
 */
export const FILE_SIGNATURES: FileSignature[] = [
  // Archives
  {
    type: 'zip',
    extension: '.zip',
    mimeType: 'application/zip',
    magicBytes: [0x50, 0x4B, 0x03, 0x04],
    offset: 0,
    description: 'ZIP Archive',
    category: 'archive',
    riskLevel: 'medium',
  },
  {
    type: 'zip_empty',
    extension: '.zip',
    mimeType: 'application/zip',
    magicBytes: [0x50, 0x4B, 0x05, 0x06],
    offset: 0,
    description: 'ZIP Archive (Empty)',
    category: 'archive',
    riskLevel: 'medium',
  },
  {
    type: 'zip_spanned',
    extension: '.zip',
    mimeType: 'application/zip',
    magicBytes: [0x50, 0x4B, 0x07, 0x08],
    offset: 0,
    description: 'ZIP Archive (Spanned)',
    category: 'archive',
    riskLevel: 'medium',
  },
  {
    type: 'rar',
    extension: '.rar',
    mimeType: 'application/vnd.rar',
    magicBytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
    offset: 0,
    description: 'RAR Archive',
    category: 'archive',
    riskLevel: 'medium',
  },
  {
    type: 'rar5',
    extension: '.rar',
    mimeType: 'application/vnd.rar',
    magicBytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00],
    offset: 0,
    description: 'RAR Archive v5+',
    category: 'archive',
    riskLevel: 'medium',
  },
  {
    type: '7z',
    extension: '.7z',
    mimeType: 'application/x-7z-compressed',
    magicBytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
    offset: 0,
    description: '7-Zip Archive',
    category: 'archive',
    riskLevel: 'medium',
  },
  {
    type: 'gzip',
    extension: '.gz',
    mimeType: 'application/gzip',
    magicBytes: [0x1F, 0x8B],
    offset: 0,
    description: 'GZIP Archive',
    category: 'archive',
    riskLevel: 'medium',
  },
  {
    type: 'tar',
    extension: '.tar',
    mimeType: 'application/x-tar',
    magicBytes: [0x75, 0x73, 0x74, 0x61, 0x72],
    offset: 257,
    description: 'TAR Archive',
    category: 'archive',
    riskLevel: 'medium',
  },

  // Office Documents (Modern XML-based - these are actually ZIP files)
  {
    type: 'docx',
    extension: '.docx',
    mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    magicBytes: [0x50, 0x4B, 0x03, 0x04],
    offset: 0,
    description: 'Microsoft Word Document (OOXML)',
    category: 'document',
    riskLevel: 'low',
  },
  {
    type: 'xlsx',
    extension: '.xlsx',
    mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    magicBytes: [0x50, 0x4B, 0x03, 0x04],
    offset: 0,
    description: 'Microsoft Excel Spreadsheet (OOXML)',
    category: 'document',
    riskLevel: 'low',
  },
  {
    type: 'pptx',
    extension: '.pptx',
    mimeType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    magicBytes: [0x50, 0x4B, 0x03, 0x04],
    offset: 0,
    description: 'Microsoft PowerPoint Presentation (OOXML)',
    category: 'document',
    riskLevel: 'low',
  },

  // Office Documents with Macros
  {
    type: 'docm',
    extension: '.docm',
    mimeType: 'application/vnd.ms-word.document.macroEnabled.12',
    magicBytes: [0x50, 0x4B, 0x03, 0x04],
    offset: 0,
    description: 'Microsoft Word Document with Macros',
    category: 'document',
    riskLevel: 'high',
  },
  {
    type: 'xlsm',
    extension: '.xlsm',
    mimeType: 'application/vnd.ms-excel.sheet.macroEnabled.12',
    magicBytes: [0x50, 0x4B, 0x03, 0x04],
    offset: 0,
    description: 'Microsoft Excel Spreadsheet with Macros',
    category: 'document',
    riskLevel: 'high',
  },
  {
    type: 'pptm',
    extension: '.pptm',
    mimeType: 'application/vnd.ms-powerpoint.presentation.macroEnabled.12',
    magicBytes: [0x50, 0x4B, 0x03, 0x04],
    offset: 0,
    description: 'Microsoft PowerPoint with Macros',
    category: 'document',
    riskLevel: 'high',
  },

  // Legacy Office Documents (OLE Compound File)
  {
    type: 'ole_compound',
    extension: '.doc',
    mimeType: 'application/msword',
    magicBytes: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
    offset: 0,
    description: 'OLE Compound File (Legacy Office)',
    category: 'document',
    riskLevel: 'medium',
  },

  // PDF
  {
    type: 'pdf',
    extension: '.pdf',
    mimeType: 'application/pdf',
    magicBytes: [0x25, 0x50, 0x44, 0x46],
    offset: 0,
    description: 'PDF Document',
    category: 'document',
    riskLevel: 'low',
  },

  // Executables
  {
    type: 'exe',
    extension: '.exe',
    mimeType: 'application/vnd.microsoft.portable-executable',
    magicBytes: [0x4D, 0x5A],
    offset: 0,
    description: 'Windows Executable',
    category: 'executable',
    riskLevel: 'critical',
  },
  {
    type: 'dll',
    extension: '.dll',
    mimeType: 'application/vnd.microsoft.portable-executable',
    magicBytes: [0x4D, 0x5A],
    offset: 0,
    description: 'Windows Dynamic Link Library',
    category: 'executable',
    riskLevel: 'critical',
  },
  {
    type: 'elf',
    extension: '',
    mimeType: 'application/x-executable',
    magicBytes: [0x7F, 0x45, 0x4C, 0x46],
    offset: 0,
    description: 'Linux ELF Executable',
    category: 'executable',
    riskLevel: 'critical',
  },
  {
    type: 'mach_o_32',
    extension: '',
    mimeType: 'application/x-mach-binary',
    magicBytes: [0xFE, 0xED, 0xFA, 0xCE],
    offset: 0,
    description: 'macOS Mach-O Executable (32-bit)',
    category: 'executable',
    riskLevel: 'critical',
  },
  {
    type: 'mach_o_64',
    extension: '',
    mimeType: 'application/x-mach-binary',
    magicBytes: [0xFE, 0xED, 0xFA, 0xCF],
    offset: 0,
    description: 'macOS Mach-O Executable (64-bit)',
    category: 'executable',
    riskLevel: 'critical',
  },
  {
    type: 'mach_o_fat',
    extension: '',
    mimeType: 'application/x-mach-binary',
    magicBytes: [0xCA, 0xFE, 0xBA, 0xBE],
    offset: 0,
    description: 'macOS Mach-O Fat Binary',
    category: 'executable',
    riskLevel: 'critical',
  },

  // Java
  {
    type: 'class',
    extension: '.class',
    mimeType: 'application/java-vm',
    magicBytes: [0xCA, 0xFE, 0xBA, 0xBE],
    offset: 0,
    description: 'Java Class File',
    category: 'executable',
    riskLevel: 'high',
  },
  {
    type: 'jar',
    extension: '.jar',
    mimeType: 'application/java-archive',
    magicBytes: [0x50, 0x4B, 0x03, 0x04],
    offset: 0,
    description: 'Java Archive',
    category: 'archive',
    riskLevel: 'high',
  },

  // Images
  {
    type: 'png',
    extension: '.png',
    mimeType: 'image/png',
    magicBytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
    offset: 0,
    description: 'PNG Image',
    category: 'image',
    riskLevel: 'safe',
  },
  {
    type: 'jpeg',
    extension: '.jpg',
    mimeType: 'image/jpeg',
    magicBytes: [0xFF, 0xD8, 0xFF],
    offset: 0,
    description: 'JPEG Image',
    category: 'image',
    riskLevel: 'safe',
  },
  {
    type: 'gif',
    extension: '.gif',
    mimeType: 'image/gif',
    magicBytes: [0x47, 0x49, 0x46, 0x38],
    offset: 0,
    description: 'GIF Image',
    category: 'image',
    riskLevel: 'safe',
  },
  {
    type: 'bmp',
    extension: '.bmp',
    mimeType: 'image/bmp',
    magicBytes: [0x42, 0x4D],
    offset: 0,
    description: 'BMP Image',
    category: 'image',
    riskLevel: 'safe',
  },
  {
    type: 'webp',
    extension: '.webp',
    mimeType: 'image/webp',
    magicBytes: [0x52, 0x49, 0x46, 0x46],
    offset: 0,
    description: 'WebP Image',
    category: 'image',
    riskLevel: 'safe',
  },

  // Media
  {
    type: 'mp3',
    extension: '.mp3',
    mimeType: 'audio/mpeg',
    magicBytes: [0xFF, 0xFB],
    offset: 0,
    description: 'MP3 Audio',
    category: 'media',
    riskLevel: 'safe',
  },
  {
    type: 'mp3_id3',
    extension: '.mp3',
    mimeType: 'audio/mpeg',
    magicBytes: [0x49, 0x44, 0x33],
    offset: 0,
    description: 'MP3 Audio (with ID3)',
    category: 'media',
    riskLevel: 'safe',
  },
  {
    type: 'mp4',
    extension: '.mp4',
    mimeType: 'video/mp4',
    magicBytes: [0x66, 0x74, 0x79, 0x70],
    offset: 4,
    description: 'MP4 Video',
    category: 'media',
    riskLevel: 'safe',
  },

  // Other
  {
    type: 'rtf',
    extension: '.rtf',
    mimeType: 'application/rtf',
    magicBytes: [0x7B, 0x5C, 0x72, 0x74, 0x66],
    offset: 0,
    description: 'Rich Text Format',
    category: 'document',
    riskLevel: 'medium',
  },
  {
    type: 'xml',
    extension: '.xml',
    mimeType: 'application/xml',
    magicBytes: [0x3C, 0x3F, 0x78, 0x6D, 0x6C],
    offset: 0,
    description: 'XML Document',
    category: 'document',
    riskLevel: 'low',
  },
];

/**
 * Dangerous file extensions that should be blocked
 */
export const DANGEROUS_EXTENSIONS: string[] = [
  // Executables
  '.exe', '.dll', '.scr', '.pif', '.com', '.bat', '.cmd', '.msi', '.msp',
  // Scripts
  '.js', '.jse', '.vbs', '.vbe', '.ps1', '.psm1', '.psd1', '.ws', '.wsf', '.wsc', '.wsh',
  '.hta', '.reg', '.inf', '.sh', '.bash', '.py', '.pyw', '.pl', '.php', '.rb',
  // Office macros
  '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm', '.xlam', '.ppam',
  // Other dangerous
  '.jar', '.jnlp', '.swf', '.application', '.gadget', '.cpl', '.lnk', '.url',
  '.iso', '.img', '.vhd', '.vhdx',
];

/**
 * Script file extensions
 */
export const SCRIPT_EXTENSIONS: string[] = [
  '.js', '.jse', '.vbs', '.vbe', '.ps1', '.psm1', '.psd1', '.ws', '.wsf',
  '.wsc', '.wsh', '.hta', '.sh', '.bash', '.py', '.pyw', '.pl', '.php', '.rb',
  '.bat', '.cmd',
];

/**
 * Executable file extensions
 */
export const EXECUTABLE_EXTENSIONS: string[] = [
  '.exe', '.dll', '.scr', '.pif', '.com', '.msi', '.msp', '.jar', '.class',
  '.app', '.dmg', '.pkg', '.deb', '.rpm', '.apk', '.ipa',
];

/**
 * Archive file extensions
 */
export const ARCHIVE_EXTENSIONS: string[] = [
  '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.cab', '.iso',
  '.img', '.dmg', '.arj', '.lzh', '.ace',
];

/**
 * Office document extensions
 */
export const OFFICE_EXTENSIONS: string[] = [
  // Modern
  '.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm',
  // Legacy
  '.doc', '.xls', '.ppt', '.rtf',
  // Templates
  '.dotx', '.dotm', '.xltx', '.xltm', '.potx', '.potm',
];

/**
 * VBA macro indicators in OLE compound files
 */
export const VBA_INDICATORS: string[] = [
  'vbaProject.bin',
  '_VBA_PROJECT',
  'VBA',
  'Macros',
  'MODULE',
  'ThisDocument',
  'ThisWorkbook',
  'Auto_Open',
  'AutoOpen',
  'Auto_Close',
  'AutoClose',
  'AutoExec',
  'Document_Open',
  'Workbook_Open',
];

/**
 * Suspicious VBA keywords that indicate malicious behavior
 */
export const SUSPICIOUS_VBA_KEYWORDS: string[] = [
  'Shell',
  'WScript.Shell',
  'CreateObject',
  'GetObject',
  'PowerShell',
  'cmd.exe',
  'cmd /c',
  'Environ',
  'URLDownloadToFile',
  'XMLHTTP',
  'WinHttp',
  'ADODB.Stream',
  'Scripting.FileSystemObject',
  'RegWrite',
  'RegRead',
  'RegDelete',
  'base64',
  'FromBase64String',
  'Decode',
  'Execute',
  'Eval',
  'CallByName',
];

/**
 * Right-to-left override character used in filename spoofing
 */
export const RTL_OVERRIDE = '\u202E';

/**
 * Other dangerous Unicode characters for filename spoofing
 */
export const DANGEROUS_UNICODE_CHARS: string[] = [
  '\u202E', // Right-to-left override
  '\u202D', // Left-to-right override
  '\u202C', // Pop directional formatting
  '\u200E', // Left-to-right mark
  '\u200F', // Right-to-left mark
  '\u2066', // Left-to-right isolate
  '\u2067', // Right-to-left isolate
  '\u2068', // First strong isolate
  '\u2069', // Pop directional isolate
];

/**
 * Match magic bytes against buffer
 */
export function matchMagicBytes(
  buffer: Buffer,
  signature: FileSignature
): boolean {
  if (buffer.length < signature.offset + signature.magicBytes.length) {
    return false;
  }

  for (let i = 0; i < signature.magicBytes.length; i++) {
    if (buffer[signature.offset + i] !== signature.magicBytes[i]) {
      return false;
    }
  }

  return true;
}

/**
 * Detect file type from buffer using magic bytes
 */
export function detectFileTypeFromBuffer(buffer: Buffer): FileSignature | null {
  // Sort signatures by magic bytes length (longer = more specific)
  const sortedSignatures = [...FILE_SIGNATURES].sort(
    (a, b) => b.magicBytes.length - a.magicBytes.length
  );

  for (const signature of sortedSignatures) {
    if (matchMagicBytes(buffer, signature)) {
      return signature;
    }
  }

  return null;
}

/**
 * Check if extension is dangerous
 */
export function isDangerousExtension(filename: string): boolean {
  const ext = getExtension(filename).toLowerCase();
  return DANGEROUS_EXTENSIONS.includes(ext);
}

/**
 * Check if extension is a script
 */
export function isScriptExtension(filename: string): boolean {
  const ext = getExtension(filename).toLowerCase();
  return SCRIPT_EXTENSIONS.includes(ext);
}

/**
 * Check if extension is an executable
 */
export function isExecutableExtension(filename: string): boolean {
  const ext = getExtension(filename).toLowerCase();
  return EXECUTABLE_EXTENSIONS.includes(ext);
}

/**
 * Check if extension is an archive
 */
export function isArchiveExtension(filename: string): boolean {
  const ext = getExtension(filename).toLowerCase();
  return ARCHIVE_EXTENSIONS.includes(ext);
}

/**
 * Check if extension is an Office document
 */
export function isOfficeExtension(filename: string): boolean {
  const ext = getExtension(filename).toLowerCase();
  return OFFICE_EXTENSIONS.includes(ext);
}

/**
 * Get file extension from filename
 */
export function getExtension(filename: string): string {
  const lastDot = filename.lastIndexOf('.');
  if (lastDot === -1 || lastDot === filename.length - 1) {
    return '';
  }
  return filename.substring(lastDot);
}

/**
 * Get all extensions from filename (for double extension detection)
 */
export function getAllExtensions(filename: string): string[] {
  const extensions: string[] = [];
  const parts = filename.split('.');

  // Skip the first part (filename without extensions)
  for (let i = 1; i < parts.length; i++) {
    extensions.push('.' + parts[i].toLowerCase());
  }

  return extensions;
}

/**
 * Check for double extension attack (e.g., invoice.pdf.exe)
 */
export function hasDoubleExtension(filename: string): boolean {
  const extensions = getAllExtensions(filename);

  if (extensions.length < 2) {
    return false;
  }

  // Check if any extension before the last one is a "safe-looking" extension
  // and the last extension is dangerous
  const safeExtensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                          '.jpg', '.jpeg', '.png', '.gif', '.txt', '.csv', '.mp3', '.mp4'];

  const lastExt = extensions[extensions.length - 1];
  const previousExts = extensions.slice(0, -1);

  // If the last extension is dangerous and any previous extension looks safe
  if (DANGEROUS_EXTENSIONS.includes(lastExt)) {
    return previousExts.some(ext => safeExtensions.includes(ext));
  }

  return false;
}

/**
 * Check for RTL override character in filename
 */
export function hasRtlOverride(filename: string): boolean {
  return DANGEROUS_UNICODE_CHARS.some(char => filename.includes(char));
}

/**
 * Detect the real extension after RTL override
 */
export function getRealExtension(filename: string): string {
  // Remove RTL override characters to get real filename
  let realFilename = filename;
  for (const char of DANGEROUS_UNICODE_CHARS) {
    realFilename = realFilename.split(char).join('');
  }
  return getExtension(realFilename);
}

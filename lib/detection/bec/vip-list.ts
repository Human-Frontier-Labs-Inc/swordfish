/**
 * VIP/Executive List Management
 * Manages lists of important personnel for BEC impersonation detection
 */

import { sql } from '@/lib/db';

export interface VIPEntry {
  id: string;
  tenantId: string;
  email: string;
  displayName: string;
  title?: string;
  department?: string;
  role: VIPRole;
  aliases: string[];
  createdAt: Date;
  updatedAt: Date;
}

export type VIPRole =
  | 'executive'      // C-suite, VP, Directors
  | 'finance'        // CFO, Controllers, AP/AR
  | 'hr'             // HR leadership
  | 'it'             // IT leadership
  | 'legal'          // General Counsel, Legal team
  | 'board'          // Board members
  | 'assistant'      // Executive assistants
  | 'custom';        // Custom role

// Common executive titles for auto-detection
const EXECUTIVE_TITLES = [
  'ceo', 'chief executive', 'president',
  'cfo', 'chief financial', 'finance director',
  'coo', 'chief operating', 'operations director',
  'cto', 'chief technology', 'chief technical',
  'cio', 'chief information',
  'ciso', 'chief security',
  'cmo', 'chief marketing',
  'cpo', 'chief product', 'chief people',
  'svp', 'senior vice president',
  'evp', 'executive vice president',
  'vp', 'vice president',
  'director', 'managing director',
  'general counsel', 'chief legal',
  'controller', 'treasurer',
  'board member', 'chairman', 'chairwoman',
];

// Finance-related titles (high risk for wire fraud)
const FINANCE_TITLES = [
  'cfo', 'chief financial',
  'controller', 'comptroller',
  'treasurer', 'finance director',
  'accounts payable', 'accounts receivable',
  'financial analyst', 'finance manager',
  'bookkeeper', 'accountant',
];

/**
 * Get all VIPs for a tenant
 */
export async function getVIPList(tenantId: string): Promise<VIPEntry[]> {
  try {
    const result = await sql`
      SELECT * FROM vip_list
      WHERE tenant_id = ${tenantId}
      ORDER BY role, display_name
    `;

    return result.map(row => ({
      id: row.id,
      tenantId: row.tenant_id,
      email: row.email,
      displayName: row.display_name,
      title: row.title,
      department: row.department,
      role: row.role as VIPRole,
      aliases: row.aliases || [],
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    }));
  } catch {
    // Table might not exist yet
    return [];
  }
}

/**
 * Add a VIP to the list
 */
export async function addVIP(
  tenantId: string,
  entry: Omit<VIPEntry, 'id' | 'tenantId' | 'createdAt' | 'updatedAt'>
): Promise<VIPEntry> {
  const id = crypto.randomUUID();

  await sql`
    INSERT INTO vip_list (
      id, tenant_id, email, display_name, title, department, role, aliases, created_at, updated_at
    ) VALUES (
      ${id}, ${tenantId}, ${entry.email.toLowerCase()}, ${entry.displayName},
      ${entry.title || null}, ${entry.department || null}, ${entry.role},
      ${JSON.stringify(entry.aliases || [])}, NOW(), NOW()
    )
  `;

  return {
    id,
    tenantId,
    ...entry,
    email: entry.email.toLowerCase(),
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

/**
 * Update a VIP entry
 */
export async function updateVIP(
  tenantId: string,
  id: string,
  updates: Partial<Omit<VIPEntry, 'id' | 'tenantId' | 'createdAt' | 'updatedAt'>>
): Promise<void> {
  const setClauses: string[] = ['updated_at = NOW()'];
  const values: Record<string, unknown> = {};

  if (updates.email !== undefined) {
    setClauses.push('email = ${email}');
    values.email = updates.email.toLowerCase();
  }
  if (updates.displayName !== undefined) {
    setClauses.push('display_name = ${displayName}');
    values.displayName = updates.displayName;
  }
  if (updates.title !== undefined) {
    setClauses.push('title = ${title}');
    values.title = updates.title;
  }
  if (updates.department !== undefined) {
    setClauses.push('department = ${department}');
    values.department = updates.department;
  }
  if (updates.role !== undefined) {
    setClauses.push('role = ${role}');
    values.role = updates.role;
  }
  if (updates.aliases !== undefined) {
    setClauses.push('aliases = ${aliases}');
    values.aliases = JSON.stringify(updates.aliases);
  }

  await sql`
    UPDATE vip_list
    SET ${sql.unsafe(setClauses.join(', '))}
    WHERE tenant_id = ${tenantId} AND id = ${id}
  `;
}

/**
 * Remove a VIP from the list
 */
export async function removeVIP(tenantId: string, id: string): Promise<void> {
  await sql`
    DELETE FROM vip_list
    WHERE tenant_id = ${tenantId} AND id = ${id}
  `;
}

/**
 * Find VIP by email address
 */
export async function findVIPByEmail(
  tenantId: string,
  email: string
): Promise<VIPEntry | null> {
  try {
    const result = await sql`
      SELECT * FROM vip_list
      WHERE tenant_id = ${tenantId}
        AND (email = ${email.toLowerCase()} OR aliases @> ${JSON.stringify([email.toLowerCase()])})
      LIMIT 1
    `;

    if (result.length === 0) return null;

    const row = result[0];
    return {
      id: row.id,
      tenantId: row.tenant_id,
      email: row.email,
      displayName: row.display_name,
      title: row.title,
      department: row.department,
      role: row.role as VIPRole,
      aliases: row.aliases || [],
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    };
  } catch {
    return null;
  }
}

/**
 * Find VIP by display name (fuzzy match)
 */
export async function findVIPByDisplayName(
  tenantId: string,
  displayName: string
): Promise<VIPEntry[]> {
  const normalizedName = normalizeDisplayName(displayName);

  try {
    const result = await sql`
      SELECT * FROM vip_list
      WHERE tenant_id = ${tenantId}
    `;

    return result
      .filter(row => {
        const vipName = normalizeDisplayName(row.display_name);
        return fuzzyNameMatch(normalizedName, vipName);
      })
      .map(row => ({
        id: row.id,
        tenantId: row.tenant_id,
        email: row.email,
        displayName: row.display_name,
        title: row.title,
        department: row.department,
        role: row.role as VIPRole,
        aliases: row.aliases || [],
        createdAt: new Date(row.created_at),
        updatedAt: new Date(row.updated_at),
      }));
  } catch {
    return [];
  }
}

/**
 * Check if a name matches any VIP (for impersonation detection)
 */
export async function checkVIPImpersonation(
  tenantId: string,
  senderEmail: string,
  senderDisplayName: string
): Promise<{
  isImpersonation: boolean;
  matchedVIP?: VIPEntry;
  confidence: number;
  reason?: string;
}> {
  // First, check if sender is actually the VIP
  const actualVIP = await findVIPByEmail(tenantId, senderEmail);
  if (actualVIP) {
    return { isImpersonation: false, confidence: 0 };
  }

  // Check if display name matches any VIP
  const matchedVIPs = await findVIPByDisplayName(tenantId, senderDisplayName);

  if (matchedVIPs.length === 0) {
    return { isImpersonation: false, confidence: 0 };
  }

  // Found a match - this could be impersonation
  const matchedVIP = matchedVIPs[0];
  const confidence = calculateImpersonationConfidence(
    senderEmail,
    senderDisplayName,
    matchedVIP
  );

  return {
    isImpersonation: confidence > 0.5,
    matchedVIP,
    confidence,
    reason: `Display name "${senderDisplayName}" matches VIP "${matchedVIP.displayName}" but email "${senderEmail}" doesn't match expected "${matchedVIP.email}"`,
  };
}

/**
 * Auto-detect potential VIPs from display name/title
 */
export function detectPotentialVIP(displayName: string, title?: string): {
  isPotentialVIP: boolean;
  suggestedRole: VIPRole;
  matchedTitle?: string;
} {
  const combinedText = `${displayName} ${title || ''}`.toLowerCase();

  // Check for executive titles
  for (const execTitle of EXECUTIVE_TITLES) {
    if (combinedText.includes(execTitle)) {
      return {
        isPotentialVIP: true,
        suggestedRole: 'executive',
        matchedTitle: execTitle,
      };
    }
  }

  // Check for finance titles
  for (const financeTitle of FINANCE_TITLES) {
    if (combinedText.includes(financeTitle)) {
      return {
        isPotentialVIP: true,
        suggestedRole: 'finance',
        matchedTitle: financeTitle,
      };
    }
  }

  return {
    isPotentialVIP: false,
    suggestedRole: 'custom',
  };
}

/**
 * Bulk import VIPs from directory sync
 */
export async function bulkImportVIPs(
  tenantId: string,
  entries: Array<{
    email: string;
    displayName: string;
    title?: string;
    department?: string;
  }>
): Promise<{ imported: number; skipped: number }> {
  let imported = 0;
  let skipped = 0;

  for (const entry of entries) {
    // Check if potential VIP based on title
    const detection = detectPotentialVIP(entry.displayName, entry.title);

    if (!detection.isPotentialVIP) {
      skipped++;
      continue;
    }

    // Check if already exists
    const existing = await findVIPByEmail(tenantId, entry.email);
    if (existing) {
      skipped++;
      continue;
    }

    // Add to VIP list
    await addVIP(tenantId, {
      email: entry.email,
      displayName: entry.displayName,
      title: entry.title,
      department: entry.department,
      role: detection.suggestedRole,
      aliases: [],
    });

    imported++;
  }

  return { imported, skipped };
}

// Helper functions

function normalizeDisplayName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function fuzzyNameMatch(name1: string, name2: string): boolean {
  // Exact match
  if (name1 === name2) return true;

  // Check if one contains the other
  if (name1.includes(name2) || name2.includes(name1)) return true;

  // Check word overlap
  const words1 = new Set(name1.split(' '));
  const words2 = new Set(name2.split(' '));

  let overlap = 0;
  for (const word of words1) {
    if (word.length > 2 && words2.has(word)) {
      overlap++;
    }
  }

  // At least 2 words match or >50% overlap
  const minWords = Math.min(words1.size, words2.size);
  return overlap >= 2 || (minWords > 0 && overlap / minWords >= 0.5);
}

function calculateImpersonationConfidence(
  senderEmail: string,
  senderDisplayName: string,
  vip: VIPEntry
): number {
  let confidence = 0.5; // Base confidence for name match

  // Higher confidence if VIP is executive or finance
  if (vip.role === 'executive' || vip.role === 'finance') {
    confidence += 0.1;
  }

  // Higher confidence if email domain is external
  const senderDomain = senderEmail.split('@')[1]?.toLowerCase();
  const vipDomain = vip.email.split('@')[1]?.toLowerCase();

  if (senderDomain && vipDomain && senderDomain !== vipDomain) {
    confidence += 0.2;
  }

  // Higher confidence if display name is very similar
  const normalizedSender = normalizeDisplayName(senderDisplayName);
  const normalizedVIP = normalizeDisplayName(vip.displayName);

  if (normalizedSender === normalizedVIP) {
    confidence += 0.15;
  }

  // Look for title spoofing (CEO, CFO added to name)
  const titleKeywords = ['ceo', 'cfo', 'president', 'director', 'chief'];
  if (titleKeywords.some(t => senderDisplayName.toLowerCase().includes(t))) {
    confidence += 0.1;
  }

  return Math.min(confidence, 1.0);
}

/**
 * Get VIP statistics for a tenant
 */
export async function getVIPStats(tenantId: string): Promise<{
  total: number;
  byRole: Record<VIPRole, number>;
}> {
  const vips = await getVIPList(tenantId);

  const byRole: Record<VIPRole, number> = {
    executive: 0,
    finance: 0,
    hr: 0,
    it: 0,
    legal: 0,
    board: 0,
    assistant: 0,
    custom: 0,
  };

  for (const vip of vips) {
    byRole[vip.role]++;
  }

  return {
    total: vips.length,
    byRole,
  };
}

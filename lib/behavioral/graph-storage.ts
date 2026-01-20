/**
 * Graph Storage Layer
 * Phase 4.1: Persistence for contact graph data
 */

import { sql } from '@/lib/db';

export interface StoredContact {
  id: string;
  tenantId: string;
  email: string;
  displayName: string | null;
  domain: string;
  contactType: 'internal' | 'external';
  firstSeen: Date;
  lastSeen: Date;
  totalEmails: number;
  metadata?: Record<string, unknown>;
}

export interface StoredRelationship {
  id: string;
  tenantId: string;
  senderEmail: string;
  recipientEmail: string;
  firstContact: Date;
  lastContact: Date;
  communicationCount: number;
  recipientTypes: {
    to: number;
    cc: number;
    bcc: number;
  };
  isBidirectional: boolean;
  relationshipStrength: number;
  metadata?: Record<string, unknown>;
}

export interface ContactStats {
  totalCommunications: number;
  sentCount: number;
  receivedCount: number;
  firstContact: Date | null;
  lastContact: Date | null;
  isBidirectional: boolean;
  relationshipStrength: number;
}

/**
 * Graph Storage class for persisting contact and relationship data
 */
export class GraphStorage {
  private tenantId: string;

  constructor(tenantId: string) {
    this.tenantId = tenantId;
  }

  /**
   * Save a new contact to the database
   */
  async saveContact(contact: Omit<StoredContact, 'id'>): Promise<string> {
    const id = `contact_${Date.now()}_${Math.random().toString(36).substring(7)}`;

    try {
      await sql`
        INSERT INTO contact_graph (
          id, tenant_id, email, display_name, domain, contact_type,
          first_seen, last_seen, total_emails, metadata, created_at, updated_at
        ) VALUES (
          ${id},
          ${this.tenantId},
          ${contact.email},
          ${contact.displayName},
          ${contact.domain},
          ${contact.contactType},
          ${contact.firstSeen},
          ${contact.lastSeen},
          ${contact.totalEmails},
          ${JSON.stringify(contact.metadata || {})},
          NOW(),
          NOW()
        )
        ON CONFLICT (tenant_id, email) DO UPDATE SET
          display_name = COALESCE(EXCLUDED.display_name, contact_graph.display_name),
          last_seen = GREATEST(contact_graph.last_seen, EXCLUDED.last_seen),
          total_emails = contact_graph.total_emails + 1,
          metadata = EXCLUDED.metadata,
          updated_at = NOW()
      `;
    } catch (error) {
      console.error('Failed to save contact:', error);
    }

    return id;
  }

  /**
   * Get a contact by email
   */
  async getContact(email: string): Promise<StoredContact | null> {
    try {
      const result = await sql`
        SELECT
          id, tenant_id as "tenantId", email, display_name as "displayName",
          domain, contact_type as "contactType", first_seen as "firstSeen",
          last_seen as "lastSeen", total_emails as "totalEmails", metadata
        FROM contact_graph
        WHERE tenant_id = ${this.tenantId} AND email = ${email}
        LIMIT 1
      `;

      if (result.length === 0) return null;

      return result[0] as StoredContact;
    } catch (error) {
      console.error('Failed to get contact:', error);
      return null;
    }
  }

  /**
   * Update an existing contact
   */
  async updateContact(email: string, updates: Partial<StoredContact>): Promise<void> {
    try {
      // Update all provided fields using COALESCE to keep existing values
      const displayName = updates.displayName ?? null;
      const lastSeen = updates.lastSeen ?? null;
      const totalEmails = updates.totalEmails ?? null;
      const metadata = updates.metadata ? JSON.stringify(updates.metadata) : null;

      await sql`
        UPDATE contact_graph
        SET
          display_name = COALESCE(${displayName}, display_name),
          last_seen = COALESCE(${lastSeen}, last_seen),
          total_emails = COALESCE(${totalEmails}, total_emails),
          metadata = COALESCE(${metadata}::jsonb, metadata),
          updated_at = NOW()
        WHERE tenant_id = ${this.tenantId} AND email = ${email}
      `;
    } catch (error) {
      console.error('Failed to update contact:', error);
    }
  }

  /**
   * Get all contacts for a user
   */
  async getContactsForUser(
    userEmail: string,
    contactType?: 'internal' | 'external'
  ): Promise<StoredContact[]> {
    try {
      const baseQuery = sql`
        SELECT DISTINCT cg.*
        FROM contact_graph cg
        JOIN contact_relationships cr ON (
          (cr.sender_email = ${userEmail} AND cr.recipient_email = cg.email)
          OR
          (cr.recipient_email = ${userEmail} AND cr.sender_email = cg.email)
        )
        WHERE cg.tenant_id = ${this.tenantId}
      `;

      if (contactType) {
        return await sql`
          ${baseQuery}
          AND cg.contact_type = ${contactType}
          ORDER BY cg.total_emails DESC
        ` as StoredContact[];
      }

      return await sql`
        ${baseQuery}
        ORDER BY cg.total_emails DESC
      ` as StoredContact[];
    } catch (error) {
      console.error('Failed to get contacts for user:', error);
      return [];
    }
  }

  /**
   * Save or update a relationship
   */
  async saveRelationship(relationship: Omit<StoredRelationship, 'id'>): Promise<string> {
    const id = `rel_${Date.now()}_${Math.random().toString(36).substring(7)}`;

    try {
      await sql`
        INSERT INTO contact_relationships (
          id, tenant_id, sender_email, recipient_email, first_contact,
          last_contact, communication_count, recipient_types, is_bidirectional,
          relationship_strength, metadata, created_at, updated_at
        ) VALUES (
          ${id},
          ${this.tenantId},
          ${relationship.senderEmail},
          ${relationship.recipientEmail},
          ${relationship.firstContact},
          ${relationship.lastContact},
          ${relationship.communicationCount},
          ${JSON.stringify(relationship.recipientTypes)},
          ${relationship.isBidirectional},
          ${relationship.relationshipStrength},
          ${JSON.stringify(relationship.metadata || {})},
          NOW(),
          NOW()
        )
        ON CONFLICT (tenant_id, sender_email, recipient_email) DO UPDATE SET
          last_contact = GREATEST(contact_relationships.last_contact, EXCLUDED.last_contact),
          communication_count = contact_relationships.communication_count + 1,
          recipient_types = EXCLUDED.recipient_types,
          is_bidirectional = EXCLUDED.is_bidirectional,
          relationship_strength = EXCLUDED.relationship_strength,
          metadata = EXCLUDED.metadata,
          updated_at = NOW()
      `;
    } catch (error) {
      console.error('Failed to save relationship:', error);
    }

    return id;
  }

  /**
   * Get relationship between two contacts
   */
  async getRelationship(senderEmail: string, recipientEmail: string): Promise<StoredRelationship | null> {
    try {
      const result = await sql`
        SELECT
          id, tenant_id as "tenantId", sender_email as "senderEmail",
          recipient_email as "recipientEmail", first_contact as "firstContact",
          last_contact as "lastContact", communication_count as "communicationCount",
          recipient_types as "recipientTypes", is_bidirectional as "isBidirectional",
          relationship_strength as "relationshipStrength", metadata
        FROM contact_relationships
        WHERE tenant_id = ${this.tenantId}
          AND sender_email = ${senderEmail}
          AND recipient_email = ${recipientEmail}
        LIMIT 1
      `;

      if (result.length === 0) return null;

      return result[0] as StoredRelationship;
    } catch (error) {
      console.error('Failed to get relationship:', error);
      return null;
    }
  }

  /**
   * Get communication stats between two parties
   */
  async getContactStats(email1: string, email2: string): Promise<ContactStats | null> {
    try {
      const result = await sql`
        WITH outbound AS (
          SELECT
            communication_count,
            first_contact,
            last_contact
          FROM contact_relationships
          WHERE tenant_id = ${this.tenantId}
            AND sender_email = ${email1}
            AND recipient_email = ${email2}
        ),
        inbound AS (
          SELECT
            communication_count,
            first_contact,
            last_contact
          FROM contact_relationships
          WHERE tenant_id = ${this.tenantId}
            AND sender_email = ${email2}
            AND recipient_email = ${email1}
        )
        SELECT
          COALESCE(o.communication_count, 0) + COALESCE(i.communication_count, 0) as total,
          COALESCE(o.communication_count, 0) as sent,
          COALESCE(i.communication_count, 0) as received,
          LEAST(o.first_contact, i.first_contact) as first_contact,
          GREATEST(o.last_contact, i.last_contact) as last_contact,
          (o.communication_count > 0 AND i.communication_count > 0) as is_bidirectional
        FROM outbound o
        FULL OUTER JOIN inbound i ON true
      `;

      if (result.length === 0) return null;

      const row = result[0];
      return {
        totalCommunications: Number(row.total) || 0,
        sentCount: Number(row.sent) || 0,
        receivedCount: Number(row.received) || 0,
        firstContact: row.first_contact,
        lastContact: row.last_contact,
        isBidirectional: Boolean(row.is_bidirectional),
        relationshipStrength: this.calculateStrength(Number(row.total) || 0, Boolean(row.is_bidirectional)),
      };
    } catch (error) {
      console.error('Failed to get contact stats:', error);
      return null;
    }
  }

  /**
   * Get all relationships for a user
   */
  async getRelationshipsForUser(userEmail: string): Promise<StoredRelationship[]> {
    try {
      return await sql`
        SELECT
          id, tenant_id as "tenantId", sender_email as "senderEmail",
          recipient_email as "recipientEmail", first_contact as "firstContact",
          last_contact as "lastContact", communication_count as "communicationCount",
          recipient_types as "recipientTypes", is_bidirectional as "isBidirectional",
          relationship_strength as "relationshipStrength", metadata
        FROM contact_relationships
        WHERE tenant_id = ${this.tenantId}
          AND (sender_email = ${userEmail} OR recipient_email = ${userEmail})
        ORDER BY communication_count DESC
      ` as StoredRelationship[];
    } catch (error) {
      console.error('Failed to get relationships for user:', error);
      return [];
    }
  }

  /**
   * Check if relationship is bidirectional
   */
  async checkBidirectional(email1: string, email2: string): Promise<boolean> {
    try {
      const result = await sql`
        SELECT COUNT(*) as count
        FROM contact_relationships
        WHERE tenant_id = ${this.tenantId}
          AND (
            (sender_email = ${email1} AND recipient_email = ${email2})
            OR
            (sender_email = ${email2} AND recipient_email = ${email1})
          )
      `;

      return Number(result[0]?.count) === 2;
    } catch (error) {
      console.error('Failed to check bidirectional:', error);
      return false;
    }
  }

  /**
   * Calculate relationship strength (0-1)
   */
  private calculateStrength(totalCommunications: number, isBidirectional: boolean): number {
    // Base strength from communication count (logarithmic scale, max out at ~50 communications)
    const countStrength = Math.min(Math.log10(totalCommunications + 1) / Math.log10(51), 1);

    // Bidirectional bonus
    const bidirectionalBonus = isBidirectional ? 0.2 : 0;

    return Math.min(countStrength + bidirectionalBonus, 1);
  }

  /**
   * Bulk save contacts
   */
  async bulkSaveContacts(contacts: Omit<StoredContact, 'id'>[]): Promise<void> {
    if (contacts.length === 0) return;

    try {
      // Use transaction for bulk insert
      for (const contact of contacts) {
        await this.saveContact(contact);
      }
    } catch (error) {
      console.error('Failed to bulk save contacts:', error);
    }
  }

  /**
   * Get recently active contacts (last 30 days)
   */
  async getRecentlyActiveContacts(limit: number = 100): Promise<StoredContact[]> {
    try {
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

      return await sql`
        SELECT
          id, tenant_id as "tenantId", email, display_name as "displayName",
          domain, contact_type as "contactType", first_seen as "firstSeen",
          last_seen as "lastSeen", total_emails as "totalEmails", metadata
        FROM contact_graph
        WHERE tenant_id = ${this.tenantId}
          AND last_seen >= ${thirtyDaysAgo}
        ORDER BY last_seen DESC
        LIMIT ${limit}
      ` as StoredContact[];
    } catch (error) {
      console.error('Failed to get recently active contacts:', error);
      return [];
    }
  }

  /**
   * Delete old contacts (cleanup)
   */
  async deleteOldContacts(olderThanDays: number = 365): Promise<number> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);

      const result = await sql`
        DELETE FROM contact_graph
        WHERE tenant_id = ${this.tenantId}
          AND last_seen < ${cutoffDate}
          AND total_emails < 5
        RETURNING id
      `;

      return result.length;
    } catch (error) {
      console.error('Failed to delete old contacts:', error);
      return 0;
    }
  }
}

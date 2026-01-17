/**
 * Contact Graph Module
 * Phase 4.1: Track communication relationships between contacts
 */

import { GraphStorage, StoredContact, StoredRelationship, ContactStats } from './graph-storage';

export interface EmailAddress {
  address: string;
  displayName?: string;
}

export interface EmailInput {
  from: EmailAddress;
  to: EmailAddress[];
  cc?: EmailAddress[];
  bcc?: EmailAddress[];
  date: Date;
  messageId: string;
}

export interface ContactPair {
  sender: string;
  recipient: string;
  recipientType: 'to' | 'cc' | 'bcc';
  date: Date;
  messageId: string;
}

export interface ContactRelationship {
  email: string;
  displayName?: string;
  type: 'internal' | 'external';
  firstContact: Date;
  lastContact: Date;
  communicationCount: number;
  direction: 'inbound' | 'outbound' | 'bidirectional';
}

export type ContactType = 'internal' | 'external';

export interface CommunicationStats {
  totalCommunications: number;
  sentCount: number;
  receivedCount: number;
  firstContact: Date | null;
  lastContact: Date | null;
  isBidirectional: boolean;
  relationshipStrength: number;
}

interface LocalStats {
  communicationCount: number;
  firstContactDate: Date;
  lastContactDate: Date;
  recipientTypes: {
    to: number;
    cc: number;
    bcc: number;
  };
}

interface LocalContact {
  email: string;
  displayName?: string;
  type: ContactType;
  firstSeen: Date;
  lastSeen: Date;
  totalEmails: number;
}

/**
 * Relationship interface for getRelationship method
 */
export interface Relationship {
  senderEmail: string;
  recipientEmail: string;
  communicationCount: number;
  firstContact: Date;
  lastContact: Date;
  isBidirectional: boolean;
  relationshipStrength: number;
  recipientTypes: {
    to: number;
    cc: number;
    bcc: number;
  };
}

/**
 * Contact interface for user contact queries
 */
export interface Contact {
  email: string;
  displayName?: string;
  type: ContactType;
  firstSeen: Date;
  lastSeen: Date;
  totalEmails: number;
}

/**
 * ContactGraph class for tracking and analyzing communication relationships
 */
export class ContactGraph {
  private tenantId: string;
  private orgDomain: string;
  private storage: GraphStorage | null;

  // In-memory caches for fast lookups
  private relationships: Map<string, LocalStats> = new Map();
  private contacts: Map<string, LocalContact> = new Map();
  private userContacts: Map<string, Set<string>> = new Map();

  constructor(tenantId: string, orgDomain: string, storage?: GraphStorage) {
    this.tenantId = tenantId;
    this.orgDomain = orgDomain.toLowerCase();
    this.storage = storage || null;
  }

  /**
   * Static method to check if an email is internal to a domain
   */
  static isInternalContact(email: string, tenantDomain: string): boolean {
    const domain = email.split('@')[1]?.toLowerCase();
    const normalizedTenantDomain = tenantDomain.toLowerCase();

    if (!domain) return false;

    // Check exact match or subdomain
    return domain === normalizedTenantDomain || domain.endsWith(`.${normalizedTenantDomain}`);
  }

  /**
   * Generate a key for a sender-recipient pair
   */
  private getPairKey(sender: string, recipient: string): string {
    return `${sender.toLowerCase()}|${recipient.toLowerCase()}`;
  }

  /**
   * Extract all sender-recipient contact pairs from an email
   */
  async extractContactPairs(email: EmailInput): Promise<ContactPair[]> {
    const pairs: ContactPair[] = [];
    const sender = email.from.address.toLowerCase();

    // Process TO recipients
    for (const recipient of email.to) {
      pairs.push({
        sender,
        recipient: recipient.address.toLowerCase(),
        recipientType: 'to',
        date: email.date,
        messageId: email.messageId,
      });
    }

    // Process CC recipients
    if (email.cc) {
      for (const recipient of email.cc) {
        pairs.push({
          sender,
          recipient: recipient.address.toLowerCase(),
          recipientType: 'cc',
          date: email.date,
          messageId: email.messageId,
        });
      }
    }

    // Process BCC recipients
    if (email.bcc) {
      for (const recipient of email.bcc) {
        pairs.push({
          sender,
          recipient: recipient.address.toLowerCase(),
          recipientType: 'bcc',
          date: email.date,
          messageId: email.messageId,
        });
      }
    }

    return pairs;
  }

  /**
   * Process an email and update the contact graph
   */
  async processEmail(email: EmailInput): Promise<void> {
    const pairs = await this.extractContactPairs(email);

    // Update sender contact
    this.updateContact(
      email.from.address.toLowerCase(),
      email.from.displayName,
      email.date
    );

    // Process each pair
    for (const pair of pairs) {
      // Update recipient contact
      const recipientDisplayName = this.getRecipientDisplayName(email, pair.recipient);
      this.updateContact(pair.recipient, recipientDisplayName, pair.date);

      // Update relationship
      this.updateRelationship(pair);

      // Track user contacts
      this.addUserContact(pair.sender, pair.recipient);
    }

    // Persist to storage if available
    if (this.storage) {
      await this.persistChanges(email, pairs);
    }
  }

  /**
   * Get display name for a recipient from email data
   */
  private getRecipientDisplayName(email: EmailInput, recipientEmail: string): string | undefined {
    const allRecipients = [
      ...email.to,
      ...(email.cc || []),
      ...(email.bcc || []),
    ];

    const recipient = allRecipients.find(
      r => r.address.toLowerCase() === recipientEmail
    );

    return recipient?.displayName;
  }

  /**
   * Update contact information
   */
  private updateContact(email: string, displayName: string | undefined, date: Date): void {
    const normalizedEmail = email.toLowerCase();
    const existing = this.contacts.get(normalizedEmail);

    if (existing) {
      existing.displayName = displayName || existing.displayName;
      existing.lastSeen = date > existing.lastSeen ? date : existing.lastSeen;
      existing.totalEmails++;
    } else {
      this.contacts.set(normalizedEmail, {
        email: normalizedEmail,
        displayName,
        type: this.classifyContact(normalizedEmail),
        firstSeen: date,
        lastSeen: date,
        totalEmails: 1,
      });
    }
  }

  /**
   * Update relationship between sender and recipient
   */
  private updateRelationship(pair: ContactPair): void {
    const key = this.getPairKey(pair.sender, pair.recipient);
    const existing = this.relationships.get(key);

    if (existing) {
      existing.communicationCount++;
      existing.lastContactDate = pair.date > existing.lastContactDate
        ? pair.date
        : existing.lastContactDate;
      existing.recipientTypes[pair.recipientType]++;
    } else {
      this.relationships.set(key, {
        communicationCount: 1,
        firstContactDate: pair.date,
        lastContactDate: pair.date,
        recipientTypes: {
          to: pair.recipientType === 'to' ? 1 : 0,
          cc: pair.recipientType === 'cc' ? 1 : 0,
          bcc: pair.recipientType === 'bcc' ? 1 : 0,
        },
      });
    }
  }

  /**
   * Add contact to user's contact list
   */
  private addUserContact(userEmail: string, contactEmail: string): void {
    const normalized = userEmail.toLowerCase();
    if (!this.userContacts.has(normalized)) {
      this.userContacts.set(normalized, new Set());
    }
    this.userContacts.get(normalized)!.add(contactEmail.toLowerCase());
  }

  /**
   * Classify if a contact is internal or external
   */
  private classifyContact(email: string): ContactType {
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return 'external';

    // Check exact match or subdomain
    if (domain === this.orgDomain || domain.endsWith(`.${this.orgDomain}`)) {
      return 'internal';
    }

    return 'external';
  }

  /**
   * Persist changes to storage
   */
  private async persistChanges(email: EmailInput, pairs: ContactPair[]): Promise<void> {
    if (!this.storage) return;

    // Save sender contact
    const senderEmail = email.from.address.toLowerCase();
    const senderContact = this.contacts.get(senderEmail);
    if (senderContact) {
      await this.storage.saveContact({
        tenantId: this.tenantId,
        email: senderContact.email,
        displayName: senderContact.displayName || null,
        domain: senderEmail.split('@')[1] || '',
        contactType: senderContact.type,
        firstSeen: senderContact.firstSeen,
        lastSeen: senderContact.lastSeen,
        totalEmails: senderContact.totalEmails,
      });
    }

    // Save each relationship
    for (const pair of pairs) {
      const recipientContact = this.contacts.get(pair.recipient);
      if (recipientContact) {
        await this.storage.saveContact({
          tenantId: this.tenantId,
          email: recipientContact.email,
          displayName: recipientContact.displayName || null,
          domain: pair.recipient.split('@')[1] || '',
          contactType: recipientContact.type,
          firstSeen: recipientContact.firstSeen,
          lastSeen: recipientContact.lastSeen,
          totalEmails: recipientContact.totalEmails,
        });
      }

      const key = this.getPairKey(pair.sender, pair.recipient);
      const stats = this.relationships.get(key);
      if (stats) {
        await this.storage.saveRelationship({
          tenantId: this.tenantId,
          senderEmail: pair.sender,
          recipientEmail: pair.recipient,
          firstContact: stats.firstContactDate,
          lastContact: stats.lastContactDate,
          communicationCount: stats.communicationCount,
          recipientTypes: stats.recipientTypes,
          isBidirectional: this.isBidirectionalRelationship(pair.sender, pair.recipient),
          relationshipStrength: this.calculateRelationshipStrength(pair.sender, pair.recipient),
        });
      }
    }
  }

  /**
   * Get local stats for a sender-recipient pair
   */
  getLocalStats(sender: string, recipient: string): LocalStats | undefined {
    const key = this.getPairKey(sender, recipient);
    return this.relationships.get(key);
  }

  /**
   * Get communication frequency between two contacts
   */
  getCommunicationFrequency(sender: string, recipient: string): number {
    const stats = this.getLocalStats(sender, recipient);
    return stats?.communicationCount || 0;
  }

  /**
   * Check if relationship is bidirectional
   */
  isBidirectionalRelationship(email1: string, email2: string): boolean {
    const forward = this.getLocalStats(email1, email2);
    const reverse = this.getLocalStats(email2, email1);

    return !!(forward && reverse && forward.communicationCount > 0 && reverse.communicationCount > 0);
  }

  /**
   * Get relationship type between two contacts
   */
  getRelationshipType(from: string, to: string): 'outbound' | 'inbound' | 'bidirectional' | 'none' {
    const outbound = this.getLocalStats(from, to);
    const inbound = this.getLocalStats(to, from);

    if (outbound && inbound) return 'bidirectional';
    if (outbound) return 'outbound';
    if (inbound) return 'inbound';
    return 'none';
  }

  /**
   * Get contact type (internal/external)
   */
  getContactType(email: string): ContactType {
    const contact = this.contacts.get(email.toLowerCase());
    return contact?.type || this.classifyContact(email);
  }

  /**
   * Get all contacts for a user, optionally filtered by type
   */
  getContactsForUser(userEmail: string, filterType?: ContactType): ContactRelationship[] {
    const normalized = userEmail.toLowerCase();
    const contactEmails = this.userContacts.get(normalized);

    if (!contactEmails) return [];

    const contacts: ContactRelationship[] = [];

    for (const contactEmail of contactEmails) {
      const contact = this.contacts.get(contactEmail);
      if (!contact) continue;

      if (filterType && contact.type !== filterType) continue;

      const outboundStats = this.getLocalStats(normalized, contactEmail);
      const inboundStats = this.getLocalStats(contactEmail, normalized);

      const direction = outboundStats && inboundStats
        ? 'bidirectional'
        : outboundStats
        ? 'outbound'
        : 'inbound';

      contacts.push({
        email: contactEmail,
        displayName: contact.displayName,
        type: contact.type,
        firstContact: outboundStats?.firstContactDate || inboundStats?.firstContactDate || new Date(),
        lastContact: outboundStats?.lastContactDate || inboundStats?.lastContactDate || new Date(),
        communicationCount: (outboundStats?.communicationCount || 0) + (inboundStats?.communicationCount || 0),
        direction,
      });
    }

    return contacts;
  }

  /**
   * Get comprehensive communication stats between two parties
   */
  getCommunicationStatsBetween(email1: string, email2: string): CommunicationStats {
    const outbound = this.getLocalStats(email1, email2);
    const inbound = this.getLocalStats(email2, email1);

    if (!outbound && !inbound) {
      return {
        totalCommunications: 0,
        sentCount: 0,
        receivedCount: 0,
        firstContact: null,
        lastContact: null,
        isBidirectional: false,
        relationshipStrength: 0,
      };
    }

    const sentCount = outbound?.communicationCount || 0;
    const receivedCount = inbound?.communicationCount || 0;
    const totalCommunications = sentCount + receivedCount;

    const firstDates = [outbound?.firstContactDate, inbound?.firstContactDate].filter(Boolean) as Date[];
    const lastDates = [outbound?.lastContactDate, inbound?.lastContactDate].filter(Boolean) as Date[];

    const firstContact = firstDates.length > 0
      ? new Date(Math.min(...firstDates.map(d => d.getTime())))
      : null;
    const lastContact = lastDates.length > 0
      ? new Date(Math.max(...lastDates.map(d => d.getTime())))
      : null;

    const isBidirectional = sentCount > 0 && receivedCount > 0;

    return {
      totalCommunications,
      sentCount,
      receivedCount,
      firstContact,
      lastContact,
      isBidirectional,
      relationshipStrength: this.calculateRelationshipStrength(email1, email2),
    };
  }

  /**
   * Calculate relationship strength (0-1)
   * Note: Uses direct stats lookup to avoid recursion with getCommunicationStatsBetween
   */
  private calculateRelationshipStrength(email1: string, email2: string): number {
    const outbound = this.getLocalStats(email1, email2);
    const inbound = this.getLocalStats(email2, email1);

    const sentCount = outbound?.communicationCount || 0;
    const receivedCount = inbound?.communicationCount || 0;
    const totalCommunications = sentCount + receivedCount;
    const isBidirectional = sentCount > 0 && receivedCount > 0;

    // Base strength from communication count (logarithmic scale)
    const countStrength = Math.min(Math.log10(totalCommunications + 1) / Math.log10(51), 1);

    // Bidirectional bonus
    const bidirectionalBonus = isBidirectional ? 0.2 : 0;

    // Recency bonus (if last contact was recent)
    let recencyBonus = 0;
    const lastDates = [outbound?.lastContactDate, inbound?.lastContactDate].filter(Boolean) as Date[];
    if (lastDates.length > 0) {
      const lastContact = new Date(Math.max(...lastDates.map(d => d.getTime())));
      const daysSinceContact = (Date.now() - lastContact.getTime()) / (1000 * 60 * 60 * 24);
      if (daysSinceContact < 7) recencyBonus = 0.1;
      else if (daysSinceContact < 30) recencyBonus = 0.05;
    }

    return Math.min(countStrength + bidirectionalBonus + recencyBonus, 1);
  }

  /**
   * Get all contacts in the graph
   */
  getAllContacts(): LocalContact[] {
    return Array.from(this.contacts.values());
  }

  /**
   * Check if a contact exists in the graph
   */
  hasContact(email: string): boolean {
    return this.contacts.has(email.toLowerCase());
  }

  /**
   * Get graph statistics
   */
  getGraphStats(): {
    totalContacts: number;
    internalContacts: number;
    externalContacts: number;
    totalRelationships: number;
    bidirectionalRelationships: number;
  } {
    const contacts = this.getAllContacts();
    const internal = contacts.filter(c => c.type === 'internal').length;
    const external = contacts.filter(c => c.type === 'external').length;

    let bidirectional = 0;
    const processedPairs = new Set<string>();

    for (const [key] of this.relationships) {
      const [sender, recipient] = key.split('|');
      const pairKey = [sender, recipient].sort().join('|');

      if (processedPairs.has(pairKey)) continue;
      processedPairs.add(pairKey);

      if (this.isBidirectionalRelationship(sender, recipient)) {
        bidirectional++;
      }
    }

    return {
      totalContacts: contacts.length,
      internalContacts: internal,
      externalContacts: external,
      totalRelationships: this.relationships.size,
      bidirectionalRelationships: bidirectional,
    };
  }

  // ============================================
  // Required API Methods (per specification)
  // ============================================

  /**
   * Record a communication (alias for processEmail)
   * This is the main entry point for recording email communications
   */
  async recordCommunication(email: EmailInput): Promise<void> {
    return this.processEmail(email);
  }

  /**
   * Get relationship between two users
   * Returns null if no relationship exists
   */
  async getRelationship(user1: string, user2: string): Promise<Relationship | null> {
    const normalized1 = user1.toLowerCase();
    const normalized2 = user2.toLowerCase();
    const stats = this.getLocalStats(normalized1, normalized2);

    if (!stats) {
      return null;
    }

    return {
      senderEmail: normalized1,
      recipientEmail: normalized2,
      communicationCount: stats.communicationCount,
      firstContact: stats.firstContactDate,
      lastContact: stats.lastContactDate,
      isBidirectional: this.isBidirectionalRelationship(normalized1, normalized2),
      relationshipStrength: this.calculateRelationshipStrength(normalized1, normalized2),
      recipientTypes: stats.recipientTypes,
    };
  }

  /**
   * Check if a contact is known to a user
   * Returns true if there has been any communication between them
   */
  async isKnownContact(userId: string, contactEmail: string): Promise<boolean> {
    const normalizedUser = userId.toLowerCase();
    const normalizedContact = contactEmail.toLowerCase();

    // Check both directions
    const outbound = this.getLocalStats(normalizedUser, normalizedContact);
    const inbound = this.getLocalStats(normalizedContact, normalizedUser);

    return !!(outbound || inbound);
  }

  /**
   * Get relationship strength between two contacts
   * Returns a value between 0 and 1
   */
  async getRelationshipStrength(userId: string, contactEmail: string): Promise<number> {
    const normalized1 = userId.toLowerCase();
    const normalized2 = contactEmail.toLowerCase();

    return this.calculateRelationshipStrength(normalized1, normalized2);
  }

  /**
   * Get the first contact date between two users
   * Returns null if no communication exists
   */
  async getFirstContactDate(userId: string, contactEmail: string): Promise<Date | null> {
    const normalized1 = userId.toLowerCase();
    const normalized2 = contactEmail.toLowerCase();

    const stats = this.getLocalStats(normalized1, normalized2);
    return stats?.firstContactDate || null;
  }

  /**
   * Get communication count between two users
   * Returns 0 if no communication exists
   */
  async getCommunicationCount(userId: string, contactEmail: string): Promise<number> {
    const normalized1 = userId.toLowerCase();
    const normalized2 = contactEmail.toLowerCase();

    const stats = this.getLocalStats(normalized1, normalized2);
    return stats?.communicationCount || 0;
  }

  /**
   * Get contacts filtered by domain
   */
  getContactsByDomain(domain: string): Contact[] {
    const normalizedDomain = domain.toLowerCase();
    const contacts: Contact[] = [];

    for (const [, contact] of this.contacts) {
      const contactDomain = contact.email.split('@')[1];
      if (contactDomain === normalizedDomain) {
        contacts.push({
          email: contact.email,
          displayName: contact.displayName,
          type: contact.type,
          firstSeen: contact.firstSeen,
          lastSeen: contact.lastSeen,
          totalEmails: contact.totalEmails,
        });
      }
    }

    return contacts;
  }

  /**
   * Get async version of contacts for user (for storage integration)
   */
  async getContactsForUserAsync(userId: string): Promise<Contact[]> {
    const contacts = this.getContactsForUser(userId);
    return contacts.map(c => ({
      email: c.email,
      displayName: c.displayName,
      type: c.type,
      firstSeen: c.firstContact,
      lastSeen: c.lastContact,
      totalEmails: c.communicationCount,
    }));
  }
}

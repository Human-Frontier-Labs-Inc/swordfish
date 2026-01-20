/**
 * Contact Graph Tests
 * Phase 4.1: Communication relationship tracking
 * TDD: 25 tests for contact graph functionality
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ContactGraph, type ContactPair, type ContactRelationship, type ContactType, type CommunicationStats } from '@/lib/behavioral/contact-graph';

// Mock database
vi.mock('@/lib/db', () => ({
  sql: vi.fn().mockImplementation(() => Promise.resolve([])),
}));

// Create mock storage for testing
function createMockStorage() {
  return {
    saveContact: vi.fn().mockResolvedValue('contact_123'),
    getContact: vi.fn().mockResolvedValue(null),
    updateContact: vi.fn().mockResolvedValue(undefined),
    getContactsForUser: vi.fn().mockResolvedValue([]),
    getContactStats: vi.fn().mockResolvedValue(null),
    saveRelationship: vi.fn().mockResolvedValue('rel_123'),
    getRelationship: vi.fn().mockResolvedValue(null),
  };
}

describe('Contact Graph', () => {
  let contactGraph: ContactGraph;
  const testTenantId = 'tenant_123';
  const testOrgDomain = 'company.com';

  beforeEach(() => {
    vi.clearAllMocks();
    contactGraph = new ContactGraph(testTenantId, testOrgDomain);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Extract sender/recipient pairs from email', () => {
    it('should extract simple sender-recipient pair', async () => {
      const email = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-001',
      };

      const pairs = await contactGraph.extractContactPairs(email);

      expect(pairs.length).toBe(1);
      expect(pairs[0].sender).toBe('sender@company.com');
      expect(pairs[0].recipient).toBe('recipient@company.com');
    });

    it('should extract multiple sender-recipient pairs for multiple recipients', async () => {
      const email = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [
          { address: 'recipient1@company.com', displayName: 'Recipient 1' },
          { address: 'recipient2@company.com', displayName: 'Recipient 2' },
        ],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-002',
      };

      const pairs = await contactGraph.extractContactPairs(email);

      expect(pairs.length).toBe(2);
      expect(pairs.map(p => p.recipient)).toContain('recipient1@company.com');
      expect(pairs.map(p => p.recipient)).toContain('recipient2@company.com');
    });

    it('should normalize email addresses to lowercase', async () => {
      const email = {
        from: { address: 'SENDER@Company.COM', displayName: 'Sender' },
        to: [{ address: 'RECIPIENT@Company.COM', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-003',
      };

      const pairs = await contactGraph.extractContactPairs(email);

      expect(pairs[0].sender).toBe('sender@company.com');
      expect(pairs[0].recipient).toBe('recipient@company.com');
    });
  });

  describe('Track communication frequency between pairs', () => {
    it('should increment frequency when processing new email', async () => {
      const email = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-004',
      };

      await contactGraph.processEmail(email);
      const stats = contactGraph.getLocalStats('sender@company.com', 'recipient@company.com');

      expect(stats?.communicationCount).toBe(1);
    });

    it('should track frequency over multiple emails', async () => {
      const email1 = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-005',
      };

      const email2 = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-16T10:00:00Z'),
        messageId: 'msg-006',
      };

      await contactGraph.processEmail(email1);
      await contactGraph.processEmail(email2);

      const stats = contactGraph.getLocalStats('sender@company.com', 'recipient@company.com');
      expect(stats?.communicationCount).toBe(2);
    });

    it('should return total frequency for a contact pair', async () => {
      const email = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-007',
      };

      await contactGraph.processEmail(email);
      await contactGraph.processEmail({ ...email, messageId: 'msg-008' });
      await contactGraph.processEmail({ ...email, messageId: 'msg-009' });

      const frequency = contactGraph.getCommunicationFrequency('alice@company.com', 'bob@company.com');
      expect(frequency).toBe(3);
    });
  });

  describe('Track first contact date', () => {
    it('should record first contact date', async () => {
      const email = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-010',
      };

      await contactGraph.processEmail(email);
      const stats = contactGraph.getLocalStats('sender@company.com', 'recipient@company.com');

      expect(stats?.firstContactDate).toEqual(new Date('2024-01-15T10:00:00Z'));
    });

    it('should not update first contact date on subsequent emails', async () => {
      const email1 = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-011',
      };

      const email2 = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-20T10:00:00Z'),
        messageId: 'msg-012',
      };

      await contactGraph.processEmail(email1);
      await contactGraph.processEmail(email2);

      const stats = contactGraph.getLocalStats('sender@company.com', 'recipient@company.com');
      expect(stats?.firstContactDate).toEqual(new Date('2024-01-15T10:00:00Z'));
    });
  });

  describe('Track last contact date', () => {
    it('should record last contact date', async () => {
      const email = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-013',
      };

      await contactGraph.processEmail(email);
      const stats = contactGraph.getLocalStats('sender@company.com', 'recipient@company.com');

      expect(stats?.lastContactDate).toEqual(new Date('2024-01-15T10:00:00Z'));
    });

    it('should update last contact date on subsequent emails', async () => {
      const email1 = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-014',
      };

      const email2 = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-20T10:00:00Z'),
        messageId: 'msg-015',
      };

      await contactGraph.processEmail(email1);
      await contactGraph.processEmail(email2);

      const stats = contactGraph.getLocalStats('sender@company.com', 'recipient@company.com');
      expect(stats?.lastContactDate).toEqual(new Date('2024-01-20T10:00:00Z'));
    });
  });

  describe('Detect bidirectional relationships', () => {
    it('should detect bidirectional relationship after mutual emails', async () => {
      const emailAtoB = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-016',
      };

      const emailBtoA = {
        from: { address: 'bob@company.com', displayName: 'Bob' },
        to: [{ address: 'alice@company.com', displayName: 'Alice' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-16T10:00:00Z'),
        messageId: 'msg-017',
      };

      await contactGraph.processEmail(emailAtoB);
      await contactGraph.processEmail(emailBtoA);

      const isBidirectional = contactGraph.isBidirectionalRelationship('alice@company.com', 'bob@company.com');
      expect(isBidirectional).toBe(true);
    });

    it('should not detect bidirectional relationship for one-way communication', async () => {
      const email = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-018',
      };

      await contactGraph.processEmail(email);

      const isBidirectional = contactGraph.isBidirectionalRelationship('alice@company.com', 'bob@company.com');
      expect(isBidirectional).toBe(false);
    });

    it('should return relationship type', async () => {
      const emailAtoB = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-019',
      };

      await contactGraph.processEmail(emailAtoB);

      const relationship = contactGraph.getRelationshipType('alice@company.com', 'bob@company.com');
      expect(relationship).toBe('outbound');

      const reverseRelationship = contactGraph.getRelationshipType('bob@company.com', 'alice@company.com');
      expect(reverseRelationship).toBe('inbound');
    });
  });

  describe('Classify internal vs external contacts', () => {
    it('should classify internal contact correctly', async () => {
      const email = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-020',
      };

      await contactGraph.processEmail(email);

      const contactType = contactGraph.getContactType('alice@company.com');
      expect(contactType).toBe('internal');
    });

    it('should classify external contact correctly', async () => {
      const email = {
        from: { address: 'external@other.com', displayName: 'External' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-021',
      };

      await contactGraph.processEmail(email);

      const contactType = contactGraph.getContactType('external@other.com');
      expect(contactType).toBe('external');
    });

    it('should handle subdomain classification', async () => {
      const contactGraphWithSubdomain = new ContactGraph(testTenantId, 'company.com');

      const email = {
        from: { address: 'user@sub.company.com', displayName: 'User' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-022',
      };

      await contactGraphWithSubdomain.processEmail(email);

      // Subdomains should be treated as internal
      const contactType = contactGraphWithSubdomain.getContactType('user@sub.company.com');
      expect(contactType).toBe('internal');
    });
  });

  describe('Handle CC/BCC recipients', () => {
    it('should include CC recipients in contact pairs', async () => {
      const email = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [{ address: 'cc@company.com', displayName: 'CC Person' }],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-023',
      };

      const pairs = await contactGraph.extractContactPairs(email);

      expect(pairs.length).toBe(2);
      expect(pairs.map(p => p.recipient)).toContain('cc@company.com');
      expect(pairs.find(p => p.recipient === 'cc@company.com')?.recipientType).toBe('cc');
    });

    it('should include BCC recipients in contact pairs', async () => {
      const email = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [{ address: 'bcc@company.com', displayName: 'BCC Person' }],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-024',
      };

      const pairs = await contactGraph.extractContactPairs(email);

      expect(pairs.length).toBe(2);
      expect(pairs.map(p => p.recipient)).toContain('bcc@company.com');
      expect(pairs.find(p => p.recipient === 'bcc@company.com')?.recipientType).toBe('bcc');
    });

    it('should track recipient types correctly', async () => {
      const email = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'to@company.com', displayName: 'To Person' }],
        cc: [{ address: 'cc@company.com', displayName: 'CC Person' }],
        bcc: [{ address: 'bcc@company.com', displayName: 'BCC Person' }],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-025',
      };

      const pairs = await contactGraph.extractContactPairs(email);

      expect(pairs.find(p => p.recipient === 'to@company.com')?.recipientType).toBe('to');
      expect(pairs.find(p => p.recipient === 'cc@company.com')?.recipientType).toBe('cc');
      expect(pairs.find(p => p.recipient === 'bcc@company.com')?.recipientType).toBe('bcc');
    });
  });

  describe('Graph persistence and updates', () => {
    it('should persist contact data on process', async () => {
      const storage = createMockStorage();
      const graphWithStorage = new ContactGraph(testTenantId, testOrgDomain, storage as any);

      const email = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-026',
      };

      await graphWithStorage.processEmail(email);

      expect(storage.saveContact).toHaveBeenCalled();
    });

    it('should update existing contact on subsequent emails', async () => {
      const storage = createMockStorage();
      const graphWithStorage = new ContactGraph(testTenantId, testOrgDomain, storage as any);

      const email1 = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-027',
      };

      const email2 = {
        from: { address: 'sender@company.com', displayName: 'Sender Updated' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-16T10:00:00Z'),
        messageId: 'msg-028',
      };

      await graphWithStorage.processEmail(email1);
      await graphWithStorage.processEmail(email2);

      // saveContact is called on each email, which handles updates via upsert
      expect(storage.saveContact).toHaveBeenCalledTimes(4); // 2 contacts x 2 emails
    });

    it('should save relationship data', async () => {
      const storage = createMockStorage();
      const graphWithStorage = new ContactGraph(testTenantId, testOrgDomain, storage as any);

      const email = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-029',
      };

      await graphWithStorage.processEmail(email);

      expect(storage.saveRelationship).toHaveBeenCalled();
    });
  });

  describe('Query contacts for a user', () => {
    it('should return all contacts for a user', async () => {
      const email1 = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-030',
      };

      const email2 = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'charlie@company.com', displayName: 'Charlie' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-16T10:00:00Z'),
        messageId: 'msg-031',
      };

      await contactGraph.processEmail(email1);
      await contactGraph.processEmail(email2);

      const contacts = contactGraph.getContactsForUser('alice@company.com');

      expect(contacts.length).toBe(2);
      expect(contacts.map(c => c.email)).toContain('bob@company.com');
      expect(contacts.map(c => c.email)).toContain('charlie@company.com');
    });

    it('should filter contacts by type (internal/external)', async () => {
      const email1 = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-032',
      };

      const email2 = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'external@other.com', displayName: 'External' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-16T10:00:00Z'),
        messageId: 'msg-033',
      };

      await contactGraph.processEmail(email1);
      await contactGraph.processEmail(email2);

      const internalContacts = contactGraph.getContactsForUser('alice@company.com', 'internal');
      const externalContacts = contactGraph.getContactsForUser('alice@company.com', 'external');

      expect(internalContacts.length).toBe(1);
      expect(internalContacts[0].email).toBe('bob@company.com');
      expect(externalContacts.length).toBe(1);
      expect(externalContacts[0].email).toBe('external@other.com');
    });

    it('should return empty array for user with no contacts', () => {
      const contacts = contactGraph.getContactsForUser('unknown@company.com');
      expect(contacts).toEqual([]);
    });
  });

  describe('Get communication stats between two parties', () => {
    it('should return comprehensive stats for a contact pair', async () => {
      const email1 = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-034',
      };

      const email2 = {
        from: { address: 'bob@company.com', displayName: 'Bob' },
        to: [{ address: 'alice@company.com', displayName: 'Alice' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-16T10:00:00Z'),
        messageId: 'msg-035',
      };

      await contactGraph.processEmail(email1);
      await contactGraph.processEmail(email2);

      const stats = contactGraph.getCommunicationStatsBetween('alice@company.com', 'bob@company.com');

      expect(stats.totalCommunications).toBe(2);
      expect(stats.sentCount).toBe(1);
      expect(stats.receivedCount).toBe(1);
      expect(stats.firstContact).toEqual(new Date('2024-01-15T10:00:00Z'));
      expect(stats.lastContact).toEqual(new Date('2024-01-16T10:00:00Z'));
      expect(stats.isBidirectional).toBe(true);
    });

    it('should calculate relationship strength score', async () => {
      // Process multiple emails to build relationship
      for (let i = 0; i < 10; i++) {
        const email = {
          from: { address: 'alice@company.com', displayName: 'Alice' },
          to: [{ address: 'bob@company.com', displayName: 'Bob' }],
          cc: [],
          bcc: [],
          date: new Date(Date.UTC(2024, 0, 15 + i, 10, 0, 0)),
          messageId: `msg-strength-${i}`,
        };
        await contactGraph.processEmail(email);
      }

      const stats = contactGraph.getCommunicationStatsBetween('alice@company.com', 'bob@company.com');

      expect(stats.relationshipStrength).toBeGreaterThan(0);
      expect(stats.relationshipStrength).toBeLessThanOrEqual(1);
    });

    it('should return null stats for unknown pair', () => {
      const stats = contactGraph.getCommunicationStatsBetween('unknown1@company.com', 'unknown2@company.com');
      expect(stats.totalCommunications).toBe(0);
    });
  });

  describe('Required API Methods', () => {
    describe('recordCommunication', () => {
      it('should record communication as alias for processEmail', async () => {
        const email = {
          from: { address: 'sender@company.com', displayName: 'Sender' },
          to: [{ address: 'recipient@company.com', displayName: 'Recipient' }],
          cc: [],
          bcc: [],
          date: new Date('2024-01-15T10:00:00Z'),
          messageId: 'msg-record-001',
        };

        await contactGraph.recordCommunication(email);

        const stats = contactGraph.getLocalStats('sender@company.com', 'recipient@company.com');
        expect(stats?.communicationCount).toBe(1);
      });
    });

    describe('getRelationship', () => {
      it('should return relationship details between two users', async () => {
        const email = {
          from: { address: 'alice@company.com', displayName: 'Alice' },
          to: [{ address: 'bob@company.com', displayName: 'Bob' }],
          cc: [],
          bcc: [],
          date: new Date('2024-01-15T10:00:00Z'),
          messageId: 'msg-rel-001',
        };

        await contactGraph.processEmail(email);

        const relationship = await contactGraph.getRelationship('alice@company.com', 'bob@company.com');

        expect(relationship).not.toBeNull();
        expect(relationship?.communicationCount).toBe(1);
        expect(relationship?.firstContact).toEqual(new Date('2024-01-15T10:00:00Z'));
      });

      it('should return null for non-existent relationship', async () => {
        const relationship = await contactGraph.getRelationship('unknown1@company.com', 'unknown2@company.com');
        expect(relationship).toBeNull();
      });
    });

    describe('isKnownContact', () => {
      it('should return true for known contact', async () => {
        const email = {
          from: { address: 'alice@company.com', displayName: 'Alice' },
          to: [{ address: 'bob@company.com', displayName: 'Bob' }],
          cc: [],
          bcc: [],
          date: new Date('2024-01-15T10:00:00Z'),
          messageId: 'msg-known-001',
        };

        await contactGraph.processEmail(email);

        const isKnown = await contactGraph.isKnownContact('alice@company.com', 'bob@company.com');
        expect(isKnown).toBe(true);
      });

      it('should return false for unknown contact', async () => {
        const isKnown = await contactGraph.isKnownContact('alice@company.com', 'stranger@external.com');
        expect(isKnown).toBe(false);
      });

      it('should handle case-insensitive email comparison', async () => {
        const email = {
          from: { address: 'alice@company.com', displayName: 'Alice' },
          to: [{ address: 'bob@company.com', displayName: 'Bob' }],
          cc: [],
          bcc: [],
          date: new Date('2024-01-15T10:00:00Z'),
          messageId: 'msg-known-002',
        };

        await contactGraph.processEmail(email);

        const isKnown = await contactGraph.isKnownContact('ALICE@Company.COM', 'BOB@COMPANY.COM');
        expect(isKnown).toBe(true);
      });
    });

    describe('getRelationshipStrength', () => {
      it('should return strength score between 0 and 1', async () => {
        const email = {
          from: { address: 'alice@company.com', displayName: 'Alice' },
          to: [{ address: 'bob@company.com', displayName: 'Bob' }],
          cc: [],
          bcc: [],
          date: new Date('2024-01-15T10:00:00Z'),
          messageId: 'msg-str-001',
        };

        await contactGraph.processEmail(email);

        const strength = await contactGraph.getRelationshipStrength('alice@company.com', 'bob@company.com');

        expect(strength).toBeGreaterThanOrEqual(0);
        expect(strength).toBeLessThanOrEqual(1);
      });

      it('should return higher strength for more frequent communication', async () => {
        // Few communications
        const email1 = {
          from: { address: 'alice@company.com', displayName: 'Alice' },
          to: [{ address: 'bob@company.com', displayName: 'Bob' }],
          cc: [],
          bcc: [],
          date: new Date('2024-01-15T10:00:00Z'),
          messageId: 'msg-str-002',
        };

        await contactGraph.processEmail(email1);
        const lowStrength = await contactGraph.getRelationshipStrength('alice@company.com', 'bob@company.com');

        // Many communications
        for (let i = 0; i < 20; i++) {
          await contactGraph.processEmail({
            ...email1,
            messageId: `msg-str-many-${i}`,
            date: new Date(Date.UTC(2024, 0, 15 + i, 10, 0, 0)),
          });
        }
        const highStrength = await contactGraph.getRelationshipStrength('alice@company.com', 'bob@company.com');

        expect(highStrength).toBeGreaterThan(lowStrength);
      });

      it('should return 0 for unknown contacts', async () => {
        const strength = await contactGraph.getRelationshipStrength('unknown1@company.com', 'unknown2@company.com');
        expect(strength).toBe(0);
      });
    });

    describe('isInternalContact (static)', () => {
      it('should return true for same domain', () => {
        const isInternal = ContactGraph.isInternalContact('user@company.com', 'company.com');
        expect(isInternal).toBe(true);
      });

      it('should return true for subdomain', () => {
        const isInternal = ContactGraph.isInternalContact('user@sub.company.com', 'company.com');
        expect(isInternal).toBe(true);
      });

      it('should return false for different domain', () => {
        const isInternal = ContactGraph.isInternalContact('user@external.com', 'company.com');
        expect(isInternal).toBe(false);
      });

      it('should handle case-insensitive comparison', () => {
        const isInternal = ContactGraph.isInternalContact('user@COMPANY.COM', 'company.com');
        expect(isInternal).toBe(true);
      });

      it('should return false for lookalike domain', () => {
        const isInternal = ContactGraph.isInternalContact('user@company.net', 'company.com');
        expect(isInternal).toBe(false);
      });
    });

    describe('getFirstContactDate', () => {
      it('should return first contact date', async () => {
        const email = {
          from: { address: 'alice@company.com', displayName: 'Alice' },
          to: [{ address: 'bob@company.com', displayName: 'Bob' }],
          cc: [],
          bcc: [],
          date: new Date('2024-01-15T10:00:00Z'),
          messageId: 'msg-first-001',
        };

        await contactGraph.processEmail(email);

        const firstDate = await contactGraph.getFirstContactDate('alice@company.com', 'bob@company.com');
        expect(firstDate).toEqual(new Date('2024-01-15T10:00:00Z'));
      });

      it('should not change first contact date on subsequent communications', async () => {
        const email1 = {
          from: { address: 'alice@company.com', displayName: 'Alice' },
          to: [{ address: 'bob@company.com', displayName: 'Bob' }],
          cc: [],
          bcc: [],
          date: new Date('2024-01-15T10:00:00Z'),
          messageId: 'msg-first-002',
        };

        const email2 = {
          from: { address: 'alice@company.com', displayName: 'Alice' },
          to: [{ address: 'bob@company.com', displayName: 'Bob' }],
          cc: [],
          bcc: [],
          date: new Date('2024-03-20T10:00:00Z'),
          messageId: 'msg-first-003',
        };

        await contactGraph.processEmail(email1);
        await contactGraph.processEmail(email2);

        const firstDate = await contactGraph.getFirstContactDate('alice@company.com', 'bob@company.com');
        expect(firstDate).toEqual(new Date('2024-01-15T10:00:00Z'));
      });

      it('should return null for unknown contacts', async () => {
        const firstDate = await contactGraph.getFirstContactDate('unknown1@company.com', 'unknown2@company.com');
        expect(firstDate).toBeNull();
      });
    });

    describe('getCommunicationCount', () => {
      it('should return communication count between contacts', async () => {
        const email = {
          from: { address: 'alice@company.com', displayName: 'Alice' },
          to: [{ address: 'bob@company.com', displayName: 'Bob' }],
          cc: [],
          bcc: [],
          date: new Date('2024-01-15T10:00:00Z'),
          messageId: 'msg-count-001',
        };

        await contactGraph.processEmail(email);
        await contactGraph.processEmail({ ...email, messageId: 'msg-count-002' });
        await contactGraph.processEmail({ ...email, messageId: 'msg-count-003' });

        const count = await contactGraph.getCommunicationCount('alice@company.com', 'bob@company.com');
        expect(count).toBe(3);
      });

      it('should return 0 for unknown contacts', async () => {
        const count = await contactGraph.getCommunicationCount('unknown1@company.com', 'unknown2@company.com');
        expect(count).toBe(0);
      });
    });
  });

  describe('Tenant isolation for graphs', () => {
    it('should isolate contacts between tenants', async () => {
      const tenant1Graph = new ContactGraph('tenant_1', 'company1.com');
      const tenant2Graph = new ContactGraph('tenant_2', 'company2.com');

      const email1 = {
        from: { address: 'alice@company1.com', displayName: 'Alice' },
        to: [{ address: 'bob@company1.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-tenant-001',
      };

      const email2 = {
        from: { address: 'charlie@company2.com', displayName: 'Charlie' },
        to: [{ address: 'dave@company2.com', displayName: 'Dave' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-tenant-002',
      };

      await tenant1Graph.processEmail(email1);
      await tenant2Graph.processEmail(email2);

      // Tenant 1 should only see their contacts
      expect(tenant1Graph.hasContact('alice@company1.com')).toBe(true);
      expect(tenant1Graph.hasContact('charlie@company2.com')).toBe(false);

      // Tenant 2 should only see their contacts
      expect(tenant2Graph.hasContact('charlie@company2.com')).toBe(true);
      expect(tenant2Graph.hasContact('alice@company1.com')).toBe(false);
    });

    it('should not share relationship data between tenants', async () => {
      const tenant1Graph = new ContactGraph('tenant_1', 'company1.com');
      const tenant2Graph = new ContactGraph('tenant_2', 'company2.com');

      const email = {
        from: { address: 'shared@external.com', displayName: 'Shared' },
        to: [{ address: 'bob@company1.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-tenant-003',
      };

      await tenant1Graph.processEmail(email);

      // Tenant 2 should not see tenant 1's relationship
      const relationship = await tenant2Graph.getRelationship('shared@external.com', 'bob@company1.com');
      expect(relationship).toBeNull();
    });
  });

  describe('Merge duplicate contacts', () => {
    it('should merge contacts with same email address', async () => {
      const email1 = {
        from: { address: 'alice@company.com', displayName: 'Alice Smith' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-merge-001',
      };

      const email2 = {
        from: { address: 'alice@company.com', displayName: 'Alice Johnson' },
        to: [{ address: 'charlie@company.com', displayName: 'Charlie' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-16T10:00:00Z'),
        messageId: 'msg-merge-002',
      };

      await contactGraph.processEmail(email1);
      await contactGraph.processEmail(email2);

      // Should have only one contact for alice
      const allContacts = contactGraph.getAllContacts();
      const aliceContacts = allContacts.filter(c => c.email === 'alice@company.com');
      expect(aliceContacts.length).toBe(1);
    });

    it('should update display name on merge if newer email has it', async () => {
      const email1 = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-merge-003',
      };

      const email2 = {
        from: { address: 'alice@company.com', displayName: 'Alice Smith' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-16T10:00:00Z'),
        messageId: 'msg-merge-004',
      };

      await contactGraph.processEmail(email1);
      await contactGraph.processEmail(email2);

      const allContacts = contactGraph.getAllContacts();
      const alice = allContacts.find(c => c.email === 'alice@company.com');
      expect(alice?.displayName).toBe('Alice Smith');
    });

    it('should accumulate total emails count on merge', async () => {
      const email1 = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'bob@company.com', displayName: 'Bob' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-merge-005',
      };

      await contactGraph.processEmail(email1);
      await contactGraph.processEmail({ ...email1, messageId: 'msg-merge-006' });
      await contactGraph.processEmail({ ...email1, messageId: 'msg-merge-007' });

      const allContacts = contactGraph.getAllContacts();
      const alice = allContacts.find(c => c.email === 'alice@company.com');
      expect(alice?.totalEmails).toBe(3);
    });

    it('should merge duplicate contacts from different email fields', async () => {
      const email = {
        from: { address: 'sender@company.com', displayName: 'Sender' },
        to: [
          { address: 'recipient@company.com', displayName: 'Recipient' },
        ],
        cc: [
          { address: 'recipient@company.com', displayName: 'Recipient CC' }, // Duplicate
        ],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-merge-008',
      };

      await contactGraph.processEmail(email);

      const allContacts = contactGraph.getAllContacts();
      const recipients = allContacts.filter(c => c.email === 'recipient@company.com');
      expect(recipients.length).toBe(1);
    });
  });

  describe('Query contacts by domain', () => {
    it('should filter contacts by domain', async () => {
      const email1 = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'bob@external.com', displayName: 'Bob External' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-15T10:00:00Z'),
        messageId: 'msg-domain-001',
      };

      const email2 = {
        from: { address: 'alice@company.com', displayName: 'Alice' },
        to: [{ address: 'charlie@another.com', displayName: 'Charlie' }],
        cc: [],
        bcc: [],
        date: new Date('2024-01-16T10:00:00Z'),
        messageId: 'msg-domain-002',
      };

      await contactGraph.processEmail(email1);
      await contactGraph.processEmail(email2);

      const externalContacts = contactGraph.getContactsByDomain('external.com');
      expect(externalContacts.length).toBe(1);
      expect(externalContacts[0].email).toBe('bob@external.com');
    });

    it('should return empty array for non-existent domain', () => {
      const contacts = contactGraph.getContactsByDomain('nonexistent.com');
      expect(contacts).toEqual([]);
    });
  });
});

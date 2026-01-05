/**
 * Email Processing Pipeline Tests
 *
 * TDD tests for the email processing queue and pipeline
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock external dependencies
vi.mock('@/lib/db', () => ({
  sql: vi.fn().mockImplementation((strings: TemplateStringsArray, ...values: unknown[]) => {
    return Promise.resolve([]);
  }),
}));

vi.mock('@/lib/detection/pipeline', () => ({
  analyzeEmail: vi.fn().mockResolvedValue({
    verdict: 'pass',
    overallScore: 0,
    signals: [],
    categories: { phishing: 0, malware: 0, spam: 0, bec: 0 },
    actions: ['allow'],
  }),
}));

vi.mock('@/lib/detection/storage', () => ({
  storeVerdict: vi.fn().mockResolvedValue({ id: 'verdict-1' }),
}));

vi.mock('@/lib/db/audit', () => ({
  logAuditEvent: vi.fn().mockResolvedValue(undefined),
}));

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

import {
  EmailProcessingQueue,
  ProcessingJob,
  JobResult,
  QueueConfig,
} from '@/lib/workers/processing-queue';
import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';

describe('Email Processing Queue', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Queue Management', () => {
    it('should add jobs to the queue', async () => {
      const queue = new EmailProcessingQueue({
        maxConcurrent: 5,
        maxRetries: 3,
      });

      const job: ProcessingJob = {
        id: 'job-1',
        tenantId: 'tenant-1',
        email: {
          messageId: 'msg-1',
          from: { address: 'sender@example.com' },
          to: [{ address: 'recipient@example.com' }],
          subject: 'Test Email',
          body: { html: '<p>Test</p>', text: 'Test' },
          receivedAt: new Date(),
          headers: [],
          attachments: [],
        },
        priority: 'normal',
        createdAt: new Date(),
      };

      await queue.enqueue(job);

      expect(queue.getQueueSize()).toBe(1);
    });

    it('should process high priority jobs first', async () => {
      const queue = new EmailProcessingQueue({
        maxConcurrent: 1,
        maxRetries: 3,
      });

      const processedOrder: string[] = [];

      // Override processor to track order
      queue.setProcessor(async (job) => {
        processedOrder.push(job.id);
        return { success: true, verdictId: 'v-1' };
      });

      // Add normal priority first
      await queue.enqueue(createJob('job-1', 'normal'));
      await queue.enqueue(createJob('job-2', 'high'));
      await queue.enqueue(createJob('job-3', 'critical'));
      await queue.enqueue(createJob('job-4', 'low'));

      // Process all jobs
      await queue.processAll();

      // Critical > High > Normal > Low
      expect(processedOrder).toEqual(['job-3', 'job-2', 'job-1', 'job-4']);
    });

    it('should respect max concurrent limit', async () => {
      const queue = new EmailProcessingQueue({
        maxConcurrent: 2,
        maxRetries: 3,
      });

      let activeJobs = 0;
      let maxActiveJobs = 0;

      queue.setProcessor(async (job) => {
        activeJobs++;
        maxActiveJobs = Math.max(maxActiveJobs, activeJobs);
        await new Promise(resolve => setTimeout(resolve, 10));
        activeJobs--;
        return { success: true, verdictId: 'v-1' };
      });

      // Add 5 jobs
      for (let i = 0; i < 5; i++) {
        await queue.enqueue(createJob(`job-${i}`, 'normal'));
      }

      await queue.processAll();

      expect(maxActiveJobs).toBeLessThanOrEqual(2);
    });

    it('should retry failed jobs', async () => {
      const queue = new EmailProcessingQueue({
        maxConcurrent: 1,
        maxRetries: 3,
        retryDelayMs: 10,
      });

      let attempts = 0;

      queue.setProcessor(async () => {
        attempts++;
        if (attempts < 3) {
          throw new Error('Processing failed');
        }
        return { success: true, verdictId: 'v-1' };
      });

      await queue.enqueue(createJob('job-1', 'normal'));
      await queue.processAll();

      expect(attempts).toBe(3);
    });

    it('should move to dead letter queue after max retries', async () => {
      const queue = new EmailProcessingQueue({
        maxConcurrent: 1,
        maxRetries: 2,
        retryDelayMs: 10,
      });

      queue.setProcessor(async () => {
        throw new Error('Always fails');
      });

      await queue.enqueue(createJob('job-1', 'normal'));
      await queue.processAll();

      expect(queue.getDeadLetterQueueSize()).toBe(1);
    });
  });

  describe('Email Processing', () => {
    it('should analyze email and store verdict', async () => {
      const queue = new EmailProcessingQueue({
        maxConcurrent: 5,
        maxRetries: 3,
      });

      const job = createJob('job-1', 'normal');
      await queue.enqueue(job);
      await queue.processAll();

      expect(analyzeEmail).toHaveBeenCalled();
      expect(storeVerdict).toHaveBeenCalled();
    });

    it('should handle malicious emails differently', async () => {
      (analyzeEmail as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        verdict: 'block',
        overallScore: 85,
        signals: [{ type: 'phishing_url', severity: 'critical' }],
        categories: { phishing: 85, malware: 0, spam: 10, bec: 0 },
        actions: ['block', 'quarantine'],
      });

      const onThreatDetected = vi.fn();
      const queue = new EmailProcessingQueue({
        maxConcurrent: 5,
        maxRetries: 3,
        onThreatDetected,
      });

      await queue.enqueue(createJob('job-1', 'normal'));
      await queue.processAll();

      expect(onThreatDetected).toHaveBeenCalledWith(
        expect.objectContaining({
          verdict: 'block',
          overallScore: 85,
        })
      );
    });

    it('should emit progress events', async () => {
      const queue = new EmailProcessingQueue({
        maxConcurrent: 5,
        maxRetries: 3,
      });

      const progressEvents: Array<{ processed: number; total: number }> = [];
      queue.on('progress', (data) => progressEvents.push(data));

      for (let i = 0; i < 3; i++) {
        await queue.enqueue(createJob(`job-${i}`, 'normal'));
      }

      await queue.processAll();

      expect(progressEvents.length).toBe(3);
      expect(progressEvents[2]).toEqual({ processed: 3, total: 3 });
    });
  });

  describe('Batch Operations', () => {
    it('should batch enqueue multiple jobs', async () => {
      const queue = new EmailProcessingQueue({
        maxConcurrent: 5,
        maxRetries: 3,
      });

      const jobs = [
        createJob('job-1', 'normal'),
        createJob('job-2', 'normal'),
        createJob('job-3', 'high'),
      ];

      await queue.enqueueBatch(jobs);

      expect(queue.getQueueSize()).toBe(3);
    });

    it('should process batch with progress tracking', async () => {
      const queue = new EmailProcessingQueue({
        maxConcurrent: 3,
        maxRetries: 3,
      });

      const jobs = [];
      for (let i = 0; i < 10; i++) {
        jobs.push(createJob(`job-${i}`, 'normal'));
      }

      const result = await queue.processBatch(jobs);

      expect(result.processed).toBe(10);
      expect(result.failed).toBe(0);
      expect(result.duration).toBeGreaterThan(0);
    });
  });

  describe('Queue Persistence', () => {
    it('should serialize queue state', async () => {
      const queue = new EmailProcessingQueue({
        maxConcurrent: 5,
        maxRetries: 3,
      });

      await queue.enqueue(createJob('job-1', 'normal'));
      await queue.enqueue(createJob('job-2', 'high'));

      const state = queue.serialize();

      expect(state.pending).toHaveLength(2);
      expect(state.processing).toHaveLength(0);
    });

    it('should restore queue from serialized state', async () => {
      const state = {
        pending: [
          createJob('job-1', 'normal'),
          createJob('job-2', 'high'),
        ],
        processing: [],
        deadLetter: [],
      };

      const queue = EmailProcessingQueue.deserialize(state, {
        maxConcurrent: 5,
        maxRetries: 3,
      });

      expect(queue.getQueueSize()).toBe(2);
    });
  });

  describe('Stats and Metrics', () => {
    it('should track processing metrics', async () => {
      const queue = new EmailProcessingQueue({
        maxConcurrent: 5,
        maxRetries: 3,
      });

      for (let i = 0; i < 5; i++) {
        await queue.enqueue(createJob(`job-${i}`, 'normal'));
      }

      await queue.processAll();

      const stats = queue.getStats();

      expect(stats.processed).toBe(5);
      expect(stats.failed).toBe(0);
      expect(stats.avgProcessingTime).toBeGreaterThanOrEqual(0);
    });

    it('should track threat detection rate', async () => {
      // Mock alternating verdicts
      (analyzeEmail as ReturnType<typeof vi.fn>)
        .mockResolvedValueOnce({ verdict: 'pass', overallScore: 0, signals: [], categories: {}, actions: [] })
        .mockResolvedValueOnce({ verdict: 'block', overallScore: 80, signals: [], categories: {}, actions: [] })
        .mockResolvedValueOnce({ verdict: 'pass', overallScore: 10, signals: [], categories: {}, actions: [] })
        .mockResolvedValueOnce({ verdict: 'quarantine', overallScore: 60, signals: [], categories: {}, actions: [] });

      const queue = new EmailProcessingQueue({
        maxConcurrent: 5,
        maxRetries: 3,
      });

      for (let i = 0; i < 4; i++) {
        await queue.enqueue(createJob(`job-${i}`, 'normal'));
      }

      await queue.processAll();

      const stats = queue.getStats();

      expect(stats.threatRate).toBe(0.5); // 2 out of 4 were threats
    });
  });
});

describe('Integration with Sync Workers', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
  });

  it('should process emails from O365 sync worker', async () => {
    // This test would verify the integration between O365SyncWorker and ProcessingQueue
    // The actual implementation would connect the sync worker output to the queue input

    const queue = new EmailProcessingQueue({
      maxConcurrent: 5,
      maxRetries: 3,
    });

    // Simulate emails coming from sync worker
    const syncedEmails = [
      {
        messageId: 'msg-1',
        from: { address: 'sender@example.com' },
        to: [{ address: 'recipient@example.com' }],
        subject: 'Synced Email 1',
        body: { html: '', text: '' },
        receivedAt: new Date(),
        headers: [],
        attachments: [],
      },
      {
        messageId: 'msg-2',
        from: { address: 'attacker@evil.com' },
        to: [{ address: 'victim@example.com' }],
        subject: 'Urgent: Wire Transfer Needed',
        body: { html: '', text: '' },
        receivedAt: new Date(),
        headers: [],
        attachments: [],
      },
    ];

    const jobs = syncedEmails.map((email, i) => ({
      id: `job-${i}`,
      tenantId: 'tenant-1',
      email,
      priority: 'normal' as const,
      createdAt: new Date(),
    }));

    const result = await queue.processBatch(jobs);

    expect(result.processed).toBe(2);
  });

  it('should handle real-time webhook emails with high priority', async () => {
    const queue = new EmailProcessingQueue({
      maxConcurrent: 5,
      maxRetries: 3,
    });

    const processedOrder: string[] = [];
    queue.setProcessor(async (job) => {
      processedOrder.push(job.id);
      return { success: true, verdictId: 'v-1' };
    });

    // Add background sync jobs (normal priority)
    for (let i = 0; i < 3; i++) {
      await queue.enqueue(createJob(`sync-${i}`, 'normal'));
    }

    // Add real-time webhook job (high priority)
    await queue.enqueue(createJob('webhook-1', 'high'));

    await queue.processAll();

    // Webhook should be processed first
    expect(processedOrder[0]).toBe('webhook-1');
  });
});

// Helper function to create test jobs
function createJob(id: string, priority: 'critical' | 'high' | 'normal' | 'low'): ProcessingJob {
  return {
    id,
    tenantId: 'tenant-1',
    email: {
      messageId: `msg-${id}`,
      from: { address: 'sender@example.com' },
      to: [{ address: 'recipient@example.com' }],
      subject: `Test Email ${id}`,
      body: { html: '<p>Test</p>', text: 'Test' },
      receivedAt: new Date(),
      headers: [],
      attachments: [],
    },
    priority,
    createdAt: new Date(),
  };
}

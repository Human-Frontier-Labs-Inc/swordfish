/**
 * Email Processing Queue
 *
 * Priority-based queue for processing emails through the detection pipeline
 */

import { analyzeEmail } from '@/lib/detection/pipeline';
import { storeVerdict } from '@/lib/detection/storage';
import type { ParsedEmail, EmailVerdict } from '@/lib/detection/types';
import { EventEmitter } from 'events';

export interface EmailData {
  messageId: string;
  from: { address: string; name?: string };
  to: Array<{ address: string; name?: string }>;
  cc?: Array<{ address: string; name?: string }>;
  subject: string;
  body: { html: string; text: string };
  receivedAt: Date;
  headers: Array<{ name: string; value: string }>;
  attachments: Array<{
    id: string;
    name: string;
    contentType: string;
    size: number;
    content?: string;
  }>;
}

export interface ProcessingJob {
  id: string;
  tenantId: string;
  email: EmailData;
  priority: 'critical' | 'high' | 'normal' | 'low';
  createdAt: Date;
  retryCount?: number;
  lastError?: string;
}

export interface JobResult {
  success: boolean;
  verdictId?: string;
  verdict?: EmailVerdict;
  error?: string;
  processingTime?: number;
}

export interface QueueConfig {
  maxConcurrent: number;
  maxRetries: number;
  retryDelayMs?: number;
  onThreatDetected?: (verdict: EmailVerdict) => void | Promise<void>;
}

export interface QueueStats {
  processed: number;
  failed: number;
  avgProcessingTime: number;
  threatRate: number;
  queueSize: number;
}

export interface QueueState {
  pending: ProcessingJob[];
  processing: ProcessingJob[];
  deadLetter: ProcessingJob[];
}

type ProcessorFn = (job: ProcessingJob) => Promise<JobResult>;

const PRIORITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  normal: 2,
  low: 3,
};

export class EmailProcessingQueue extends EventEmitter {
  private pending: ProcessingJob[] = [];
  private processing: Map<string, ProcessingJob> = new Map();
  private deadLetter: ProcessingJob[] = [];
  private config: QueueConfig;
  private customProcessor?: ProcessorFn;

  // Stats
  private processedCount = 0;
  private failedCount = 0;
  private threatCount = 0;
  private totalProcessingTime = 0;

  constructor(config: QueueConfig) {
    super();
    this.config = {
      ...config,
      retryDelayMs: config.retryDelayMs || 1000,
    };
  }

  /**
   * Set custom processor for testing
   */
  setProcessor(processor: ProcessorFn): void {
    this.customProcessor = processor;
  }

  /**
   * Add a job to the queue
   */
  async enqueue(job: ProcessingJob): Promise<void> {
    this.pending.push(job);
    this.sortQueue();
    this.emit('enqueue', job);
  }

  /**
   * Add multiple jobs to the queue
   */
  async enqueueBatch(jobs: ProcessingJob[]): Promise<void> {
    this.pending.push(...jobs);
    this.sortQueue();
    this.emit('enqueueBatch', jobs);
  }

  /**
   * Process a batch of jobs and return results
   */
  async processBatch(jobs: ProcessingJob[]): Promise<{
    processed: number;
    failed: number;
    duration: number;
    results: JobResult[];
  }> {
    const startTime = Date.now();
    await this.enqueueBatch(jobs);
    await this.processAll();

    return {
      processed: this.processedCount,
      failed: this.failedCount,
      duration: Date.now() - startTime,
      results: [],
    };
  }

  /**
   * Process all jobs in the queue
   */
  async processAll(): Promise<void> {
    const total = this.pending.length;
    let processed = 0;

    while (this.pending.length > 0 || this.processing.size > 0) {
      // Start processing up to maxConcurrent jobs
      while (this.pending.length > 0 && this.processing.size < this.config.maxConcurrent) {
        const job = this.pending.shift()!;
        this.processing.set(job.id, job);
        this.processJob(job).then(() => {
          this.processing.delete(job.id);
          processed++;
          this.emit('progress', { processed, total });
        });
      }

      // Wait for at least one job to complete
      if (this.processing.size > 0) {
        await new Promise(resolve => setTimeout(resolve, 1));
      }
    }
  }

  /**
   * Process a single job
   */
  private async processJob(job: ProcessingJob): Promise<JobResult> {
    const startTime = Date.now();

    try {
      let result: JobResult;

      if (this.customProcessor) {
        result = await this.customProcessor(job);
      } else {
        result = await this.defaultProcessor(job);
      }

      const processingTime = Date.now() - startTime;
      result.processingTime = processingTime;

      this.processedCount++;
      this.totalProcessingTime += processingTime;

      // Check if threat detected
      if (result.verdict && result.verdict.verdict !== 'pass' && result.verdict.overallScore >= 50) {
        this.threatCount++;
        if (this.config.onThreatDetected) {
          await this.config.onThreatDetected(result.verdict);
        }
      }

      this.emit('processed', { job, result });
      return result;
    } catch (error) {
      const retryCount = (job.retryCount || 0) + 1;

      if (retryCount < this.config.maxRetries) {
        // Retry
        job.retryCount = retryCount;
        job.lastError = error instanceof Error ? error.message : 'Unknown error';

        await new Promise(resolve => setTimeout(resolve, this.config.retryDelayMs));
        return this.processJob(job);
      } else {
        // Move to dead letter queue
        this.deadLetter.push(job);
        this.failedCount++;

        this.emit('failed', { job, error });
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        };
      }
    }
  }

  /**
   * Default email processor
   */
  private async defaultProcessor(job: ProcessingJob): Promise<JobResult> {
    // Convert EmailData to ParsedEmail
    const parsedEmail: ParsedEmail = {
      messageId: job.email.messageId,
      from: {
        email: job.email.from.address,
        name: job.email.from.name,
        domain: job.email.from.address.split('@')[1] || '',
      },
      to: job.email.to.map(t => ({
        email: t.address,
        name: t.name,
      })),
      subject: job.email.subject,
      body: {
        text: job.email.body.text,
        html: job.email.body.html,
      },
      headers: job.email.headers.reduce((acc, h) => ({ ...acc, [h.name]: h.value }), {} as Record<string, string>),
      receivedAt: job.email.receivedAt,
      attachments: job.email.attachments.map(a => ({
        filename: a.name,
        contentType: a.contentType,
        size: a.size,
        content: a.content,
      })),
    };

    // Analyze email
    const verdict = await analyzeEmail(parsedEmail, job.tenantId, {
      skipLLM: true, // Skip LLM for queue processing to maintain throughput
    });

    // Store verdict
    const stored = await storeVerdict(job.tenantId, job.email.messageId, verdict);

    return {
      success: true,
      verdictId: stored?.id,
      verdict,
    };
  }

  /**
   * Sort queue by priority
   */
  private sortQueue(): void {
    this.pending.sort((a, b) => {
      const priorityDiff = PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority];
      if (priorityDiff !== 0) return priorityDiff;
      return a.createdAt.getTime() - b.createdAt.getTime();
    });
  }

  /**
   * Get current queue size
   */
  getQueueSize(): number {
    return this.pending.length;
  }

  /**
   * Get dead letter queue size
   */
  getDeadLetterQueueSize(): number {
    return this.deadLetter.length;
  }

  /**
   * Get queue statistics
   */
  getStats(): QueueStats {
    const totalProcessed = this.processedCount + this.failedCount;
    return {
      processed: this.processedCount,
      failed: this.failedCount,
      avgProcessingTime: totalProcessed > 0 ? this.totalProcessingTime / totalProcessed : 0,
      threatRate: this.processedCount > 0 ? this.threatCount / this.processedCount : 0,
      queueSize: this.pending.length,
    };
  }

  /**
   * Serialize queue state for persistence
   */
  serialize(): QueueState {
    return {
      pending: [...this.pending],
      processing: Array.from(this.processing.values()),
      deadLetter: [...this.deadLetter],
    };
  }

  /**
   * Deserialize queue from state
   */
  static deserialize(state: QueueState, config: QueueConfig): EmailProcessingQueue {
    const queue = new EmailProcessingQueue(config);
    queue.pending = [...state.pending, ...state.processing]; // Re-queue processing jobs
    queue.deadLetter = [...state.deadLetter];
    queue.sortQueue();
    return queue;
  }
}

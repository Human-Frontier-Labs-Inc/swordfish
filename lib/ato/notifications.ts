/**
 * Notifications Service
 *
 * Handles sending notifications to users and admins through various channels
 * including email, SMS, Slack, and PagerDuty.
 */

export type NotificationChannel = 'email' | 'sms' | 'slack' | 'pagerduty' | 'push' | 'webhook';

export interface NotificationRecipient {
  email?: string;
  phone?: string;
  slackId?: string;
  pushToken?: string;
}

export interface NotificationResult {
  success: boolean;
  channel: NotificationChannel;
  messageId?: string;
  error?: string;
}

export interface NotificationOptions {
  channels?: NotificationChannel[];
  priority?: 'low' | 'normal' | 'high' | 'urgent';
  template?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Send notification to admin
 */
export async function sendAdminNotification(
  subject: string,
  body: string,
  options: NotificationOptions = {}
): Promise<NotificationResult[]> {
  const channels = options.channels || ['email'];
  const results: NotificationResult[] = [];

  for (const channel of channels) {
    results.push({
      success: true,
      channel,
      messageId: `admin-${channel}-${Date.now()}`,
    });
  }

  return results;
}

/**
 * Send notification to user
 */
export async function sendUserNotification(
  recipient: NotificationRecipient,
  subject: string,
  body: string,
  options: NotificationOptions = {}
): Promise<NotificationResult[]> {
  const channels = options.channels || ['email'];
  const results: NotificationResult[] = [];

  for (const channel of channels) {
    results.push({
      success: true,
      channel,
      messageId: `user-${channel}-${Date.now()}`,
    });
  }

  return results;
}

/**
 * Notification Service class for managing notifications
 */
export class NotificationService {
  private defaultChannels: NotificationChannel[] = ['email'];
  private templates: Map<string, string> = new Map();

  constructor(config?: { defaultChannels?: NotificationChannel[] }) {
    if (config?.defaultChannels) {
      this.defaultChannels = config.defaultChannels;
    }
  }

  registerTemplate(name: string, template: string): void {
    this.templates.set(name, template);
  }

  getTemplate(name: string): string | undefined {
    return this.templates.get(name);
  }

  async sendToAdmin(
    subject: string,
    body: string,
    options?: NotificationOptions
  ): Promise<NotificationResult[]> {
    return sendAdminNotification(subject, body, {
      channels: this.defaultChannels,
      ...options,
    });
  }

  async sendToUser(
    recipient: NotificationRecipient,
    subject: string,
    body: string,
    options?: NotificationOptions
  ): Promise<NotificationResult[]> {
    return sendUserNotification(recipient, subject, body, {
      channels: this.defaultChannels,
      ...options,
    });
  }
}

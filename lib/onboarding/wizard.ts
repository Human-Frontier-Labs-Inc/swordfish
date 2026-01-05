/**
 * Onboarding Wizard
 *
 * User onboarding flow and setup wizard implementation
 */

export interface OnboardingStep {
  id: string;
  title: string;
  description: string;
  order: number;
  optional: boolean;
  icon?: string;
}

export interface OnboardingState {
  tenantId: string;
  currentStep: number;
  completedSteps: string[];
  skippedSteps: string[];
  stepData: Record<string, Record<string, unknown>>;
  steps: OnboardingStep[];
  startedAt: Date;
  completedAt?: Date;
}

export interface StepValidation {
  valid: boolean;
  errors: string[];
}

export interface ChecklistItem {
  id: string;
  title: string;
  completed: boolean;
  optional: boolean;
}

type EventType = 'stepCompleted' | 'stepChanged' | 'wizardCompleted';
type EventHandler = (data: Record<string, unknown>) => void;

const DEFAULT_STEPS: OnboardingStep[] = [
  {
    id: 'welcome',
    title: 'Welcome',
    description: 'Welcome to Swordfish email security',
    order: 1,
    optional: false,
  },
  {
    id: 'organization',
    title: 'Organization Setup',
    description: 'Configure your organization details',
    order: 2,
    optional: false,
  },
  {
    id: 'email-integration',
    title: 'Email Integration',
    description: 'Connect your email provider',
    order: 3,
    optional: false,
  },
  {
    id: 'security-settings',
    title: 'Security Settings',
    description: 'Configure threat detection settings',
    order: 4,
    optional: false,
  },
  {
    id: 'invite-users',
    title: 'Invite Team Members',
    description: 'Add users to your organization',
    order: 5,
    optional: true,
  },
  {
    id: 'complete',
    title: 'Setup Complete',
    description: 'Review and finish setup',
    order: 6,
    optional: false,
  },
];

const VALID_THREAT_LEVELS = ['low', 'medium', 'high', 'critical'];

export class OnboardingWizard {
  private state: OnboardingState;
  private eventListeners: Map<EventType, Set<EventHandler>> = new Map();

  constructor(tenantId: string, steps: OnboardingStep[] = DEFAULT_STEPS) {
    this.state = {
      tenantId,
      currentStep: 0,
      completedSteps: [],
      skippedSteps: [],
      stepData: {},
      steps: [...steps],
      startedAt: new Date(),
    };
  }

  getState(): OnboardingState {
    return { ...this.state };
  }

  getSteps(): OnboardingStep[] {
    return [...this.state.steps];
  }

  getProgress(): number {
    const totalRequired = this.state.steps.filter(s => !s.optional).length;
    const completedRequired = this.state.completedSteps.filter(id => {
      const step = this.state.steps.find(s => s.id === id);
      return step && !step.optional;
    }).length;

    return Math.round((completedRequired / totalRequired) * 100);
  }

  nextStep(): void {
    if (this.state.currentStep < this.state.steps.length - 1) {
      const previousStep = this.state.currentStep;
      this.state.currentStep++;
      this.emit('stepChanged', {
        previousStep,
        currentStep: this.state.currentStep,
        tenantId: this.state.tenantId,
      });
    }
  }

  previousStep(): void {
    if (this.state.currentStep > 0) {
      const previousStep = this.state.currentStep;
      this.state.currentStep--;
      this.emit('stepChanged', {
        previousStep,
        currentStep: this.state.currentStep,
        tenantId: this.state.tenantId,
      });
    }
  }

  goToStep(stepIndex: number): void {
    if (stepIndex >= 0 && stepIndex < this.state.steps.length) {
      const previousStep = this.state.currentStep;
      this.state.currentStep = stepIndex;
      this.emit('stepChanged', {
        previousStep,
        currentStep: this.state.currentStep,
        tenantId: this.state.tenantId,
      });
    }
  }

  completeStep(stepId: string): void {
    if (!this.state.completedSteps.includes(stepId)) {
      this.state.completedSteps.push(stepId);
      this.emit('stepCompleted', {
        stepId,
        tenantId: this.state.tenantId,
      });

      // Check if wizard is complete
      if (this.isComplete()) {
        this.state.completedAt = new Date();
        this.emit('wizardCompleted', {
          tenantId: this.state.tenantId,
          completedAt: this.state.completedAt,
        });
      }
    }
  }

  isStepCompleted(stepId: string): boolean {
    return this.state.completedSteps.includes(stepId);
  }

  isComplete(): boolean {
    const requiredSteps = this.state.steps.filter(s => !s.optional);
    return requiredSteps.every(step => this.state.completedSteps.includes(step.id));
  }

  setStepData(stepId: string, data: Record<string, unknown>): void {
    this.state.stepData[stepId] = {
      ...this.state.stepData[stepId],
      ...data,
    };
  }

  getStepData(stepId: string): Record<string, unknown> {
    return { ...this.state.stepData[stepId] } || {};
  }

  getAllData(): Record<string, Record<string, unknown>> {
    return { ...this.state.stepData };
  }

  validateStep(stepId: string, data: Record<string, unknown>): StepValidation {
    const errors: string[] = [];

    switch (stepId) {
      case 'welcome':
        // Welcome step has no required data
        break;

      case 'organization':
        if (!data.name) {
          errors.push('Organization name is required');
        }
        break;

      case 'email-integration':
        if (!data.provider || !data.connected) {
          errors.push('At least one email integration is required');
        }
        break;

      case 'security-settings':
        if (data.threatLevel && !VALID_THREAT_LEVELS.includes(data.threatLevel as string)) {
          errors.push('Invalid threat sensitivity level');
        }
        break;

      case 'invite-users':
        // Optional step, no required validation
        break;

      case 'complete':
        // Final step, no validation needed
        break;
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  skipStep(stepId: string): boolean {
    const step = this.state.steps.find(s => s.id === stepId);
    if (!step || !step.optional) {
      return false;
    }

    if (!this.state.skippedSteps.includes(stepId)) {
      this.state.skippedSteps.push(stepId);
    }
    return true;
  }

  exportState(): string {
    return JSON.stringify({
      tenantId: this.state.tenantId,
      currentStep: this.state.currentStep,
      completedSteps: this.state.completedSteps,
      skippedSteps: this.state.skippedSteps,
      stepData: this.state.stepData,
    });
  }

  importState(jsonState: string): void {
    try {
      const parsed = JSON.parse(jsonState);
      this.state.currentStep = parsed.currentStep ?? 0;
      this.state.completedSteps = parsed.completedSteps ?? [];
      this.state.skippedSteps = parsed.skippedSteps ?? [];
      this.state.stepData = parsed.stepData ?? {};
    } catch {
      // Invalid JSON, keep current state
    }
  }

  getChecklist(): ChecklistItem[] {
    return this.state.steps.map(step => ({
      id: step.id,
      title: step.title,
      completed: this.state.completedSteps.includes(step.id),
      optional: step.optional,
    }));
  }

  on(event: EventType, handler: EventHandler): void {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, new Set());
    }
    this.eventListeners.get(event)!.add(handler);
  }

  off(event: EventType, handler: EventHandler): void {
    this.eventListeners.get(event)?.delete(handler);
  }

  private emit(event: EventType, data: Record<string, unknown>): void {
    this.eventListeners.get(event)?.forEach(handler => handler(data));
  }
}

// Integration Guides

export interface IntegrationGuideStep {
  order: number;
  title: string;
  description: string;
  screenshot?: string;
  code?: string;
}

export interface IntegrationGuide {
  provider: string;
  displayName: string;
  steps: IntegrationGuideStep[];
  requiredPermissions: string[];
  estimatedTime: string;
  helpUrl: string;
}

const MICROSOFT_365_GUIDE: IntegrationGuide = {
  provider: 'microsoft365',
  displayName: 'Microsoft 365',
  steps: [
    {
      order: 1,
      title: 'Azure AD App Registration',
      description: 'Navigate to Azure Portal > Azure Active Directory > App registrations and click "New registration". Enter a name for your application (e.g., "Swordfish Email Security") and select the appropriate account type.',
    },
    {
      order: 2,
      title: 'Configure API Permissions',
      description: 'In your app registration, go to "API permissions" and add the following Microsoft Graph permissions: Mail.Read, Mail.ReadBasic, User.Read. Click "Grant admin consent" to approve the permissions.',
    },
    {
      order: 3,
      title: 'Create Client Secret',
      description: 'Go to "Certificates & secrets" and click "New client secret". Copy the secret value immediately as it will not be shown again. Store this securely.',
    },
    {
      order: 4,
      title: 'Configure Redirect URI',
      description: 'In "Authentication", add a redirect URI: https://app.swordfish.com/api/auth/callback/microsoft. Ensure "Access tokens" and "ID tokens" are checked.',
    },
    {
      order: 5,
      title: 'Enter Credentials in Swordfish',
      description: 'Copy your Application (client) ID, Directory (tenant) ID, and client secret into Swordfish. Click "Connect" to complete the integration.',
    },
  ],
  requiredPermissions: [
    'Mail.Read',
    'Mail.ReadBasic',
    'User.Read',
    'offline_access',
  ],
  estimatedTime: '10-15 minutes',
  helpUrl: 'https://docs.swordfish.com/integrations/microsoft365',
};

const GOOGLE_WORKSPACE_GUIDE: IntegrationGuide = {
  provider: 'google',
  displayName: 'Google Workspace',
  steps: [
    {
      order: 1,
      title: 'Google Cloud Console Setup',
      description: 'Go to console.cloud.google.com and create a new project or select an existing one. Enable the Gmail API from the API Library.',
    },
    {
      order: 2,
      title: 'Configure OAuth Consent Screen',
      description: 'Navigate to APIs & Services > OAuth consent screen. Select "Internal" for workspace users or "External" for testing. Fill in the required app information.',
    },
    {
      order: 3,
      title: 'Create OAuth Credentials',
      description: 'Go to APIs & Services > Credentials and click "Create Credentials" > "OAuth client ID". Select "Web application" and add the redirect URI.',
    },
    {
      order: 4,
      title: 'Add Required Scopes',
      description: 'In the OAuth consent screen, add the following scopes: gmail.readonly, gmail.metadata, userinfo.email, userinfo.profile.',
    },
    {
      order: 5,
      title: 'Connect to Swordfish',
      description: 'Copy your Client ID and Client Secret into Swordfish. Click "Authorize with Google" to complete the OAuth flow.',
    },
  ],
  requiredPermissions: [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.metadata',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
  ],
  estimatedTime: '10-15 minutes',
  helpUrl: 'https://docs.swordfish.com/integrations/google-workspace',
};

const INTEGRATION_GUIDES: Record<string, IntegrationGuide> = {
  microsoft365: MICROSOFT_365_GUIDE,
  google: GOOGLE_WORKSPACE_GUIDE,
};

export function getIntegrationGuide(provider: string): IntegrationGuide {
  const guide = INTEGRATION_GUIDES[provider];
  if (!guide) {
    throw new Error(`No integration guide found for provider: ${provider}`);
  }
  return guide;
}

/**
 * Onboarding Wizard Tests
 *
 * TDD tests for user onboarding flow and setup wizard
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

import {
  OnboardingWizard,
  OnboardingStep,
  OnboardingState,
  StepValidation,
  IntegrationGuide,
  getIntegrationGuide,
} from '@/lib/onboarding/wizard';

describe('Onboarding Wizard', () => {
  let wizard: OnboardingWizard;

  beforeEach(() => {
    wizard = new OnboardingWizard('tenant-1');
  });

  describe('Initialization', () => {
    it('should initialize with default steps', () => {
      const state = wizard.getState();

      expect(state.tenantId).toBe('tenant-1');
      expect(state.currentStep).toBe(0);
      expect(state.steps.length).toBeGreaterThan(0);
      expect(state.completedSteps).toEqual([]);
    });

    it('should have required onboarding steps', () => {
      const steps = wizard.getSteps();

      const stepIds = steps.map(s => s.id);
      expect(stepIds).toContain('welcome');
      expect(stepIds).toContain('organization');
      expect(stepIds).toContain('email-integration');
      expect(stepIds).toContain('security-settings');
      expect(stepIds).toContain('invite-users');
      expect(stepIds).toContain('complete');
    });

    it('should calculate progress percentage', () => {
      expect(wizard.getProgress()).toBe(0);

      wizard.completeStep('welcome');
      expect(wizard.getProgress()).toBeGreaterThan(0);
    });
  });

  describe('Step Navigation', () => {
    it('should advance to next step', () => {
      wizard.completeStep('welcome');
      wizard.nextStep();

      const state = wizard.getState();
      expect(state.currentStep).toBe(1);
    });

    it('should go back to previous step', () => {
      wizard.completeStep('welcome');
      wizard.nextStep();
      wizard.previousStep();

      const state = wizard.getState();
      expect(state.currentStep).toBe(0);
    });

    it('should not go back before first step', () => {
      wizard.previousStep();

      const state = wizard.getState();
      expect(state.currentStep).toBe(0);
    });

    it('should not advance beyond last step', () => {
      const steps = wizard.getSteps();

      // Complete and advance through all steps
      for (let i = 0; i < steps.length; i++) {
        wizard.completeStep(steps[i].id);
        wizard.nextStep();
      }

      const state = wizard.getState();
      expect(state.currentStep).toBe(steps.length - 1);
    });

    it('should jump to specific step', () => {
      wizard.completeStep('welcome');
      wizard.goToStep(2);

      const state = wizard.getState();
      expect(state.currentStep).toBe(2);
    });

    it('should not jump to invalid step', () => {
      wizard.goToStep(100);

      const state = wizard.getState();
      expect(state.currentStep).toBe(0);
    });
  });

  describe('Step Completion', () => {
    it('should mark step as completed', () => {
      wizard.completeStep('welcome');

      const state = wizard.getState();
      expect(state.completedSteps).toContain('welcome');
    });

    it('should not duplicate completed steps', () => {
      wizard.completeStep('welcome');
      wizard.completeStep('welcome');

      const state = wizard.getState();
      expect(state.completedSteps.filter(s => s === 'welcome').length).toBe(1);
    });

    it('should check if step is completed', () => {
      expect(wizard.isStepCompleted('welcome')).toBe(false);

      wizard.completeStep('welcome');
      expect(wizard.isStepCompleted('welcome')).toBe(true);
    });

    it('should check if all steps are completed', () => {
      expect(wizard.isComplete()).toBe(false);

      const steps = wizard.getSteps();
      steps.forEach(step => wizard.completeStep(step.id));

      expect(wizard.isComplete()).toBe(true);
    });
  });

  describe('Step Data', () => {
    it('should store step data', () => {
      wizard.setStepData('organization', {
        name: 'Acme Corp',
        domain: 'acme.com',
      });

      const data = wizard.getStepData('organization');
      expect(data.name).toBe('Acme Corp');
      expect(data.domain).toBe('acme.com');
    });

    it('should merge step data', () => {
      wizard.setStepData('organization', { name: 'Acme Corp' });
      wizard.setStepData('organization', { domain: 'acme.com' });

      const data = wizard.getStepData('organization');
      expect(data.name).toBe('Acme Corp');
      expect(data.domain).toBe('acme.com');
    });

    it('should get all collected data', () => {
      wizard.setStepData('organization', { name: 'Acme Corp' });
      wizard.setStepData('security-settings', { mfa: true });

      const allData = wizard.getAllData();
      expect(allData.organization.name).toBe('Acme Corp');
      expect(allData['security-settings'].mfa).toBe(true);
    });
  });

  describe('Step Validation', () => {
    it('should validate organization step', () => {
      const result = wizard.validateStep('organization', {});

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Organization name is required');
    });

    it('should pass validation with valid data', () => {
      const result = wizard.validateStep('organization', {
        name: 'Acme Corp',
        domain: 'acme.com',
      });

      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('should validate email integration step', () => {
      const result = wizard.validateStep('email-integration', {});

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('At least one email integration is required');
    });

    it('should pass email integration with valid provider', () => {
      const result = wizard.validateStep('email-integration', {
        provider: 'microsoft365',
        connected: true,
      });

      expect(result.valid).toBe(true);
    });

    it('should validate security settings step', () => {
      const result = wizard.validateStep('security-settings', {
        threatLevel: 'invalid',
      });

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid threat sensitivity level');
    });

    it('should pass security settings with valid config', () => {
      const result = wizard.validateStep('security-settings', {
        threatLevel: 'medium',
        quarantineEnabled: true,
      });

      expect(result.valid).toBe(true);
    });
  });

  describe('Skip Functionality', () => {
    it('should allow skipping optional steps', () => {
      const steps = wizard.getSteps();
      const optionalStep = steps.find(s => s.optional);

      if (optionalStep) {
        wizard.skipStep(optionalStep.id);
        const state = wizard.getState();
        expect(state.skippedSteps).toContain(optionalStep.id);
      }
    });

    it('should not allow skipping required steps', () => {
      const steps = wizard.getSteps();
      const requiredStep = steps.find(s => !s.optional);

      if (requiredStep) {
        const result = wizard.skipStep(requiredStep.id);
        expect(result).toBe(false);
      }
    });
  });

  describe('State Persistence', () => {
    it('should export state to JSON', () => {
      wizard.completeStep('welcome');
      wizard.setStepData('organization', { name: 'Test' });

      const exported = wizard.exportState();
      const parsed = JSON.parse(exported);

      expect(parsed.tenantId).toBe('tenant-1');
      expect(parsed.completedSteps).toContain('welcome');
    });

    it('should import state from JSON', () => {
      const state = {
        tenantId: 'tenant-1',
        currentStep: 2,
        completedSteps: ['welcome', 'organization'],
        skippedSteps: [],
        stepData: { organization: { name: 'Test' } },
      };

      wizard.importState(JSON.stringify(state));

      expect(wizard.getState().currentStep).toBe(2);
      expect(wizard.isStepCompleted('welcome')).toBe(true);
    });
  });
});

describe('Integration Guides', () => {
  describe('Microsoft 365 Guide', () => {
    it('should return Microsoft 365 setup guide', () => {
      const guide = getIntegrationGuide('microsoft365');

      expect(guide.provider).toBe('microsoft365');
      expect(guide.steps.length).toBeGreaterThan(0);
      expect(guide.estimatedTime).toBeDefined();
    });

    it('should include Azure AD app registration steps', () => {
      const guide = getIntegrationGuide('microsoft365');
      const stepTitles = guide.steps.map(s => s.title.toLowerCase());

      expect(stepTitles.some(t => t.includes('azure') || t.includes('app registration'))).toBe(true);
    });

    it('should include required permissions', () => {
      const guide = getIntegrationGuide('microsoft365');

      expect(guide.requiredPermissions).toBeDefined();
      expect(guide.requiredPermissions.length).toBeGreaterThan(0);
    });
  });

  describe('Google Workspace Guide', () => {
    it('should return Google Workspace setup guide', () => {
      const guide = getIntegrationGuide('google');

      expect(guide.provider).toBe('google');
      expect(guide.steps.length).toBeGreaterThan(0);
    });

    it('should include Google Cloud Console steps', () => {
      const guide = getIntegrationGuide('google');
      const stepTitles = guide.steps.map(s => s.title.toLowerCase());

      expect(stepTitles.some(t => t.includes('google') || t.includes('cloud console'))).toBe(true);
    });

    it('should include Gmail API scopes', () => {
      const guide = getIntegrationGuide('google');

      expect(guide.requiredPermissions).toBeDefined();
      expect(guide.requiredPermissions.some(p => p.includes('gmail'))).toBe(true);
    });
  });

  describe('Guide Steps', () => {
    it('should have numbered steps', () => {
      const guide = getIntegrationGuide('microsoft365');

      guide.steps.forEach((step, index) => {
        expect(step.order).toBe(index + 1);
      });
    });

    it('should include step instructions', () => {
      const guide = getIntegrationGuide('microsoft365');

      guide.steps.forEach(step => {
        expect(step.title).toBeDefined();
        expect(step.description).toBeDefined();
        expect(step.description.length).toBeGreaterThan(10);
      });
    });

    it('should include help links', () => {
      const guide = getIntegrationGuide('microsoft365');

      expect(guide.helpUrl).toBeDefined();
      expect(guide.helpUrl).toMatch(/^https?:\/\//);
    });
  });
});

describe('Onboarding Events', () => {
  let wizard: OnboardingWizard;
  let eventHandler: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    wizard = new OnboardingWizard('tenant-1');
    eventHandler = vi.fn();
  });

  it('should emit event on step completion', () => {
    wizard.on('stepCompleted', eventHandler);
    wizard.completeStep('welcome');

    expect(eventHandler).toHaveBeenCalledWith({
      stepId: 'welcome',
      tenantId: 'tenant-1',
    });
  });

  it('should emit event on step navigation', () => {
    wizard.on('stepChanged', eventHandler);
    wizard.nextStep();

    expect(eventHandler).toHaveBeenCalledWith({
      previousStep: 0,
      currentStep: 1,
      tenantId: 'tenant-1',
    });
  });

  it('should emit event on wizard completion', () => {
    wizard.on('wizardCompleted', eventHandler);

    const steps = wizard.getSteps();
    steps.forEach(step => wizard.completeStep(step.id));

    expect(eventHandler).toHaveBeenCalledWith({
      tenantId: 'tenant-1',
      completedAt: expect.any(Date),
    });
  });

  it('should remove event listener', () => {
    wizard.on('stepCompleted', eventHandler);
    wizard.off('stepCompleted', eventHandler);
    wizard.completeStep('welcome');

    expect(eventHandler).not.toHaveBeenCalled();
  });
});

describe('Onboarding Checklist', () => {
  let wizard: OnboardingWizard;

  beforeEach(() => {
    wizard = new OnboardingWizard('tenant-1');
  });

  it('should generate checklist items', () => {
    const checklist = wizard.getChecklist();

    expect(checklist.length).toBeGreaterThan(0);
    checklist.forEach(item => {
      expect(item.id).toBeDefined();
      expect(item.title).toBeDefined();
      expect(item.completed).toBeDefined();
    });
  });

  it('should mark checklist items as completed', () => {
    wizard.completeStep('welcome');
    const checklist = wizard.getChecklist();

    const welcomeItem = checklist.find(item => item.id === 'welcome');
    expect(welcomeItem?.completed).toBe(true);
  });

  it('should show checklist progress', () => {
    const initialChecklist = wizard.getChecklist();
    const initialCompleted = initialChecklist.filter(i => i.completed).length;

    wizard.completeStep('welcome');
    wizard.completeStep('organization');

    const updatedChecklist = wizard.getChecklist();
    const updatedCompleted = updatedChecklist.filter(i => i.completed).length;

    expect(updatedCompleted).toBe(initialCompleted + 2);
  });
});

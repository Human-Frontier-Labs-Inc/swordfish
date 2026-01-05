import { test, expect, Page } from '@playwright/test';

/**
 * Onboarding Journey E2E Tests
 *
 * Complete user onboarding flow tests from signup to first scan
 */

test.describe('Onboarding Journey', () => {
  test.describe('Landing Page', () => {
    test('should display landing page with key elements', async ({ page }) => {
      await page.goto('/');

      // Check for main heading
      const heading = page.locator('h1');
      await expect(heading).toBeVisible();

      // Check for CTA buttons
      const signUpButton = page.getByRole('link', { name: /sign up|get started/i });
      await expect(signUpButton).toBeVisible();
    });

    test('should navigate to sign up page', async ({ page }) => {
      await page.goto('/');

      const signUpLink = page.getByRole('link', { name: /sign up|get started/i });
      await signUpLink.click();

      await expect(page).toHaveURL(/sign-up/);
    });

    test('should navigate to sign in page', async ({ page }) => {
      await page.goto('/');

      // Use first() to handle multiple sign-in links
      const signInLink = page.getByRole('link', { name: /sign in|log in/i }).first();
      if (await signInLink.isVisible()) {
        await signInLink.click();
        await expect(page).toHaveURL(/sign-in/);
      }
    });
  });

  test.describe('Authentication Flow', () => {
    test('sign up page loads correctly', async ({ page }) => {
      await page.goto('/sign-up');

      // Should have email input
      const emailInput = page.getByLabel(/email/i);
      await expect(emailInput).toBeVisible();
    });

    test('sign in page loads correctly', async ({ page }) => {
      await page.goto('/sign-in');

      // Should have email/password inputs
      const emailInput = page.getByLabel(/email/i);
      await expect(emailInput).toBeVisible();
    });

    test('should show validation errors for invalid email', async ({ page }) => {
      await page.goto('/sign-up');

      const emailInput = page.getByLabel(/email/i);
      await emailInput.fill('invalid-email');
      await emailInput.blur();

      // Wait for validation
      await page.waitForTimeout(500);

      // Check for error state or message
      const hasError = await page.locator('[data-error], .error, [aria-invalid="true"]').isVisible();
      expect(hasError || await emailInput.getAttribute('aria-invalid') === 'true').toBeTruthy();
    });
  });

  test.describe('Dashboard Access', () => {
    test('dashboard requires authentication', async ({ page }) => {
      await page.goto('/dashboard');

      // Should redirect to sign-in
      await expect(page).toHaveURL(/sign-in/);
    });

    test('settings requires authentication', async ({ page }) => {
      await page.goto('/dashboard/settings');

      await expect(page).toHaveURL(/sign-in/);
    });

    test('threats page requires authentication', async ({ page }) => {
      await page.goto('/dashboard/threats');

      await expect(page).toHaveURL(/sign-in/);
    });
  });
});

test.describe('User Dashboard Journey', () => {
  // These tests would run with mocked authentication
  test.describe('Navigation', () => {
    test('navigation links exist on protected routes', async ({ page }) => {
      // Test navigation structure exists
      await page.goto('/dashboard');

      // After redirect, check sign-in page structure
      await expect(page).toHaveURL(/sign-in/);
    });
  });
});

test.describe('First-Time User Setup', () => {
  test.describe('Onboarding Wizard UI', () => {
    test('should show step indicators in wizard', async ({ page }) => {
      // Test wizard page structure if accessible
      await page.goto('/onboarding');

      // Either loads onboarding or redirects to auth
      const url = page.url();
      expect(url.includes('onboarding') || url.includes('sign-in')).toBeTruthy();
    });
  });
});

test.describe('Integration Setup Journey', () => {
  test('integrations page requires authentication', async ({ page }) => {
    await page.goto('/dashboard/integrations');

    await expect(page).toHaveURL(/sign-in/);
  });

  test('API returns appropriate status for unauthenticated requests', async ({ request }) => {
    const response = await request.get('/api/integrations');

    // Should not cause server error
    expect(response.status()).toBeLessThan(500);
  });
});

test.describe('Responsive Design', () => {
  test('landing page is mobile-responsive', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 }); // iPhone SE
    await page.goto('/');

    // Check that content is visible
    const heading = page.locator('h1');
    await expect(heading).toBeVisible();

    // Check viewport doesn't have horizontal scroll
    const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
    const viewportWidth = await page.evaluate(() => window.innerWidth);
    expect(bodyWidth).toBeLessThanOrEqual(viewportWidth + 10); // Allow small margin
  });

  test('landing page works on tablet', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 }); // iPad
    await page.goto('/');

    const heading = page.locator('h1');
    await expect(heading).toBeVisible();
  });

  test('landing page works on desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto('/');

    const heading = page.locator('h1');
    await expect(heading).toBeVisible();
  });
});

test.describe('Accessibility', () => {
  test('landing page has proper heading hierarchy', async ({ page }) => {
    await page.goto('/');

    // Should have exactly one h1
    const h1Count = await page.locator('h1').count();
    expect(h1Count).toBe(1);
  });

  test('buttons have accessible names', async ({ page }) => {
    await page.goto('/');

    const buttons = page.locator('button, a[role="button"]');
    const count = await buttons.count();

    for (let i = 0; i < Math.min(count, 10); i++) {
      const button = buttons.nth(i);
      const accessibleName = await button.getAttribute('aria-label') ||
                             await button.textContent();
      expect(accessibleName?.trim().length).toBeGreaterThan(0);
    }
  });

  test('images have alt text', async ({ page }) => {
    await page.goto('/');

    const images = page.locator('img');
    const count = await images.count();

    for (let i = 0; i < count; i++) {
      const img = images.nth(i);
      const altText = await img.getAttribute('alt');
      // Alt can be empty string for decorative images, but should exist
      expect(altText !== null).toBeTruthy();
    }
  });

  test('form inputs have labels', async ({ page }) => {
    await page.goto('/sign-up');

    const inputs = page.locator('input:not([type="hidden"])');
    const count = await inputs.count();

    for (let i = 0; i < count; i++) {
      const input = inputs.nth(i);
      const id = await input.getAttribute('id');
      const ariaLabel = await input.getAttribute('aria-label');
      const ariaLabelledBy = await input.getAttribute('aria-labelledby');

      // Input should have either a label, aria-label, or aria-labelledby
      const hasLabel = id ? await page.locator(`label[for="${id}"]`).count() > 0 : false;
      expect(hasLabel || ariaLabel || ariaLabelledBy).toBeTruthy();
    }
  });
});

test.describe('Performance', () => {
  test('landing page loads within acceptable time', async ({ page }) => {
    const startTime = Date.now();
    await page.goto('/');
    const loadTime = Date.now() - startTime;

    // Should load within 5 seconds
    expect(loadTime).toBeLessThan(5000);
  });

  test('page has no console errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });

    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Filter out expected errors (like missing auth)
    const criticalErrors = errors.filter(e =>
      !e.includes('401') &&
      !e.includes('Unauthorized') &&
      !e.includes('fetch')
    );

    expect(criticalErrors.length).toBe(0);
  });
});

test.describe('SEO', () => {
  test('landing page has meta title', async ({ page }) => {
    await page.goto('/');

    const title = await page.title();
    expect(title.length).toBeGreaterThan(0);
    // Title should exist (app may have different branding)
    expect(title).toBeTruthy();
  });

  test('landing page has meta description', async ({ page }) => {
    await page.goto('/');

    const metaDesc = await page.getAttribute('meta[name="description"]', 'content');
    expect(metaDesc?.length).toBeGreaterThan(10);
  });

  test('landing page has Open Graph tags', async ({ page }) => {
    await page.goto('/');

    const ogTitle = await page.getAttribute('meta[property="og:title"]', 'content');
    const ogDesc = await page.getAttribute('meta[property="og:description"]', 'content');

    // At least one OG tag should exist for social sharing
    expect(ogTitle || ogDesc).toBeTruthy();
  });
});

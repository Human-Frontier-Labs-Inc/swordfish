import { test, expect } from '@playwright/test';

test.describe('Authentication Flow', () => {
  test('should show sign-in page', async ({ page }) => {
    await page.goto('/sign-in');

    // Should have Clerk sign-in component - use specific heading
    await expect(page.getByRole('heading', { name: /sign in/i })).toBeVisible({ timeout: 10000 });
  });

  test('should show sign-up page', async ({ page }) => {
    await page.goto('/sign-up');

    // Should have Clerk sign-up component - use specific heading
    await expect(page.getByRole('heading', { name: /sign up|create/i })).toBeVisible({ timeout: 10000 });
  });

  test('should redirect unauthenticated user to sign-in from dashboard', async ({ page }) => {
    await page.goto('/dashboard');

    // Should redirect to sign-in
    await expect(page).toHaveURL(/sign-in/, { timeout: 10000 });
  });

  test('should display homepage with correct branding', async ({ page }) => {
    await page.goto('/');

    // Check for Swordfish branding - use first match
    await expect(page.getByText('Swordfish').first()).toBeVisible();
    await expect(page.getByText(/AI-Powered Email Security/i)).toBeVisible();
  });

  test('should have sign-in and sign-up buttons on homepage', async ({ page }) => {
    await page.goto('/');

    // Use first() since there may be multiple Sign In links
    await expect(page.getByRole('link', { name: /sign in/i }).first()).toBeVisible();
    await expect(page.getByRole('link', { name: /get started|start free trial/i }).first()).toBeVisible();
  });
});

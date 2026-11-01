'use strict';
const { test, expect } = require('@playwright/test');

test('@public Yara login, privacy and viewport smoke', async ({ page }, testInfo) => {
  const response = await page.goto('/login', { waitUntil: 'domcontentloaded' });
  expect(response?.status()).toBe(200);
  await expect(page.locator('#login-heading')).toBeVisible();
  await expect(page.locator('.login-submit')).toBeVisible();
  await expect(page).toHaveTitle(/Yara/i);
  await expect(page.locator('a[href="/privacy"]')).toBeVisible();
  const visible = await page.locator('body').innerText();
  expect(visible).not.toMatch(/\bVHV\b/i);
  const overflows = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth + 1
  );
  expect(overflows, 'horizontal overflow on ' + testInfo.project.name).toBe(false);
  // Public anonymous page only. No private account state or tokens in this artifact.
  await page.screenshot({ path: testInfo.outputPath('login.png'), fullPage: true });
  const privacy = await page.goto('/privacy', { waitUntil: 'domcontentloaded' });
  expect(privacy?.status()).toBe(200);
  const privacyText = await page.locator('body').innerText();
  expect(privacyText).not.toMatch(/\bVHV\b/i);
});

test.describe('authorized read-only Yara', () => {
  test.use({
    storageState: process.env.YARA_E2E_SCOPE === 'full'
      ? process.env.YARA_E2E_QA_STATE_FILE
      : { cookies: [], origins: [] },
  });

  test('@auth Today, Tasks and Plans navigation', async ({ page }) => {
    const response = await page.goto('/', { waitUntil: 'domcontentloaded' });
    expect(response?.status()).toBe(200);
    await expect(page.locator('#assistant-command')).toBeVisible();
    const tabs = page.locator('nav.tabbar');
    await expect(tabs).toBeVisible();
    for (const name of [/Справи|Tasks/i, /Плани|Plans/i, /Сьогодні|Today/i]) {
      const button = tabs.getByRole('button', { name });
      await expect(button).toBeVisible();
      await button.click();
      await expect(button).toHaveAttribute('aria-current', 'page');
    }
    const visible = await page.locator('body').innerText();
    expect(visible).not.toMatch(/\bVHV\b/i);
    // Client-only migration: preserve previously selected EN locale after rename.
    await page.evaluate(() => {
      localStorage.removeItem('qdip-yara-locale');
      localStorage.setItem('qdip-vhv-locale', 'en');
    });
    await page.reload({ waitUntil: 'domcontentloaded' });
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    const keys = await page.evaluate(() => ({
      current: localStorage.getItem('qdip-yara-locale'),
      retired: localStorage.getItem('qdip-vhv-locale'),
    }));
    expect(keys).toEqual({ current: 'en', retired: null });
    // No authenticated screenshots in the public qdip-e2e repository.
  });
});

/**
 * Independent read-only browser acceptance for Dzvin PR #589 release preview.
 * Runs on the real Vercel URL, never mocks responses or writes user data.
 * Screenshots contain PUBLIC landing content only (no authenticated pages).
 * A missing cookie Reject action is an intentional failing release gate.
 */
import { chromium } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';

const ORIGIN = process.env.DZVIN_PREVIEW_ORIGIN;
const DEPLOYMENT = process.env.DZVIN_PREVIEW_DEPLOYMENT;
const FRONT_SHA = process.env.DZVIN_PREVIEW_SHA;
const VIEWPORTS = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'mobile-portrait', width: 390, height: 844 },
  { name: 'mobile-landscape', width: 844, height: 390 },
];
const failures = [];
const evidenceDir = join(process.env.RUNNER_TEMP || '/tmp', 'dzvin-release-anonymous-evidence');

function assert(condition, code) {
  if (!condition) throw new Error(code);
}
function guard() {
  assert(process.env.DZVIN_QA_READONLY_ACK === '1', 'READONLY_APPROVAL_REQUIRED');
  assert(/^https:\/\/mentality-[a-z0-9]+-taras-gezs-projects\.vercel\.app$/.test(ORIGIN || ''),
    'EXACT_PREVIEW_HOST_REQUIRED');
  assert(ORIGIN === process.env.DZVIN_EXPECTED_PREVIEW_ORIGIN,
    'PREVIEW_ALLOWLIST_MISMATCH');
  assert(/^dpl_[A-Za-z0-9]+$/.test(DEPLOYMENT || ''), 'PINNED_DEPLOYMENT_ID_REQUIRED');
  assert(/^[0-9a-f]{40}$/.test(FRONT_SHA || ''), 'PINNED_40_CHAR_SHA_REQUIRED');
}
async function check(label, action) {
  try {
    await action();
    console.log('DZVIN_' + label + '=PASS');
  } catch (error) {
    const code = error instanceof Error && /^[A-Z0-9_]{5,100}$/.test(error.message)
      ? error.message : 'SANITIZED_TEST_FAILURE';
    failures.push(label + ':' + code);
    console.error('DZVIN_' + label + '=FAIL:' + code);
  }
}
async function anonymousApi(context) {
  await check('ANONYMOUS_AUTH_DENIED', async () => {
    const response = await context.request.get(ORIGIN + '/api/auth/session');
    assert(response.status() === 401, 'ANONYMOUS_SESSION_NOT_401');
    assert((response.headers()['cache-control'] || '').includes('no-store'),
      'SESSION_NOT_NO_STORE');
    const body = await response.text();
    assert(!/access_token|refresh_token|id_token/i.test(body),
      'ANONYMOUS_SESSION_TOKEN_EXPOSURE');
  });
  await check('ANONYMOUS_DIARY_DENIED', async () => {
    const response = await context.request.get(ORIGIN + '/api/backend/diary/user');
    assert(response.status() === 401, 'ANONYMOUS_DIARY_NOT_401');
    assert((response.headers()['cache-control'] || '').includes('no-store'),
      'DIARY_DENIAL_NOT_NO_STORE');
  });
  await check('CROSS_ORIGIN_MUTATION_DENIED', async () => {
    // Invalid Origin must reject BEFORE backend access; deliberately no valid data.
    const response = await context.request.post(ORIGIN + '/api/backend/diary', {
      headers: { origin: 'https://cross-origin.invalid' },
      data: {},
    });
    assert(response.status() === 403, 'CROSS_ORIGIN_MUTATION_NOT_403');
  });
  await check('MISSING_ORIGIN_TOKEN_EXCHANGE_DENIED', async () => {
    const response = await context.request.post(ORIGIN + '/api/auth/exchange', {
      data: { grantType: 'refresh_token' },
    });
    assert(response.status() === 403, 'MISSING_ORIGIN_EXCHANGE_NOT_403');
  });
}
async function landing(browser, viewport) {
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
    isMobile: viewport.name !== 'desktop',
    hasTouch: viewport.name !== 'desktop',
    serviceWorkers: 'block',
    acceptDownloads: false,
  });
  try {
    const page = await context.newPage();
    await check(viewport.name.toUpperCase().replace(/-/g, '_') + '_LANDING', async () => {
      const response = await page.goto(ORIGIN + '/en', {
        waitUntil: 'domcontentloaded', timeout: 35000,
      });
      assert(response?.status() === 200, 'LANDING_HTTP_NOT_200');
      assert(new URL(page.url()).pathname === '/en', 'LANDING_UNEXPECTED_REDIRECT');
      const html = await response.text();
      assert(html.includes('data-dpl-id="' + DEPLOYMENT + '"'),
        'PREVIEW_DEPLOYMENT_MISMATCH');
      const ctas = page.locator('a[href*="/auth"], a[href*="/my-day"]');
      assert(await ctas.count() > 0, 'LANDING_PRIMARY_CTA_MISSING');
      assert(await page.locator('main').count() > 0, 'LANDING_MAIN_MISSING');
      const dimensions = await page.evaluate(() => ({
        document: document.documentElement.scrollWidth,
        viewport: window.innerWidth,
      }));
      assert(dimensions.document <= dimensions.viewport + 2, 'LANDING_HORIZONTAL_OVERFLOW');
    });
    await check(viewport.name.toUpperCase().replace(/-/g, '_') + '_COOKIE_CONSENT', async () => {
      const consent = page.getByRole('region', { name: 'We use cookies' });
      await consent.waitFor({ state: 'visible', timeout: 12000 });
      assert(await consent.getByRole('link', { name: 'Cookie policy' }).count() === 1,
        'COOKIE_POLICY_LINK_MISSING');
      // GDPR/ePrivacy gate: Reject must be as accessible as Accept.
      const reject = consent.getByRole('button', { name: /^(reject|decline)$/i });
      assert(await reject.count() > 0, 'COOKIE_REJECT_ACTION_MISSING');
    });
    await check(viewport.name.toUpperCase().replace(/-/g, '_') + '_COOKIE_REJECT_PERSISTENCE', async () => {
      const consent = page.getByRole('region', { name: 'We use cookies' });
      await consent.getByRole('button', { name: 'Reject' }).click();
      await consent.waitFor({ state: 'hidden', timeout: 6000 });
      let cookies = await context.cookies(ORIGIN);
      assert(cookies.some(c => c.name === 'cookie_consent' && c.value === '0'),
        'REJECT_NOT_PERSISTED');
      await page.reload({ waitUntil: 'domcontentloaded' });
      assert(await page.getByRole('region', { name: 'We use cookies' }).count() === 0,
        'REJECT_NOT_RESPECTED_ON_RELOAD');
      await context.clearCookies();
      await page.reload({ waitUntil: 'domcontentloaded' });
      await page.getByRole('region', { name: 'We use cookies' })
        .waitFor({ state: 'visible', timeout: 12000 });
    });
    await check(viewport.name.toUpperCase().replace(/-/g, '_') + '_COOKIE_ACCEPT', async () => {
      const consent = page.getByRole('region', { name: 'We use cookies' });
      const accept = consent.getByRole('button', { name: 'Accept' });
      assert(await accept.isVisible(), 'COOKIE_ACCEPT_ACTION_MISSING');
      await accept.click();
      await consent.waitFor({ state: 'hidden', timeout: 6000 });
      const values = await context.cookies(ORIGIN);
      assert(values.some(c => c.name === 'cookie_consent' && c.value === '1'),
        'ACCEPT_NOT_PERSISTED');
    });
    // Public-only visual evidence. Never screenshot the signed-in diary or QA data.
    await check(viewport.name.toUpperCase().replace(/-/g, '_') + '_SCREENSHOT', async () => {
      await page.screenshot({ path: join(evidenceDir, viewport.name + '.png'), fullPage: true,
        animations: 'disabled' });
    });
    if (viewport.name === 'desktop') {
      await anonymousApi(context);
      for (const locale of ['uk', 'pl']) {
        await check(locale.toUpperCase() + '_LANDING', async () => {
          const response = await page.goto(ORIGIN + '/' + locale, {
            waitUntil: 'domcontentloaded', timeout: 35000,
          });
          assert(response?.status() === 200, 'LOCALIZED_LANDING_NOT_200');
          assert(new URL(page.url()).pathname === '/' + locale, 'LOCALIZED_LANDING_REDIRECT');
          const html = await response.text();
          assert(html.includes('data-dpl-id="' + DEPLOYMENT + '"'),
            'LOCALIZED_DEPLOYMENT_MISMATCH');
        });
      }
      await check('ANONYMOUS_PROTECTED_ROUTE', async () => {
        const response = await page.goto(ORIGIN + '/en/diary', {
          waitUntil: 'domcontentloaded', timeout: 35000,
        });
        assert(response?.status() === 200 || response?.status() === 302 ||
          response?.status() === 307, 'PROTECTED_UNEXPECTED_HTTP_STATUS');
        assert(new URL(page.url()).pathname === '/en/auth',
          'ANONYMOUS_PROTECTED_ROUTE_NOT_REDIRECTED');
      });
    }
  } finally {
    await context.close();
  }
}
async function main() {
  guard();
  await mkdir(evidenceDir, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  try {
    for (const viewport of VIEWPORTS) await landing(browser, viewport);
  } finally {
    await browser.close();
  }
  console.log('DZVIN_PREVIEW_FRONT_SHA=' + FRONT_SHA);
  console.log('DZVIN_BROWSER_CASE_FAILURES=' + failures.length);
  console.log('DZVIN_AUTHENTICATED_REFRESH_AND_PRIVACY=SEPARATE_QA1_QA2_GATE');
  if (failures.length) process.exitCode = 1;
}
main().catch(() => {
  console.error('DZVIN_RELEASE_ANONYMOUS=FAIL:SANITIZED_SETUP_OR_BROWSER_FAILURE');
  process.exitCode = 1;
});

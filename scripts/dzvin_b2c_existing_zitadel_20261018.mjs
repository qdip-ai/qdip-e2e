/**
 * One-off, read-only Dzvin B2C staging qualification using EXISTING
 * encrypted qdip-e2e Zitadel credentials. No login secrets leave Actions.
 * Never print emails, tokens, redirects, cookies, response bodies or identifiers.
 * No data writes and a maximum of one password attempt per identity.
 */
import { chromium } from '@playwright/test';

// This pre-existing dev-only alias currently resolves to the exact e098d84 deployment.
// It is also an established Zitadel redirect origin; do not use a random preview host.
const SITE = 'https://mentality-web.vercel.app';
const FRONT_SHA = 'e098d847c72e8c6f96735742f8f2a92f63117678';
const BACK_SHA = '05dd3f327e05fef2c897a5ed1b9959fb0b391b6a';

const identities = [
  { label: 'QA1', email: process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN, password: process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD },
  { label: 'QA2', email: process.env.QDIP_E2E_ZITADEL_TEST2_LOGIN, password: process.env.QDIP_E2E_ZITADEL_TEST2_PASSWORD },
];
const fallback = {
  label: 'EXISTING_TEST_USER',
  email: process.env.QDIP_E2E_ZITADEL_TEST_LOGIN,
  password: process.env.QDIP_E2E_ZITADEL_TEST_PASSWORD,
};

function check(value, stage) {
  if (!value) throw new Error(stage);
}
async function visibleField(page, selectors, waitMs = 12000) {
  const deadline = Date.now() + waitMs;
  while (Date.now() < deadline) {
    for (const selector of selectors) {
      const el = page.locator(selector).first();
      if (await el.isVisible().catch(() => false)) return el;
    }
    await page.waitForTimeout(250);
  }
  return null;
}
async function get(context, path, expected, label) {
  const r = await context.request.get(SITE + path, { maxRedirects: 0, timeout: 15000 });
  check(r.status() === expected, label + '_HTTP_' + r.status());
  check((r.headers()['cache-control'] || '').includes('no-store'), label + '_CACHE_MISSING');
  return r;
}
function strictPreview() {
  const host = new URL(SITE).hostname;
  check(host === 'mentality-web.vercel.app', 'PREVIEW_HOST_UNEXPECTED');
  check(!host.startsWith('dzvin.co') && !host.includes('production'), 'PRODUCTION_TARGET_REJECTED');
}
async function login(browser, identity) {
  const context = await browser.newContext({ ignoreHTTPSErrors: false, serviceWorkers: 'block',
    acceptDownloads: false, viewport: { width: 1280, height: 800 } });
  try {
    const page = await context.newPage();
    page.setDefaultTimeout(12000);
    const authRequests = [];
    page.on('request', req => {
      try {
        const u = new URL(req.url());
        if (u.pathname.endsWith('/oauth/v2/authorize')) authRequests.push(u);
      } catch { /* don't log */ }
    });
    const initialResponse = await page.goto(SITE + '/en/auth', {
      waitUntil: 'domcontentloaded', timeout: 30000,
    });
    await page.waitForURL(u => u.origin !== SITE, { timeout: 20000 });
    console.log(identity.label + '_ZITADEL_PAGE_HTTP=' + (initialResponse?.status() ?? 'UNKNOWN'));
    check(authRequests.length > 0, identity.label + '_OIDC_AUTHORIZE_MISSING');
    const a = authRequests[0];
    check(a.searchParams.get('code_challenge_method') === 'S256', identity.label + '_PKCE_INVALID');
    const callback = a.searchParams.get('redirect_uri');
    check(Boolean(callback), identity.label + '_OIDC_CALLBACK_MISSING');
    const callbackOrigin = new URL(callback).origin;
    if (callbackOrigin !== SITE) {
      console.error(identity.label + '_OIDC_CALLBACK_TARGETS_OTHER_ORIGIN');
      throw new Error(identity.label + '_PREVIEW_CALLBACK_MISMATCH');
    }
    console.log(identity.label + '_OIDC_PREVIEW_CALLBACK_AND_PKCE=PASS');

    const username = await visibleField(page, [
      'input[autocomplete="username"]', 'input[name="loginName"]',
      'input[name="loginname"]', 'input[name="username"]',
      'input[name="email"]', 'input[type="email"]', 'input[type="text"]',
    ]);
    if (!username) {
      // Nothing entered yet. Log only whitelisted structure and error categories;
      // never record full URLs, form content, credentials, OAuth state or cookies.
      const shape = await page.locator('input').evaluateAll(els =>
        els.slice(0, 8).map(el => ({
          type: el.getAttribute('type')?.slice(0, 24) ?? '',
          name: el.getAttribute('name')?.slice(0, 40) ?? '',
          autocomplete: el.getAttribute('autocomplete')?.slice(0, 32) ?? '',
        })),
      ).catch(() => []);
      const text = (await page.locator('body').innerText({ timeout: 4000 }).catch(() => '')).toLowerCase();
      const hint = /redirect.uri|redirect uri|redirect_url|invalid redirect/.test(text)
        ? 'INVALID_REDIRECT' : /client.*invalid|invalid.*client/.test(text)
        ? 'INVALID_CLIENT' : /unauthoriz|forbidden|access denied/.test(text)
        ? 'ACCESS_DENIED' : /error|something went wrong|not found/.test(text)
        ? 'PROVIDER_ERROR' : /login|sign in|anmelden|увійти/.test(text)
        ? 'LOGIN_VIEW' : 'UNKNOWN';
      console.log(identity.label + '_ZITADEL_VIEW_HINT=' + hint);
      console.log(identity.label + '_ZITADEL_INPUT_SHAPE=' + JSON.stringify(shape));
      console.log(identity.label + '_ZITADEL_FRAME_COUNT=' + page.frames().length);
    }
    check(username, identity.label + '_ZITADEL_USERNAME_FIELD_MISSING');
    await username.fill(identity.email);
    let password = await visibleField(page, [
      'input[autocomplete="current-password"]', 'input[type="password"]',
    ], 1200);
    if (!password) {
      await username.press('Enter');
      password = await visibleField(page, [
        'input[autocomplete="current-password"]', 'input[type="password"]',
      ]);
    }
    check(password, identity.label + '_ZITADEL_PASSWORD_FIELD_MISSING');
    await password.fill(identity.password);
    await password.press('Enter'); // One attempt, never retry passwords.

    let session;
    for (let i = 0; i < 18; i++) {
      await page.waitForTimeout(1000);
      const response = await context.request.get(SITE + '/api/auth/session', {
        maxRedirects: 0, timeout: 9000,
      }).catch(() => null);
      if (response?.status() === 200) {
        session = await response.json().catch(() => null);
        if (session?.id) break;
      }
    }
    check(session?.id, identity.label + '_AUTH_SESSION_NOT_ESTABLISHED');
    check(session.email?.toLowerCase() === identity.email.toLowerCase(),
      identity.label + '_IDENTITY_MISMATCH');
    check(session.role !== 'admin', identity.label + '_PRIVILEGED_ACCOUNT_NOT_B2C');
    const cookie = (await context.cookies(SITE)).find(c => c.name === 'auth-tokens' && c.httpOnly);
    check(cookie, identity.label + '_HTTPONLY_AUTH_COOKIE_MISSING');
    console.log(identity.label + '_ZITADEL_LOGIN_AND_COOKIE=PASS');

    for (const path of ['/api/backend/mood-risk/actionable', '/api/backend/mood-feed',
        '/api/backend/companies']) {
      await get(context, path, 404, identity.label + '_B2C_POLICY');
    }
    console.log(identity.label + '_B2C_RELEASE_BOUNDARY=PASS');
    for (const path of ['/api/backend/user-statistics/mood?timeZone=Europe%2FWarsaw',
        '/api/backend/diary/user']) {
      await get(context, path, 200, identity.label + '_PERSONAL_DATA');
    }
    console.log(identity.label + '_PERSONAL_STATISTICS_AND_DIARY=PASS');
    return { context, userId: session.id };
  } catch (e) {
    await context.close();
    throw e;
  }
}
async function main() {
  strictPreview();
  console.log('DZVIN_B2C_EXACT_WEB_SHA=' + FRONT_SHA);
  console.log('DZVIN_B2C_EXACT_BACK_SHA=' + BACK_SHA);
  const pair = identities.every(x => Boolean(x.email && x.password));
  const one = Boolean(fallback.email && fallback.password);
  check(pair || one, 'EXISTING_ZITADEL_TEST_CREDENTIALS_UNAVAILABLE');
  console.log('DZVIN_QA_PAIR_BINDING=' + (pair ? 'PRESENT' : 'MISSING'));
  console.log('DZVIN_EXISTING_TEST_BINDING=' + (one ? 'PRESENT' : 'MISSING'));
  const toTest = pair ? identities : [fallback];
  const browser = await chromium.launch({ headless: true });
  const actors = [];
  try {
    for (const identity of toTest) actors.push(await login(browser, identity));
    if (actors.length === 2) {
      check(actors[0].userId !== actors[1].userId, 'QA_TEST_ACCOUNTS_NOT_DISTINCT');
      console.log('DZVIN_REAL_QA_USER_IDENTITIES_ISOLATED=PASS');
    } else {
      console.log('DZVIN_BIDIRECTIONAL_TWO_USER_TEST=NOT_TESTED');
    }
    console.log('DZVIN_REAL_ZITADEL_B2C_STAGING=PASS');
  } finally {
    await Promise.all(actors.map(x => x.context.close()));
    await browser.close();
  }
}
main().catch(e => {
  const stage = e instanceof Error && /^[A-Z0-9_]{4,110}$/.test(e.message)
    ? e.message : 'SANITIZED_BROWSER_FAILURE';
  console.error('DZVIN_REAL_ZITADEL_B2C_STAGING=FAIL:' + stage);
  process.exitCode = 1;
});

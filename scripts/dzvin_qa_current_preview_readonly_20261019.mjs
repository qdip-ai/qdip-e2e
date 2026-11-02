/**
 * Read-only, manual two-account B2C QA acceptance on the exact newer
 * Vercel preview. Credentials remain inside the protected GitHub runner.
 * The established Zitadel callback completes on the existing dev alias;
 * a scoped HttpOnly test cookie is copied in-memory to this other preview.
 * This proves authenticated BFF behavior but NOT an independent OAuth
 * callback registration for the new hostname.
 *
 * Never log personal diary text, secrets, cookies, subject IDs or response bodies.
 * No server writes, mutation endpoint calls or browser test artifacts.
 */
import { chromium } from '@playwright/test';

const LOGIN_ORIGIN = 'https://mentality-web.vercel.app';
const PREVIEW_ORIGIN = process.env.DZVIN_PREVIEW_ORIGIN || 'https://mentality-piytogl1z-taras-gezs-projects.vercel.app';
const PREVIEW_DEPLOYMENT = process.env.DZVIN_PREVIEW_DEPLOYMENT || 'dpl_CS2bbA8uibuoUujHfvXq7xvFVk5b';
const FRONT_SHA = process.env.DZVIN_PREVIEW_SHA || 'ca5871766e3f44bcb4978a3212e1eb60b2895fa7';

const users = [
  { label: 'QA1', email: process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN,
    password: process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD },
  { label: 'QA2', email: process.env.QDIP_E2E_ZITADEL_TEST2_LOGIN,
    password: process.env.QDIP_E2E_ZITADEL_TEST2_PASSWORD },
];
function assert(value, code) {
  if (!value) throw new Error(code);
}
function validateInputs() {
  assert(process.env.DZVIN_QA_READONLY_ACK === '1', 'READONLY_EXPLICIT_APPROVAL_REQUIRED');
  assert(process.env.DZVIN_EXPECTED_PREVIEW_ORIGIN === PREVIEW_ORIGIN,
    'PREVIEW_ORIGIN_ALLOWLIST_MISMATCH');
  for (const actor of users) {
    assert(Boolean(actor.email && actor.password), actor.label + '_TEST_SECRET_MISSING');
  }
  assert(users[0].email.toLowerCase() !== users[1].email.toLowerCase(),
    'INDEPENDENT_QA_IDENTITIES_REQUIRED');
  assert(/^https:\/\/mentality-[a-z0-9]+-taras-gezs-projects\.vercel\.app$/.test(PREVIEW_ORIGIN),
    'EXACT_PROJECT_PREVIEW_HOST_REQUIRED');
  assert(/^dpl_[a-zA-Z0-9]+$/.test(PREVIEW_DEPLOYMENT), 'INVALID_PREVIEW_DEPLOYMENT');
  assert(/^[0-9a-f]{40}$/.test(FRONT_SHA), 'IMMUTABLE_FRONT_SHA_REQUIRED');
  assert(PREVIEW_ORIGIN !== LOGIN_ORIGIN, 'PREVIEW_MUST_BE_INDEPENDENT');
  assert(!PREVIEW_ORIGIN.includes('dzvin.co') &&
    !PREVIEW_ORIGIN.includes('-git-production-'), 'PRODUCTION_HOST_FORBIDDEN');
}
async function findVisible(page, selectors, timeout = 12000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) {
    for (const selector of selectors) {
      const node = page.locator(selector).first();
      if (await node.isVisible().catch(() => false)) return node;
    }
    await page.waitForTimeout(250);
  }
  return null;
}
async function login(browser, actor) {
  const context = await browser.newContext({
    ignoreHTTPSErrors: false, serviceWorkers: 'block', acceptDownloads: true,
  });
  try {
    const page = await context.newPage();
    let pkceVerified = false;
    page.on('request', (req) => {
      try {
        const u = new URL(req.url());
        if (u.pathname.endsWith('/oauth/v2/authorize')) {
          const cb = u.searchParams.get('redirect_uri');
          if (cb && new URL(cb).origin === LOGIN_ORIGIN &&
            u.searchParams.get('code_challenge_method') === 'S256') pkceVerified = true;
        }
      } catch { /* no URL disclosure */ }
    });
    await page.goto(LOGIN_ORIGIN + '/en/auth', {
      waitUntil: 'domcontentloaded', timeout: 30000,
    });
    await page.waitForURL(url => url.origin !== LOGIN_ORIGIN, { timeout: 24000 });
    assert(pkceVerified, actor.label + '_OIDC_PKCE_OR_CALLBACK_INVALID');
    const username = await findVisible(page, [
      'input[autocomplete="username"]', 'input[name="loginName"]',
      'input[name="loginname"]', 'input[name="username"]',
      'input[name="email"]', 'input[type="email"]', 'input[type="text"]',
    ]);
    assert(username, actor.label + '_USERNAME_FIELD_MISSING');
    await username.fill(actor.email);
    let password = await findVisible(page, [
      'input[autocomplete="current-password"]', 'input[type="password"]',
    ], 1500);
    if (!password) {
      await username.press('Enter');
      password = await findVisible(page, [
        'input[autocomplete="current-password"]', 'input[type="password"]',
      ]);
    }
    assert(password, actor.label + '_PASSWORD_FIELD_MISSING');
    await password.fill(actor.password);
    await password.press('Enter'); // Never retry a password.
    let session = null;
    for (let t = 0; t < 20; t++) {
      await page.waitForTimeout(800);
      const r = await context.request.get(LOGIN_ORIGIN + '/api/auth/session', {
        timeout: 9000, maxRedirects: 0,
      }).catch(() => null);
      if (r?.status() === 200) {
        session = await r.json().catch(() => null);
        if (session?.id) break;
      }
    }
    assert(session?.id, actor.label + '_LOGIN_SESSION_NOT_ESTABLISHED');
    assert(session.email?.toLowerCase() === actor.email.toLowerCase(),
      actor.label + '_SUBJECT_EMAIL_MISMATCH');
    assert(session.role !== 'admin', actor.label + '_QA_ROLE_UNEXPECTED');

    const source = (await context.cookies(LOGIN_ORIGIN))
      .find(c => c.name === 'auth-tokens' && c.httpOnly && c.secure);
    assert(source, actor.label + '_SERVER_COOKIE_NOT_FOUND');
    console.log(actor.label + '_ZITADEL_OLD_ALIAS_PKCE_LOGIN=PASS');

    // Never export token/cookie to disk, logs, artifacts or external endpoints.
    const preview = await browser.newContext({
      ignoreHTTPSErrors: false, serviceWorkers: 'block', acceptDownloads: true,
    });
    try {
      const hostname = new URL(PREVIEW_ORIGIN).hostname;
      await preview.addCookies([{
        name: source.name, value: source.value, domain: hostname,
        path: source.path, httpOnly: true, secure: true, sameSite: source.sameSite,
        ...(source.expires > 0 ? { expires: source.expires } : {}),
      }]);
      const valid = await preview.request.get(PREVIEW_ORIGIN + '/api/auth/session', {
        maxRedirects: 0,
      });
      assert(valid.status() === 200, actor.label + '_PREVIEW_COOKIE_NOT_ACCEPTED');
      const previewSession = await valid.json();
      assert(previewSession.id === session.id &&
        previewSession.email?.toLowerCase() === actor.email.toLowerCase(),
        actor.label + '_PREVIEW_IDENTITY_MISMATCH');
      assert(!Object.keys(previewSession).some(k => /token|secret|password/i.test(k)),
        actor.label + '_SESSION_JSON_EXPOSES_CREDENTIAL_FIELD');
      assert((valid.headers()['cache-control'] || '').includes('no-store'),
        actor.label + '_SESSION_CACHE_POLICY_MISSING');

      const pagePreview = await preview.newPage();
      const pageResponse = await pagePreview.goto(PREVIEW_ORIGIN + '/en/diary', {
        waitUntil: 'domcontentloaded', timeout: 30000,
      });
      assert(pageResponse?.status() === 200, actor.label + '_PREVIEW_DIARY_PAGE_FAIL');
      assert(new URL(pagePreview.url()).pathname === '/en/diary',
        actor.label + '_PREVIEW_DIARY_REDIRECT');
      const html = await pageResponse.text();
      assert(html.includes('data-dpl-id="' + PREVIEW_DEPLOYMENT + '"'),
        actor.label + '_PREVIEW_DEPLOYMENT_CHANGED');
      for (const path of [
        '/api/backend/mood-risk/actionable', '/api/backend/mood-feed',
        '/api/backend/companies',
      ]) {
        const denied = await preview.request.get(PREVIEW_ORIGIN + path);
        assert(denied.status() === 404, actor.label + '_B2C_SCOPE_BYPASS');
      }
      // These requests must be rejected at the BFF without mutating QA data.
      const foreignWrite = await preview.request.post(PREVIEW_ORIGIN + '/api/backend/diary', {
        headers: { origin: 'https://cross-origin.invalid', 'content-type': 'application/json' },
        data: {},
      });
      assert(foreignWrite.status() === 403, actor.label + '_CROSS_ORIGIN_MUTATION_NOT_DENIED');
      const missingOrigin = await preview.request.post(PREVIEW_ORIGIN + '/api/auth/exchange', {
        data: { grantType: 'refresh_token' },
      });
      assert(missingOrigin.status() === 403, actor.label + '_TOKEN_EXCHANGE_PROVENANCE_BYPASS');
      for (const path of ['/en/my-day', '/en/mood-tracker', '/en/my-progress']) {
        const response = await pagePreview.goto(PREVIEW_ORIGIN + path, {
          waitUntil: 'domcontentloaded',
        });
        assert(response?.status() === 200, actor.label + '_B2C_PAGE_FAILURE');
        assert(new URL(pagePreview.url()).pathname === path,
          actor.label + '_B2C_PAGE_REDIRECT');
      }
      // Exercise the real UI download without uploading, saving or printing the file.
      // Notes must exactly match the server-scoped authenticated diary list.
      const diaryPage = await pagePreview.goto(PREVIEW_ORIGIN + '/en/diary', {
        waitUntil: 'domcontentloaded',
      });
      assert(diaryPage?.status() === 200, actor.label + '_DIARY_EXPORT_PAGE_FAIL');

      const listing = await preview.request.get(PREVIEW_ORIGIN + '/api/backend/diary/user');
      assert(listing.status() === 200, actor.label + '_DIARY_LIST_UNAVAILABLE');
      assert((listing.headers()['cache-control'] || '').includes('no-store'),
        actor.label + '_DIARY_NO_STORE_MISSING');
      const notes = await listing.json();
      assert(Array.isArray(notes), actor.label + '_DIARY_LIST_INVALID');
      const owned = notes.map(n => n?.id ?? n?._id)
        .filter(id => /^[a-f0-9]{24}$/i.test(id || ''));
      const downloadButton = pagePreview.getByRole('button', {
        name: 'Export all diary entries (JSON)',
      });
      if (owned.length) {
        assert(await downloadButton.isEnabled(), actor.label + '_DIARY_EXPORT_DISABLED');
        const [download] = await Promise.all([
          pagePreview.waitForEvent('download', { timeout: 12000 }),
          downloadButton.click(),
        ]);
        assert(/^dzvin-diary-\d{4}-\d{2}-\d{2}\.json$/.test(download.suggestedFilename()),
          actor.label + '_EXPORT_FILENAME_INVALID');
        const stream = await download.createReadStream();
        const bytes = [];
        for await (const part of stream) bytes.push(Buffer.from(part));
        const exported = JSON.parse(Buffer.concat(bytes).toString('utf8'));
        assert(exported?.format === 'dzvin-diary' && exported.version === 1 &&
          Array.isArray(exported.entries), actor.label + '_EXPORT_SCHEMA_INVALID');
        const downloadedIds = exported.entries.map(x => x.id);
        const expectedIds = new Set(owned);
        assert(downloadedIds.length === expectedIds.size &&
          new Set(downloadedIds).size === expectedIds.size &&
          downloadedIds.every(id => expectedIds.has(id)),
          actor.label + '_EXPORT_OWNERSHIP_OR_COMPLETENESS_MISMATCH');
        console.log(actor.label + '_DIARY_BROWSER_EXPORT=PASS_OWNED_ONLY');
      } else {
        assert(await downloadButton.isDisabled(), actor.label + '_EMPTY_EXPORT_SHOULD_DISABLE');
        console.log(actor.label + '_DIARY_BROWSER_EXPORT=NOT_TESTED_EMPTY_DIARY');
      }
      for (const item of [
        { lang: 'en', help: 'Need urgent help?', privacy: 'How your data is handled' },
        { lang: 'uk', help: 'Потрібна термінова допомога?', privacy: 'Як обробляються дані' },
        { lang: 'pl', help: 'Potrzebujesz pilnej pomocy?', privacy: 'Jak przetwarzane są dane' },
      ]) {
        const pageLoad = await pagePreview.goto(PREVIEW_ORIGIN + '/' + item.lang + '/diary', {
          waitUntil: 'domcontentloaded',
        });
        assert(pageLoad?.status() === 200, actor.label + '_LOCALIZED_DIARY_UNAVAILABLE');
        const label = actor.label + '_' + item.lang.toUpperCase();
        const help = pagePreview.getByText(item.help, { exact: true });
        const privacy = pagePreview.getByRole('link', { name: item.privacy });
        const helpVisible = await help.waitFor({ state: 'visible', timeout: 12000 })
          .then(() => true, () => false);
        assert(helpVisible, label + '_URGENT_HELP_MISSING');
        const privacyVisible = await privacy.waitFor({ state: 'visible', timeout: 12000 })
          .then(() => true, () => false);
        if (!privacyVisible) {
          // Print only safe structural evidence; never diary HTML or account data.
          const matchingHref = await pagePreview.locator('a[href*="privacy"]')
            .count().catch(() => 0);
          console.log(label + '_PRIVACY_LINK_HREF_MATCHES=' + matchingHref);
        }
        assert(privacyVisible, label + '_PRIVACY_NOTICE_MISSING');
        console.log(label + '_URGENT_HELP_AND_PRIVACY=PASS');
      }
      console.log(actor.label + '_CURRENT_PREVIEW_B2C_AND_DIARY_EXPORT=PASS');
      return { context: preview, userId: session.id, owned };
    } catch (e) {
      await preview.close();
      throw e;
    }
  } finally {
    await context.close();
  }
}
// No private screenshots/artifacts: only structural assertions on real signed-in pages.
async function checkResponsivePrivacy(browser, account) {
  const source = (await account.context.cookies(PREVIEW_ORIGIN))
    .find(c => c.name === 'auth-tokens' && c.httpOnly && c.secure);
  assert(source, 'RESPONSIVE_QA_COOKIE_MISSING');
  for (const device of [
    { label: 'DESKTOP', width: 1440, height: 900, mobile: false },
    { label: 'MOBILE_PORTRAIT', width: 390, height: 844, mobile: true },
    { label: 'MOBILE_LANDSCAPE', width: 844, height: 390, mobile: true },
  ]) {
    const context = await browser.newContext({
      viewport: { width: device.width, height: device.height },
      isMobile: device.mobile, hasTouch: device.mobile, serviceWorkers: 'block',
    });
    try {
      await context.addCookies([{
        name: source.name, value: source.value, domain: new URL(PREVIEW_ORIGIN).hostname,
        path: source.path, httpOnly: true, secure: true, sameSite: source.sameSite,
        ...(source.expires > 0 ? { expires: source.expires } : {}),
      }]);
      const page = await context.newPage();
      for (const route of ['/en/my-day', '/en/diary']) {
        const response = await page.goto(PREVIEW_ORIGIN + route, {
          waitUntil: 'domcontentloaded', timeout: 35000,
        });
        assert(response?.status() === 200 && new URL(page.url()).pathname === route,
          'QA_' + device.label + '_PROTECTED_PAGE_FAILED');
        const emergency = page.getByText('Need urgent help?', { exact: true });
        await emergency.waitFor({ state: 'visible', timeout: 12000 });
        const dimensions = await page.evaluate(() => ({
          pageWidth: document.documentElement.scrollWidth,
          viewportWidth: window.innerWidth,
        }));
        assert(dimensions.pageWidth <= dimensions.viewportWidth + 2,
          'QA_' + device.label + '_HORIZONTAL_OVERFLOW');
      }
      console.log('DZVIN_QA_' + device.label + '_SAFETY_RESPONSIVE=PASS');
    } finally {
      await context.close();
    }
  }
}
// Explicit opt-in: this rotates a disposable QA user's refresh token, so run
// only after the read-only and ownership checks have completed.
async function checkExpiredSession(browser, account) {
  if (process.env.DZVIN_QA_EXPIRED_SESSION_ACK !== '1') {
    console.log('DZVIN_EXPIRED_TWO_TAB_REFRESH=NOT_TESTED_APPROVAL_REQUIRED');
    return;
  }
  const original = (await account.context.cookies(PREVIEW_ORIGIN))
    .find(c => c.name === 'auth-tokens' && c.httpOnly && c.secure);
  assert(original, 'QA_REFRESH_SOURCE_COOKIE_MISSING');
  let token;
  try { token = JSON.parse(original.value); } catch { throw new Error('QA_REFRESH_COOKIE_NOT_JSON'); }
  assert(typeof token.refreshToken === 'string' && token.refreshToken.length > 0,
    'QA_REFRESH_TOKEN_REQUIRED');
  assert(Number.isFinite(token.expiresAt), 'QA_EXPIRY_METADATA_INVALID');
  token.expiresAt = Math.floor(Date.now() / 1000) - 60;
  const context = await browser.newContext({ serviceWorkers: 'block' });
  try {
    await context.addCookies([{
      name: original.name, value: JSON.stringify(token), domain: new URL(PREVIEW_ORIGIN).hostname,
      path: original.path, httpOnly: true, secure: true, sameSite: original.sameSite,
      ...(original.expires > 0 ? { expires: original.expires } : {}),
    }]);
    const a = await context.newPage();
    const b = await context.newPage();
    await Promise.all([a.goto(PREVIEW_ORIGIN + '/en/my-day', { waitUntil: 'domcontentloaded' }),
      b.goto(PREVIEW_ORIGIN + '/en/my-day', { waitUntil: 'domcontentloaded' })]);
    const reached = page => page.waitForURL(url => url.origin === PREVIEW_ORIGIN &&
      url.pathname === '/en/my-day', { timeout: 60000 });
    await Promise.all([reached(a), reached(b)]);
    const validated = await context.request.get(PREVIEW_ORIGIN + '/api/auth/session');
    assert(validated.status() === 200, 'QA_REFRESH_BACKEND_SESSION_INVALID');
    const user = await validated.json();
    assert(user?.id === account.userId, 'QA_REFRESH_SUBJECT_CHANGED');
    const updated = (await context.cookies(PREVIEW_ORIGIN)).find(c => c.name === 'auth-tokens');
    assert(updated?.httpOnly && updated?.secure && updated.value !== JSON.stringify(token),
      'QA_REFRESH_COOKIE_NOT_ROTATED');
    console.log('DZVIN_EXPIRED_TWO_TAB_REFRESH=PASS');
  } finally {
    await context.close();
  }
}
async function main() {
  validateInputs();
  const browser = await chromium.launch({ headless: true });
  const active = [];
  try {
    for (const actor of users) active.push(await login(browser, actor));
    assert(active[0].userId !== active[1].userId, 'NOT_TWO_DISTINCT_USERS');

    let successfulDirections = 0;
    for (const [viewer, target] of [[active[0], active[1]], [active[1], active[0]]]) {
      if (!target.owned.length) continue;
      const id = target.owned[0];
      const denied = await viewer.context.request.get(PREVIEW_ORIGIN + '/api/backend/diary/' + id);
      assert(denied.status() === 404, 'FOREIGN_DIARY_NOT_HIDDEN');
      assert((denied.headers()['cache-control'] || '').includes('no-store'),
        'FOREIGN_DENIAL_CACHE_POLICY_MISSING');
      successfulDirections++;
    }
    console.log('DZVIN_QA_TWO_USER_CROSS_READ=' +
      (successfulDirections === 2 ? 'PASS_BOTH' :
       successfulDirections === 1 ? 'PASS_ONE_DIRECTION_QA_FIXTURE_MISSING' :
       'NOT_TESTED_NO_OWNER_FIXTURES'));
    assert(successfulDirections >= 1, 'QA_DIARY_FIXTURES_MISSING');
    await checkResponsivePrivacy(browser, active[0]);
    await checkExpiredSession(browser, active[0]);
    console.log('DZVIN_QA_CURRENT_PREVIEW_READONLY=PASS_LIMITED');
    console.log('DZVIN_QA_EXPECTED_FRONT_SHA=' + FRONT_SHA);
    console.log('DZVIN_QA_DIARY_CREATE_DELETE_E2E=NOT_TESTED');
  } finally {
    await Promise.all(active.map(a => a.context.close()));
    await browser.close();
  }
}
main().catch(error => {
  // Never print browser exception details: redirect URLs may contain OAuth codes.
  const code = error instanceof Error && /^[A-Z0-9_]{5,100}$/.test(error.message)
    ? error.message : 'SANITIZED_TEST_FAILURE';
  console.error('DZVIN_QA_CURRENT_PREVIEW=FAIL:' + code);
  process.exitCode = 1;
});

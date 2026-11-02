/**
 * Read-only, manual two-account B2C QA acceptance on the exact newer
 * Vercel preview. Credentials remain inside the protected GitHub runner.
 * The established Zitadel callback completes on the existing dev alias;
 * a scoped HttpOnly test cookie is copied in-memory to this other preview.
 * This proves authenticated BFF behavior but NOT an independent OAuth
 * callback registration for the new hostname.
 *
 * Never log personal diary text, secrets, cookies, subject IDs or response bodies.
 * Only rejected CSRF POSTs and a scoped QA cookie logout; no backend data writes or private artifacts.
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
      // Enforce the same B2C denylist on direct GET and same-origin POST,
      // not merely on hidden navigation. GET must deny before attempting any POST.
      for (const path of [
        '/api/backend/mood-risk/actionable',
        '/api/backend/mood-feed',
        '/api/backend/companies',
        '/api/backend/admin',
        '/api/backend/dip-admin/organizations',
        '/api/backend/research/projects',
        '/api/backend/decision-support',
        '/api/backend/team/v1/overview',
        '/api/backend/operational/v1/reports',
        '/api/backend/prediction',
      ]) {
        const deniedRead = await preview.request.get(PREVIEW_ORIGIN + path);
        assert(deniedRead.status() === 404, actor.label + '_B2C_READ_SCOPE_BYPASS');
        const deniedWrite = await preview.request.post(PREVIEW_ORIGIN + path, {
          headers: { origin: PREVIEW_ORIGIN, 'content-type': 'application/json' },
          data: {}, maxRedirects: 0,
        });
        assert(deniedWrite.status() === 404, actor.label + '_B2C_WRITE_SCOPE_BYPASS');
      }
      console.log(actor.label + '_PRIVILEGED_B2C_GET_POST_DENIED=PASS');
      // Production/dev dailyHabits.ts decoder must agree with the real BFF wire contract.
      const habits = await preview.request.get(
        PREVIEW_ORIGIN + '/api/backend/daily-habits?timeZone=Europe%2FWarsaw'
      );
      assert(habits.status() === 200, actor.label + '_DAILY_HABITS_GET_FAILED');
      assert((habits.headers()['cache-control'] || '').includes('no-store'),
        actor.label + '_HABITS_CACHE_POLICY_MISSING');
      const habitRows = await habits.json();
      const kinds = ['breathing', 'movement', 'journaling', 'screenBreak'];
      assert(Array.isArray(habitRows) && habitRows.length <= kinds.length &&
        habitRows.every(row => kinds.includes(row?.kind) && typeof row.doneToday === 'boolean') &&
        new Set(habitRows.map(row => row.kind)).size === habitRows.length,
        actor.label + '_DAILY_HABITS_CONTRACT_INVALID');
      console.log(actor.label + '_DAILY_HABITS_READONLY=PASS');
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
// No mutation to the shared backend: verify authenticated mood reads and schema only.
async function checkMoodHistory(accounts) {
  for (let i = 0; i < accounts.length; i++) {
    const label = 'QA' + (i + 1);
    const account = accounts[i];
    const response = await account.context.request.get(
      PREVIEW_ORIGIN + '/api/backend/mood-record?page=1&limit=50&order=newest'
    );
    assert(response.status() === 200, label + '_MOOD_HISTORY_READ_FAILED');
    assert((response.headers()['cache-control'] || '').includes('no-store'),
      label + '_MOOD_HISTORY_PRIVATE_CACHE');
    const data = await response.json();
    assert(Array.isArray(data), label + '_MOOD_HISTORY_CONTRACT_INVALID');
    for (const entry of data) {
      assert(typeof entry.id === 'string' && Number.isFinite(Date.parse(entry.createdAt)),
        label + '_MOOD_HISTORY_DATE_INVALID');
      for (const dimension of ['moodLevel', 'stressLevel', 'energyLevel', 'focusLevel']) {
        assert(typeof entry[dimension] === 'number' && Number.isFinite(entry[dimension]),
          label + '_MOOD_HISTORY_DIMENSION_MISSING');
      }
      assert(entry.tags == null || Array.isArray(entry.tags),
        label + '_MOOD_HISTORY_TAGS_INVALID');
    }
    console.log(label + '_MOOD_HISTORY=' + (data.length ? 'PASS_EXISTING_ENTRIES' : 'NOT_TESTED_EMPTY'));
  }
}
// Logout is isolated to a copied test cookie; it cannot log out the original QA context.
async function checkLogout(browser, account) {
  const source = (await account.context.cookies(PREVIEW_ORIGIN))
    .find(c => c.name === 'auth-tokens' && c.httpOnly && c.secure);
  assert(source, 'QA_LOGOUT_COOKIE_NOT_FOUND');
  const isolated = await browser.newContext({ serviceWorkers: 'block' });
  try {
    await isolated.addCookies([{
      name: source.name, value: source.value, domain: new URL(PREVIEW_ORIGIN).hostname,
      path: source.path, httpOnly: true, secure: true, sameSite: source.sameSite,
      ...(source.expires > 0 ? { expires: source.expires } : {}),
    }]);
    const before = await isolated.request.get(PREVIEW_ORIGIN + '/api/auth/session');
    assert(before.status() === 200, 'QA_LOGOUT_PRE_SESSION_MISSING');
    const denied = await isolated.request.post(PREVIEW_ORIGIN + '/api/auth/logout',
      { maxRedirects: 0 });
    assert(denied.status() === 403, 'QA_LOGOUT_CSRF_MISSING_ORIGIN_BYPASS');
    const logout = await isolated.request.post(PREVIEW_ORIGIN + '/api/auth/logout', {
      headers: { origin: PREVIEW_ORIGIN }, maxRedirects: 0,
    });
    assert(logout.status() === 303, 'QA_LOGOUT_REDIRECT_INVALID');
    const location = new URL(logout.headers()['location'] ?? '', PREVIEW_ORIGIN);
    assert(location.protocol === 'https:' && location.origin !== PREVIEW_ORIGIN &&
      location.pathname.endsWith('/oidc/v1/end_session'), 'QA_LOGOUT_IDP_REDIRECT_INVALID');
    const after = await isolated.request.get(PREVIEW_ORIGIN + '/api/auth/session');
    assert(after.status() === 401, 'QA_LOGOUT_SESSION_STILL_PRESENT');
    const deniedPrivate = await isolated.request.get(PREVIEW_ORIGIN + '/api/backend/diary/user');
    assert(deniedPrivate.status() === 401, 'QA_LOGOUT_PRIVATE_BACKEND_ACCESS');
    console.log('DZVIN_QA_LOGOUT_CSRF_COOKIE_AND_PRIVATE_DENIAL=PASS');
  } finally {
    await isolated.close();
  }
}
// Exercise unauthenticated HTTP boundary against the exact preview without invoking IdP tokens.
async function checkExchangeProvenance(browser) {
  const context = await browser.newContext({ serviceWorkers: 'block' });
  try {
    const url = PREVIEW_ORIGIN + '/api/auth/exchange';
    const post = (data, headers = {}) => context.request.post(url, {
      data, headers: { 'content-type': 'application/json', ...headers }, maxRedirects: 0,
    });
    const cases = [
      ['MISSING_ORIGIN', '{}', {}, 403],
      ['FOREIGN_ORIGIN', '{}', { origin: 'https://malicious.invalid' }, 403],
      ['FORGED_FETCH_METADATA', '{}', { origin: PREVIEW_ORIGIN, 'sec-fetch-site': 'cross-site' }, 403],
      ['MALFORMED_JSON', '{', { origin: PREVIEW_ORIGIN }, 400],
      ['OVERSIZED_JSON', JSON.stringify({ filler: 'a'.repeat(9000) }), { origin: PREVIEW_ORIGIN }, 413],
      ['INVALID_GRANT', JSON.stringify({ grantType: 'invalid' }), { origin: PREVIEW_ORIGIN }, 400],
      ['MISSING_REFRESH_COOKIE', JSON.stringify({ grantType: 'refresh_token' }), { origin: PREVIEW_ORIGIN }, 400],
    ];
    for (const [label, payload, headers, status] of cases) {
      const response = await post(payload, headers);
      assert(response.status() === status, 'QA_EXCHANGE_' + label + '_STATUS');
      assert((response.headers()['cache-control'] || '').includes('no-store'),
        'QA_EXCHANGE_' + label + '_CACHE');
      const result = await response.json();
      const message = JSON.stringify(result);
      assert(!/access_token|refresh_token|client_secret|stack|trace|ZITADEL_CLIENT_SECRET/i.test(message),
        'QA_EXCHANGE_' + label + '_SECRET_LEAK');
      console.log('DZVIN_QA_EXCHANGE_' + label + '=PASS');
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
  // Playwright exposes the wire value (percent-encoded by Next.js), unlike NextRequest.cookies.
  try { token = JSON.parse(decodeURIComponent(original.value)); } catch { throw new Error('QA_REFRESH_COOKIE_NOT_JSON'); }
  assert(typeof token.refreshToken === 'string' && token.refreshToken.length > 0,
    'QA_REFRESH_TOKEN_REQUIRED');
  assert(Number.isFinite(token.expiresAt), 'QA_EXPIRY_METADATA_INVALID');
  token.expiresAt = Math.floor(Date.now() / 1000) - 60;
  const expiredCookieValue = encodeURIComponent(JSON.stringify(token));
  const context = await browser.newContext({ serviceWorkers: 'block' });
  try {
    await context.addCookies([{
      name: original.name, value: expiredCookieValue, domain: new URL(PREVIEW_ORIGIN).hostname,
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
    assert(updated?.httpOnly && updated?.secure && updated.value !== expiredCookieValue,
      'QA_REFRESH_COOKIE_NOT_ROTATED');
    // Real hard reload and idle-tab return after a concurrent cookie rotation.
    const hardReload = await a.reload({ waitUntil: 'domcontentloaded', timeout: 35000 });
    assert(hardReload?.status() === 200 && new URL(a.url()).pathname === '/en/my-day',
      'QA_REFRESH_HARD_RELOAD_FAILED');
    await b.bringToFront();
    await b.waitForTimeout(15_000);
    await a.bringToFront();
    const focused = await context.request.get(PREVIEW_ORIGIN + '/api/auth/session');
    assert(focused.status() === 200, 'QA_REFRESH_IDLE_RETURN_SESSION_FAILED');
    const focusedUser = await focused.json();
    assert(focusedUser?.id === account.userId, 'QA_REFRESH_IDLE_RETURN_SUBJECT_CHANGED');
    const bReload = await b.reload({ waitUntil: 'domcontentloaded', timeout: 35000 });
    assert(bReload?.status() === 200 && new URL(b.url()).pathname === '/en/my-day',
      'QA_REFRESH_SECOND_TAB_RELOAD_FAILED');
    console.log('DZVIN_QA_HARD_RELOAD_AND_IDLE_TAB_RETURN=PASS');
    console.log('DZVIN_EXPIRED_TWO_TAB_REFRESH=PASS');
  } finally {
    await context.close();
  }
}
async function main() {
  validateInputs();
  const browser = await chromium.launch({ headless: true });
  await checkExchangeProvenance(browser);
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
    await checkMoodHistory(active);
    await checkResponsivePrivacy(browser, active[0]);
    await checkExpiredSession(browser, active[0]);
    await checkLogout(browser, active[0]);
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

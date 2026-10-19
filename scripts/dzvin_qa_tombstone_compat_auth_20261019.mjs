/**
 * One-time, credential-backed authentication for Dzvin diary E2E.
 * The existing Zitadel callback is registered for the dev alias. The
 * server-signed HttpOnly cookie is copied in memory to the pinned preview.
 * Credentials and resulting Playwright storageStates never leave the runner.
 *
 * This script performs only reads; the export verifier never mutates records.
 */
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const LOGIN_ORIGIN = 'https://mentality-web.vercel.app';
const PREVIEW_ORIGIN = 'https://mentality-ho9v3tydz-taras-gezs-projects.vercel.app';
const PREVIEW_DEPLOYMENT = 'dpl_GTj2HAr1GTsk2cDk6zFsiWdM1PZy';
const actors = [
  {
    label: 'QA1',
    email: process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN,
    password: process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD,
  },
  {
    label: 'QA2',
    email: process.env.QDIP_E2E_ZITADEL_TEST2_LOGIN,
    password: process.env.QDIP_E2E_ZITADEL_TEST2_PASSWORD,
  },
];

function assert(value, code) {
  if (!value) throw new Error(code);
}
function preflight() {
  assert(process.env.DZVIN_MOOD_EXPORT_READONLY_ACK === '1', 'SCOPED_QA_APPROVAL_REQUIRED');
  assert(process.env.E2E_BASE_URL === PREVIEW_ORIGIN, 'PREVIEW_ORIGIN_NOT_PINNED');
  assert(process.env.E2E_ALLOWED_MUTATION_ORIGIN === PREVIEW_ORIGIN, 'QA_ORIGIN_NOT_ALLOWLISTED');
  assert(process.env.E2E_QA_SHARED_BACKEND_SCOPED_APPROVED === '1', 'SCOPED_BACKEND_APPROVAL_MISSING');
  assert(process.env.E2E_DISPOSABLE_TENANT_CONFIRMED !== '1', 'SHARED_BACKEND_NOT_DISPOSABLE');
  assert(process.env.E2E_DEPLOYED_WEB_SHA === 'ec4a1875ebc9e6e3300d9728c3859dff88da3d79',
    'WEB_SHA_NOT_PINNED');
  assert(process.env.E2E_DEPLOYED_BACKEND_SHA === '8894bfcd1ed3d5f1a99e526e64fbbc007abc31ae',
    'BACKEND_SHA_NOT_PINNED');
  assert(process.env.GITHUB_WORKSPACE, 'RUNNER_WORKSPACE_REQUIRED');
  for (const actor of actors) {
    assert(Boolean(actor.email && actor.password), actor.label + '_SECRET_MISSING');
  }
  assert(actors[0].email.toLowerCase() !== actors[1].email.toLowerCase(),
    'DISTINCT_QA_USERS_REQUIRED');
}

async function findVisible(page, selectors, timeout = 12000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) {
    for (const selector of selectors) {
      const el = page.locator(selector).first();
      if (await el.isVisible().catch(() => false)) return el;
    }
    await page.waitForTimeout(250);
  }
  return null;
}

async function login(browser, actor) {
  const loginContext = await browser.newContext({
    ignoreHTTPSErrors: false,
    serviceWorkers: 'block',
  });
  let preview;
  try {
    const page = await loginContext.newPage();
    let pkceVerified = false;
    page.on('request', request => {
      try {
        const url = new URL(request.url());
        if (url.pathname.endsWith('/oauth/v2/authorize')) {
          const cb = url.searchParams.get('redirect_uri');
          if (cb && new URL(cb).origin === LOGIN_ORIGIN &&
              url.searchParams.get('code_challenge_method') === 'S256') {
            pkceVerified = true;
          }
        }
      } catch { /* Never print IdP URLs containing codes. */ }
    });
    await page.goto(LOGIN_ORIGIN + '/en/auth', {
      waitUntil: 'domcontentloaded',
      timeout: 30000,
    });
    await page.waitForURL(url => url.origin !== LOGIN_ORIGIN, { timeout: 24000 });
    assert(pkceVerified, actor.label + '_OIDC_CALLBACK_OR_PKCE_INVALID');

    const username = await findVisible(page, [
      'input[autocomplete="username"]',
      'input[name="loginName"]',
      'input[name="loginname"]',
      'input[name="username"]',
      'input[name="email"]',
      'input[type="email"]',
      'input[type="text"]',
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
    await password.press('Enter'); // Exactly one password submission.
    let session = null;
    for (let i = 0; i < 20; i++) {
      await page.waitForTimeout(800);
      const result = await loginContext.request.get(LOGIN_ORIGIN + '/api/auth/session', {
        maxRedirects: 0,
        timeout: 9000,
      }).catch(() => null);
      if (result?.status() === 200) {
        session = await result.json().catch(() => null);
        if (session?.id) break;
      }
    }
    assert(session?.id, actor.label + '_ZITADEL_SESSION_MISSING');
    assert(session.email?.toLowerCase() === actor.email.toLowerCase(),
      actor.label + '_SESSION_EMAIL_MISMATCH');
    assert(session.role !== 'admin', actor.label + '_ADMIN_NOT_ALLOWED');

    const source = (await loginContext.cookies(LOGIN_ORIGIN)).find(cookie =>
      cookie.name === 'auth-tokens' && cookie.httpOnly && cookie.secure);
    assert(source, actor.label + '_HTTPONLY_COOKIE_MISSING');

    preview = await browser.newContext({
      ignoreHTTPSErrors: false,
      serviceWorkers: 'block',
      acceptDownloads: true,
    });
    await preview.addCookies([{
      name: source.name,
      value: source.value,
      domain: new URL(PREVIEW_ORIGIN).hostname,
      path: source.path,
      httpOnly: true,
      secure: true,
      sameSite: source.sameSite,
      ...(source.expires > 0 ? { expires: source.expires } : {}),
    }]);
    const identity = await preview.request.get(PREVIEW_ORIGIN + '/api/auth/session', {
      maxRedirects: 0,
    });
    assert(identity.status() === 200, actor.label + '_PREVIEW_SESSION_INVALID');
    const previewSession = await identity.json();
    assert(previewSession.id === session.id &&
      previewSession.email?.toLowerCase() === actor.email.toLowerCase(),
      actor.label + '_PREVIEW_SESSION_MISMATCH');
    const diary = await preview.request.get(PREVIEW_ORIGIN + '/en/diary', {
      maxRedirects: 0,
    });
    assert(diary.status() === 200, actor.label + '_DIARY_PREVIEW_NOT_ACCESSIBLE');
    const html = await diary.text();
    assert(html.includes('data-dpl-id="' + PREVIEW_DEPLOYMENT + '"'),
      actor.label + '_PREVIEW_DEPLOYMENT_MISMATCH');

    const list = await preview.request.get(PREVIEW_ORIGIN + '/api/backend/diary/user');
    assert(list.status() === 200, actor.label + '_BACKEND_SCOPED_READ_FAILED');
    assert((list.headers()['cache-control'] || '').includes('no-store'),
      actor.label + '_PRIVATE_CACHE_POLICY_MISSING');
    const notes = await list.json();
    assert(Array.isArray(notes), actor.label + '_BAD_DIARY_LIST_CONTRACT');

    const state = await preview.storageState();
    assert(state.cookies.filter(c => c.name === 'auth-tokens').length === 1,
      actor.label + '_PREVIEW_AUTH_COOKIE_NOT_UNIQUE');
    assert(state.cookies.every(c => c.domain === new URL(PREVIEW_ORIGIN).hostname),
      actor.label + '_PREVIEW_COOKIE_DOMAIN_LEAK');
    console.log(actor.label + '_ZITADEL_LOGIN_AND_SCOPED_PREVIEW=PASS');
    return { state, userId: session.id };
  } finally {
    await loginContext.close();
    await preview?.close();
  }
}
async function main() {
  preflight();
  const browser = await chromium.launch({ headless: true });
  try {
    const a = await login(browser, actors[0]);
    const b = await login(browser, actors[1]);
    assert(a.userId !== b.userId, 'QA_IDENTITIES_NOT_DISTINCT');
    // All writes are restricted to the dedicated QA account cookies in
    // this single job. No files or artifacts containing secrets are uploaded.
    const auth = join(process.cwd(), 'playwright', '.auth');
    mkdirSync(auth, { recursive: true, mode: 0o700 });
    const entries = [
      ['b2c-a.json', a.state],
      ['b2c-b.json', b.state],
    ];
    for (const [filename, state] of entries) {
      writeFileSync(join(auth, filename), JSON.stringify(state), { mode: 0o600 });
    }
    const safeId = id => /^[A-Za-z0-9_-]+$/.test(id || '');
    assert(safeId(a.userId) && safeId(b.userId), 'QA_SERVER_ID_NOT_SHELL_SAFE');
    const encoded = state => Buffer.from(JSON.stringify(state)).toString('base64');
    const lines = [
      'E2E_QA_A_USER_ID=' + a.userId,
      'E2E_QA_B_USER_ID=' + b.userId,
      'E2E_B2C_A_STORAGE_STATE_BASE64=' + encoded(a.state),
      'E2E_B2C_B_STORAGE_STATE_BASE64=' + encoded(b.state),
    ];
    writeFileSync(join(auth, 'qa-approval.env'), lines.join('\n') + '\n', { mode: 0o600 });
    console.log('DZVIN_QA_CREDENTIALS_AND_PINNED_IDS=READY_FOR_READONLY_EXPORT_CHECK');
  } finally {
    await browser.close();
  }
}
main().catch(error => {
  // Redact errors: browser and IdP errors may contain secrets/codes.
  const code = error instanceof Error && /^[A-Z0-9_]{5,100}$/.test(error.message)
    ? error.message : 'SANITIZED_QA_LOGIN_FAILURE';
  console.error('DZVIN_QA_SETUP=FAIL:' + code);
  process.exitCode = 1;
});
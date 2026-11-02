import { chromium, request } from '@playwright/test';

const LOGIN = 'https://mentality-web.vercel.app';
const API = 'https://dzvin-b2c-rc-build-qa.up.railway.app';
const actors = [
  { name: 'QA1', login: process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN, password: process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD },
  { name: 'QA2', login: process.env.QDIP_E2E_ZITADEL_TEST2_LOGIN, password: process.env.QDIP_E2E_ZITADEL_TEST2_PASSWORD },
];
const assert = (condition, message) => { if (!condition) throw new Error(message); };

async function field(page, selectors, timeout = 12000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    for (const selector of selectors) {
      const element = page.locator(selector).first();
      if (await element.isVisible().catch(() => false)) return element;
    }
    await page.waitForTimeout(250);
  }
  throw Error('ZITADEL_FIELD_MISSING');
}

async function tokenFromLogin(browser, actor) {
  const context = await browser.newContext({ serviceWorkers: 'block' });
  try {
    const page = await context.newPage();
    await page.goto(LOGIN + '/en/auth', { waitUntil: 'domcontentloaded', timeout: 30000 });
    const user = await field(page, ['input[autocomplete="username"]', 'input[name="loginName"]', 'input[name="username"]', 'input[type="email"]', 'input[type="text"]']);
    await user.fill(actor.login);
    let password = await field(page, ['input[autocomplete="current-password"]', 'input[type="password"]'], 1500).catch(() => null);
    if (!password) {
      await user.press('Enter');
      password = await field(page, ['input[autocomplete="current-password"]', 'input[type="password"]']);
    }
    await password.fill(actor.password);
    await password.press('Enter');
    let session = null;
    for (let i = 0; i < 25; i++) {
      await page.waitForTimeout(800);
      const result = await context.request.get(LOGIN + '/api/auth/session', { timeout: 9000 }).catch(() => null);
      if (result?.status() === 200) {
        session = await result.json().catch(() => null);
        if (session?.id) break;
      }
    }
    assert(session?.email?.toLowerCase() === actor.login.toLowerCase(), actor.name + '_IDENTITY_MISMATCH');
    const cookie = (await context.cookies(LOGIN)).find(c => c.name === 'auth-tokens' && c.httpOnly && c.secure);
    assert(cookie, actor.name + '_AUTH_COOKIE_MISSING');
    const stored = JSON.parse(decodeURIComponent(cookie.value));
    assert(typeof stored.accessToken === 'string' && stored.accessToken.length > 20, actor.name + '_TOKEN_MISSING');
    console.log(actor.name + '_ZITADEL_LOGIN=PASS');
    return stored.accessToken;
  } finally {
    await context.close();
  }
}

async function main() {
  assert(process.env.DZVIN_DISPOSABLE_DB_RESET_ACK === '1', 'RESET_ACK_MISSING');
  assert(actors.every(a => a.login && a.password), 'QA_SECRETS_MISSING');
  const browser = await chromium.launch({ headless: true });
  try {
    for (const actor of actors) {
      const token = await tokenFromLogin(browser, actor);
      const api = await request.newContext({ baseURL: API, extraHTTPHeaders: { Authorization: 'Bearer ' + token } });
      try {
        const validation = await api.post('/api/auth/validate-token');
        assert([201, 202].includes(validation.status()), actor.name + '_VALIDATION_' + validation.status());
        const mood = await api.get('/api/mood-record');
        assert(mood.status() === 200, actor.name + '_MOOD_HTTP_' + mood.status());
        const records = await mood.json();
        assert(Array.isArray(records) && records.length === 0, actor.name + '_MOOD_RECORDS_REMAIN');
        const feed = await api.get('/api/mood-feed');
        assert(feed.status() === 200, actor.name + '_FEED_HTTP_' + feed.status());
        const messages = await feed.json();
        assert(Array.isArray(messages) && messages.length === 0, actor.name + '_FEED_SIDE_EFFECTS_REMAIN');
        const story = await api.get('/api/mood-story/latest');
        assert(story.status() === 404, actor.name + '_STORY_SIDE_EFFECTS_REMAIN_' + story.status());
        const tags = await api.get('/api/user-tags');
        assert(tags.status() === 200, actor.name + '_TAGS_HTTP_' + tags.status());
        assert(Array.isArray(await tags.json()) && (await tags.json()).length === 0, actor.name + '_TAG_FIXTURE_REMAINS');
        console.log(actor.name + '_MOOD_FEED_STORY_TAG_TEARDOWN=PASS');
      } finally {
        await api.dispose();
      }
    }
    console.log('DZVIN_ISOLATED_MONGO_POST_RESET_READBACK=PASS');
  } finally {
    await browser.close();
  }
}
main().catch(error => {
  const reason = error instanceof Error && /^[A-Z0-9_]{5,100}$/.test(error.message) ? error.message : 'REDACTED_ERROR';
  console.error('DZVIN_ISOLATED_MONGO_POST_RESET_READBACK=FAIL:' + reason);
  process.exitCode = 1;
});

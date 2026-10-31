/** Real AutoDev claimed-recovery browser E2E. No fake HTTP, permits or model calls.
 * Modes: anonymous (safe default), review (read-only, real stage closer),
 * close-claimed (one operator-approved irreversible state transition).
 * Never emit JWTs, passwords, request bodies, screenshots or user profiles.
 */
import { chromium } from '@playwright/test';
import { createPublicKey, verify, randomUUID } from 'node:crypto';

const SITE = 'https://autodev.qdip.ai';
const ISSUER = 'https://mentality-rmwj0i.eu1.zitadel.cloud';
const PROJECT = '394565917515719957';
const ORG = '368555767923594379';
const CLIENT = '395658023814660262';
const MODES = new Set(['anonymous', 'review', 'close-claimed']);
const mode = process.env.QDIP_AUTODEV_RECOVERY_MODE || 'anonymous';
const runId = process.env.QDIP_AUTODEV_RECOVERY_RUN_ID || '';
const login = process.env.QDIP_AUTODEV_CLOSER_LOGIN;
const password = process.env.QDIP_AUTODEV_CLOSER_PASSWORD;
const targetRun = /^rr388-[0-9a-f]{20}$/;
const views = [['desktop', 1440, 900], ['portrait', 390, 844], ['landscape', 844, 390]];
const check = (condition, reason) => { if (!condition) throw Error(reason); };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function safeError(error) {
 const code = error instanceof Error ? error.message : '';
 return /^[A-Z0-9_]{5,90}$/.test(code) ? code : 'UNEXPECTED_FAILURE_REDACTED';
}
async function api(context, token, path, options = {}) {
 return context.request.fetch(SITE + path, {
  method: options.method || 'GET',
  headers: {
   'Origin': SITE, 'Authorization': token ? 'Bearer ' + token : '',
   'Accept': 'application/json',
   ...(options.body ? { 'Content-Type': 'application/json',
                     'Idempotency-Key': options.requestId } : {}),
  },
  ...(options.body ? {data: options.body} : {}),
  maxRedirects: 0, failOnStatusCode: false, timeout: 12000,
 });
}
function tokenFromStore() {
 for (const storage of [localStorage, sessionStorage]) {
  for (let i = 0; i < storage.length; i++) {
   const key = storage.key(i);
   if (!key?.startsWith('oidc.user:')) continue;
   try {
    const user = JSON.parse(storage.getItem(key) || '{}');
    if (typeof user.access_token === 'string') return user.access_token;
   } catch {}
  }
 }
 return null;
}
async function field(page, selectors, timeout = 12000) {
 const end = Date.now() + timeout;
 while (Date.now() < end) {
  for (const selector of selectors) {
   const input = page.locator(selector).first();
   if (await input.isVisible().catch(() => false)) return input;
  }
  await page.waitForTimeout(200);
 }
 return null;
}
async function signedStageCloser(token) {
 check(typeof token === 'string' && token.length < 8192, 'OIDC_ACCESS_TOKEN_MISSING');
 const parts = token.split('.');
 check(parts.length === 3, 'OIDC_JWT_REQUIRED');
 const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
 const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
 check(['RS256', 'RS384'].includes(header.alg) && typeof header.kid === 'string',
       'OIDC_JWT_ALGORITHM_INVALID');
 const response = await fetch(ISSUER + '/oauth/v2/keys',
  {signal: AbortSignal.timeout(12000), redirect:'error'});
 check(response.ok, 'OIDC_JWKS_NOT_AVAILABLE');
 const jwks = await response.json();
 const key = jwks.keys?.find(k => k.kty === 'RSA' && k.kid === header.kid);
 check(Boolean(key), 'OIDC_SIGNING_KEY_MISSING');
 check(verify(header.alg === 'RS384' ? 'RSA-SHA384' : 'RSA-SHA256',
  Buffer.from(parts[0] + '.' + parts[1]),
  createPublicKey({key, format:'jwk'}), Buffer.from(parts[2], 'base64url')),
  'OIDC_JWT_SIGNATURE_INVALID');
 const now = Math.floor(Date.now() / 1000);
 check(claims.iss === ISSUER && typeof claims.sub === 'string'
  && claims.exp > now && claims.iat <= now + 20
  && (claims.aud === PROJECT ||
      Array.isArray(claims.aud) && claims.aud.includes(PROJECT)),
  'OIDC_JWT_SCOPE_INVALID');
 const roles = claims['urn:zitadel:iam:org:project:' + PROJECT + ':roles'];
 check(Boolean(roles?.autodev_stage_closer?.[ORG])
       && Boolean(roles?.autodev_operator?.[ORG]),
       'OIDC_INDEPENDENT_CLOSER_AND_OPERATOR_ROLES_REQUIRED');
}
async function signIn(context) {
 const page = await context.newPage();
 try {
  const first = await page.goto(SITE, {waitUntil:'domcontentloaded', timeout:30000});
  check(first?.status() === 200, 'PWA_UNAVAILABLE');
  const entry = page.locator('button.live-monitor__login');
  await entry.waitFor({state:'visible', timeout:20000});
  let pkce = null;
  page.on('request', req => {
   try {
    const url = new URL(req.url());
    if (url.origin === ISSUER && url.pathname === '/oauth/v2/authorize')
     pkce = {client:url.searchParams.get('client_id'),
             challenge:url.searchParams.get('code_challenge_method'),
             redirect:url.searchParams.get('redirect_uri')};
   } catch {}
  });
  await entry.click();
  await page.waitForURL(url => url.origin === ISSUER, {timeout:30000});
  check(pkce?.client === CLIENT && pkce.challenge === 'S256'
    && pkce.redirect === SITE + '/auth/callback', 'OIDC_PKCE_MISMATCH');
  const username = await field(page, [
   'input[autocomplete="username"]', 'input[name="loginName"]',
   'input[name="loginname"]', 'input[name="username"]',
   'input[name="email"]', 'input[type="email"]', 'input[type="text"]',
  ]);
  check(Boolean(username), 'OIDC_USERNAME_MISSING');
  await username.fill(login);
  let pass = await field(page, [
   'input[autocomplete="current-password"]', 'input[type="password"]'], 1200);
  if (!pass) {
   await username.press('Enter');
   pass = await field(page, [
    'input[autocomplete="current-password"]', 'input[type="password"]']);
  }
  check(Boolean(pass), 'OIDC_PASSWORD_MISSING');
  await pass.fill(password);
  await pass.press('Enter'); // One password attempt. No fallback to another identity.
  try {
   await page.waitForURL(url => url.origin === SITE, {timeout:45000});
   await page.waitForFunction(tokenFromStore, null, {timeout:18000});
  } catch { throw Error('OIDC_MFA_OR_CALLBACK_BLOCKED'); }
  const token = await page.evaluate(tokenFromStore);
  await signedStageCloser(token);
  const role = await api(context, token, '/v1/autodev/stage-closer/whoami');
  check(role.status() === 200, 'STAGE_CLOSER_HTTP_NOT_200');
  const result = await role.json();
  check(result.granted === true && result.role === 'autodev_stage_closer',
        'STAGE_CLOSER_ROLE_NOT_ACKNOWLEDGED');
  const monitor = await api(context, token, '/v1/autodev/monitor');
  check(monitor.status() === 200, 'OPERATOR_MONITOR_NOT_200');
  return token;
 } finally { await page.close(); }
}
async function anonymous(browser) {
 for (const [name, width, height] of views) {
  const context = await browser.newContext({
   viewport:{width,height},serviceWorkers:'block',ignoreHTTPSErrors:false
  });
  try {
   const page = await context.newPage();
   const errors = [];
   page.on('pageerror', () => errors.push('PAGE_ERROR'));
   const res = await page.goto(SITE, {waitUntil:'networkidle',timeout:30000});
   check(res?.status() === 200, 'PWA_HTTP_NOT_200');
   await page.locator('button.live-monitor__login').waitFor({state:'visible'});
   check(await page.getByText('Потрібен вхід через Zitadel').isVisible(),
         'ANONYMOUS_LOGIN_PROMPT_MISSING');
   check(await page.getByText('Завершити завислу спробу').count() === 0,
         'ANONYMOUS_RECOVERY_VISIBLE');
   check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
         'HORIZONTAL_OVERFLOW');
   check(errors.length === 0, 'BROWSER_PAGE_ERROR');
   const body = {attemptKey:'rr-pilot-attempt:'+'a'.repeat(64),
                 runId:'rr388-'+'b'.repeat(20),
                 action:'CLOSE_CLAIMED_NO_RESULT',
                 requestId:randomUUID(),
                 confirmation:'NO_CHARGE_CONFIRMED:rr388-'+'b'.repeat(20)};
   const denied = await api(context, null, '/v1/autodev/ai-attempts/cancel',
                            {method:'POST', body,requestId:body.requestId});
   check(denied.status() === 403 && (await denied.json()).code === 'NOT_AUTHORIZED',
         'ANONYMOUS_CLOSURE_NOT_DENIED');
   console.log('AUTODEV_RECOVERY_ANONYMOUS_' + name.toUpperCase() + '=PASS');
  } finally {await context.close();}
 }
}
async function operator(browser) {
 check(typeof login === 'string' && login.length > 0
       && typeof password === 'string' && password.length > 0,
       'STAGE_CLOSER_IDENTITY_NOT_CONFIGURED');
 check(targetRun.test(runId), 'RECOVERY_EXACT_RUN_ID_REQUIRED');
 if (mode === 'close-claimed')
  check(process.env.QDIP_AUTODEV_NO_CHARGE_CONFIRMED_RUN === runId
        && process.env.QDIP_AUTODEV_APPROVE_CLOSURE === 'true',
        'OPERATOR_NO_CHARGE_APPROVAL_REQUIRED');
 // Login only once; keep OAuth state exclusively in memory, never persist it.
 const signedContext = await browser.newContext({
  viewport:{width:1440,height:900},serviceWorkers:'block',ignoreHTTPSErrors:false
 });
 let token, storage;
 try {token = await signIn(signedContext);storage = await signedContext.storageState();}
 finally {await signedContext.close();}
 const contexts = [];
 try {
  for (const [name, width, height] of views) {
   const context = await browser.newContext({
    viewport:{width,height},storageState:storage,
    serviceWorkers:'block',ignoreHTTPSErrors:false
   });
   contexts.push(context);
   const review = await api(context, token, '/v1/autodev/ai-attempts/review');
   check(review.status() === 200, 'RECOVERY_REVIEW_HTTP_NOT_200');
   const data = await review.json();
   check(data.schemaVersion === 1 && data.readOnly === true &&
    Array.isArray(data.items), 'RECOVERY_REVIEW_CONTRACT_INVALID');
   const item = data.items.find(x => x.runId === runId);
   check(Boolean(item) && item.repository === 'qdip-ai/qdip-core'
    && item.issueNumber === 388 && item.status === 'OUTCOME_UNKNOWN'
    && item.action === 'CLOSE_CLAIMED_NO_RESULT'
    && /^rr-pilot-attempt:[0-9a-f]{64}$/.test(item.key),
    'RECOVERY_EXACT_CLAIM_NOT_ELIGIBLE');
   const page = await context.newPage();
   const errors = [];
   const posts = [];
   page.on('pageerror', () => errors.push('PAGE_ERROR'));
   page.on('request', request => {
    if (request.method() === 'POST' && new URL(request.url()).pathname
        === '/v1/autodev/ai-attempts/cancel') posts.push(request);
   });
   const response = await page.goto(SITE, {waitUntil:'networkidle',timeout:30000});
   check(response?.status() === 200, 'PWA_HTTP_NOT_200');
   const reviewButton = page.getByRole('button',{
    name:'Звірити AI-спробу для qdip-ai/qdip-core #388'
   });
   await reviewButton.waitFor({state:'visible',timeout:20000});
   await reviewButton.click();
   const close = page.getByRole('button',{name:'Завершити завислу спробу'});
   await close.waitFor({state:'visible',timeout:15000});
   await close.click();
   const input = page.getByRole('textbox',{name:'Точний runId для закриття'});
   await input.waitFor({state:'visible'});
   const confirm = page.locator('.portfolio__cancel-confirm').getByRole('button',{name:'Підтвердити'});
   check(await confirm.isDisabled(), 'CLOSURE_NOT_DISABLED_WITHOUT_CONFIRMATION');
   await input.fill('rr388-'+'0'.repeat(20));
   check(await confirm.isDisabled(), 'CLOSURE_ACCEPTED_WRONG_RUN');
   await input.fill(runId);
   check(await confirm.isEnabled(), 'CLOSURE_DENIED_CORRECT_RUN');
   check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
         'HORIZONTAL_OVERFLOW');
   check(errors.length === 0, 'BROWSER_PAGE_ERROR');
   console.log('AUTODEV_RECOVERY_REVIEW_' + name.toUpperCase() + '=PASS');
   if (mode === 'close-claimed' && name === 'landscape') {
    const resultPromise = page.waitForResponse(r =>
     new URL(r.url()).pathname === '/v1/autodev/ai-attempts/cancel'
     && r.request().method() === 'POST', {timeout:20000});
    await confirm.click(); // Exactly one live irreversible transition.
    const result = await resultPromise;
    check(posts.length === 1, 'RECOVERY_POST_COUNT_INVALID');
    const sent = posts[0].postDataJSON();
    check(sent.attemptKey === item.key && sent.runId === runId
     && sent.action === 'CLOSE_CLAIMED_NO_RESULT'
     && sent.confirmation === 'NO_CHARGE_CONFIRMED:' + runId
     && posts[0].headers()['idempotency-key'] === sent.requestId,
     'RECOVERY_POST_IDENTITY_INVALID');
    check(result.status() === 200, 'RECOVERY_CLOSURE_HTTP_NOT_200');
    const receipt = await result.json();
    check(receipt.status === 'CLOSED' && receipt.attemptKey === item.key
     && receipt.requestId === sent.requestId
     && receipt.providerRetried === false
     && receipt.auditPreserved === true
     && receipt.operatorAssertedNoCharge === true,
     'RECOVERY_ACKNOWLEDGEMENT_INVALID');
    let stillUnresolved = true;
    for (let attempt=0;attempt<8;attempt++) {
     const after = await api(context,token,'/v1/autodev/ai-attempts/review');
     check(after.status() === 200, 'RECOVERY_READBACK_UNAVAILABLE');
     const body = await after.json();
     stillUnresolved = body.items?.some(x=>x.runId === runId);
     if (!stillUnresolved) break;
     await sleep(500);
    }
    check(!stillUnresolved,'RECOVERY_STILL_UNRESOLVED');
    console.log('AUTODEV_RECOVERY_LIVE_OPERATOR_CLAIMED_CLOSE=PASS');
   } else check(posts.length === 0, 'READ_ONLY_MODE_SENT_CLOSURE_POST');
   await page.close();
  }
 } finally {for (const context of contexts) await context.close();}
}
async function main() {
 check(MODES.has(mode), 'INVALID_E2E_MODE');
 const browser = await chromium.launch({headless:true});
 try {
  if (mode === 'anonymous') await anonymous(browser);
  else await operator(browser);
  console.log('AUTODEV_RECOVERY_MODE_' + mode.toUpperCase().replaceAll('-','_') + '=PASS');
 } finally {await browser.close();}
}
main().catch(error => {
 console.error('AUTODEV_RECOVERY_E2E=FAIL:' + safeError(error));
 process.exitCode = 1;
});

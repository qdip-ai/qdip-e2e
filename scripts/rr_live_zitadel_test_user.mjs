/**
 * Credential-bound real Zitadel browser acceptance for the EXISTING test account.
 * Never creates a user, changes roles, or makes RR mutations.
 * No traces, screenshots, video, token/cookie dumps, or auth URLs in output.
 * One login attempt to avoid locking out the existing account.
 */
import { chromium } from '@playwright/test'
import { createHash, randomBytes } from 'node:crypto'

const SITE = 'https://qdip.ai'
const RR = 'https://observatory.qdip.ai'
const TEST_LOGIN = process.env.QDIP_E2E_ZITADEL_TEST_LOGIN
const TEST_PASSWORD = process.env.QDIP_E2E_ZITADEL_TEST_PASSWORD
const EXPECTED_CLIENT = '394566248211424533'
const EXPECTED_PROJECT = '394565917515719957'

const fail = (stage) => { throw new Error(stage) }
const requireStage = (condition, stage) => { if (!condition) fail(stage) }
const safeJson = async (response, stage) => {
  requireStage(response.ok(), stage + '_http')
  try { return await response.json() } catch { fail(stage + '_json') }
}

async function locateVisible(page, selectors, waitMs=10000) {
  const deadline = Date.now() + waitMs
  while (Date.now() < deadline) {
    for (const sel of selectors) {
      const locator = page.locator(sel).first()
      if (await locator.isVisible().catch(() => false)) return locator
    }
    await page.waitForTimeout(300)
  }
  return null
}

async function main() {
  requireStage(typeof TEST_LOGIN === 'string' && TEST_LOGIN.trim().length > 0, 'EXISTING_TEST_LOGIN_SECRET_MISSING')
  requireStage(typeof TEST_PASSWORD === 'string' && TEST_PASSWORD.length > 0, 'EXISTING_TEST_PASSWORD_SECRET_MISSING')

  const browser = await chromium.launch({headless:true})
  const context = await browser.newContext({
    ignoreHTTPSErrors:false,
    serviceWorkers:'block',
    recordVideo: undefined,
    viewport:{width:1280,height:800},
  })
  const page = await context.newPage()
  page.setDefaultTimeout(12000)

  try {
    const initial = await context.request.get(SITE + '/api/auth/login', {maxRedirects:0})
    requireStage(initial.status() === 302, 'LOGIN_NOT_REDIRECTED')
    const target = new URL(initial.headers()['location'] || '')
    requireStage(target.protocol === 'https:' && target.origin !== SITE, 'INVALID_LIVE_ZITADEL_REDIRECT')
    requireStage(target.searchParams.get('client_id') === EXPECTED_CLIENT, 'WRONG_OIDC_CLIENT')
    requireStage(target.searchParams.get('redirect_uri') === SITE + '/api/auth/callback/zitadel', 'WRONG_OIDC_CALLBACK')
    requireStage(target.searchParams.get('code_challenge_method') === 'S256', 'PKCE_NOT_S256')
    requireStage((target.searchParams.get('scope') || '').includes(EXPECTED_PROJECT), 'WRONG_OIDC_PROJECT')

    const discovery = await context.request.get(target.origin + '/.well-known/openid-configuration')
    const doc = await safeJson(discovery, 'LIVE_ISSUER_DISCOVERY')
    requireStage(doc.issuer === target.origin, 'LIVE_ISSUER_MISMATCH')
    requireStage(new URL(doc.authorization_endpoint).origin === target.origin, 'ISSUER_AUTH_ENDPOINT_MISMATCH')
    requireStage(target.origin === new URL(doc.authorization_endpoint).origin, 'UNEXPECTED_AUTH_PROVIDER')
    console.log('LIVE_ZITADEL_REAL_ISSUER_AND_PKCE=PASS')

    // Navigate through the real issuer and enter the EXISTING test account once.
    await page.goto(SITE + '/api/auth/login?return_to=' + encodeURIComponent(SITE + '/en'), {waitUntil:'domcontentloaded',timeout:30000})
    requireStage(page.url().startsWith(target.origin + '/'), 'DID_NOT_REACH_REAL_ZITADEL')

    const login = await locateVisible(page, [
      'input[autocomplete="username"]','input[name="loginName"]','input[name="loginname"]',
      'input[name="username"]','input[name="email"]','input[type="email"]',
      'input[type="text"]',
    ])
    requireStage(Boolean(login), 'REAL_ZITADEL_LOGIN_FORM_UNRECOGNIZED')
    await login.fill(TEST_LOGIN)

    let password = await locateVisible(page, ['input[autocomplete="current-password"]','input[type="password"]'],1000)
    if (!password) {
      await login.press('Enter')
      password = await locateVisible(page,['input[autocomplete="current-password"]','input[type="password"]'],12000)
    }
    requireStage(Boolean(password), 'PASSWORD_STEP_NOT_AVAILABLE_OR_INTERACTIVE_CHALLENGE')
    await password.fill(TEST_PASSWORD)
    await password.press('Enter')

    // No further password attempts. MFA/consent screens are blockers, never bypassed.
    try {
      await page.waitForURL(url => url.origin === SITE, {timeout:30000})
    } catch {
      fail('REAL_USER_LOGIN_NOT_COMPLETED_OR_MFA_REQUIRED')
    }
    const siteSession = await safeJson(await context.request.get(SITE + '/api/auth/session'), 'SITE_SESSION')
    requireStage(siteSession.authenticated === true, 'REAL_USER_QDIP_SESSION_DENIED')
    requireStage(siteSession.operator === true, 'REAL_USER_RR_OPERATOR_GRANT_MISSING')
    const rrSession = await safeJson(await context.request.get(RR + '/api/rr-operator/session'), 'RR_SESSION')
    requireStage(rrSession.authenticated === true, 'REAL_USER_RR_SESSION_DENIED')
    console.log('LIVE_ZITADEL_REAL_USER_RR_OPERATOR_LOGIN=PASS')

    // Acquire a real *access* token, not an ID token or QDIP session cookie.
    // Run only in this public-repo workflow whose existing GitHub Secrets
    // already supply the TEST account. No new Zitadel user/app is created.
    // Fresh PKCE authorization code is intercepted before the site's
    // callback (which cannot know our verifier). Token never leaves memory,
    // is not stored in artifacts and is never printed.
    requireStage(doc.token_endpoint && new URL(doc.token_endpoint).origin === target.origin,
      'UNTRUSTED_OAUTH_TOKEN_ENDPOINT')
    requireStage(doc.userinfo_endpoint && new URL(doc.userinfo_endpoint).origin === target.origin,
      'UNTRUSTED_OAUTH_USERINFO_ENDPOINT')
    const verifier = randomBytes(32).toString('base64url')
    const challenge = createHash('sha256').update(verifier).digest('base64url')
    const state = randomBytes(24).toString('base64url')
    const nonce = randomBytes(24).toString('base64url')
    const authorization = new URL(doc.authorization_endpoint)
    for (const [key, value] of Object.entries({
      client_id: EXPECTED_CLIENT,
      response_type: 'code',
      redirect_uri: SITE + '/api/auth/callback/zitadel',
      scope: target.searchParams.get('scope') || '',
      state, nonce, code_challenge: challenge, code_challenge_method: 'S256',
    })) authorization.searchParams.set(key, value)

    let callbackCode = null
    const intercept = async route => {
      const callback = new URL(route.request().url())
      if (callback.searchParams.get('state') !== state) {
        await route.continue()
        return
      }
      const code = callback.searchParams.get('code')
      if (typeof code === 'string' && code.length > 12 && code.length < 4096)
        callbackCode = code
      await route.fulfill({
        status: 200, contentType: 'text/html',
        body: '<!doctype html><html><body>OIDC QA token exchange</body></html>',
      })
    }
    await page.route(SITE + '/api/auth/callback/zitadel**', intercept)
    try {
      // A Zitadel browser session was just established above. No second
      // password attempt, bypass of MFA, consent or new redirect URI.
      await page.goto(authorization.toString(), {waitUntil:'domcontentloaded',timeout:30000})
    } catch {
      fail('EXISTING_TEST_USER_PKCE_AUTHORIZATION_NOT_COMPLETED')
    } finally {
      await page.unroute(SITE + '/api/auth/callback/zitadel**', intercept)
    }
    if (!callbackCode) {
      // Zitadel can complete a consent/redirect asynchronously after the
      // initial document load. Do not repeat the password or bypass MFA.
      await page.waitForTimeout(7000)
    }
    if (!callbackCode) {
      const current = new URL(page.url())
      const category = current.origin === target.origin ? 'ZITADEL_INTERACTION_REQUIRED'
        : current.origin === SITE && current.pathname === '/api/auth/callback/zitadel'
          ? 'CALLBACK_HANDLED_OUTSIDE_INTERCEPT' : 'OTHER_OIDC_NAVIGATION'
      const hasPasswordInput = await page.locator('input[type="password"]').count().catch(() => 0)
      const hasVisibleApproval = await page.getByRole('button', {
        name:/approve|allow|consent|continue|fortfahren|zezwól|дозволити/i,
      }).count().catch(() => 0)
      console.log('EXISTING_TEST_USER_PKCE_STAGE=' + category)
      console.log('EXISTING_TEST_USER_PKCE_PASSWORD_CHALLENGE=' + Boolean(hasPasswordInput))
      console.log('EXISTING_TEST_USER_PKCE_CONSENT_UI=' + Boolean(hasVisibleApproval))
    }
    requireStage(Boolean(callbackCode), 'EXISTING_TEST_USER_PKCE_CODE_NOT_OBTAINED')
    const tokenResponse = await context.request.post(doc.token_endpoint, {
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      data:new URLSearchParams({
        grant_type:'authorization_code', code:callbackCode,
        client_id:EXPECTED_CLIENT,
        redirect_uri:SITE + '/api/auth/callback/zitadel',
        code_verifier:verifier,
      }).toString(),
      maxRedirects:0, timeout:15000,
    })
    // Sanitized errors only. OAuth code/token and HTTP bodies are never logged.
    requireStage(tokenResponse.status() === 200, 'EXISTING_TEST_USER_PKCE_TOKEN_EXCHANGE_DENIED')
    const tokenPayload = await tokenResponse.json().catch(() => null)
    requireStage(tokenPayload && tokenPayload.token_type?.toLowerCase() === 'bearer' &&
      typeof tokenPayload.access_token === 'string' && tokenPayload.access_token.length >= 32 &&
      Number.isFinite(tokenPayload.expires_in) && tokenPayload.expires_in > 60,
      'EXISTING_TEST_USER_OAUTH_ACCESS_TOKEN_INVALID')
    const accessToken = tokenPayload.access_token
    const userinfoResponse = await context.request.get(doc.userinfo_endpoint, {
      headers:{Authorization:'Bearer ' + accessToken},
      maxRedirects:0, timeout:15000,
    })
    requireStage(userinfoResponse.status() === 200, 'EXISTING_TEST_USER_USERINFO_DENIED')
    const userinfo = await userinfoResponse.json().catch(() => null)
    requireStage(
      userinfo && typeof userinfo.sub === 'string' &&
      userinfo.sub === siteSession.user?.id,
      'EXISTING_TEST_USER_OAUTH_SUBJECT_MISMATCH'
    )
    console.log('LIVE_ZITADEL_EXISTING_TEST_USER_ACCESS_TOKEN=PASS')
    console.log('LIVE_ZITADEL_EXISTING_TEST_USERINFO_SUBJECT=PASS')
    console.log('LIVE_ZITADEL_ACCESS_TOKEN_STAGING_DELIVERY=NOT_CONFIGURED')
    // Access token is intentionally not returned, logged, persisted or
    // transferred. RR staging needs an independently scoped bearer delivery.

    // Non-mutating real signed-in RR BFF -> Core probes. A fresh impossible
    // synthetic execution ID cannot refer to an actual customer record.
    // Never log the URI, response payload, cookies, authorization or identity.
    const syntheticId = 'rr-live-nonexistent-' + Date.now().toString(36)
    const readPath = RR + '/api/rr-operator/kernel/executions/' + syntheticId + '/presentation'
    const noExecution = await context.request.get(readPath, {maxRedirects:0,timeout:20000})
    console.log('LIVE_ZITADEL_RR_CORE_READ_HTTP=' + noExecution.status())
    if (noExecution.status() === 403) {
      // Only fixed enum categories are emitted. Never display a server response
      // body, origin, organization, credential or framework error details.
      let denial = 'UNKNOWN_403'
      const contentType = (noExecution.headers()['content-type'] || '').toLowerCase()
      const kind = contentType.startsWith('application/json') ? 'JSON'
        : contentType.startsWith('text/html') ? 'HTML' : 'OTHER'
      // Booleans/enums only: helps distinguish the BFF's validated Core
      // forward response from an upstream Cloudflare or reverse-proxy denial.
      console.log('LIVE_ZITADEL_RR_CORE_READ_BODY_TYPE=' + kind)
      console.log('LIVE_ZITADEL_RR_CORE_READ_NOSNIFF=' +
        (noExecution.headers()['x-content-type-options'] === 'nosniff'))
      const response = kind === 'JSON' ? await noExecution.json().catch(() => null) : null
      const detail = response && typeof response === 'object' ? response.detail : null
      const error = response && typeof response === 'object' ? response.error : null
      // QDIP Core normalizes HTTPException to { error: { code, message } }.
      // Classify only known RBAC constants; never print the actual message.
      const coreMessage = error && typeof error === 'object' &&
        error.code === 'http_error' && typeof error.message === 'string'
        ? error.message : null
      if (coreMessage === 'Permission required: decisions:read') denial = 'MISSING_DECISIONS_READ'
      else if (coreMessage === 'Permission required: audit:read') denial = 'MISSING_AUDIT_READ'
      else if (coreMessage === 'This endpoint requires an org-scoped API key') denial = 'MISSING_ORG_SCOPE'
      else if (detail === 'Permission required: decisions:read') denial = 'MISSING_DECISIONS_READ'
      else if (detail === 'Permission required: audit:read') denial = 'MISSING_AUDIT_READ'
      else if (detail === 'This endpoint requires an org-scoped API key') denial = 'MISSING_ORG_SCOPE'
      else if (error === 'TLS required') denial = 'WEB_TLS_POLICY'
      else if (error === 'Forbidden origin') denial = 'WEB_ORIGIN_POLICY'
      else if (typeof detail === 'string' && /audit:read/i.test(detail)) denial = 'AUDIT_READ_RELATED'
      else if (typeof detail === 'string' && /decisions:read/i.test(detail)) denial = 'DECISIONS_READ_RELATED'
      else if (typeof detail === 'string' && /organi[sz]ation|org.scoped/i.test(detail)) denial = 'ORGANIZATION_SCOPE_RELATED'
      else if (typeof detail === 'string') denial = 'OTHER_CORE_DETAIL_STRING'
      else if (typeof error === 'string') denial = 'OTHER_WEB_ERROR_STRING'
      else if (response !== null) denial = 'UNRECOGNIZED_JSON_SCHEMA'
      console.log('LIVE_ZITADEL_RR_CORE_READ_DENIAL=' + denial)
    }
    requireStage(noExecution.status() === 404, 'REAL_RR_AUTHORIZED_CORE_READ_NOT_404')
    requireStage((noExecution.headers()['cache-control'] || '').includes('no-store'),
      'REAL_RR_AUTHORIZED_CORE_READ_CACHE_UNSAFE')
    console.log('LIVE_ZITADEL_RR_AUTHORIZED_CORE_READ_BOUNDARY=PASS')

    // Invalid preflight has no possible durable execution or procurement effect.
    // A real 422 proves the same-origin operator session passes the Web proxy
    // and Core's admission validator, not just the session lookup endpoint.
    const invalidPreflight = await context.request.post(RR + '/api/rr-operator/kernel/preflight', {
      headers:{Origin:RR,'Content-Type':'application/json'},
      data:{}, maxRedirects:0,timeout:20000,
    })
    console.log('LIVE_ZITADEL_RR_CORE_INVALID_PREFLIGHT_HTTP=' + invalidPreflight.status())
    requireStage(invalidPreflight.status() === 422, 'REAL_RR_CORE_INVALID_PREFLIGHT_NOT_422')
    console.log('LIVE_ZITADEL_RR_CORE_INVALID_PREFLIGHT_DENIED=PASS')

    // This request must never reach Core: QDIP site != Observatory origin.
    const crossOrigin = await context.request.post(RR + '/api/rr-operator/kernel/preflight', {
      headers:{Origin:SITE,'Content-Type':'application/json'},
      data:{}, maxRedirects:0,timeout:20000,
    })
    requireStage(crossOrigin.status() === 403, 'REAL_RR_CROSS_ORIGIN_NOT_403')
    console.log('LIVE_ZITADEL_RR_CROSS_ORIGIN_POST_DENIED=PASS')

    const result = await context.request.post(SITE + '/api/auth/logout', {
      headers: {Origin:SITE},
    })
    requireStage(result.status() === 200, 'SITE_LOGOUT_FAILED')
    const after = await safeJson(await context.request.get(SITE + '/api/auth/session'), 'SITE_AFTER_LOGOUT')
    const afterRr = await safeJson(await context.request.get(RR + '/api/rr-operator/session'), 'RR_AFTER_LOGOUT')
    requireStage(after.authenticated === false && after.operator === false, 'SITE_SESSION_NOT_REVOKED')
    requireStage(afterRr.authenticated === false, 'RR_SESSION_NOT_REVOKED')
    // Backend access itself, not just session status, must be revoked.
    const afterRead = await context.request.get(readPath, {maxRedirects:0,timeout:15000})
    console.log('LIVE_ZITADEL_RR_CORE_AFTER_LOGOUT_HTTP=' + afterRead.status())
    requireStage(afterRead.status() === 401, 'REAL_RR_CORE_READ_NOT_REVOKED')
    console.log('LIVE_ZITADEL_RR_CORE_READ_REVOKED_AFTER_LOGOUT=PASS')
    console.log('LIVE_ZITADEL_REAL_USER_LOGOUT_AND_RR_REVOCATION=PASS')

    // Only one existing identity: cannot falsely qualify wrong-organization or
    // roleless user grants without a separate pre-existing negative identity.
    console.log('LIVE_ZITADEL_WRONG_ORG_REAL_IDENTITY=NOT_TESTED')
    console.log('LIVE_ZITADEL_ROLELESS_REAL_IDENTITY=NOT_TESTED')
    console.log('LIVE_ZITADEL_EXISTING_TEST_USER_E2E=PASS')
  } finally {
    await context.close()
    await browser.close()
  }
}

main().catch(err => {
  const stage = err instanceof Error && /^[A-Z0-9_]{4,90}$/.test(err.message) ? err.message : 'SANITIZED_BROWSER_FAILURE'
  console.error('LIVE_ZITADEL_EXISTING_TEST_USER_E2E=FAIL:' + stage)
  process.exitCode = 1
})

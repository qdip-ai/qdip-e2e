/**
 * Credential-bound real Zitadel browser acceptance for the EXISTING test account.
 * Never creates a user, changes roles, or makes RR mutations.
 * No traces, screenshots, video, token/cookie dumps, or auth URLs in output.
 * One login attempt to avoid locking out the existing account.
 */
import { chromium } from '@playwright/test'

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

    // Non-mutating real signed-in RR BFF -> Core probes. A fresh impossible
    // synthetic execution ID cannot refer to an actual customer record.
    // Never log the URI, response payload, cookies, authorization or identity.
    const syntheticId = 'rr-live-nonexistent-' + Date.now().toString(36)
    const readPath = RR + '/api/rr-operator/kernel/executions/' + syntheticId + '/presentation'
    const noExecution = await context.request.get(readPath, {maxRedirects:0,timeout:20000})
    console.log('LIVE_ZITADEL_RR_CORE_READ_HTTP=' + noExecution.status())
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

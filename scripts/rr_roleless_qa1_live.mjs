/** Real existing QA1 Zitadel login; RR roleless denial, read-only.
 * One password attempt. No fake cookies, traces, screenshots, auth URLs,
 * tokens, passwords or personally identifying data in the logs.
 */
import { chromium } from '@playwright/test'

const SITE = 'https://qdip.ai'
const RR = 'https://observatory.qdip.ai'
const ISSUER = 'https://mentality-rmwj0i.eu1.zitadel.cloud'
const CLIENT = '394566248211424533'
const ACCOUNT = 'qa1@qdip.ai'
const PASSWORD = process.env.QDIP_E2E_ZITADEL_QA1_PASSWORD

function check(ok, stage) {
  if (!ok) throw new Error(stage)
}

async function locate(page, selectors, timeout = 12000) {
  const until = Date.now() + timeout
  while (Date.now() < until) {
    for (const selector of selectors) {
      const field = page.locator(selector).first()
      if (await field.isVisible().catch(() => false)) return field
    }
    await page.waitForTimeout(250)
  }
  return null
}

async function session(context, url, stage) {
  const response = await context.request.get(url, { timeout: 15000, maxRedirects: 0 })
  check(response.status() === 200, stage + '_HTTP')
  const data = await response.json().catch(() => null)
  check(data && typeof data === 'object', stage + '_JSON')
  return data
}

async function main() {
  check(typeof PASSWORD === 'string' && PASSWORD.length > 0, 'QA1_SECRET_MISSING')
  const browser = await chromium.launch({ headless: true })
  const context = await browser.newContext({
    ignoreHTTPSErrors: false, serviceWorkers: 'block',
    acceptDownloads: false, viewport: { width: 1280, height: 800 },
  })
  try {
    const initial = await session(context, SITE + '/api/auth/session', 'INITIAL_SESSION')
    check(initial.authenticated === false, 'INITIAL_SESSION_NOT_ANONYMOUS')
    const auth = await context.request.get(SITE + '/api/auth/login', {
      maxRedirects: 0, timeout: 15000,
    })
    check(auth.status() === 302, 'QA1_LOGIN_NOT_REDIRECTED')
    const target = new URL(auth.headers()['location'] || '')
    check(target.origin === ISSUER && target.protocol === 'https:', 'QA1_WRONG_REAL_ISSUER')
    check(target.searchParams.get('client_id') === CLIENT, 'QA1_WRONG_CLIENT')
    check(target.searchParams.get('code_challenge_method') === 'S256', 'QA1_PKCE_NOT_S256')
    console.log('RR_QA1_REAL_ZITADEL_ISSUER_AND_PKCE=PASS')

    const page = await context.newPage()
    page.setDefaultTimeout(12000)
    await page.goto(
      SITE + '/api/auth/login?return_to=' + encodeURIComponent(SITE + '/en'),
      { waitUntil: 'domcontentloaded', timeout: 30000 }
    )
    check(new URL(page.url()).origin === ISSUER, 'QA1_NOT_ON_ZITADEL')
    const username = await locate(page, [
      'input[autocomplete="username"]', 'input[name="loginName"]',
      'input[name="loginname"]', 'input[name="username"]',
      'input[name="email"]', 'input[type="email"]', 'input[type="text"]',
    ])
    check(Boolean(username), 'QA1_USERNAME_FORM_MISSING')
    await username.fill(ACCOUNT)
    let password = await locate(
      page, ['input[autocomplete="current-password"]', 'input[type="password"]'], 1200
    )
    if (!password) {
      await username.press('Enter')
      password = await locate(page, [
        'input[autocomplete="current-password"]', 'input[type="password"]',
      ])
    }
    check(Boolean(password), 'QA1_PASSWORD_FORM_MISSING')
    await password.fill(PASSWORD)
    await password.press('Enter') // No credential retries or MFA bypass.
    try {
      await page.waitForURL(url => url.origin === SITE, { timeout: 40000 })
    } catch {
      throw new Error('QA1_REAL_LOGIN_OR_MFA_BLOCKED')
    }
    const site = await session(context, SITE + '/api/auth/session', 'QA1_SITE_SESSION')
    check(site.authenticated === true, 'QA1_REAL_AUTH_NOT_CONFIRMED')
    check(site.operator === false, 'QA1_UNEXPECTED_RR_OPERATOR_ROLE')
    console.log('RR_QA1_REAL_LOGIN_WITHOUT_RR_OPERATOR=PASS')

    const rr = await session(context, RR + '/api/rr-operator/session', 'QA1_RR_SESSION')
    check(rr.configured === true && rr.authenticated === false, 'QA1_RR_ACCESS_GRANTED')
    const proof = await context.request.get(
      RR + '/api/rr-operator/kernel/executions/qa1-no-access/presentation',
      { timeout: 15000, maxRedirects: 0 }
    )
    check(proof.status() === 401, 'QA1_RR_API_NOT_401')
    check((proof.headers()['cache-control'] || '').includes('no-store'), 'QA1_RR_DENIAL_CACHE_UNSAFE')
    console.log('RR_QA1_REAL_RR_API_DENIED_401=PASS')

    const logout = await context.request.post(SITE + '/api/auth/logout', {
      headers: { Origin: SITE }, timeout: 15000, maxRedirects: 0,
    })
    check(logout.status() === 200, 'QA1_LOGOUT_FAILED')
    const after = await session(context, SITE + '/api/auth/session', 'QA1_AFTER_LOGOUT')
    const rrAfter = await session(context, RR + '/api/rr-operator/session', 'RR_AFTER_LOGOUT')
    check(after.authenticated === false && rrAfter.authenticated === false, 'QA1_LOGOUT_REVOKE_FAILED')
    console.log('RR_QA1_REAL_LOGOUT_REVOCATION=PASS')
    console.log('RR_QA1_LIVE_ROLELESS_E2E=PASS')
    console.log('RR_QA1_WRONG_ORGANIZATION_IDENTITY=NOT_TESTED')
  } finally {
    await context.close()
    await browser.close()
  }
}

main().catch(error => {
  const stage = error instanceof Error && /^[A-Z0-9_]{5,100}$/.test(error.message)
    ? error.message : 'SANITIZED_BROWSER_ERROR'
  console.error('RR_QA1_LIVE_ROLELESS_E2E=FAIL:' + stage)
  process.exitCode = 1
})

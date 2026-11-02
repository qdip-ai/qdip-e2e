/** Read-only real Zitadel QDIP session & Observatory role-denial smoke for existing QA1/QA2. */
import { chromium } from '@playwright/test'

const SITE = 'https://qdip.ai'
const OBS = 'https://observatory.qdip.ai'
const accounts = [
  { label: 'QA1', login: process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN,
    password: process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD, expected: 'qa1@qdip.ai' },
  { label: 'QA2', login: process.env.QDIP_E2E_ZITADEL_TEST2_LOGIN,
    password: process.env.QDIP_E2E_ZITADEL_TEST2_PASSWORD, expected: 'qa2@qdip.ai' },
]
function gate(ok, code) { if (!ok) throw new Error(code) }
async function field(page, selectors, limitMs = 14000) {
  const end = Date.now() + limitMs
  while (Date.now() < end) {
    for (const selector of selectors) {
      const element = page.locator(selector).first()
      if (await element.isVisible().catch(() => false)) return element
    }
    await page.waitForTimeout(250)
  }
  return null
}
for (const account of accounts) {
  gate(account.login === account.expected && Boolean(account.password),
       account.label + '_EXISTING_ZITADEL_CREDENTIAL_BINDING_MISSING')
}
const browser = await chromium.launch({ headless: true })
try {
  for (const account of accounts) {
    // Never reuse auth state across QA organizations or accounts.
    const context = await browser.newContext({
      acceptDownloads: false, serviceWorkers: 'block', ignoreHTTPSErrors: false,
    })
    try {
      const page = await context.newPage()
      page.setDefaultTimeout(14000)
      await page.goto(SITE + '/api/auth/login?return_to=' +
        encodeURIComponent(SITE + '/en'), {
          waitUntil: 'domcontentloaded', timeout: 40000,
        })
      gate(page.url().startsWith('https://'), account.label + '_AUTH_NOT_HTTPS')
      const user = await field(page, [
        'input[autocomplete="username"]', 'input[name="loginName"]',
        'input[name="loginname"]', 'input[name="username"]',
        'input[name="email"]', 'input[type="email"]', 'input[type="text"]',
      ])
      gate(Boolean(user), account.label + '_USERNAME_INPUT_NOT_AVAILABLE')
      await user.fill(account.login)
      let pass = await field(page,
        ['input[autocomplete="current-password"]', 'input[type="password"]'], 1000)
      if (!pass) {
        await user.press('Enter')
        pass = await field(page,
          ['input[autocomplete="current-password"]', 'input[type="password"]'])
      }
      gate(Boolean(pass), account.label + '_PASSWORD_INPUT_NOT_AVAILABLE')
      // Exactly one password attempt, no retries or bypass of MFA.
      await pass.fill(account.password)
      await pass.press('Enter')
      try {
        await page.waitForURL(url => url.origin === SITE, { timeout: 35000 })
      } catch {
        throw Error(account.label + '_REAL_ZITADEL_LOGIN_NOT_COMPLETED')
      }
      const response = await context.request.get(SITE + '/api/auth/session',
        { timeout: 15000 })
      gate(response.status() === 200, account.label + '_QDIP_SESSION_HTTP_ERROR')
      const session = await response.json()
      gate(session.authenticated === true, account.label + '_QDIP_SESSION_MISSING')
      console.log(account.label + '_REAL_ZITADEL_QDIP_SESSION=PASS')
      const admin = await context.request.get(
        OBS + '/api/observatory/admin/plugins', { timeout: 15000 })
      gate(admin.status() === 403, account.label +
        '_OBS_ADMIN_DENIAL_EXPECTED_GOT_' + admin.status())
      console.log(account.label + '_OBS_ADMIN_DENIAL=PASS')
    } finally {
      await context.close()
    }
  }
  console.log('SDK407_EXISTING_TWO_QA_USERS_REAL_OIDC_DENIAL=PASS')
} finally {
  await browser.close()
}

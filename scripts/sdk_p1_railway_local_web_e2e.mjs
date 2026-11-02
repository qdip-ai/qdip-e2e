import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { chromium } from '@playwright/test'

// Isolated browser test of the actual Web build and its reviewer component.
// Test-scoped cookie and intercepted submission API are NOT a real Zitadel/Core E2E.
const site = 'http://observatory.localhost:3000'
const secret = 'e2e-only-qdip-session-signing-key-not-for-production'
const issuer = 'https://identity.example.test'
const sizes = [
  ['desktop', 1440, 900],
  ['mobile-portrait', 390, 844],
  ['mobile-landscape', 844, 390],
]
const expiresAt = Math.floor(Date.now() / 1000) + 1800
const payload = Buffer.from(JSON.stringify({
  sub: 'local-e2e-account', issuer,
  clientId: 'qdip-browser-e2e-client', projectId: '123456789',
  organizationId: '987654321', expiresAt, roles: ['observatory_admin'],
})).toString('base64url')
const sig = createHmac('sha256', secret).update('session-v1:' + payload).digest('base64url')
const cookie = {
  name: 'qdip_oidc_session', value: payload + '.' + sig,
  domain: 'observatory.localhost', path: '/', expires: expiresAt,
  httpOnly: true, secure: false, sameSite: 'Lax',
}
const item = {
  plugin_name: 'third-party-review-qa', capability_id: 'demo.plan',
  plugin_version: '1.0.0', expected_revision: 4,
  status: 'PENDING_SECURITY_REVIEW',
  catalog: {
    display_name: 'Isolated Review Fixture', description: 'Disposable test record',
    application_launch_url: 'https://developer.example.org', launch_url_verified: true,
  },
}
const outputDir = '/tmp/sdk-p1-railway-web318'
mkdirSync(outputDir, { recursive: true })
const browser = await chromium.launch({
  executablePath: '/usr/bin/chromium',
  headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'],
})
try {
  // A genuine request to Next must deny a roleless visitor at the API boundary.
  const negative = await browser.newContext()
  const anon = await negative.request.get(site + '/api/observatory/admin/plugin-publication-submissions')
  assert.equal(anon.status(), 401, 'anonymous GET must fail closed')
  const anonPost = await negative.request.post(
    site + '/api/observatory/admin/plugin-publication-submissions/third-party-review-qa/moderate',
    { data: { expected_revision: 4, action: 'reject', reason: 'Test decline reason' },
      headers: { origin: site } },
  )
  assert.equal(anonPost.status(), 401, 'anonymous mutation must fail closed')
  await negative.close()
  console.log('SDK_P1_LOCAL_ANONYMOUS_DENIAL=PASS')
  for (const [name, width, height] of sizes) {
    const context = await browser.newContext({ viewport: { width, height }, deviceScaleFactor: 1 })
    await context.addCookies([cookie])
    const page = await context.newPage()
    const errors = []
    page.on('pageerror', error => errors.push(error.message))
    await page.route('**/api/observatory/admin/plugins', route => route.fulfill({
      status: 200, contentType: 'application/json', body: JSON.stringify({ plugins: [] }),
    }))
    await page.route('**/api/observatory/admin/plugin-publication-submissions', route => route.fulfill({
      status: 200, contentType: 'application/json', body: JSON.stringify({ items: [item] }),
    }))
    let moderation = null
    await page.route('**/api/observatory/admin/plugin-publication-submissions/third-party-review-qa/moderate',
      async route => {
        moderation = route.request().postDataJSON()
        await route.fulfill({ status: 409, contentType: 'application/json',
          body: JSON.stringify({ error: 'Changed; refresh' }) })
      })
    const response = await page.goto(site + '/uk/admin/plugins', { waitUntil: 'domcontentloaded', timeout: 45000 })
    assert.equal(response?.status(), 200, name + ': actual Next page must render')
    const panel = page.getByRole('region', { name: 'Заявки сторонніх розробників' })
    await panel.waitFor({ state: 'visible', timeout: 25000 })
    await panel.getByRole('heading', { name: 'Isolated Review Fixture' }).waitFor({ timeout: 20000 })
    const reject = panel.getByRole('button', { name: 'Відхилити' })
    assert.equal(await reject.isDisabled(), true, name + ': empty reason must disable action')
    await panel.getByRole('textbox', { name: 'Причина рішення (обов’язково)' })
      .fill('Reviewed and rejected in isolated browser QA')
    assert.equal(await reject.isEnabled(), true, name + ': valid reason must enable action')
    const initialWidth = await page.evaluate(() => ({
      document: document.documentElement.scrollWidth, viewport: window.innerWidth,
    }))
    assert.ok(initialWidth.document <= initialWidth.viewport + 1,
      name + ': horizontal overflow ' + JSON.stringify(initialWidth))
    await reject.click()
    await panel.getByRole('alert').getByText('Стан заявки змінився. Оновіть дані.').waitFor()
    assert.deepEqual(moderation, {
      expected_revision: 4, action: 'reject',
      reason: 'Reviewed and rejected in isolated browser QA',
    })
    assert.equal(errors.length, 0, name + ': browser JS errors: ' + errors.join(' | '))
    const png = await page.screenshot({ fullPage: true, path: outputDir + '/' + name + '.png' })
    // Lossy viewport evidence in Railway logs; full-page PNG stays in test container.
    const jpeg = await page.screenshot({ type: 'jpeg', quality: 30, fullPage: false })
    console.log('SDK_P1_RAILWAY_JPEG_' + name + '=' + jpeg.toString('base64'))
    console.log('SDK_P1_RAILWAY_VIEWPORT=' + name + ' ' + width + 'x' + height +
      ' screenshot=' + outputDir + '/' + name + '.png pngBytes=' + png.length +
      ' result=PASS')
    await context.close()
  }
  console.log('SDK_P1_RAILWAY_LOCAL_WEB_UI=PASS')
  console.log('LIMITATION=isolated_browser_real_next_synthetic_session_and_mocked_core_not_zitadel_or_production')
} finally {
  await browser.close()
}

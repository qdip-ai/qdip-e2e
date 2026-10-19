/**
 * Independent RR OIDC E2E browser configuration.
 *
 * DO NOT import qdip-web/e2e/oidc-test-session or use its default Playwright
 * storageState: that fixture pre-authenticates *every* test as both roles
 * with an unrelated cookie secret and makes anonymous checks meaningless.
 *
 * This file is copied into qdip-web at test time. The only auth fixture is
 * the ephemeral cookie signed by the independent suite using the SAME
 * secret that this config passes to Next.js at runtime.
 */
import { defineConfig, devices } from '@playwright/test'

const mandatory = [
  'QDIP_AUTH_COOKIE_SECRET',
  'ZITADEL_ISSUER',
  'ZITADEL_CLIENT_ID',
  'ZITADEL_QDIP_PROJECT_ID',
  'ZITADEL_QDIP_ORGANIZATION_ID',
  'QDIP_STUDIO_ZITADEL_ROLE_KEY',
  'QDIP_RR_ZITADEL_ROLE_KEY',
  'DIP_API_KEY',
  // Server-only, disposable platform-admin key: Core publication catalog
  // requires admin:* while RR execution keeps the separate org-scoped key.
  'DIP_ADMIN_API_KEY',
  'RR_ACTOR_ASSERTION_SECRET',
] as const

if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RR_E2E_CONTRACT_MODE !== 'rr-oidc-session-v1')
  throw new Error('Independent RR browser config is for isolated GitHub E2E only')
for (const key of mandatory) {
  if (!process.env[key]) throw new Error('Missing isolated browser configuration: ' + key)
}
if (process.env.ZITADEL_ISSUER !== 'https://qdip-e2e.invalid' ||
    process.env.ZITADEL_QDIP_PROJECT_ID !== '123456789' ||
    process.env.ZITADEL_QDIP_ORGANIZATION_ID !== '987654321' ||
    (process.env.QDIP_AUTH_COOKIE_SECRET ?? '').length < 32)
  throw new Error('Untrusted RR browser E2E identity fixture')

// Do not use a globally signed storageState. Each test starts unauthenticated
// and must explicitly create a role-scoped browser session where appropriate.
export default defineConfig({
  testDir: './e2e',
  timeout: 45_000,
  retries: 0,
  use: {
    baseURL: 'http://observatory.localhost:3000',
    storageState: { cookies: [], origins: [] },
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm start --hostname 127.0.0.1',
    url: 'http://127.0.0.1:3000',
    reuseExistingServer: false,
    timeout: 120_000,
    env: Object.fromEntries(mandatory.map((key) => [key, process.env[key]!])) as Record<string, string>,
  },
})

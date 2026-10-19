import { readFileSync } from 'node:fs'
import { createHmac } from 'node:crypto'
import { expect, test } from '@playwright/test'

// This spec is owned by the independent E2E suite and copied to the checked-out
// qdip-web/e2e directory ONLY when the rr-oidc-session-v1 contract is required.
// The E2E fixture injects an ephemeral signed session; live Zitadel login is NOT tested.
// HTTP, Core, Mongo persistence and BFF authorization are never mocked.
const ORIGIN = 'http://observatory.localhost:3000'
const PAGE = `${ORIGIN}/en/readiness-recovery`
const ROUTE = `${ORIGIN}/api/rr-operator/kernel`

type CivilianRequest = {
  execution_id: string
  source: { source_system: string; snapshot_id: string; source_version: string; captured_at: string }
  ingested_at: string
  payload: { decision_id: string; operator_directives?: { excluded_job_ids: string[] } }
}


type IsolatedRole = 'rr_operator' | 'studio'
type IsolatedClaims = {
  sub: string
  issuer: string
  clientId: string
  projectId: string
  organizationId: string
  expiresAt: number
  roles: IsolatedRole[]
}

/** Test-only signed session against real QDIP Web BFF; NOT a live Zitadel login. */
function makeIsolatedClaims(role: 'rr' | 'studio'): { secret: string; claims: IsolatedClaims } {
  const secret = process.env.QDIP_AUTH_COOKIE_SECRET ?? ''
  const issuer = process.env.ZITADEL_ISSUER ?? ''
  const clientId = process.env.ZITADEL_CLIENT_ID ?? ''
  const projectId = process.env.ZITADEL_QDIP_PROJECT_ID ?? ''
  const organizationId = process.env.ZITADEL_QDIP_ORGANIZATION_ID ?? ''
  const rrSubject = process.env.RR_E2E_OPERATOR_SUBJECT ?? ''
  const studioSubject = process.env.RR_E2E_STUDIO_SUBJECT ?? ''
  if (
    process.env.GITHUB_ACTIONS !== 'true' ||
    secret.length < 32 ||
    issuer !== 'https://qdip-e2e.invalid' ||
    clientId !== 'qdip-e2e-client' ||
    projectId !== '123456789' ||
    organizationId !== '987654321' ||
    process.env.QDIP_RR_ZITADEL_ROLE_KEY !== 'rr_operator' ||
    process.env.QDIP_STUDIO_ZITADEL_ROLE_KEY !== 'studio' ||
    rrSubject !== 'qdip-e2e-operator' ||
    studioSubject !== 'qdip-e2e-studio-only'
  ) throw new Error('Isolated OIDC test configuration incompatible with current Web contract')
  return {
    secret,
    claims: {
      sub: role === 'rr' ? rrSubject : studioSubject,
      issuer, clientId, projectId, organizationId,
      expiresAt: Math.floor(Date.now() / 1000) + 900,
      roles: [role === 'rr' ? 'rr_operator' : 'studio'],
    },
  }
}

async function installIsolatedOidcSession(
  page: import('@playwright/test').Page,
  role: 'rr' | 'studio' = 'rr',
  overrides: Partial<IsolatedClaims> = {}
) {
  const { secret, claims } = makeIsolatedClaims(role)
  const payload = Buffer.from(JSON.stringify({ ...claims, ...overrides })).toString('base64url')
  const signature = createHmac('sha256', secret).update('session-v1:' + payload).digest('base64url')
  await page.context().addCookies([{
    name: 'qdip_oidc_session',
    value: payload + '.' + signature,
    domain: 'observatory.localhost',
    path: '/',
    httpOnly: true,
    secure: false,
    sameSite: 'Lax',
    expires: Math.floor(Date.now() / 1000) + 900,
  }])
}

function actualInput(): CivilianRequest {
  if (process.env.RR_E2E_CONTRACT_MODE !== 'rr-oidc-session-v1')
    throw new Error('The real plugin browser suite requires rr-oidc-session-v1 mode')
  const path = process.env.RR_E2E_API_REQUEST_PATH
  if (!path)
    throw new Error('The disposable RR API request fixture is required')
  const input = JSON.parse(readFileSync(path, 'utf8')) as CivilianRequest
  const unique = `${Date.now().toString(36)}-${process.pid.toString(36)}`
  const now = new Date().toISOString()
  input.execution_id = `rr-plugin-browser-${unique}-01`
  input.source.captured_at = now
  input.source.snapshot_id = `browser-snapshot-${unique}`
  input.ingested_at = now
  input.payload.decision_id = `civilian-browser-${unique}`
  return input
}

// Only small predefined statuses/booleans are recorded; never persist a cookie,
// response body, subject, or production credential in public runner evidence.
function mark(label: string, value: number | boolean) {
  test.info().annotations.push({ type: 'rr-' + label, description: String(value) })
}

async function markOperatorSession(page: import('@playwright/test').Page) {
  const response = await page.request.get(`${ORIGIN}/api/rr-operator/session`)
  mark('session-http', response.status())
  if (response.status() === 200) {
    const value = (await response.json()) as { configured?: boolean; authenticated?: boolean }
    mark('session-configured', value.configured === true)
    mark('session-authenticated', value.authenticated === true)
  }
}

test('anonymous RR workspace is role-gated; no public optimizer or preview leaks', async ({ page }) => {
  await page.goto(PAGE, { waitUntil: 'domcontentloaded' })
  const gate = page.getByTestId('qdip-access-gate')
  await expect(gate).toBeVisible()
  await expect(gate.getByRole('heading', { name: 'Sign in to continue' })).toBeVisible()
  await expect(gate.getByText('RR Operator', { exact: true })).toBeVisible()
  await expect(gate.getByRole('link', { name: 'Sign in' })).toBeVisible()
  await expect(page.getByTestId('rr-kernel-only-workspace')).toHaveCount(0)
  await expect(page.getByTestId('rr-reference-preview')).toHaveCount(0)
  await expect(page.getByTestId('rr-production-operator')).toHaveCount(0)

  const deprecated = await page.request.post(`${ORIGIN}/readiness/scenarios`, {
    data: { input: { untrusted: true } },
  })
  expect(deprecated.status()).toBe(410)
})

test('anonymous browser cannot preflight, read Kernel evidence or export history', async ({ page }) => {
  const noPassword = await page.request.post(`${ORIGIN}/api/rr-operator/session`, { data: {password: 'obsolete'} })
  const preflight = await page.request.post(`${ROUTE}/preflight`, { data: {} })
  const execution = await page.request.post(`${ROUTE}/executions`, { data: {} })
  const presentation = await page.request.get(`${ROUTE}/executions/not-allowed/presentation`)
  const history = await page.request.get(`${ROUTE}/decisions/not-allowed/history/export-complete`)
  mark('legacy-login-http', noPassword.status())
  mark('anonymous-preflight-http', preflight.status())
  mark('anonymous-presentation-http', presentation.status())
  mark('anonymous-history-http', history.status())
  await markOperatorSession(page)
  expect(noPassword.status()).toBe(410)
  expect(preflight.status()).toBe(401)
  expect(execution.status()).toBe(401)
  expect(presentation.status()).toBe(401)
  expect(history.status()).toBe(401)
})

test('isolated signed Studio-only role cannot access RR operator', async ({ page }) => {
  await installIsolatedOidcSession(page, 'studio')
  const globalSession = await page.request.get(`${ORIGIN}/api/auth/session`)
  expect(globalSession.status()).toBe(200)
  const identity = (await globalSession.json()) as { authenticated: boolean; studio: boolean; operator: boolean }
  expect(identity.authenticated).toBe(true)
  expect(identity.studio).toBe(true)
  expect(identity.operator).toBe(false)
  const operatorSession = await page.request.get(`${ORIGIN}/api/rr-operator/session`)
  expect(operatorSession.status()).toBe(200)
  expect(((await operatorSession.json()) as { authenticated: boolean }).authenticated).toBe(false)
  const denied = await page.request.post(`${ROUTE}/preflight`, { data: {} })
  expect(denied.status()).toBe(401)
  const write = await page.request.post(`${ROUTE}/executions`, { data: {} })
  expect(write.status()).toBe(401)
  const evidence = await page.request.get(`${ROUTE}/executions/not-allowed/presentation`)
  expect(evidence.status()).toBe(401)
})


test('signed RR role with wrong project, organization, issuer or expiry is denied', async ({ page }) => {
  const invalid: Partial<IsolatedClaims>[] = [
    { projectId: '123456788' },
    { organizationId: '987654320' },
    { issuer: 'https://other-e2e.invalid' },
    { expiresAt: Math.floor(Date.now() / 1000) - 10 },
    { expiresAt: Math.floor(Date.now() / 1000) + 7200 },
    { roles: [] },
    { roles: ['studio'] },
  ]
  for (const [index, changed] of invalid.entries()) {
    // Only the synthetic case index and boolean/HTTP checks enter public diagnostics.
    mark('negative-case-code', 200 + index)
    await installIsolatedOidcSession(page, 'rr', changed)
    const global = await page.request.get(`${ORIGIN}/api/auth/session`)
    mark('negative-global-http', global.status())
    expect(global.status()).toBe(200)
    const identity = (await global.json()) as { configured: boolean; authenticated: boolean; operator: boolean }
    mark('negative-global-configured', identity.configured)
    mark('negative-global-operator', identity.operator)
    mark('negative-global-authenticated', identity.authenticated)
    expect(identity.configured).toBe(true)
    expect(identity.operator).toBe(false)
    // OIDC authentication is separate from RR role authorization. A signed
    // identity with zero roles remains authenticated, but cannot operate RR.
    // Invalid issuer/project/org/expiry must invalidate the entire session.
    expect(identity.authenticated).toBe(changed.roles !== undefined)
    const rr = await page.request.get(`${ORIGIN}/api/rr-operator/session`)
    mark('negative-rr-http', rr.status())
    expect(rr.status()).toBe(200)
    const rrIdentity = (await rr.json()) as { configured: boolean; authenticated: boolean }
    mark('negative-rr-configured', rrIdentity.configured)
    mark('negative-rr-authenticated', rrIdentity.authenticated)
    expect(rrIdentity).toMatchObject({ configured: true, authenticated: false })
    const denied = await page.request.post(`${ROUTE}/preflight`, { data: {} })
    mark('negative-preflight-http', denied.status())
    expect(denied.status()).toBe(401)
    const executeDenied = await page.request.post(`${ROUTE}/executions`, { data: {} })
    mark('negative-execute-http', executeDenied.status())
    expect(executeDenied.status()).toBe(401)
  }
})

test('anonymous and Studio-only browser cannot access RR workspace or operate Core', async ({ page }) => {
  await page.goto(PAGE, { waitUntil: 'domcontentloaded' })
  const gate = page.getByTestId('qdip-access-gate')
  await expect(gate).toBeVisible()
  await expect(gate.getByRole('heading', { name: 'Sign in to continue' })).toBeVisible()
  await expect(gate.getByRole('link', { name: 'Sign in' })).toBeVisible()
  await expect(page.getByTestId('rr-production-operator')).toHaveCount(0)
  await expect(page.getByLabel('Kernel execution JSON')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Create execution' })).toHaveCount(0)
  await expect(page.getByTestId('rr-decision-first')).toHaveCount(0)

  const anonymous = await page.request.get(`${ORIGIN}/api/auth/session`)
  expect(anonymous.status()).toBe(200)
  expect(await anonymous.json()).toMatchObject({ configured: true, authenticated: false, operator: false })

  await installIsolatedOidcSession(page, 'studio')
  const denied = await page.request.get(`${ORIGIN}/api/rr-operator/session`)
  expect(denied.status()).toBe(200)
  expect(await denied.json()).toMatchObject({ configured: true, authenticated: false })
  const deniedAction = await page.request.post(`${ROUTE}/executions`, { data: {} })
  expect(deniedAction.status()).toBe(401)
  await page.reload()
  await expect(gate).toBeVisible()
  await expect(gate.getByRole('heading', { name: 'Access restricted' })).toBeVisible()
  await expect(gate.getByText('RR Operator', { exact: true })).toBeVisible()
  await expect(page.getByTestId('rr-production-operator')).toHaveCount(0)
  await expect(page.getByLabel('Kernel execution JSON')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Create execution' })).toHaveCount(0)
  await expect(page.getByTestId('rr-decision-first')).toHaveCount(0)
})

test('tampered isolated OIDC session never authorizes the Web BFF', async ({ page }) => {
  await installIsolatedOidcSession(page)
  const cookies = await page.context().cookies(ORIGIN)
  const session = cookies.find((cookie) => cookie.name === 'qdip_oidc_session')
  if (!session) throw new Error('Isolated browser session cookie missing')
  const last = session.value.slice(-1)
  await page.context().addCookies([{
    ...session,
    value: session.value.slice(0, -1) + (last === 'A' ? 'B' : 'A'),
  }])
  const denied = await page.request.get(`${ROUTE}/executions/denied/presentation`)
  mark('tampered-presentation-http', denied.status())
  await markOperatorSession(page)
  expect(denied.status()).toBe(401)
  const status = await page.request.get(`${ORIGIN}/api/rr-operator/session`)
  expect(status.status()).toBe(200)
  expect(((await status.json()) as {authenticated: boolean}).authenticated).toBe(false)
})

test('isolated signed-session browser → real Core → CP-SAT → Mongo → replan → verified export', async ({ page }) => {
  test.setTimeout(240_000)
  const original = actualInput()
  await installIsolatedOidcSession(page)
  await page.goto(PAGE, { waitUntil: 'domcontentloaded' })
  await markOperatorSession(page)
  const globalSession = await page.request.get(`${ORIGIN}/api/auth/session`)
  expect(globalSession.status()).toBe(200)
  expect(await globalSession.json()).toMatchObject({
    configured: true, authenticated: true, operator: true, studio: false,
  })
  const operatorSession = await page.request.get(`${ORIGIN}/api/rr-operator/session`)
  expect(operatorSession.status()).toBe(200)
  expect(await operatorSession.json()).toMatchObject({
    configured: true, authenticated: true, mode: 'zitadel-oidc',
  })
  const panel = page.getByTestId('rr-production-operator')
  await expect(panel).toBeVisible()
  await expect(panel.getByRole('button', { name: 'Sign out' })).toBeVisible()

  const field = panel.getByLabel('Kernel execution JSON')
  await field.fill(JSON.stringify(original))
  await expect(page.getByTestId('rr-kernel-preflight')).toContainText(original.execution_id)
  await expect(page.getByRole('button', { name: 'Create execution', exact: true })).toBeEnabled()
  const createResponse = page.waitForResponse((r) =>
    r.url().endsWith('/api/rr-operator/kernel/executions') && r.request().method() === 'POST'
  )
  await panel.getByRole('button', { name: 'Create execution', exact: true }).click()
  const actualCreated = await createResponse
  mark('execution-create-http', actualCreated.status())
  const originHeader = actualCreated.request().headers()['origin']
  mark('execution-create-origin-match', originHeader === ORIGIN)
  if (actualCreated.status() !== 201) {
    const body = (await actualCreated.json().catch(() => ({}))) as { error?: string; detail?: string }
    mark('execution-create-forbidden-origin', body.error === 'Forbidden origin')
    mark('execution-create-operator-unconfigured', body.error === 'RR operator mode is not configured')
    mark('execution-create-operator-unauthorized', body.error === 'RR operator login required')
    mark('execution-create-transport', body.error === 'TLS required')
    mark('execution-create-backend-unavailable', body.error === 'RR backend unavailable')
  }
  expect(actualCreated.status()).toBe(201)
  const persisted = (await actualCreated.json()) as {actor_id: string; audit_evidence: {actor_id: string}}
  expect(persisted.actor_id).toMatch(/^zitadel:[a-f0-9]{64}$/)
  expect(persisted.audit_evidence.actor_id).toBe(persisted.actor_id)
  const summary = page.getByTestId('rr-decision-first')
  await expect(summary).toBeVisible()
  const evidence = summary.getByTestId('rr-kernel-evidence')
  await expect(evidence).toHaveAttribute('data-actionable', 'true')
  await expect(evidence).toContainText(original.source.snapshot_id)
  await expect(evidence).toContainText(original.execution_id)
  await expect(summary.getByTestId('rr-kernel-schedule').locator('tbody tr').first()).toBeVisible()
  await expect(panel.getByTestId('rr-technical-response')).toBeVisible()

  // Workspace presets alter only presentation; no new Kernel run or change in result.
  await panel.getByRole('button', { name: 'Business view' }).click()
  await expect(summary).toHaveAttribute('data-testid', 'rr-decision-first')
  await panel.getByRole('button', { name: 'Analyst view' }).click()
  await expect(summary).toBeVisible()

  const successorId = `${original.execution_id}-replanned`
  const later = new Date(Date.now() + 2000).toISOString()
  const changed = {
    execution_id: successorId,
    change_id: `change-${original.execution_id}`,
    kind: 'OVERRIDE',
    reason: 'Exclude the invented sensor-service job during isolated E2E testing.',
    requested_at: later,
    source: original.source,
    ingested_at: later,
    payload: {
      ...original.payload,
      operator_directives: { excluded_job_ids: ['sensor-service'] },
    },
  }
  await panel.getByLabel('Kernel replan JSON').fill(JSON.stringify(changed))
  const replanResponse = page.waitForResponse((r) =>
    r.url().endsWith(`/executions/${original.execution_id}/replan`) && r.request().method() === 'POST'
  )
  await panel.getByRole('button', { name: 'Replan from predecessor' }).click()
  const actualReplan = await replanResponse
  mark('replan-http', actualReplan.status())
  expect(actualReplan.status()).toBe(201)
  const persistedRevision = (await actualReplan.json()) as {actor_id: string; audit_evidence: {actor_id: string}}
  expect(persistedRevision.actor_id).toBe(persisted.actor_id)
  expect(persistedRevision.audit_evidence.actor_id).toBe(persisted.actor_id)
  await expect(summary).toBeVisible()
  await expect(summary.getByTestId('rr-kernel-evidence')).toContainText(successorId)
  await expect(summary.getByTestId('rr-kernel-schedule')).not.toContainText('sensor-service')
  mark('replan-presentation', true)

  const historyResponse = page.waitForResponse((r) =>
    r.url().endsWith(`/decisions/${original.payload.decision_id}/history`)
  )
  await panel.getByRole('button', { name: 'History', exact: true }).click()
  const actualHistory = await historyResponse
  mark('history-http', actualHistory.status())
  const history = await actualHistory.json() as { executions: unknown[] }
  mark('history-two-executions', Array.isArray(history.executions) && history.executions.length === 2)
  expect(history.executions).toHaveLength(2)

  const replayResponse = page.waitForResponse((r) =>
    r.url().endsWith(`/executions/${successorId}/replay-verification`)
  )
  await panel.getByRole('button', { name: 'Replay' }).click()
  const actualReplay = await replayResponse
  mark('replay-http', actualReplay.status())
  const replayValue = (await actualReplay.json()) as { verified: boolean }
  mark('replay-verified', replayValue.verified)
  expect(replayValue.verified).toBe(true)

  // Verify the exact Core/Web route in use. The client assembles a complete
  // export from independently attested pages; it does not call export-complete.
  const verifiedPage = page.waitForResponse((r) =>
    r.url().includes(`/decisions/${original.payload.decision_id}/history/verified-export-page`)
  )
  const downloadPromise = page.waitForEvent('download')
  await panel.getByRole('button', { name: 'Export complete history' }).click()
  const verifiedResponse = await verifiedPage
  mark('verified-export-page-http', verifiedResponse.status())
  expect(verifiedResponse.status()).toBe(200)
  const attestation = (await verifiedResponse.json()) as {
    history_manifest_digest: string
    head_execution_id: string
    history_verified: boolean
  }
  expect(attestation.history_verified).toBe(true)
  expect(attestation.head_execution_id).toBe(successorId)
  expect(attestation.history_manifest_digest).toMatch(/^[a-f0-9]{64}$/)
  const downloaded = await downloadPromise
  expect(downloaded.suggestedFilename()).toBe(`rr-history-${original.payload.decision_id}.json`)
  const saved = await downloaded.path()
  if (!saved) throw new Error('Verified history download did not produce a local file')
  const exported = JSON.parse(readFileSync(saved, 'utf8')) as {
    head_execution_id: string
    history_manifest_digest: string
    history_verified: boolean
    export_complete: boolean
    executions: unknown[]
  }
  expect(exported.head_execution_id).toBe(successorId)
  expect(exported.history_manifest_digest).toBe(attestation.history_manifest_digest)
  expect(exported.history_verified).toBe(true)
  expect(exported.export_complete).toBe(true)
  expect(exported.executions).toHaveLength(2)
  mark('verified-history-downloaded', true)

  const logoutResponse = page.waitForResponse((r) =>
    r.url().endsWith('/api/auth/logout') && r.request().method() === 'POST'
  )
  await panel.getByRole('button', { name: 'Sign out' }).click()
  const logout = await logoutResponse
  mark('logout-http', logout.status())
  expect(logout.status()).toBe(200)
  await expect(panel.getByRole('button', { name: 'Sign out' })).not.toBeVisible()
  const afterLogout = await page.request.get(`${ROUTE}/executions/${successorId}/presentation`)
  mark('logout-revocation-http', afterLogout.status())
  expect(afterLogout.status()).toBe(401)
})

/**
 * Economic-v2 source fixture mirrors the independent Core public-contract
 * test: synthetic inputs only. It is a compiler/admission preview, NOT a
 * solver decision, reservation, purchase order or financial advantage.
 */
function economicInput() {
  const decisionId = 'econ-browser-' + Date.now().toString(36) + '-' + process.pid.toString(36)
  return {
    schema_version: 'readiness-recovery.economic-state.v2',
    operational: {
      decision_id: decisionId,
      horizon_slots: 4,
      workshop_capacity: 1,
      technicians: [{ id: 'tech', skills: ['repair'], available_slots: [0, 1, 2] }],
      jobs: [{
        id: 'repair', duration_slots: 1, required_skills: ['repair'],
        deadline_slot: 4, readiness_gain_units: 0,
        parts: [{ part_id: 'bearing', quantity: 1 }],
      }],
    },
    snapshot_id: 'synthetic-econ-browser-snapshot-v1',
    assets: [{ id: 'machine', state_revision: 1 }],
    restorations: [{ job_id: 'repair', asset_id: 'machine' }],
    occupations: [{ job_id: 'repair', asset_ids: ['machine'] }],
    job_costs: [{ job_id: 'repair', all_in_cost_cents: 0 }],
    procurements: [
      {
        id: 'expedite', alternative_group_id: 'replacement-bearing',
        part_id: 'bearing', quantity: 1, arrival_slot: 0, all_in_cost_cents: 150000,
      },
      {
        id: 'regular', alternative_group_id: 'replacement-bearing',
        part_id: 'bearing', quantity: 1, arrival_slot: 2, all_in_cost_cents: 20000,
      },
    ],
    capabilities: [{
      id: 'saleable-output', asset_ids: ['machine'],
      contribution_cents_by_slot: [0, 100000, 100000, 100000],
    }],
  }
}

test('economic-v2 preview reaches real Core but cannot execute, mutate or authorize procurement', async ({ page }) => {
  test.setTimeout(120_000)
  const input = economicInput()
  const endpoint = `${ROUTE}/economic-v2/preflight`
  const post = (body: unknown) => page.request.post(endpoint, {
    data: body, headers: { Origin: ORIGIN, 'Content-Type': 'application/json' },
  })

  const anonymous = await post(input)
  mark('economic-anonymous-http', anonymous.status())
  expect(anonymous.status()).toBe(401)

  await installIsolatedOidcSession(page, 'studio')
  const studio = await post(input)
  mark('economic-studio-http', studio.status())
  expect(studio.status()).toBe(401)

  await installIsolatedOidcSession(page, 'rr', { organizationId: 'wrong-org' })
  const wrongOrg = await post(input)
  expect(wrongOrg.status()).toBe(401)
  await installIsolatedOidcSession(page, 'rr')
  const result = await post(input)
  mark('economic-core-http', result.status())
  expect(result.status()).toBe(200)
  const compiled = (await result.json()) as Record<string, unknown>
  expect(Object.keys(compiled).sort()).toEqual([
    'schema_version', 'economic_version', 'decision_id', 'ir_semantic_hash',
    'job_count', 'asset_count', 'procurement_offer_count', 'donor_extraction_count',
    'state', 'actionable', 'supply_source_verified', 'atomic_plan_committed',
  ].sort())
  expect(compiled).toMatchObject({
    schema_version: 'readiness-recovery.economic-preflight.v2',
    economic_version: input.schema_version,
    decision_id: input.operational.decision_id,
    job_count: 1, asset_count: 1,
    procurement_offer_count: 2, donor_extraction_count: 0,
    state: 'COMPILED_PREVIEW_ONLY',
    actionable: false, supply_source_verified: false, atomic_plan_committed: false,
  })
  expect(compiled.ir_semantic_hash).toMatch(/^[a-f0-9]{64}$/)
  const repeated = await post(input)
  expect(repeated.status()).toBe(200)
  expect((await repeated.json()).ir_semantic_hash).toBe(compiled.ir_semantic_hash)
  mark('economic-stable-compile', true)

  const malformed = { ...input, procurements: [{ ...input.procurements[0], quantity: 0 }, input.procurements[1]] }
  const rejected = await post(malformed)
  mark('economic-invalid-http', rejected.status())
  expect(rejected.status()).toBe(422)
  for (const path of ['economic-v2/execute', 'economic-v2/orders', 'economic-v2/apply']) {
    const denied = await page.request.post(`${ROUTE}/${path}`, {
      data: input, headers: { Origin: ORIGIN },
    })
    expect(denied.status()).toBe(404)
  }
  mark('economic-no-action-routes', true)

  const initialHistory = await page.request.get(`${ROUTE}/decisions/${input.operational.decision_id}/history`)
  expect([200, 404]).toContain(initialHistory.status())
  const initialCount = initialHistory.status() === 200
    ? ((await initialHistory.json()) as { executions: unknown[] }).executions.length : 0
  expect(initialCount).toBe(0)

  await page.goto(PAGE, { waitUntil: 'domcontentloaded' })
  const panel = page.getByTestId('rr-economic-v2-preflight')
  await expect(panel).toBeVisible()
  await expect(panel.getByTestId('rr-economic-v2-warning')).toContainText('NOT ACTIONABLE')
  await panel.getByLabel('RR-ECON-v2 JSON').fill(JSON.stringify(input))
  const response = page.waitForResponse((r) =>
    r.url().endsWith('/api/rr-operator/kernel/economic-v2/preflight') &&
    r.request().method() === 'POST'
  )
  await panel.getByRole('button', { name: 'Validate in Core (no execution)' }).click()
  const actual = await response
  mark('economic-browser-http', actual.status())
  expect(actual.status()).toBe(200)
  const preview = panel.getByTestId('rr-economic-v2-result')
  await expect(preview).toBeVisible()
  await expect(preview).toHaveAttribute('data-actionable', 'false')
  await expect(preview).toContainText(String(compiled.ir_semantic_hash))
  await expect(panel.getByRole('button', { name: /apply|execute|purchase/i })).toHaveCount(0)

  const persisted = await page.evaluate(() => Object.values(localStorage).join(' '))
  expect(persisted).not.toContain(input.operational.decision_id)
  const afterHistory = await page.request.get(`${ROUTE}/decisions/${input.operational.decision_id}/history`)
  expect([200, 404]).toContain(afterHistory.status())
  if (afterHistory.status() === 200)
    expect(((await afterHistory.json()) as { executions: unknown[] }).executions).toHaveLength(0)
  mark('economic-zero-executions', true)
})

test('invalid input fails closed in real Core preflight; no fabricated decision appears', async ({ page }) => {
  actualInput()
  await installIsolatedOidcSession(page)
  await page.goto(PAGE, { waitUntil: 'domcontentloaded' })
  await markOperatorSession(page)
  const panel = page.getByTestId('rr-production-operator')
  await expect(panel.getByRole('button', { name: 'Sign out' })).toBeVisible()
  await panel.getByLabel('Kernel execution JSON').fill('{"execution_id":"invalid-input","source":{},"payload":{"jobs":[]}}')
  await expect(page.getByTestId('rr-kernel-preflight')).toContainText('Server preflight')
  await expect(panel.getByRole('button', { name: 'Create execution', exact: true })).toBeDisabled()
  await expect(page.getByTestId('rr-decision-first')).toHaveCount(0)
})

/** Browser-only fault injection after a genuinely committed Core/Mongo write.
 * The browser sees HTTP 502 instead of the 201 returned by the real BFF.
 * All persistence, auth, Core HTTP, and presentation reads remain genuine.
 */
test('post-commit lost acknowledgement reconciles real create and replan without retrying POST', async ({ page }) => {
  test.setTimeout(180_000)
  const original = actualInput()
  await installIsolatedOidcSession(page)
  await page.goto(PAGE, { waitUntil: 'domcontentloaded' })
  const panel = page.getByTestId('rr-production-operator')
  await expect(panel).toBeVisible()
  await panel.getByLabel('Kernel execution JSON').fill(JSON.stringify(original))
  const createButton = panel.getByRole('button', { name: 'Create execution', exact: true })
  await expect(createButton).toBeEnabled()
  let createPosts = 0
  let createReads = 0
  await page.route(ROUTE + '/executions', async route => {
    if (route.request().method() !== 'POST') return route.continue()
    createPosts++
    const committed = await route.fetch({ timeout: 50_000 })
    expect(committed.status()).toBe(201)
    await route.fulfill({ status: 502, contentType: 'application/json',
      body: JSON.stringify({ error: 'RR backend unavailable' }) })
  })
  await page.route(ROUTE + '/executions/' + original.execution_id + '/presentation', async route => {
    createReads++
    await route.continue()
  })
  await createButton.click()
  await expect(panel.getByText('Saved execution confirmed after lost acknowledgement.')).toBeVisible()
  await expect(page.getByTestId('rr-decision-first')).toContainText(original.execution_id)
  expect(createPosts).toBe(1)
  expect(createReads).toBeGreaterThanOrEqual(1)
  await page.unroute(ROUTE + '/executions')
  await page.unroute(ROUTE + '/executions/' + original.execution_id + '/presentation')
  const revised = original.execution_id + '-ack-replanned'
  const later = new Date(Date.now() + 2000).toISOString()
  const change = {
    execution_id: revised, change_id: 'lost-ack-' + original.execution_id,
    kind: 'OVERRIDE',
    reason: 'Isolated post-commit response-loss acceptance for real Mongo replan.',
    requested_at: later, source: original.source, ingested_at: later,
    payload: { ...original.payload, operator_directives: { excluded_job_ids: ['sensor-service'] } },
  }
  await panel.getByLabel('Kernel replan JSON').fill(JSON.stringify(change))
  const replanButton = panel.getByRole('button', { name: 'Replan from predecessor' })
  await expect(replanButton).toBeEnabled()
  let replanPosts = 0
  let replanReads = 0
  await page.route(ROUTE + '/executions/' + original.execution_id + '/replan', async route => {
    if (route.request().method() !== 'POST') return route.continue()
    replanPosts++
    const committed = await route.fetch({ timeout: 50_000 })
    expect(committed.status()).toBe(201)
    await route.fulfill({ status: 502, contentType: 'application/json',
      body: JSON.stringify({ error: 'RR backend unavailable' }) })
  })
  await page.route(ROUTE + '/executions/' + revised + '/presentation', async route => {
    replanReads++
    await route.continue()
  })
  await replanButton.click()
  await expect(panel.getByText('Saved execution confirmed after lost acknowledgement.')).toBeVisible()
  await expect(page.getByTestId('rr-decision-first')).toContainText(revised)
  expect(replanPosts).toBe(1)
  expect(replanReads).toBeGreaterThanOrEqual(1)
  await page.unroute(ROUTE + '/executions/' + original.execution_id + '/replan')
  await page.unroute(ROUTE + '/executions/' + revised + '/presentation')
  const historyResponse = await page.request.get(ROUTE + '/decisions/' + original.payload.decision_id + '/history')
  expect(historyResponse.status()).toBe(200)
  const history = (await historyResponse.json()) as { executions: unknown[] }
  expect(history.executions).toHaveLength(2)
  const replay = await page.request.get(ROUTE + '/executions/' + revised + '/replay-verification')
  expect(replay.status()).toBe(200)
  expect(((await replay.json()) as { verified: boolean }).verified).toBe(true)
  mark('lost-ack-create-and-replan-reconciled', true)
  mark('lost-ack-only-two-mongo-executions', true)
})

test('post-commit lost write and unavailable read stays UNKNOWN and blocks duplicate create', async ({ page }) => {
  test.setTimeout(150_000)
  const original = actualInput()
  await installIsolatedOidcSession(page)
  await page.goto(PAGE, { waitUntil: 'domcontentloaded' })
  const panel = page.getByTestId('rr-production-operator')
  await expect(panel).toBeVisible()
  await panel.getByLabel('Kernel execution JSON').fill(JSON.stringify(original))
  const createButton = panel.getByRole('button', { name: 'Create execution', exact: true })
  await expect(createButton).toBeEnabled()
  let postCount = 0
  let readCount = 0
  await page.route(ROUTE + '/executions', async route => {
    if (route.request().method() !== 'POST') return route.continue()
    postCount++
    const committed = await route.fetch({ timeout: 50_000 })
    expect(committed.status()).toBe(201)
    await route.fulfill({ status: 502, contentType: 'application/json',
      body: JSON.stringify({ error: 'RR backend unavailable' }) })
  })
  await page.route(ROUTE + '/executions/' + original.execution_id + '/presentation', async route => {
    readCount++
    await route.fulfill({ status: 502, contentType: 'application/json',
      body: JSON.stringify({ error: 'RR backend unavailable' }) })
  })
  await createButton.click()
  await expect(panel.getByRole('alert')).toContainText('Write status unknown. Do not submit again.')
  await expect(createButton).toBeDisabled()
  expect(postCount).toBe(1)
  expect(readCount).toBeGreaterThanOrEqual(1)
  await page.unroute(ROUTE + '/executions')
  await page.unroute(ROUTE + '/executions/' + original.execution_id + '/presentation')
  const historyResponse = await page.request.get(ROUTE + '/decisions/' + original.payload.decision_id + '/history')
  expect(historyResponse.status()).toBe(200)
  const history = (await historyResponse.json()) as { executions: unknown[] }
  expect(history.executions).toHaveLength(1)
  const projection = await page.request.get(ROUTE + '/executions/' + original.execution_id + '/presentation')
  expect(projection.status()).toBe(200)
  mark('lost-ack-unknown-no-duplicate-post', true)
  mark('lost-ack-unknown-real-mongo-commit', true)
})

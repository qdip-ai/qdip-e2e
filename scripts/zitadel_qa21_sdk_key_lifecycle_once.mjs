/**
 * Real QA21 account, ZITADEL cross-organization authorization probe.
 * One login attempt. Never prints passwords, tokens, cookie values, subjects,
 * org IDs, URLs with OAuth state/code, or JSON responses. Read-only on production.
 * Disposable QA-only key is created once and revoked in the same authenticated session.
 */
import { chromium } from '@playwright/test';

const SITE = 'https://qdip.ai';
const OBS = 'https://observatory.qdip.ai';
const RR = OBS;
const ISSUER = 'https://mentality-rmwj0i.eu1.zitadel.cloud';
const MAIN_ORG = '368555767923594379';
const QA_EMAIL = process.env.QDIP_E2E_ZITADEL_TEST21_LOGIN;
const QA_PASSWORD = process.env.QDIP_E2E_ZITADEL_TEST21_PASSWORD;
const EXPECTED_EMAIL = 'qa-21@qdip.ai';
const EXPECTED_QA_ORG = 'QDIP QA';
const results = [];
function check(ok, id) {
  console.log('ZITADEL_QA21_' + id + '=' + (ok ? 'PASS' : 'FAIL'));
  results.push({id, ok});
  if (!ok) throw Error(id);
}
async function visible(page, selectors, ms = 14000) {
  const stop = Date.now() + ms;
  while (Date.now() < stop) {
    for (const selector of selectors) {
      const node = page.locator(selector).first();
      if (await node.isVisible().catch(() => false)) return node;
    }
    await page.waitForTimeout(250);
  }
  return null;
}
async function json(response, id) {
  check(response.status() === 200, id + '_HTTP_200');
  return response.json().catch(() => {throw Error(id + '_INVALID_JSON');});
}
async function run() {
  check(typeof QA_EMAIL === 'string' && QA_EMAIL.trim().toLowerCase() === EXPECTED_EMAIL, 'EXPECTED_ACCOUNT_BOUND');
  check(typeof QA_PASSWORD === 'string' && QA_PASSWORD.length >= 8, 'SECRET_PRESENT');
  const browser = await chromium.launch({headless: true});
  const ctx = await browser.newContext({ignoreHTTPSErrors: false, serviceWorkers: 'block',
    acceptDownloads: false, viewport: {width:1280,height:800}});
  try {
    const anonymous = await json(await ctx.request.get(SITE+'/api/auth/session'), 'ANONYMOUS_SESSION');
    check(anonymous.authenticated === false, 'START_ANONYMOUS');
    const first = await ctx.request.get(SITE+'/api/auth/login', {maxRedirects:0,timeout:15000});
    check(first.status()===302,'OIDC_AUTH_REDIRECT');
    const auth = new URL(first.headers().location || '');
    check(auth.origin===ISSUER && auth.searchParams.get('code_challenge_method')==='S256',
      'REAL_ISSUER_AND_PKCE');
    const page = await ctx.newPage();
    await page.goto(SITE+'/api/auth/login?return_to='+encodeURIComponent(SITE+'/en'),
      {waitUntil:'domcontentloaded',timeout:30000});
    check(new URL(page.url()).origin===ISSUER,'REAL_LOGIN_FORM_ORIGIN');
    const login = await visible(page, ['input[autocomplete="username"]','input[name="loginName"]',
      'input[name="loginname"]','input[name="username"]','input[name="email"]',
      'input[type="email"]','input[type="text"]']);
    check(Boolean(login),'LOGIN_FIELD_PRESENT');
    await login.fill(QA_EMAIL);
    let pass = await visible(page,['input[autocomplete="current-password"]','input[type="password"]'],1200);
    if (!pass) {
      await login.press('Enter');
      pass = await visible(page,['input[autocomplete="current-password"]','input[type="password"]'],14000);
    }
    check(Boolean(pass),'PASSWORD_FIELD_PRESENT');
    const callback = page.waitForResponse(response => {
      try { const u=new URL(response.url());return u.origin===SITE &&
        u.pathname==='/api/auth/callback/zitadel'; } catch {return false;}
    },{timeout:40000});
    await pass.fill(QA_PASSWORD);
    await pass.press('Enter');
    let returned;
    try { returned=await callback; } catch {throw Error('REAL_LOGIN_NOT_CONFIRMED_OR_MFA');}
    check([302,303].includes(returned.status()),'REAL_ZITADEL_OAUTH_CALLBACK_SUCCESS');
    const session=await json(await ctx.request.get(SITE+'/api/auth/session'),
      'AUTHENTICATED_SITE_SESSION');
    check(session.authenticated===true,'REAL_QA21_AUTHENTICATED');
    check((session.user?.email||'').toLowerCase()===QA_EMAIL,'QA21_EXPECTED_IDENTITY');
    check(session.operator===false && session.observatoryAdmin===false &&
      session.studio===false,'MAIN_ORG_PROJECT_ROLES_DENIED');
    const rrs=await json(await ctx.request.get(RR+'/api/rr-operator/session'),'RR_SESSION');
    check(rrs.authenticated===false,'FOREIGN_ORG_RR_DENIED');
    const read=await ctx.request.get(RR+'/api/rr-operator/kernel/executions/qa21-no-access/presentation',
      {maxRedirects:0,timeout:15000});
    check(read.status()===401,'FOREIGN_ORG_RR_READ_DENIED_401');
    const admin=await ctx.request.get(OBS+'/api/observatory/admin/plugins',{maxRedirects:0});
    check([401,403].includes(admin.status()),'FOREIGN_ORG_OBSERVATORY_ADMIN_DENIED');

    // Use immutable MAIN_ORG Zitadel ID; never rely on a display-name match for target.
    const other=await ctx.request.get(OBS+'/api/observatory/admin/applications?organizationId='+MAIN_ORG,
      {maxRedirects:0,timeout:20000,headers:{'x-qdip-org-id':MAIN_ORG}});
    check(other.status()===403,'MAIN_ORG_CREDENTIAL_CATALOG_DENIED_403');
    const owned=await ctx.request.get(OBS+'/api/observatory/organizations',
      {maxRedirects:0,timeout:20000});
    check(owned.status()===200,'OWNER_DISCOVERY_HTTP_200');
    const inventory=await owned.json().catch(()=>null);
    check(Array.isArray(inventory?.organizations),'OWNER_DISCOVERY_VALID');
    const list=inventory.organizations;
    check(!list.some(x=>x?.id===MAIN_ORG),'MAIN_ORG_EXCLUDED_FROM_OWNERSHIP');
    const qa=list.filter(x=>x?.name===EXPECTED_QA_ORG&&x?.state==='active'&&
      typeof x?.id==='string'&&/^[0-9]{1,32}$/.test(x.id));
    // Failure here means ORG_OWNER not verified, NOT necessarily user membership failure.
    if(qa.length!==1) {
      throw Error('QA_ORG_OWNER_NOT_VERIFIED');
    } else {
      console.log('ZITADEL_QA21_QA_ORG_OWNER=PASS');
      const own=await ctx.request.get(OBS+'/api/observatory/admin/applications?organizationId='+qa[0].id,
        {maxRedirects:0,timeout:20000});
      console.log('ZITADEL_QA21_OWN_QA_ORG_CREDENTIAL_CATALOG_HTTP='+own.status());
      check(own.status()===200,'OWN_QA_ORG_CREDENTIAL_CATALOG_READ_200');
      const payload=await own.json().catch(()=>null);
      check(payload!==null&&typeof payload==='object' &&
        Array.isArray(payload.available) && Array.isArray(payload.connected),
        'OWN_QA_ORG_CREDENTIAL_CATALOG_VALID');

      // One disposable QA-only Worker registration credential, never exposed
      // to logs or stored in artifacts. No Worker registration/invocation.
      const pluginId='qa21-e2e-credential-once-20261102';
      const capability='qa21.e2e.credential.once';
      check(!payload.connected.some(p=>p?.id===pluginId),
        'NO_PREEXISTING_QA_TEST_CREDENTIAL');
      // Obtain the canonical UUID through the existing owner-authorized,
      // idempotent link API before issuance, ensuring emergency revoke works
      // even if read-after-issue inventory becomes unavailable.
      const bound=await ctx.request.post(OBS+'/api/observatory/organizations',{
        headers:{Origin:OBS,'content-type':'application/json'},
        data:JSON.stringify({organizationId:qa[0].id}),
        maxRedirects:0,timeout:20000,
      });
      check(bound.status()===200,'OWN_QA_CANONICAL_BINDING_RECONFIRMED');
      const identity=await bound.json().catch(()=>null);
      check(identity?.linked===true && identity?.organization?.id===qa[0].id &&
        typeof identity?.coreTenantId==='string' &&
        /^[a-f0-9-]{36}$/i.test(identity.coreTenantId),
        'OWN_QA_CORE_TENANT_UUID_AVAILABLE');
      let createdId=null;
      const createdTenant=identity.coreTenantId;
      try {
        const issue=await ctx.request.post(OBS+'/api/observatory/admin/applications',{
          headers:{Origin:OBS,'content-type':'application/json'},
          data:JSON.stringify({
            organizationId:qa[0].id,pluginId,capabilities:[capability],
            role:'worker',manual:true,
          }),maxRedirects:0,timeout:30000,
        });
        console.log('ZITADEL_QA21_SDK_ISSUE_HTTP='+issue.status());
        check(issue.status()===201,'OWN_QA_SCOPED_KEY_ISSUED_201');
        const issued=await issue.json().catch(()=>null);
        if(typeof issued?.keyId==='string' && /^[a-f0-9-]{36}$/i.test(issued.keyId))
          createdId=issued.keyId;
        check(issued && issued.pluginId===pluginId &&
          typeof issued.keyId==='string' &&
          /^[a-f0-9-]{36}$/i.test(issued.keyId) &&
          issued.role==='worker' &&
          typeof issued.key==='string' && /^dip-[a-f0-9]{32}$/.test(issued.key) &&
          Array.isArray(issued.capabilities) &&
          issued.capabilities.length===1 && issued.capabilities[0]===capability,
          'OWN_QA_SCOPED_KEY_ISSUANCE_ATTESTED');
        // Do not copy or print the secret. The response is kept in memory only.
        const visibleResult=await ctx.request.get(
          OBS+'/api/observatory/admin/applications?organizationId='+qa[0].id,
          {maxRedirects:0,timeout:20000});
        check(visibleResult.status()===200,'OWN_QA_KEY_READ_AFTER_ISSUE_200');
        const now=await visibleResult.json().catch(()=>null);
        const records=Array.isArray(now?.connected)?now.connected.flatMap(p=>
          Array.isArray(p?.keys)?p.keys:[]):[];
        const matches=records.filter(k=>k?.id===createdId &&
          k?.role==='worker'&&Array.isArray(k?.capabilities) &&
          k.capabilities.length===1&&k.capabilities[0]===capability);
        check(matches.length===1 &&
          typeof matches[0].orgId==='string' &&
          /^[a-f0-9-]{36}$/i.test(matches[0].orgId),
          'OWN_QA_KEY_INVENTORY_SCOPED');
        check(matches[0].orgId===createdTenant,'KEY_TENANT_MATCHES_BOUND_QA_ORG');
      } finally {
        // Revoke immediately even if read-after-issue assertions failed.
        // No retry or second issuance: ambiguous failures remain BLOCKED.
        if(createdId && createdTenant) {
          const revoke=await ctx.request.delete(
            OBS+'/api/observatory/admin/applications',{
              headers:{Origin:OBS,'content-type':'application/json'},
              data:JSON.stringify({
                organizationId:qa[0].id,orgId:createdTenant,keyId:createdId,
              }),maxRedirects:0,timeout:30000,
            });
          console.log('ZITADEL_QA21_SDK_REVOKE_HTTP='+revoke.status());
          check(revoke.status()===200,'OWN_QA_SCOPED_KEY_REVOKED_200');
        }
      }
      const remaining=await ctx.request.get(
        OBS+'/api/observatory/admin/applications?organizationId='+qa[0].id,
        {maxRedirects:0,timeout:20000});
      check(remaining.status()===200,'OWN_QA_CATALOG_READ_AFTER_REVOKE_200');
      const finalCatalog=await remaining.json().catch(()=>null);
      check(Array.isArray(finalCatalog?.connected) &&
        !finalCatalog.connected.some(p=>Array.isArray(p?.keys) &&
          p.keys.some(k=>k?.id===createdId)),
        'OWN_QA_TEST_KEY_NOT_ACTIVE_AFTER_REVOKE');
      console.log('ZITADEL_QA21_SDK_ISSUE_REVOKE_RESULT=PASS');
    }
    // One principal with no main-org role is not sufficient to prove
    // the reverse (main-org principal must not read QA org).
    const signout=await ctx.request.post(SITE+'/api/auth/logout',{
      headers:{Origin:SITE},maxRedirects:0,timeout:15000});
    check(signout.status()===200,'LOGOUT_SUCCESS');
    const after=await json(await ctx.request.get(SITE+'/api/auth/session'),'AFTER_LOGOUT_SESSION');
    check(after.authenticated===false,'LOGOUT_REVOKES_SESSION');
    console.log('ZITADEL_QA21_REVERSE_MAIN_TO_QA=NOT_TESTED');
    console.log('ZITADEL_QA21_RESULT='+ (qa.length===1 ? 'PASS_OWNED_ORG_PROOF':'PASS_NEGATIVE_ONLY'));
  } finally {await ctx.close();await browser.close();}
}
run().catch(error=>{
  const label=error instanceof Error && /^[A-Z0-9_]{4,96}$/.test(error.message) ?
    error.message : 'SANITIZED_BROWSER_ERROR';
  console.error('ZITADEL_QA21_E2E=FAIL_'+label);
  process.exitCode=1;
});

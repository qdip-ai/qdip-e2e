/**
 * One-shot owner-authorized QDIP QA -> Core link.
 * Real browser/real OIDC session, existing sealed QA21 credentials.
 * Never prints cookies, access tokens, passwords, user IDs, or HTTP bodies.
 * The only permitted write is POST /api/observatory/organizations for one
 * immutable Zitadel organization ID, verified by Core against ORG_OWNER.
 */
import { chromium } from '@playwright/test';

const SITE='https://qdip.ai';
const OBS='https://observatory.qdip.ai';
const ISSUER='https://mentality-rmwj0i.eu1.zitadel.cloud';
const QA_ID='397885387160184113';
const MAIN_ID='368555767923594379';
const LOGIN=process.env.QDIP_E2E_ZITADEL_TEST21_LOGIN;
const PASSWORD=process.env.QDIP_E2E_ZITADEL_TEST21_PASSWORD;

function check(ok,stage) {
  console.log('QA21_CORE_LINK_'+stage+'='+(ok?'PASS':'FAIL'));
  if(!ok)throw Error(stage);
}
async function locate(page,selectors,ms=14000) {
  const until=Date.now()+ms;
  while(Date.now()<until) {
    for(const sel of selectors) {
      const input=page.locator(sel).first();
      if(await input.isVisible().catch(()=>false))return input;
    }
    await page.waitForTimeout(250);
  }
  return null;
}
async function run() {
  check(LOGIN==='qa-21@qdip.ai' && typeof PASSWORD==='string' && PASSWORD.length>=8,
    'SEALED_EXPECTED_QA21');
  const browser=await chromium.launch({headless:true});
  const ctx=await browser.newContext({ignoreHTTPSErrors:false,serviceWorkers:'block',
    acceptDownloads:false,viewport:{width:1280,height:800}});
  try {
    const page=await ctx.newPage();
    await page.goto(SITE+'/api/auth/login?return_to='+encodeURIComponent(OBS+'/uk'),
      {waitUntil:'domcontentloaded',timeout:30000});
    check(new URL(page.url()).origin===ISSUER,'REAL_ISSUER');
    const login=await locate(page,['input[autocomplete="username"]','input[name="loginName"]',
      'input[name="loginname"]','input[name="username"]','input[name="email"]',
      'input[type="email"]','input[type="text"]']);
    check(Boolean(login),'LOGIN_FORM');
    await login.fill(LOGIN);
    let pass=await locate(page,['input[autocomplete="current-password"]','input[type="password"]'],1200);
    if(!pass){await login.press('Enter');
      pass=await locate(page,['input[autocomplete="current-password"]','input[type="password"]']);}
    check(Boolean(pass),'PASSWORD_FORM');
    const callback=page.waitForResponse(r=>{
      try {const u=new URL(r.url());return u.origin===SITE &&
        u.pathname==='/api/auth/callback/zitadel';}catch{return false;}
    },{timeout:40000});
    await pass.fill(PASSWORD);
    await pass.press('Enter');
    let cb;
    try { cb=await callback; } catch { throw Error('OAUTH_CALLBACK_UNCONFIRMED'); }
    check([302,303].includes(cb.status()),'REAL_OAUTH_CALLBACK');
    const sessionRes=await ctx.request.get(SITE+'/api/auth/session');
    check(sessionRes.status()===200,'SESSION_HTTP');
    const session=await sessionRes.json();
    check(session.authenticated===true &&
      (session.user?.email||'').toLowerCase()===LOGIN,
      'EXACT_QA21_SESSION');
    const owned=await ctx.request.get(OBS+'/api/observatory/organizations',
      {timeout:20000,maxRedirects:0});
    check(owned.status()===200,'OWNER_LIST_HTTP');
    const inventory=await owned.json().catch(()=>null);
    check(Array.isArray(inventory?.organizations) &&
      inventory.organizations.filter(x=>x?.id===QA_ID&&x?.name==='QDIP QA'&&x?.state==='active').length===1 &&
      !inventory.organizations.some(x=>x?.id===MAIN_ID),'QA_OWNER_ONLY');

    const before=await ctx.request.get(OBS+'/api/observatory/admin/applications?organizationId='+QA_ID,
      {maxRedirects:0,timeout:20000});
    console.log('QA21_CORE_LINK_PRE_LINK_CATALOG_HTTP='+before.status());
    check([200,409].includes(before.status()),'CATALOG_PRECONDITION_STATUS');
    if(before.status()===409){
      // No browser-supplied identity, HMAC or API key: the BFF derives the
      // signed subject and Core independently re-verifies actual ORG_OWNER.
      const linked=await ctx.request.post(OBS+'/api/observatory/organizations',{
        headers:{Origin:OBS,'content-type':'application/json'},
        data:JSON.stringify({organizationId:QA_ID}),
        maxRedirects:0,timeout:30000,
      });
      console.log('QA21_CORE_LINK_POST_HTTP='+linked.status());
      check(linked.status()===200,'OWNER_AUTHORIZED_LINK_HTTP');
      const result=await linked.json().catch(()=>null);
      check(result?.linked===true && result?.organization?.id===QA_ID &&
        typeof result?.coreTenantId==='string' &&
        /^[a-f0-9-]{36}$/i.test(result.coreTenantId),
        'CANONICAL_CORE_TENANT_LINKED');
    }else{
      console.log('QA21_CORE_LINK_ALREADY_LINKED=PASS');
    }

    const after=await ctx.request.get(OBS+'/api/observatory/admin/applications?organizationId='+QA_ID,
      {maxRedirects:0,timeout:20000});
    console.log('QA21_CORE_LINK_POST_LINK_CATALOG_HTTP='+after.status());
    check(after.status()===200,'OWN_QA_CATALOG_READ_200');
    const catalog=await after.json().catch(()=>null);
    check(Array.isArray(catalog?.available)&&Array.isArray(catalog?.connected),
      'OWN_QA_CATALOG_SCHEMA');
    const foreign=await ctx.request.get(OBS+'/api/observatory/admin/applications?organizationId='+MAIN_ID,
      {maxRedirects:0,timeout:20000,headers:{'x-qdip-org-id':MAIN_ID}});
    check(foreign.status()===403,'MAIN_ORG_STILL_DENIED_403');
    const logout=await ctx.request.post(SITE+'/api/auth/logout',
      {headers:{Origin:SITE},maxRedirects:0,timeout:15000});
    check(logout.status()===200,'LOGOUT');
    const sessionAfter=await (await ctx.request.get(SITE+'/api/auth/session')).json();
    check(sessionAfter.authenticated===false,'LOGOUT_REVOKES_SESSION');
    console.log('QA21_CORE_LINK_RESULT=PASS');
  }finally{await ctx.close();await browser.close();}
}
run().catch(error=>{
  const label=error instanceof Error && /^[A-Z0-9_]{4,96}$/.test(error.message)
    ? error.message : 'SANITIZED_BROWSER_ERROR';
  console.error('QA21_CORE_LINK_RESULT=FAIL_'+label);
  process.exitCode=1;
});

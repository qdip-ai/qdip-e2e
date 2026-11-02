/**
 * Main-org positive / QA-org negative live Zitadel browser proof.
 * Same sealed qa@qdip.ai credentials as the existing Observatory admin E2E.
 * Read-only, no screenshots, tokens, cookies, URLs, or response data in logs.
 */
import { chromium } from '@playwright/test';

const SITE='https://qdip.ai';
const OBS='https://observatory.qdip.ai';
const ISSUER='https://mentality-rmwj0i.eu1.zitadel.cloud';
const QA_ORG='397885387160184113'; // Live verified Zitadel organization ID, not tenant alias.
const LOGIN=process.env.QDIP_E2E_ZITADEL_TEST_LOGIN;
const PASSWORD=process.env.QDIP_E2E_ZITADEL_TEST_PASSWORD;
function check(ok, stage) {
  console.log('ZITADEL_REVERSE_'+stage+'='+(ok?'PASS':'FAIL'));
  if(!ok)throw Error(stage);
}
async function visible(page, selectors, timeout=14000) {
  const until=Date.now()+timeout;
  while(Date.now()<until) {
    for(const selector of selectors) {
      const input=page.locator(selector).first();
      if(await input.isVisible().catch(()=>false))return input;
    }
    await page.waitForTimeout(250);
  }
  return null;
}
async function run(){
  check(LOGIN==='qa@qdip.ai' && typeof PASSWORD==='string' && PASSWORD.length>=8,
    'MAIN_ACCOUNT_SEALED');
  const browser=await chromium.launch({headless:true});
  const ctx=await browser.newContext({ignoreHTTPSErrors:false,serviceWorkers:'block',
    acceptDownloads:false,viewport:{width:1280,height:800}});
  try {
    const page=await ctx.newPage();
    await page.goto(SITE+'/api/auth/login?return_to='+encodeURIComponent(OBS+'/uk/admin/plugins'),
      {waitUntil:'domcontentloaded',timeout:30000});
    check(new URL(page.url()).origin===ISSUER,'REAL_ZITADEL_ISSUER');
    const login=await visible(page,['input[autocomplete="username"]','input[name="loginName"]',
      'input[name="loginname"]','input[name="username"]','input[name="email"]',
      'input[type="email"]','input[type="text"]']);
    check(Boolean(login),'LOGIN_FORM_PRESENT');
    await login.fill(LOGIN);
    let pass=await visible(page,['input[autocomplete="current-password"]','input[type="password"]'],1000);
    if(!pass){await login.press('Enter');pass=await visible(page,
      ['input[autocomplete="current-password"]','input[type="password"]']);}
    check(Boolean(pass),'PASSWORD_FORM_PRESENT');
    const response=page.waitForResponse(r=>{
      try { const u=new URL(r.url());return u.origin===SITE &&
        u.pathname==='/api/auth/callback/zitadel'; }catch{return false;}
    },{timeout:40000});
    await pass.fill(PASSWORD);
    await pass.press('Enter');
    let callback;
    try {callback=await response;}catch{throw Error('REAL_OAUTH_LOGIN_NOT_CONFIRMED');}
    check([302,303].includes(callback.status()),'REAL_OAUTH_CALLBACK_SUCCESS');
    const sessionResult=await ctx.request.get(SITE+'/api/auth/session');
    check(sessionResult.status()===200,'SESSION_HTTP_200');
    const session=await sessionResult.json();
    check(session.authenticated===true && session.observatoryAdmin===true &&
      (session.user?.email||'').toLowerCase()==='qa@qdip.ai',
      'MAIN_ACCOUNT_ADMIN_AUTHORIZED');
    const ownCatalog=await ctx.request.get(OBS+'/api/observatory/admin/plugins',
      {timeout:15000,maxRedirects:0});
    check(ownCatalog.status()===200,'MAIN_ACCOUNT_ADMIN_CATALOG_READ_200');
    // No organization ID is accepted from a browser-supplied header or email.
    // Core independently proves whether the signed subject owns this exact QA org.
    const foreign=await ctx.request.get(
      OBS+'/api/observatory/admin/applications?organizationId='+QA_ORG,
      {timeout:20000,maxRedirects:0,headers:{'x-qdip-org-id':QA_ORG}});
    check(foreign.status()===403,'QA_ORG_CREDENTIAL_CATALOG_DENIED_403');
    const owned=await ctx.request.get(OBS+'/api/observatory/organizations',
      {timeout:20000,maxRedirects:0});
    check(owned.status()===200,'OWNER_LIST_HTTP_200');
    const data=await owned.json().catch(()=>null);
    check(Array.isArray(data?.organizations) &&
      !data.organizations.some(org=>org?.id===QA_ORG),
      'QA_ORG_NOT_OWNED_BY_MAIN_ACCOUNT');
    const logout=await ctx.request.post(SITE+'/api/auth/logout',
      {headers:{Origin:SITE},maxRedirects:0,timeout:15000});
    check(logout.status()===200,'LOGOUT_SUCCESS');
    const after=await (await ctx.request.get(SITE+'/api/auth/session')).json();
    check(after.authenticated===false,'LOGOUT_REVOKED_SESSION');
    console.log('ZITADEL_REVERSE_MAIN_TO_QA=PASS');
  } finally {await ctx.close();await browser.close();}
}
run().catch(error=>{
  const code=error instanceof Error && /^[A-Z0-9_]{4,100}$/.test(error.message)
    ? error.message : 'SANITIZED_BROWSER_ERROR';
  console.error('ZITADEL_REVERSE_E2E=FAIL_'+code);
  process.exitCode=1;
});

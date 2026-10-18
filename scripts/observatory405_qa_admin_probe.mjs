/**
 * QDIP #405 positive-admin prerequisite: real qa@qdip.ai Zitadel login.
 * Read-only probe. No credentials/cookies/tokens/screenshots/PII in logs.
 * Does not create or update any plugin. One password attempt.
 */
import { chromium, request } from "@playwright/test";
const SITE="https://qdip.ai", OBS="https://observatory.qdip.ai";
const LOGIN=process.env.QDIP_E2E_ZITADEL_TEST_LOGIN;
const PASSWORD=process.env.QDIP_E2E_ZITADEL_TEST_PASSWORD;
const guard=(okay,stage)=>{if(!okay)throw Error(stage);};
async function input(page,selectors,time=14000) {
  const until=Date.now()+time;
  while(Date.now()<until){
    for(const selector of selectors){
      const f=page.locator(selector).first();
      if(await f.isVisible().catch(()=>false))return f;
    }
    await page.waitForTimeout(200);
  }
  return null;
}
async function run(){
  guard(LOGIN==="qa@qdip.ai","QA_ADMIN_LOGIN_NOT_BOUND_TO_EXPECTED_IDENTITY");
  guard(typeof PASSWORD==="string" && PASSWORD.length>0,"QA_ADMIN_PASSWORD_MISSING");
  console.log("OBS405_QA_ADMIN_CREDENTIALS_BOUND=PASS");
  const anon=await request.newContext({ignoreHTTPSErrors:false});
  const browser=await chromium.launch({headless:true});
  const context=await browser.newContext({ignoreHTTPSErrors:false,serviceWorkers:"block",acceptDownloads:false});
  try{
    const begin=await anon.get(SITE+"/api/auth/login?return_to="+encodeURIComponent(OBS+"/uk/admin/plugins"),{maxRedirects:0});
    guard(begin.status()===302,"QA_ADMIN_OIDC_START_FAILED");
    const target=new URL(begin.headers().location||"");
    guard(target.protocol==="https:"&&target.searchParams.get("code_challenge_method")==="S256"&&
      target.searchParams.get("redirect_uri")===SITE+"/api/auth/callback/zitadel","QA_ADMIN_OIDC_PKCE_INVALID");
    console.log("OBS405_QA_ADMIN_REAL_PKCE_START=PASS");
    const page=await context.newPage();
    await page.goto(SITE+"/api/auth/login?return_to="+encodeURIComponent(OBS+"/uk/admin/plugins"),{waitUntil:"domcontentloaded",timeout:30000});
    const username=await input(page,['input[autocomplete="username"]','input[name="loginName"]','input[name="loginname"]','input[name="username"]','input[name="email"]','input[type="email"]','input[type="text"]']);
    guard(Boolean(username),"QA_ADMIN_LOGIN_FORM_MISSING");
    await username.fill(LOGIN);
    let pass=await input(page,['input[autocomplete="current-password"]','input[type="password"]'],1000);
    if(!pass){
      await username.press("Enter");
      pass=await input(page,['input[autocomplete="current-password"]','input[type="password"]']);
    }
    guard(Boolean(pass),"QA_ADMIN_PASSWORD_FORM_MISSING");
    const callback=page.waitForResponse(response=>{
      try{const u=new URL(response.url());return u.origin===SITE&&u.pathname==="/api/auth/callback/zitadel"}catch{return false}
    },{timeout:40000});
    await pass.fill(PASSWORD);
    await pass.press("Enter");
    let redirect;
    try {redirect=await callback;}catch{throw Error("QA_ADMIN_ZITADEL_AUTHENTICATION_UNCONFIRMED")}
    guard([302,303].includes(redirect.status()),"QA_ADMIN_ZITADEL_CALLBACK_DENIED");
    console.log("OBS405_QA_ADMIN_REAL_OAUTH_LOGIN=PASS");
    const sessionReply=await context.request.get(OBS+"/api/auth/session",{timeout:20000});
    guard(sessionReply.status()===200,"QA_ADMIN_SESSION_HTTP_FAILED");
    const session=await sessionReply.json();
    guard(session.authenticated===true,"QA_ADMIN_SESSION_NOT_AUTHENTICATED");
    console.log("OBS405_QA_ADMIN_REAL_OBSERVATORY_SESSION=PASS");
    if(session.observatoryAdmin!==true){
      console.log("OBS405_QA_ADMIN_ROLE_NOT_RECOGNIZED=TRUE");
      // This is a prerequisite failure, not an invitation to assign roles.
      process.exitCode=2;
      return;
    }
    console.log("OBS405_QA_ADMIN_ROLE_RECOGNIZED=PASS");
    const list=await context.request.get(OBS+"/api/observatory/admin/plugins",{timeout:20000});
    guard(list.status()===200,"QA_ADMIN_LIST_UNAVAILABLE");
    const data=await list.json();
    guard(Array.isArray(data.plugins),"QA_ADMIN_LIST_SHAPE_INVALID");
    console.log("OBS405_QA_ADMIN_LIVE_CATALOG_READ=PASS");
    console.log("OBS405_QA_ADMIN_READONLY_PROBE=PASS");
  }finally{
    await anon.dispose();await context.close();await browser.close();
  }
}
run().catch(e=>{
  const stage=e instanceof Error&&/^[A-Z0-9_]{5,90}$/.test(e.message)?e.message:"QA_ADMIN_FAILURE_REDACTED";
  console.error("OBS405_QA_ADMIN_READONLY_PROBE=FAIL:"+stage);process.exitCode=1;
});

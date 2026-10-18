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
    // Scoped temporary metadata changes to the existing VHV record. Its
    // public URL remains https://vhv.qdip.ai through the existing fallback.
    const VHV_NAME = "remote-04e7c87d7b72111c-secretary";
    const TEST_URL = "https://vhv.qdip.ai";
    const original = data.plugins.find(p => p.name === VHV_NAME);
    guard(original && original.plugin_id === "secretary" &&
      original.capability_id === "secretary.plan" &&
      original.capabilities?.includes("secretary.plan") &&
      original.slug === "vhv" &&
      original.published === true &&
      original.published_version === original.version &&
      original.enabled === true &&
      Number.isSafeInteger(original.revision) &&
      (original.application_launch_url == null ||
       (original.application_launch_url === TEST_URL && original.launch_url_verified === true)),
      "QA_ADMIN_VHV_SAFE_FIXTURE_NOT_AVAILABLE");
    console.log("OBS405_QA_ADMIN_VHV_FIXTURE_SAFE=PASS");
    const api = OBS + "/api/observatory/admin/plugins/" + encodeURIComponent(VHV_NAME);
    async function current() {
      const response = await context.request.get(OBS + "/api/observatory/admin/plugins");
      guard(response.status() === 200, "QA_ADMIN_CATALOG_READ_FAILED");
      const body = await response.json();
      const p = body.plugins?.find(x => x.name === VHV_NAME);
      guard(Boolean(p), "QA_ADMIN_VHV_RECORD_MISSING");
      return p;
    }
    async function change(revision, url, verified) {
      return context.request.put(api,{
        headers:{ Origin:OBS, "Content-Type":"application/json" },
        data:{
          published:true, expected_revision:revision,
          capability_id:"secretary.plan",
          application_launch_url:url,
          launch_url_verified:verified,
        },
        timeout:20000,
      });
    }
    // Each successful write must be followed by a compensating write, even
    // on an assertion failure. Never delete a registered Worker/plugin.
    let mutated=false, finalRestored=false;
    try {
      const put = await change(original.revision, TEST_URL, true);
      guard(put.status() === 200, "QA_ADMIN_VERIFIED_URL_PUT_NOT_ACCEPTED");
      mutated=true;
      let after = await current();
      guard(after.revision === original.revision + 1 &&
        after.application_launch_url === TEST_URL &&
        after.launch_url_verified === true,
        "QA_ADMIN_VERIFIED_URL_NOT_PERSISTED");
      console.log("OBS405_QA_ADMIN_REAL_URL_SAVE_READ=PASS");
      const detail = await context.request.get(OBS+"/uk/plugins/vhv",{timeout:20000});
      guard(detail.status() === 200, "QA_ADMIN_PUBLIC_PLUGIN_PAGE_NOT_AVAILABLE");
      const html = await detail.text();
      guard(html.includes('href="https://vhv.qdip.ai"'), "QA_ADMIN_PUBLIC_LAUNCH_LINK_MISSING");
      console.log("OBS405_QA_ADMIN_REAL_PUBLIC_LAUNCH=PASS");
      const stale=await change(original.revision,TEST_URL,true);
      guard(stale.status()===409, "QA_ADMIN_STALE_CAS_NOT_REJECTED");
      after=await current();
      guard(after.revision===original.revision+1,"QA_ADMIN_STALE_CAS_MUTATED_RECORD");
      console.log("OBS405_QA_ADMIN_REAL_STALE_CAS_409=PASS");
      const revoke=await change(after.revision,"",false);
      guard(revoke.status()===200,"QA_ADMIN_URL_REVOKE_FAILED");
      const removed=await current();
      guard(removed.revision===after.revision+1 &&
        removed.application_launch_url == null && removed.launch_url_verified===false,
        "QA_ADMIN_REVOKED_URL_STILL_VISIBLE");
      console.log("OBS405_QA_ADMIN_REAL_URL_REVOKE=PASS");
      if(original.application_launch_url == null){
        finalRestored=true;
      }else{
        const restore=await change(removed.revision,original.application_launch_url,true);
        guard(restore.status()===200,"QA_ADMIN_RESTORE_PREVIOUS_URL_FAILED");
        const restored=await current();
        guard(restored.application_launch_url===original.application_launch_url &&
          restored.launch_url_verified===true,"QA_ADMIN_OLD_URL_RESTORE_NOT_VISIBLE");
        finalRestored=true;
      }
      console.log("OBS405_QA_ADMIN_METADATA_RESTORED=PASS");
      console.log("OBS405_QA_ADMIN_REAL_LAUNCH_URL_E2E=PASS");
    } finally {
      if(mutated && !finalRestored){
        // Attempt safe recovery only for an unchanged eligible VHV record,
        // with current CAS. Do not overwrite any concurrent admin edits.
        let restored=false;
        try {
          const now=await current();
          const expected=[original.revision+1,original.revision+2,original.revision+3];
          const safe=expected.includes(now.revision) &&
            now.plugin_id==="secretary" && now.slug==="vhv" &&
            now.published===true && now.capability_id==="secretary.plan" &&
            now.version===original.version && now.published_version===original.published_version &&
            (now.application_launch_url==null || now.application_launch_url===TEST_URL);
          if(safe){
            const result=await change(now.revision,original.application_launch_url || "",
              original.application_launch_url != null);
            if(result.status()===200){
              const checkRecord=await current();
              restored=(checkRecord.application_launch_url||"")===(original.application_launch_url||"");
            }
          }
        }catch{}
        if(!restored){
          console.error("OBS405_QA_ADMIN_COMPENSATING_ROLLBACK=NEEDS_MANUAL_REVIEW");
          process.exitCode=1;
        } else {
          console.log("OBS405_QA_ADMIN_COMPENSATING_ROLLBACK=PASS");
        }
      }
    }
  }finally{
    await anon.dispose();await context.close();await browser.close();
  }
}
run().catch(e=>{
  const stage=e instanceof Error&&/^[A-Z0-9_]{5,90}$/.test(e.message)?e.message:"QA_ADMIN_FAILURE_REDACTED";
  console.error("OBS405_QA_ADMIN_READONLY_PROBE=FAIL:"+stage);process.exitCode=1;
});

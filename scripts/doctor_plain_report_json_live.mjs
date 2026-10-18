/** Doctor P1 real browser release gate using existing encrypted Zitadel test credentials.
 * Exactly one password attempt; no traces/screenshots/tokens/PII in logs.
 * Runs only on public qdip-e2e runner; never modifies accounts or role grants.
 */
import { chromium, request } from "@playwright/test";
import { readFile } from "node:fs/promises";
const SITE="https://doctor.qdip.ai";
const LOGIN=process.env.QDIP_E2E_ZITADEL_TEST_LOGIN;
const PASSWORD=process.env.QDIP_E2E_ZITADEL_TEST_PASSWORD;
function check(ok,stage){ if(!ok) throw new Error(stage); }
async function getJSON(response,stage){
  check(response.ok(),stage+"_HTTP");
  try{return await response.json()}catch{throw new Error(stage+"_JSON")}
}
async function field(page,selectors,wait=12000){
  const end=Date.now()+wait;
  while(Date.now()<end){
    for(const selector of selectors){
      const match=page.locator(selector).first();
      if(await match.isVisible().catch(()=>false))return match;
    }
    await page.waitForTimeout(250);
  }
  return null;
}
async function main(){
  check(typeof LOGIN==="string"&&LOGIN.trim(),"DOCTOR_TEST_LOGIN_SECRET_MISSING");
  check(typeof PASSWORD==="string"&&PASSWORD.length,"DOCTOR_TEST_PASSWORD_SECRET_MISSING");
  const browser=await chromium.launch({headless:true});
  const context=await browser.newContext({ignoreHTTPSErrors:false,serviceWorkers:"block",
    viewport:{width:390,height:844},acceptDownloads:true});
  const anon=await request.newContext({ignoreHTTPSErrors:false});
  await context.grantPermissions(["clipboard-read","clipboard-write"],{origin:SITE});
  try{
    const a=await getJSON(await anon.get(SITE+"/api/session"),"ANONYMOUS_SESSION");
    check(a.authenticated===false&&a.user===null,"ANONYMOUS_PROFILE_EXPOSED");
    const anonymous=await anon.post(SITE+"/api/doctor",{headers:{
      Origin:SITE,"Content-Type":"application/json"},
      data:{model_base64:"e30=",operation:"validate",time_limit_seconds:2}});
    check(anonymous.status()===401,"ANONYMOUS_SOLVER_NOT_BLOCKED");
    console.log("DOCTOR_P0_ANONYMOUS=PASS");

    const page=await context.newPage();
    page.setDefaultTimeout(12000);

    const browserFaults=[];
    page.on("pageerror",err=>browserFaults.push(err?.name||"PAGE_ERROR"));
    await page.goto(SITE+"/uk",{waitUntil:"domcontentloaded",timeout:30000});
    const anonChoice=page.locator('#example-list [data-example="assumptions"]');
    await anonChoice.click();
    await page.waitForFunction(()=>document.querySelector('[data-example="assumptions"]')?.dataset.state==="selected",{timeout:12000});
    check(await anonChoice.getAttribute("aria-pressed")==="true",
      "DOCTOR_ANON_EXAMPLE_NOT_PRESSED");
    check(await page.locator("#file-label").textContent()==="assumption-conflict.cpmodel",
      "DOCTOR_ANON_SAMPLE_NOT_LOADED");
    check(await page.locator("#run").isDisabled(),
      "DOCTOR_ANON_RUN_NOT_DENIED");
    check((await page.locator("#example-notice").textContent()||"").includes("Zitadel"),
      "DOCTOR_ANON_LOGIN_HINT_MISSING");
    console.log("DOCTOR_EXAMPLE_ANON_SELECTED=PASS");
    // Check the INITIAL OAuth redirect before the browser follows it to
    // Zitadel's hosted login UI (which may not retain PKCE query params).
    const start=await anon.get(SITE+"/auth/login?lang=uk",{maxRedirects:0});
    check(start.status()===303,"DOCTOR_OAUTH_START_NOT_REDIRECTED");
    const authorization=new URL(start.headers()["location"]||"");
    check(authorization.protocol==="https:"&&authorization.origin!==SITE
      &&authorization.searchParams.get("code_challenge_method")==="S256"
      &&authorization.searchParams.get("redirect_uri")===SITE+"/auth/callback",
      "DOCTOR_PKCE_REDIRECT_INVALID");
    const initial=await page.goto(SITE+"/auth/login?lang=uk",{
      waitUntil:"domcontentloaded",timeout:30000});
    check(Boolean(initial)&&new URL(page.url()).origin!==SITE,
      "DOCTOR_ZITADEL_LOGIN_FORM_NOT_REACHED");
    console.log("DOCTOR_P0_LIVE_ZITADEL_PKCE=PASS");

    const user=await field(page,[
      'input[autocomplete="username"]','input[name="loginName"]',
      'input[name="loginname"]','input[name="username"]',
      'input[name="email"]','input[type="email"]','input[type="text"]'
    ]);
    check(Boolean(user),"DOCTOR_ZITADEL_USERNAME_UNAVAILABLE");
    await user.fill(LOGIN);
    let pass=await field(page,[
      'input[autocomplete="current-password"]','input[type="password"]'
    ],1200);
    if(!pass){
      await user.press("Enter");
      pass=await field(page,[
        'input[autocomplete="current-password"]','input[type="password"]'
      ]);
    }
    check(Boolean(pass),"DOCTOR_ZITADEL_PASSWORD_UNAVAILABLE");
    await pass.fill(PASSWORD);
    await pass.press("Enter");
    try{
      await page.waitForURL(url=>url.origin===SITE,{timeout:30000});
    }catch{throw new Error("DOCTOR_ZITADEL_LOGIN_OR_ROLE_DENIED")}
    const logged=await getJSON(await context.request.get(SITE+"/api/session"),
      "DOCTOR_USER_SESSION");
    check(logged.authenticated===true,"DOCTOR_USER_SESSION_NOT_AUTHENTICATED");
    console.log("DOCTOR_P0_REAL_ZITADEL_LOGIN=PASS");


    await page.goto(SITE+"/uk",{waitUntil:"domcontentloaded",timeout:30000});
    const first=page.locator('#example-list [data-example="feasible"]');
    const selected=page.locator('#example-list [data-example="assumptions"]');
    await selected.click();
    await page.waitForFunction(()=>document.querySelector('[data-example="assumptions"]')?.dataset.state==="selected",{timeout:12000});
    check(await selected.getAttribute("aria-pressed")==="true"
        && await first.getAttribute("aria-pressed")==="false",
      "DOCTOR_EXAMPLE_EXCLUSIVE_SELECTION_MISSING");
    check(await page.locator("#file-label").textContent()==="assumption-conflict.cpmodel",
      "DOCTOR_EXAMPLE_MODEL_NOT_LOADED");
    check(await page.locator("#operation").inputValue()==="propose_repair",
      "DOCTOR_EXAMPLE_OPERATION_NOT_SELECTED");
    check(await page.locator("#run").isEnabled(),
      "DOCTOR_EXAMPLE_RUN_NOT_ENABLED");
    const presentation=await page.evaluate(()=>{
      const chosen=getComputedStyle(document.querySelector('[data-example="assumptions"]'));
      const unchosen=getComputedStyle(document.querySelector('[data-example="feasible"]'));
      return {border:chosen.borderTopColor,otherBorder:unchosen.borderTopColor};
    });
    check(presentation.border!==presentation.otherBorder,
      "DOCTOR_EXAMPLE_NO_VISIBLE_SELECTION");
    console.log("DOCTOR_EXAMPLE_AUTH_SELECTED_VISIBLE=PASS");

    await page.locator("#run").click();
    await page.locator("#result").waitFor({state:"visible",timeout:25000});
    await page.locator("#repair-options li").first().waitFor({state:"visible",timeout:15000});
    check(await page.locator("#repair-options li").count()===2,
      "DOCTOR_EXAMPLE_VERIFIED_REPAIRS_NOT_RENDERED");
    check((await page.locator("#solver-status").textContent()||"").trim().length>1,
      "DOCTOR_EXAMPLE_SOLVER_STATUS_EMPTY");
    check(await selected.getAttribute("aria-pressed")==="true",
      "DOCTOR_EXAMPLE_SELECTION_LOST_AFTER_EXECUTION");
    check(browserFaults.length===0,"DOCTOR_EXAMPLE_BROWSER_JS_ERROR");
    console.log("DOCTOR_EXAMPLE_REAL_CLICK_TO_CP_SAT=PASS");

    await first.click();
    await page.waitForFunction(()=>document.querySelector('[data-example="feasible"]')?.dataset.state==="selected",{timeout:12000});
    check(await first.getAttribute("aria-pressed")==="true"
        && await selected.getAttribute("aria-pressed")==="false",
      "DOCTOR_EXAMPLE_SWITCH_SELECTION_BROKEN");
    console.log("DOCTOR_EXAMPLE_SWITCH=PASS");
    await page.locator("#run").click();
    await page.locator("#plain-result").waitFor({state:"visible",timeout:25000});
    check(await page.locator("#actionable-issues").isHidden(),
      "DOCTOR_FEASIBLE_SHOWS_IRRELEVANT_REPAIR");
    check(await page.locator("#advanced-details").getAttribute("open")===null,
      "DOCTOR_ENGINEERING_DETAILS_NOT_COLLAPSED");
    check(await page.locator("#plain-result-values li").count()===1,
      "DOCTOR_FEASIBLE_KEY_ASSIGNMENT_MISSING");
    const valueRow=await page.locator("#plain-result-values li").first().innerText();
    check(valueRow.includes("shift_assigned") && valueRow.includes("1"),
      "DOCTOR_FEASIBLE_VALUE_INCORRECT");
    console.log("DOCTOR_PLAIN_RESULT_PRIMARY=PASS");

    await page.locator("#advanced-details > summary").click();
    await page.locator(".technical-result > summary").click();
    const json=(await page.locator("#raw-result").textContent()||"").trim();
    check(JSON.parse(json).solver_status==="OPTIMAL",
      "DOCTOR_RAW_JSON_DIFFERENT_FROM_EXECUTION");
    await page.locator("#copy-report").click();
    await page.waitForFunction(()=>{
      const text=document.querySelector("#report-action-status")?.textContent || "";
      return Boolean(text);
    },null,{timeout:5000});
    const copyStatus=(await page.locator("#report-action-status").textContent()||"");
    check(copyStatus.includes("скопійовано"),
      "DOCTOR_COPY_JSON_STATUS_"+(copyStatus.includes("Не вдалося")?"FAILED":"UNKNOWN"));
    check((await page.evaluate(()=>navigator.clipboard.readText())).trim()===json,
      "DOCTOR_CLIPBOARD_JSON_MISMATCH");
    console.log("DOCTOR_COPY_JSON_REAL_BROWSER=PASS");

    const promise=page.waitForEvent("download",{timeout:15000});
    await page.locator("#export-report").click();
    const download=await promise;
    check(/^doctor-report-[0-9a-f]{8}\.json$/.test(download.suggestedFilename()),
      "DOCTOR_JSON_FILENAME_BAD");
    const bytes=await readFile(await download.path(),"utf8");
    check(bytes.trim()===json,"DOCTOR_DOWNLOAD_JSON_MISMATCH");
    console.log("DOCTOR_SAVE_JSON_REAL_BROWSER=PASS");

    const csrf=await context.request.post(SITE+"/api/doctor",{
      headers:{Origin:"https://other.invalid","Content-Type":"application/json"},
      data:{model_base64:"e30=",operation:"validate",time_limit_seconds:2}});
    check(csrf.status()===403,"DOCTOR_CSRF_NOT_BLOCKED");
    const logout=await context.request.post(SITE+"/auth/logout",{headers:{Origin:SITE}});
    check(logout.status()===200,"DOCTOR_LOGOUT_HTTP_FAILED");
    const after=await getJSON(await context.request.get(SITE+"/api/session"),
      "DOCTOR_REVOKED_SESSION");
    check(after.authenticated===false,"DOCTOR_SESSION_NOT_REVOKED");
    const blocked=await context.request.post(SITE+"/api/doctor",{
      headers:{Origin:SITE,"Content-Type":"application/json"},
      data:{model_base64:"e30=",operation:"validate",time_limit_seconds:2}});
    check(blocked.status()===401,"DOCTOR_LOGOUT_SOLVER_NOT_BLOCKED");
    console.log("DOCTOR_P0_CSRF_LOGOUT=PASS");
    console.log("DOCTOR_REPORT_JSON_E2E=PASS");
    console.log("DOCTOR_ROLELESS_IDENTITY=NOT_TESTED");
  }finally{
    await anon.dispose();await context.close();await browser.close();
  }
}
main().catch(error=>{
  const stage=error instanceof Error&&/^[A-Z0-9_]{5,90}$/.test(error.message)
    ?error.message:"DOCTOR_BROWSER_FAILURE_REDACTED";
  console.error("DOCTOR_REPORT_JSON_E2E=FAIL:"+stage);
  process.exitCode=1;
});
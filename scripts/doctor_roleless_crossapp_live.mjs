/** Negative real Zitadel browser authorization, Doctor P1.
 * qa1@qdip.ai must authenticate at Zitadel but have NO doctor_user role.
 * No screenshots, traces, tokens, URLs with authorization codes, or PII logs.
 * Exactly one password attempt. Never auto-rerun on push.
 */
import { chromium, request } from "@playwright/test";
const SITE = "https://doctor.qdip.ai";
const ACCOUNT = process.env.QDIP_DOCTOR_TEST_LOGIN;
const PASSWORD = process.env.QDIP_DOCTOR_TEST_PASSWORD;
const USER_KEY = process.env.QDIP_DOCTOR_TEST_LABEL;
if (!["QA1","QA2"].includes(USER_KEY)) throw Error("INVALID_IDENTITY_LABEL");
const prefix = "DOCTOR_" + USER_KEY;
function check(ok, stage) { if (!ok) throw Error(stage); }
async function findField(page, candidates, timeout=12000) {
  const end=Date.now()+timeout;
  while(Date.now()<end) {
    for(const selector of candidates) {
      const field=page.locator(selector).first();
      if(await field.isVisible().catch(()=>false))return field;
    }
    await page.waitForTimeout(250);
  }
  return null;
}
async function main() {
  check(typeof ACCOUNT==="string" && ACCOUNT===USER_KEY.toLowerCase()+"@qdip.ai",
        "TEST_LOGIN_IDENTITY_MISMATCH");
  check(typeof PASSWORD==="string" && PASSWORD.length>0,
        "TEST_PASSWORD_SECRET_NOT_BOUND");
  const anon=await request.newContext({ignoreHTTPSErrors:false});
  const browser=await chromium.launch({headless:true});
  const context=await browser.newContext({
    ignoreHTTPSErrors:false, serviceWorkers:"block",
    viewport:{width:1280,height:800},acceptDownloads:false,
  });
  try {
    const pre=await anon.get(SITE+"/api/session");
    check(pre.status()===200 && (await pre.json()).authenticated===false,
          "QA1_PRECONDITION_ANONYMOUS_FAILED");
    console.log(prefix+"_INITIAL_ANONYMOUS=PASS");
    const auth=await anon.get(SITE+"/auth/login?lang=uk",{maxRedirects:0});
    check(auth.status()===303, "QA1_OAUTH_PKCE_REDIRECT_MISSING");
    const target=new URL(auth.headers()["location"]||"");
    check(target.protocol==="https:"&&target.origin!==SITE
          &&target.searchParams.get("code_challenge_method")==="S256"
          &&target.searchParams.get("redirect_uri")===SITE+"/auth/callback",
          "QA1_OAUTH_PKCE_PARAMETERS_INVALID");
    console.log(prefix+"_REAL_PKCE_REDIRECT=PASS");

    const page=await context.newPage();
    page.setDefaultTimeout(12000);
    const initial=await page.goto(SITE+"/auth/login?lang=uk",{
      waitUntil:"domcontentloaded",timeout:30000,
    });
    check(Boolean(initial) && new URL(page.url()).origin!==SITE,
          "QA1_REAL_ZITADEL_LOGIN_PAGE_NOT_REACHED");
    const username=await findField(page,[
      'input[autocomplete="username"]','input[name="loginName"]',
      'input[name="loginname"]','input[name="username"]',
      'input[name="email"]','input[type="email"]','input[type="text"]',
    ]);
    check(Boolean(username),"QA1_ZITADEL_USERNAME_INPUT_UNAVAILABLE");
    await username.fill(ACCOUNT);
    let password=await findField(page,[
      'input[autocomplete="current-password"]','input[type="password"]',
    ],1200);
    if(!password) {
      await username.press("Enter");
      password=await findField(page,[
        'input[autocomplete="current-password"]','input[type="password"]',
      ]);
    }
    check(Boolean(password),"QA1_ZITADEL_PASSWORD_INPUT_UNAVAILABLE");
    const callback=page.waitForResponse(response=>{
      try {
        const uri=new URL(response.url());
        return uri.origin===SITE && uri.pathname==="/auth/callback";
      }catch{return false;}
    },{timeout:40000});
    await password.fill(PASSWORD);
    await password.press("Enter");
    // Reaching the Doctor OAuth callback requires a code from Zitadel;
    // an invalid password never reaches this point. Status 403 is mandatory.
    let response;
    try {response=await callback;}
    catch {throw Error("QA1_ZITADEL_AUTHENTICATION_NOT_CONFIRMED");}
    check(response.status()===403,"QA1_DOCTOR_AUTHORIZATION_NOT_FORBIDDEN");
    const body=await response.text();
    check(body.toLowerCase().includes("<!doctype html>"),
          "QA1_DOCTOR_AUTHORIZATION_ERROR_PAGE_MISSING");
    console.log(prefix+"_REAL_ZITADEL_CODE_RETURNED=PASS");
    console.log(prefix+"_DOCTOR_OAUTH_403=PASS");

    const session=await context.request.get(SITE+"/api/session");
    check(session.status()===200,"QA1_SESSION_ENDPOINT_FAILED");
    const user=await session.json();
    check(user.authenticated===false && user.user===null,
          "QA1_UNAUTHORIZED_SESSION_CREATED");
    console.log(prefix+"_NO_DOCTOR_SESSION=PASS");
    const protectedModel=await context.request.post(SITE+"/api/doctor",{
      headers:{Origin:SITE,"Content-Type":"application/json"},
      data:{model_base64:"e30=",operation:"validate",time_limit_seconds:1},
    });
    check(protectedModel.status()===401,"QA1_SOLVER_WAS_ACCESSIBLE");
    console.log(prefix+"_SOLVER_DENIED_401=PASS");
    const mcp=await context.request.post(SITE+"/mcp",{
      headers:{"Content-Type":"application/json"},
      data:{jsonrpc:"2.0",id:1,method:"tools/list"},
    });
    check(mcp.status()===401,"QA1_MCP_WAS_ACCESSIBLE");
    console.log(prefix+"_MCP_DENIED_401=PASS");

    // No session ever issued for QA1; without OAuth token it cannot be a
    // different authorized identity from a stale default-test-user context.
    const cookies=await context.cookies(SITE);
    check(!cookies.some(c=>c.name==="__Host-doctor_session"),
          "QA1_DOCTOR_SESSION_COOKIE_ISSUED");
    console.log(prefix+"_NO_SESSION_COOKIE=PASS");
    // Test the exact denied identity inside Observatory's actual browser UI.
    await page.goto("https://observatory.qdip.ai/uk/model-doctor",{
      waitUntil:"domcontentloaded",timeout:30000,
    });
    check(new URL(page.url()).origin==="https://observatory.qdip.ai",
          "OBSERVATORY_ORIGIN_NOT_LOADED");
    await page.getByText("Увійдіть у Doctor через Zitadel", {exact:false})
      .waitFor({state:"visible",timeout:15000});
    const executeButton=page.getByRole("button",{name:"Виконати в Doctor"});
    check(await executeButton.isDisabled(),
          "OBSERVATORY_EXECUTE_ENABLED_WITHOUT_ROLE");
    const bridge=await page.evaluate(async ({site})=>{
      const s=await fetch(site+"/api/observatory/session",{
        method:"GET",mode:"cors",credentials:"include",cache:"no-store",
      });
      const data=await s.json();
      const e=await fetch(site+"/api/observatory/doctor",{
        method:"POST",mode:"cors",credentials:"include",cache:"no-store",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({model_base64:"e30=",operation:"validate",time_limit_seconds:1}),
      });
      return {sessionStatus:s.status,authenticated:data.authenticated,
              leakedUser:data.user,executeStatus:e.status,
              error:(await e.json()).error};
    },{site:SITE});
    check(bridge.sessionStatus===200 && bridge.authenticated===false
          && bridge.leakedUser===undefined && bridge.executeStatus===401
          && bridge.error==="authentication_required",
          "OBSERVATORY_BRIDGE_ROLE_DENIAL_FAILED");
    check(!(await context.cookies(SITE)).some(c=>c.name==="__Host-doctor_session"),
          "OBSERVATORY_CROSS_SITE_COOKIE_LEAKED");
    console.log(prefix+"_OBSERVATORY_REAL_BROWSER_ROLE_DENIED=PASS");

    console.log(prefix+"_REAL_ZITADEL_AND_OBSERVATORY_ROLELESS=PASS");
  } finally {
    await anon.dispose();await context.close();await browser.close();
  }
}
main().catch(error=>{
  const stage=error instanceof Error&&/^[A-Z0-9_]{5,90}$/.test(error.message)
    ?error.message:"QA1_BROWSER_ERROR_REDACTED";
  console.error(prefix+"_REAL_ZITADEL_AND_OBSERVATORY_ROLELESS=FAIL:"+stage);
  process.exitCode=1;
});

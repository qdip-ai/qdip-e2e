/** Doctor P1 real browser release gate using existing encrypted Zitadel test credentials.
 * Exactly one password attempt; no traces/screenshots/tokens/PII in logs.
 * Runs only on public qdip-e2e runner; never modifies accounts or role grants.
 */
import { chromium, request } from "@playwright/test";
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
    viewport:{width:1280,height:800},acceptDownloads:false});
  const anon=await request.newContext({ignoreHTTPSErrors:false});
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

    for(const lang of ["en","uk","pl"]){
      const res=await context.request.get(SITE+"/"+lang);
      check(res.status()===200,"DOCTOR_LANGUAGE_HTTP_FAILED");
      const html=await res.text();
      check(html.includes('<html lang="'+lang+'">')&&
        html.includes('href="https://qdip.ai/'+lang+'"'),
        "DOCTOR_LANGUAGE_LINK_WRONG");
    }
    console.log("DOCTOR_P0_LOCALES=PASS");

    async function fixture(name){
      const res=await context.request.get(SITE+"/assets/examples/"+name+".cpmodel");
      check(res.status()===200,"DOCTOR_TEST_MODEL_DOWNLOAD_FAILED");
      return (await res.body()).toString("base64");
    }
    const feasible=await fixture("feasible");
    const conflict=await fixture("assumption-conflict");
    const hard=await fixture("hard-conflict");
    const invalid=await fixture("invalid");
    async function evaluate(operation,model){
      const response=await context.request.post(SITE+"/api/doctor",{
        headers:{Origin:SITE,"Content-Type":"application/json"},
        data:{model_base64:model,operation,time_limit_seconds:2},
        timeout:20000});
      check(response.status()===200,"DOCTOR_"+operation.toUpperCase()+"_HTTP_FAILURE");
      const result=await getJSON(response,"DOCTOR_"+operation.toUpperCase());
      check(result.execution_status==="COMPLETED"&&result.operation===operation
        &&typeof result.model_wire_sha256==="string"
        &&result.model_wire_sha256.length===64,
        "DOCTOR_"+operation.toUpperCase()+"_EVIDENCE_INVALID");
      return result;
    }
    const validated=await evaluate("validate",feasible);
    check(validated.solver_status==="VALID"&&
      validated.model_inspection?.variables_total===1,"DOCTOR_VALIDATE_INCORRECT");
    console.log("DOCTOR_P0_VALIDATE=PASS");
    const solved=await evaluate("solve",feasible);
    check(solved.solver_status==="OPTIMAL"&&Array.isArray(solved.solution)
      &&solved.solution[0]===1,"DOCTOR_SOLVE_INCORRECT");
    console.log("DOCTOR_P0_SOLVE=PASS");
    const diagnosed=await evaluate("diagnose",conflict);
    check(diagnosed.solver_status==="INFEASIBLE"
      &&diagnosed.diagnosis?.kind==="VERIFIED_SUFFICIENT_ASSUMPTION_CORE"
      &&diagnosed.diagnosis.verification_status==="INFEASIBLE",
      "DOCTOR_DIAGNOSE_INCORRECT");
    console.log("DOCTOR_P0_DIAGNOSE=PASS");
    const repaired=await evaluate("propose_repair",conflict);
    check(repaired.repair?.kind==="VERIFIED_ASSUMPTION_RELAXATION_ALTERNATIVES"
      &&Array.isArray(repaired.repair.proposals)
      &&repaired.repair.proposals.length===2
      &&repaired.model_wire_sha256===diagnosed.model_wire_sha256,
      "DOCTOR_P1_MULTI_REPAIR_CONTRACT_MISMATCH");
    const proposals=repaired.repair.proposals;
    const originals=diagnosed.diagnosis.assumption_core;
    const hashes=new Set();
    const removed=new Set();
    for(const candidate of proposals){
      check(candidate?.operation==="REMOVE_ASSUMPTION"
        &&candidate.verified_by==="INDEPENDENT_CP_SAT_SOLVE"
        &&["FEASIBLE","OPTIMAL"].includes(candidate.candidate_solver_status)
        &&candidate.automatically_applied===false
        &&candidate.requires_user_approval===true
        &&typeof candidate.candidate_wire_sha256==="string"
        &&/^[0-9a-f]{64}$/.test(candidate.candidate_wire_sha256)
        &&originals.some(a=>a.literal===candidate.assumption?.literal
          &&a.variable_index===candidate.assumption?.variable_index
          &&a.negated===candidate.assumption?.negated),
        "DOCTOR_P1_REPAIR_EVIDENCE_INVALID");
      hashes.add(candidate.candidate_wire_sha256);
      removed.add(candidate.assumption.literal);
    }
    check(hashes.size===2&&removed.size===2,"DOCTOR_P1_REPAIR_ALTERNATIVES_NOT_DISTINCT");
    console.log("DOCTOR_P1_MULTI_REPAIR_REAL_USER=PASS");
    const hardCase=await evaluate("diagnose",hard);
    const invalidCase=await evaluate("validate",invalid);
    check(hardCase.diagnosis?.kind==="VERIFIED_SUFFICIENT_HARD_CONSTRAINT_CORE"
      &&hardCase.diagnosis?.verification_status==="INFEASIBLE"
      &&hardCase.diagnosis?.minimal===false
      &&hardCase.diagnosis?.original_model_mutated===false
      &&hardCase.diagnosis?.hard_constraints?.length===2
      &&invalidCase.solver_status==="MODEL_INVALID"
      &&invalidCase.model_inspection===null,
      "DOCTOR_HARD_INVALID_INCORRECT");
    console.log("DOCTOR_P1_HARD_CORE_AND_INVALID=PASS");

    // Cross-origin Observatory adapter release gate: use an actual browser
    // so CORS, SameSite and host-only HttpOnly Doctor cookie semantics are real.
    const OBS="https://observatory.qdip.ai";
    await page.goto(OBS+"/uk/model-doctor",{waitUntil:"domcontentloaded",timeout:30000});
    check(new URL(page.url()).origin===OBS,"OBSERVATORY_ORIGIN_NOT_LOADED");
    const bridge=await page.evaluate(async ({site,encoded})=>{
      const session=await fetch(site+"/api/observatory/session",{
        mode:"cors",credentials:"include",cache:"no-store"
      });
      const sessionBody=await session.json();
      const response=await fetch(site+"/api/observatory/doctor",{
        method:"POST",mode:"cors",credentials:"include",cache:"no-store",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({model_base64:encoded,operation:"solve",time_limit_seconds:2}),
      });
      return {sessionStatus:session.status,session:sessionBody,
        executeStatus:response.status,evidence:await response.json(),
        sessionCors:session.headers.get("access-control-allow-origin"),
        executionCors:response.headers.get("access-control-allow-origin")};
    },{site:SITE,encoded:feasible});
    check(bridge.sessionStatus===200
      &&bridge.session.authenticated===true
      &&bridge.session.user===undefined
      &&bridge.executionStatus===undefined
      &&bridge.executeStatus===200
      &&bridge.evidence?.contract_version==="doctor.native-cpsat.v0.1"
      &&bridge.evidence.operation==="solve"
      &&bridge.evidence.solver_status==="OPTIMAL"
      &&bridge.sessionCors===OBS
      &&bridge.executionCors===OBS,
      "OBSERVATORY_DOCTOR_CREDENTIALLED_BROWSER_BRIDGE_FAILED");
    console.log("DOCTOR_OBSERVATORY_LIVE_COOKIE_CORS_CP_SAT=PASS");

    const csrf=await context.request.post(SITE+"/api/doctor",{
      headers:{Origin:"https://other.invalid","Content-Type":"application/json"},
      data:{model_base64:feasible,operation:"validate",time_limit_seconds:2}});
    check(csrf.status()===403,"DOCTOR_CSRF_NOT_BLOCKED");
    const logout=await context.request.post(SITE+"/auth/logout",{headers:{Origin:SITE}});
    check(logout.status()===200,"DOCTOR_LOGOUT_HTTP_FAILED");
    const after=await getJSON(await context.request.get(SITE+"/api/session"),
      "DOCTOR_REVOKED_SESSION");
    check(after.authenticated===false,"DOCTOR_SESSION_NOT_REVOKED");
    const blocked=await context.request.post(SITE+"/api/doctor",{
      headers:{Origin:SITE,"Content-Type":"application/json"},
      data:{model_base64:feasible,operation:"validate",time_limit_seconds:2}});
    check(blocked.status()===401,"DOCTOR_LOGOUT_SOLVER_NOT_BLOCKED");
    console.log("DOCTOR_P0_CSRF_LOGOUT=PASS");
    console.log("DOCTOR_P1_REAL_ZITADEL_BROWSER_MULTI_REPAIR_E2E=PASS");
    console.log("DOCTOR_ROLELESS_IDENTITY=NOT_TESTED");
  }finally{
    await anon.dispose();await context.close();await browser.close();
  }
}
main().catch(error=>{
  const stage=error instanceof Error&&/^[A-Z0-9_]{5,90}$/.test(error.message)
    ?error.message:"DOCTOR_BROWSER_FAILURE_REDACTED";
  console.error("DOCTOR_P1_REAL_ZITADEL_BROWSER_MULTI_REPAIR_E2E=FAIL:"+stage);
  process.exitCode=1;
});
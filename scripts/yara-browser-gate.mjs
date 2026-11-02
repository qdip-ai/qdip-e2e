/** Shared qdip-e2e Yara gate: real Zitadel browser login; no fake signed cookies. */
import {createRequire} from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
const originText=process.env.YARA_E2E_BASE_URL;
const sha=process.env.YARA_E2E_EXPECTED_SHA;
const scope=process.env.YARA_E2E_SCOPE;
const mode=process.argv[2];
const fail=(reason)=>{throw new Error(reason)};
function validUrl(){
  let parsed;
  try{parsed=new URL(originText)}catch{fail('YARA_E2E_URL_INVALID')}
  if(parsed.protocol!=='https:' || parsed.username || parsed.password ||
    parsed.search || parsed.hash || parsed.pathname!=='/' ||
    !(parsed.hostname==='qdip.ai'||parsed.hostname.endsWith('.qdip.ai') ||
      parsed.hostname.endsWith('.up.railway.app')))
    fail('YARA_E2E_URL_UNTRUSTED');
  return parsed;
}
const base=validUrl();
if((scope==='full'||sha) && !/^[0-9a-f]{40}$/.test(sha||''))fail('YARA_SHA_INVALID');
if(!['public','full'].includes(scope))fail('YARA_SCOPE_INVALID');
if(scope==='full' && base.origin==='https://yara.qdip.ai')
  fail('YARA_FULL_GATE_REQUIRES_ISOLATED_QA_DEPLOYMENT');
if(mode==='validate'){
  console.log('YARA_INPUTS_VALIDATED=PASS');
}else if(mode==='attest'){
  if(scope!=='full')fail('YARA_SHA_ATTESTATION_FULL_ONLY');
  // Only server-produced Git SHA is accepted: a source checkout alone cannot
  // prove which version the remote browser is seeing.
  const endpoint=new URL('/api/build-identity',base);
  const response=await fetch(endpoint,{redirect:'manual',headers:{Accept:'application/json'}});
  if(response.status!==200)fail('YARA_QA_BUILD_IDENTITY_UNAVAILABLE');
  const parsed=await response.json().catch(()=>null);
  if(!parsed||typeof parsed.sha!=='string'||parsed.sha!==sha)
    fail('YARA_QA_DEPLOYED_SHA_MISMATCH');
  console.log('YARA_EXACT_SHA_QA_DEPLOYMENT=PASS');
}else if(mode==='login'){
  if(scope!=='full')fail('YARA_LIVE_ZITADEL_LOGIN_FULL_ONLY');
  const login=process.env.QDIP_E2E_ZITADEL_TEST_LOGIN;
  const password=process.env.QDIP_E2E_ZITADEL_TEST_PASSWORD;
  if(!login||!password)fail('YARA_ZITADEL_TEST_IDENTITY_MISSING');
  const runnerDir=path.resolve(process.env.YARA_E2E_RUNNER_DIR||'');
  const stateFile=path.resolve(process.env.YARA_E2E_QA_STATE_FILE||'');
  const temp=path.resolve(process.env.RUNNER_TEMP||'');
  if(!stateFile.startsWith(temp+path.sep))fail('YARA_AUTH_STATE_MUST_BE_EPHEMERAL');
  const requireRunner=createRequire(path.join(runnerDir,'package.json'));
  const {chromium}=requireRunner('@playwright/test');
  const browser=await chromium.launch({headless:true});
  const context=await browser.newContext({serviceWorkers:'block',ignoreHTTPSErrors:false});
  const page=await context.newPage();
  async function firstVisible(selectors,ms=16000){
    const end=Date.now()+ms;
    while(Date.now()<end){
      for(const selector of selectors){
        const el=page.locator(selector).first();
        if(await el.isVisible().catch(()=>false))return el;
      }
      await page.waitForTimeout(250);
    }
    return null;
  }
  try{
    const response=await page.goto(new URL('/login',base).href,{waitUntil:'domcontentloaded',timeout:30000});
    if(response?.status()!==200)fail('YARA_LOGIN_PAGE_UNAVAILABLE');
    await page.locator('.login-submit').click({timeout:12000});
    const user=await firstVisible([
      'input[autocomplete="username"]','input[name="loginName"]',
      'input[name="loginname"]','input[name="username"]',
      'input[name="email"]','input[type="email"]','input[type="text"]'
    ]);
    if(!user){
      // Diagnostic metadata only: never print query parameters, cookies,
      // user names, credentials or page content from the identity provider.
      const location=new URL(page.url());
      const inputs=await page.locator('input').evaluateAll(nodes=>nodes.map(n=>({
        type:n.getAttribute('type'),name:n.getAttribute('name'),autocomplete:n.getAttribute('autocomplete')
      })).slice(0,10));
      console.error('YARA_ZITADEL_LOGIN_LOCATION='+location.origin+location.pathname);
      // Presence/shape only, never query values (may include OAuth state/PKCE).
      const clientId=location.searchParams.get('client_id');
      console.error('YARA_OIDC_QUERY_SHAPE='+JSON.stringify({
        hasValidClientId:!!clientId&&clientId!=='undefined'&&clientId!=='null',
        hasRedirectUri:location.searchParams.has('redirect_uri'),
        hasResponseType:location.searchParams.has('response_type'),
        title:await page.title()
      }));
      console.error('YARA_ZITADEL_LOGIN_INPUT_SHAPE='+JSON.stringify(inputs));
      if(!clientId||clientId==='undefined'||clientId==='null')
        fail('YARA_QA_OIDC_CLIENT_ID_NOT_CONFIGURED');
      fail('YARA_ZITADEL_LOGIN_FORM_NOT_REACHED');
    }
    await user.fill(login);
    let pass=await firstVisible(['input[autocomplete="current-password"]','input[type="password"]'],1300);
    if(!pass){
      await user.press('Enter');
      pass=await firstVisible(['input[autocomplete="current-password"]','input[type="password"]']);
    }
    if(!pass)fail('YARA_ZITADEL_PASSWORD_FIELD_UNAVAILABLE');
    // Exactly one password submission. No retries on failed login or MFA.
    await pass.fill(password);
    await pass.press('Enter');
    await page.waitForURL(u=>u.origin===base.origin && u.pathname!=='/login',{timeout:30000})
      .catch(()=>fail('YARA_ZITADEL_LOGIN_OR_CLIENT_ACCESS_DENIED'));
    await page.locator('#assistant-command').waitFor({state:'visible',timeout:20000});
    const state=await context.storageState();
    if(!state.cookies.length)fail('YARA_AUTH_BROWSER_COOKIES_MISSING');
    fs.writeFileSync(stateFile,JSON.stringify(state),{mode:0o600,flag:'wx'});
    console.log('YARA_REAL_ZITADEL_BROWSER_LOGIN=PASS');
  }finally{
    await context.close();await browser.close();
  }
}else fail('YARA_GATE_COMMAND_INVALID');

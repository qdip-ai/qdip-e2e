/** Read-only browser acceptance for an EXISTING Zitadel TEST2 identity.
 * No new accounts/roles, no model dispatch, no privileged POST, no credential logs.
 * Public artifacts contain only screenshots cropped to model-control widgets.
 */
import {chromium} from '@playwright/test';
import {createPublicKey,verify} from 'node:crypto';
import {mkdirSync} from 'node:fs';
import {resolve} from 'node:path';

const SITE='https://autodev.qdip.ai';
const ISSUER='https://mentality-rmwj0i.eu1.zitadel.cloud';
const PROJECT='394565917515719957', ORG='368555767923594379';
const CLIENT='395658023814660262';
const USER=process.env.QDIP_E2E_ZITADEL_TEST_LOGIN;
const PASSWORD=process.env.QDIP_E2E_ZITADEL_TEST_PASSWORD;
const EVIDENCE=resolve(process.env.QDIP_E2E_BROWSER_EVIDENCE_DIR||'/tmp/autodev-operator-controls');
const VIEWS=[['DESKTOP',1440,900],['MOBILE_PORTRAIT',390,844],['MOBILE_LANDSCAPE',844,390]];
const assert=(ok,code)=>{if(!ok)throw Error(code)};
async function formField(page,selectors,timeout=12000){
 const deadline=Date.now()+timeout;
 while(Date.now()<deadline){
  for(const selector of selectors){
   const target=page.locator(selector).first();
   if(await target.isVisible().catch(()=>false))return target;
  }
  await page.waitForTimeout(200);
 }
 return null;
}
async function verifyExistingOperator(token){
 assert(typeof token==='string'&&token.length<=8192,'OPERATOR_JWT_MISSING');
 const parts=token.split('.');
 assert(parts.length===3,'OPERATOR_JWT_NOT_SIGNED');
 const head=JSON.parse(Buffer.from(parts[0],'base64url').toString());
 const claims=JSON.parse(Buffer.from(parts[1],'base64url').toString());
 assert(['RS256','RS384'].includes(head.alg)&&head.kid,'OPERATOR_JWT_ALG_UNEXPECTED');
 const response=await fetch(ISSUER+'/oauth/v2/keys',{
  redirect:'error',signal:AbortSignal.timeout(9000)});
 assert(response.ok,'OPERATOR_REAL_JWKS_UNAVAILABLE');
 const jwks=await response.json();
 const key=jwks.keys?.find(x=>x.kid===head.kid&&x.kty==='RSA');
 assert(key,'OPERATOR_JWKS_KEY_MISSING');
 const valid=verify(head.alg==='RS384'?'RSA-SHA384':'RSA-SHA256',
  Buffer.from(parts[0]+'.'+parts[1]),createPublicKey({key,format:'jwk'}),
  Buffer.from(parts[2],'base64url'));
 assert(valid,'OPERATOR_JWT_SIGNATURE_INVALID');
 const now=Math.floor(Date.now()/1000);
 assert(claims.iss===ISSUER&&typeof claims.sub==='string'&&claims.sub.length>0&&
  claims.exp>now&&claims.iat<=now+20&&
  (claims.aud===PROJECT||Array.isArray(claims.aud)&&claims.aud.includes(PROJECT)),
  'OPERATOR_JWT_CLAIMS_INVALID');
 if(typeof claims.email==='string')
  assert(claims.email.toLowerCase()===USER.toLowerCase(),'OPERATOR_SUBJECT_MISMATCH');
 const roles=claims['urn:zitadel:iam:org:project:'+PROJECT+':roles'];
 assert(typeof roles?.autodev_operator?.[ORG]==='string'&&
  roles.autodev_operator[ORG].length>0,'EXISTING_TEST_NOT_AUTODEV_OPERATOR');
 console.log('AUTODEV_EXISTING_TEST_REAL_OPERATOR_ROLE=PASS');
}
async function main(){
 assert(typeof USER==='string'&&USER.length>0&&
  typeof PASSWORD==='string'&&PASSWORD.length>0,
  'EXISTING_TEST_CREDENTIAL_BINDING_MISSING');
 mkdirSync(EVIDENCE,{recursive:true});
 const browser=await chromium.launch({headless:true});
 const context=await browser.newContext({viewport:{width:1440,height:900},
  serviceWorkers:'block',ignoreHTTPSErrors:false,acceptDownloads:false});
 try{
  const page=await context.newPage();
  page.setDefaultTimeout(14000);
  const start=await page.goto(SITE,{waitUntil:'domcontentloaded',timeout:30000});
  assert(start?.status()===200,'OPERATOR_PWA_NOT_200');
  const login=page.locator('button.live-monitor__login');
  await login.waitFor({state:'visible'});
  let pkce=null;
  page.on('request',request=>{
   const u=new URL(request.url());
   if(u.origin===ISSUER&&u.pathname==='/oauth/v2/authorize')
    pkce={client:u.searchParams.get('client_id'),
      method:u.searchParams.get('code_challenge_method'),
      redirect:u.searchParams.get('redirect_uri')};
  });
  await login.click();
  await page.waitForURL(u=>u.origin===ISSUER,{timeout:30000});
  assert(pkce?.client===CLIENT&&pkce.method==='S256'&&
   pkce.redirect===SITE+'/auth/callback','OPERATOR_PKCE_CONFIG_MISMATCH');
  console.log('AUTODEV_EXISTING_TEST_PKCE=PASS');
  const username=await formField(page,['input[autocomplete="username"]',
   'input[name="loginName"]','input[name="loginname"]','input[name="email"]',
   'input[type="email"]','input[type="text"]']);
  assert(username,'OPERATOR_LOGIN_FORM_MISSING');
  await username.fill(USER);
  let password=await formField(page,
   ['input[autocomplete="current-password"]','input[type="password"]'],1000);
  if(!password){
   await username.press('Enter');
   password=await formField(page,
    ['input[autocomplete="current-password"]','input[type="password"]']);
  }
  assert(password,'OPERATOR_PASSWORD_FORM_MISSING');
  await password.fill(PASSWORD);
  await password.press('Enter'); // Exactly one attempt, never retry automatically.
  try{
   await page.waitForURL(u=>u.origin===SITE,{timeout:42000});
   await page.waitForFunction(()=>[...Array(localStorage.length).keys()].some(i=>{
    const key=localStorage.key(i);
    if(!key?.startsWith('oidc.user:'))return false;
    try{return Boolean(JSON.parse(localStorage.getItem(key)||'{}').access_token)}
    catch{return false}
   }),null,{timeout:18000});
  }catch{throw Error('OPERATOR_REAL_LOGIN_OR_CALLBACK_BLOCKED')}
  const token=await page.evaluate(()=>{
   for(let i=0;i<localStorage.length;i++){
    const key=localStorage.key(i);
    if(!key?.startsWith('oidc.user:'))continue;
    try{const value=JSON.parse(localStorage.getItem(key)||'{}');
     if(typeof value.access_token==='string')return value.access_token}catch{}
   }
   return null;
  });
  await verifyExistingOperator(token);
  const monitor=await context.request.get(SITE+'/v1/autodev/monitor',{
   headers:{Authorization:'Bearer '+token,Origin:SITE,Accept:'application/json'},
   failOnStatusCode:false,maxRedirects:0,timeout:16000,
  });
  assert(monitor.status()===200,'EXISTING_OPERATOR_BACKEND_MONITOR_NOT_200');
  console.log('AUTODEV_EXISTING_TEST_BACKEND_ROLE=PASS');
  // Read-only; record whether this existing test identity can exercise
  // stage-closer recovery. Never mint roles or execute a destructive POST.
  const closer=await context.request.get(SITE+'/v1/autodev/stage-closer/whoami',{
   headers:{Authorization:'Bearer '+token,Origin:SITE,Accept:'application/json'},
   failOnStatusCode:false,maxRedirects:0,timeout:16000,
  });
  assert([200,403].includes(closer.status()),'OPERATOR_STAGE_CLOSER_PROBE_UNEXPECTED');
  console.log('AUTODEV_EXISTING_OPERATOR_STAGE_CLOSER_ROLE='+
   (closer.status()===200?'GRANTED':'DENIED'));

  let postCount=0,jsErrors=0;
  page.on('request',req=>{
   if(req.method()==='POST'&&new URL(req.url()).pathname.startsWith('/v1/autodev/'))
    postCount++;
  });
  page.on('pageerror',()=>jsErrors++);
  for(const [name,width,height] of VIEWS){
   await page.setViewportSize({width,height});
   const response=await page.goto(SITE,{waitUntil:'networkidle',timeout:30000});
   assert(response?.status()===200,'OPERATOR_BROWSER_HTTP_NOT_200');
   const work=page.locator('.live-monitor__runs select').filter({
    has:page.locator('option[value="ollama/qwen2.5-coder:1.5b"]')}).first();
   await work.waitFor({state:'visible',timeout:20000});
   assert((await work.locator('option').evaluateAll(os=>
    os.map(o=>o.value))).includes('claude-sonnet-5.5'),
    'OPERATOR_CLAUDE_OPTION_MISSING');
   await work.selectOption('ollama/qwen2.5-coder:1.5b');
   assert(await work.inputValue()==='ollama/qwen2.5-coder:1.5b',
    'OPERATOR_WORK_SELECT_NOT_PERSISTED');
   await work.screenshot({path:resolve(EVIDENCE,'work-'+name+'.png')});
   // Real signed-operator PWA; inspect the exact RR #388 control, read-only.
   const rr=page.locator('.portfolio__command-line').filter({
    has:page.locator('a[href="https://github.com/qdip-ai/qdip-core/issues/388"]'),
   }).first();
   await rr.waitFor({state:'visible',timeout:20000});
   const actions=rr.locator('.portfolio__command-ai-launch');
   const close=actions.locator('button.portfolio__review-action');
   await close.waitFor({state:'visible'});
   assert((await close.innerText()).trim()==='Завершити завислу операцію'||
    (await close.innerText()).trim()==='Close stalled operation',
    'OPERATOR_RR_CLOSE_ACTION_NOT_VISIBLE');
   const bounds=await close.evaluate(button=>{
    const rect=button.getBoundingClientRect();
    const container=button.parentElement.getBoundingClientRect();
    const all=[...button.parentElement.querySelectorAll('button')]
     .map(el=>el.getBoundingClientRect()).sort((a,b)=>a.left-b.left);
    const text=document.createRange();
    text.selectNodeContents(button);
    const label=text.getBoundingClientRect();
    return {
     contained:rect.left>=container.left-1&&rect.right<=container.right+1,
     noOverlap:all.length<2||all[0].right<=all[1].left+1,
     textFits:label.left>=rect.left-2&&label.right<=rect.right+2&&
      label.top>=rect.top-2&&label.bottom<=rect.bottom+2,
     noScroll:button.scrollWidth<=button.clientWidth+1&&
      button.scrollHeight<=button.clientHeight+1,
    };
   });
   assert(bounds.contained&&bounds.noOverlap&&bounds.textFits&&bounds.noScroll,
    'OPERATOR_RR_CLOSE_BUTTON_OVERFLOW');
   await actions.screenshot({path:resolve(EVIDENCE,'rr388-actions-'+name+'.png')});
   console.log('AUTODEV_EXISTING_OPERATOR_RR388_LAYOUT_'+name+'=PASS');
   const securityTab=page.locator('nav.bottom-nav button').filter({
    hasText:/^(Безпека|Security)$/}).first();
   if(!(await securityTab.isVisible())){
    const toggle=page.locator('button.bottom-nav__toggle');
    if(await toggle.isVisible())await toggle.click();
   }
   await securityTab.click();
   const models=page.locator('.security-view__notice select');
   await models.first().waitFor({state:'visible',timeout:12000});
   assert(await models.count()===2,'OPERATOR_TWO_MODEL_SELECTORS_MISSING');
   const reviewer=models.nth(0),auditor=models.nth(1);
   const options=await reviewer.locator('option:not([disabled])').evaluateAll(os=>
    os.map(o=>o.value).filter(Boolean));
   assert(options.length>0,'OPERATOR_REVIEWER_CATALOG_NO_SUPPORTED_MODEL');
   await reviewer.selectOption(options[0]);
   assert(await auditor.inputValue()==='','OPERATOR_REVIEW_CHANGED_GATE');
   await auditor.selectOption(options[0]);
   assert(await reviewer.inputValue()===options[0],'OPERATOR_GATE_CHANGED_REVIEW');
   await page.locator('.security-view__notice').first().screenshot({
    path:resolve(EVIDENCE,'security-'+name+'.png')});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),
    'OPERATOR_HORIZONTAL_OVERFLOW');
   assert(jsErrors===0,'OPERATOR_JS_ERROR');
   assert(postCount===0,'OPERATOR_SELECTOR_SENT_PRIVILEGED_POST');
   console.log('AUTODEV_EXISTING_OPERATOR_MODELS_'+name+'=PASS');
  }
  console.log('AUTODEV_EXISTING_OPERATOR_BROWSER_E2E=PASS');
 }finally{await context.close();await browser.close()}
}
main().catch(e=>{
 const code=e instanceof Error&&/^[A-Z0-9_]{6,100}$/.test(e.message)?
  e.message:'OPERATOR_BROWSER_FAILURE_REDACTED';
 console.error('AUTODEV_EXISTING_OPERATOR_BROWSER_E2E=FAIL:'+code);
 process.exitCode=1;
});

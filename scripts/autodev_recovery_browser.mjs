/** Browser E2E for AutoDev recovery in qdip-e2e.
 * Auth is out of scope. Recovery modes reuse an already-authenticated
 * Playwright storageState. No backend route mocks, no provider retries.
 */
import {chromium} from '@playwright/test';
import {mkdirSync} from 'node:fs';
import {resolve} from 'node:path';

const SITE='https://autodev.qdip.ai';
const MODE=process.env.QDIP_E2E_AUTODEV_MODE||'smoke';
const SESSION=process.env.QDIP_E2E_AUTODEV_STORAGE_STATE;
const RUN=process.env.QDIP_E2E_AUTODEV_RUN_ID||'';
const APPROVED=process.env.QDIP_E2E_AUTODEV_NO_CHARGE_RUN||'';
const DIR=resolve(process.env.QDIP_E2E_BROWSER_EVIDENCE_DIR||'/tmp/qdip-e2e-autodev');
const VIEWS=[['desktop',1440,900],['mobile-portrait',390,844],['mobile-landscape',844,390]];
const check=(ok,code)=>{if(!ok)throw Error(code)};
const tag=s=>s.toUpperCase().replaceAll('-','_');
const safeError=e=>e instanceof Error&&/^[A-Z0-9_]{5,90}$/.test(e.message)
 ?e.message:'BROWSER_FAILURE_REDACTED';

async function screenshot(page,stage){await page.screenshot({
 path:resolve(DIR,'autodev-'+stage+'.png'),fullPage:true});}
async function realReview(page){
 const result=await page.evaluate(async()=>{
  // Read existing OIDC browser state only, without login or credential changes.
  let token=null;
  for(let i=0;i<localStorage.length;i++){
   const key=localStorage.key(i);
   if(!key?.startsWith('oidc.user:'))continue;
   try{const user=JSON.parse(localStorage.getItem(key)||'{}');
    if(typeof user.access_token==='string'){token=user.access_token;break;}
   }catch{}
  }
  if(!token)return {status:0};
  try{
   const response=await fetch('/v1/autodev/ai-attempts/review',{
    method:'GET',headers:{Authorization:'Bearer '+token,Accept:'application/json'},
    cache:'no-store',redirect:'error'});
   return {status:response.status,data:response.ok?await response.json():null};
  }catch{return {status:0};}
 });
 check(result.status===200,'CONTROLLER_REVIEW_NOT_AVAILABLE');
 check(result.data?.schemaVersion===1&&result.data.readOnly===true&&
  Array.isArray(result.data.items),'REVIEW_CONTRACT_INVALID');
 return result.data.items;
}
async function publicSmoke(browser){
 for(const [name,width,height] of VIEWS){
  const context=await browser.newContext({viewport:{width,height},
   serviceWorkers:'block',ignoreHTTPSErrors:false});
  try{
   const page=await context.newPage(),errors=[];
   page.on('pageerror',()=>errors.push(1));
   const response=await page.goto(SITE,{waitUntil:'networkidle',timeout:30000});
   check(response?.status()===200,'PWA_HTTP_NOT_200');
   await page.locator('header.app-global-header').waitFor({state:'visible',timeout:12000});
   check((await page.title()).startsWith('QDIP AutoDev'),'PWA_TITLE_INVALID');
   check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),
    'HORIZONTAL_OVERFLOW');
   check(errors.length===0,'BROWSER_JS_ERROR');
   await screenshot(page,'smoke-'+name);
   console.log('AUTODEV_BROWSER_SMOKE_'+tag(name)+'=PASS');
  }finally{await context.close();}
 }
}
/** Read-only model controls on a REAL authenticated PWA, not a DOM fixture.
 * Requires an existing authorized operator session and the candidate SHA
 * deployed to the target. Never submits a provider request or stores tokens.
 */
async function modelControls(browser){
 check(typeof SESSION==='string'&&SESSION.length>0,'EXISTING_SESSION_FILE_REQUIRED');
 const context=await browser.newContext({storageState:SESSION,
  viewport:{width:1440,height:900},serviceWorkers:'block',ignoreHTTPSErrors:false});
 try{
  for(const [name,width,height] of VIEWS){
   const page=await context.newPage();
   await page.setViewportSize({width,height});
   const errors=[],posts=[];
   page.on('pageerror',()=>errors.push(1));
   page.on('request',request=>{
    if(request.method()==='POST'&&
       new URL(request.url()).pathname.startsWith('/v1/autodev/'))posts.push(1);
   });
   try{
    const response=await page.goto(SITE,{waitUntil:'networkidle',timeout:30000});
    check(response?.status()===200,'PWA_HTTP_NOT_200');
    const work=page.locator('.live-monitor__runs select').filter({
     has:page.locator('option[value="ollama/qwen2.5-coder:1.5b"]')
    }).first();
    await work.waitFor({state:'visible',timeout:20000});
    check((await work.locator('option').evaluateAll(options=>
      options.map(option=>option.value))).includes('claude-sonnet-5.5'),
      'WORK_CLAUDE_OPTION_MISSING');
    await work.selectOption('ollama/qwen2.5-coder:1.5b');
    check(await work.inputValue()==='ollama/qwen2.5-coder:1.5b',
      'WORK_MODEL_SELECTION_FAILED');
    await page.locator('nav.bottom-nav button').filter({
     hasText:/^(Безпека|Security)$/
    }).click();
    const security=page.locator('.security-view__notice select');
    await security.first().waitFor({state:'visible',timeout:15000});
    check(await security.count()===2,'REVIEW_GATE_SELECTION_NOT_SEPARATE');
    const reviewer=security.nth(0),gate=security.nth(1);
    const supported=await reviewer.locator('option:not([disabled])').evaluateAll(
      options=>options.map(option=>option.value).filter(Boolean));
    check(supported.length>0,'REVIEW_MODEL_CATALOG_EMPTY');
    await reviewer.selectOption(supported[0]);
    check(await gate.inputValue()==='','REVIEW_CHANGED_SECURITY_GATE_MODEL');
    await gate.selectOption(supported[0]);
    check(await reviewer.inputValue()===supported[0],
      'GATE_CHANGED_REVIEW_MODEL');
    check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),
      'HORIZONTAL_OVERFLOW');
    check(errors.length===0,'BROWSER_JS_ERROR');
    check(posts.length===0,'MODEL_SELECTION_SENT_PRIVILEGED_POST');
    await screenshot(page,'model-controls-'+name);
    console.log('AUTODEV_MODEL_CONTROLS_'+tag(name)+'=PASS');
   }finally{await page.close();}
  }
 }finally{await context.close();}
}
async function recovery(browser){
 check(typeof SESSION==='string'&&SESSION.length>0,'EXISTING_SESSION_FILE_REQUIRED');
 check(/^rr388-[0-9a-f]{20}$/.test(RUN),'EXACT_RUN_ID_REQUIRED');
 if(MODE==='recovery-close')check(APPROVED===RUN,'EXACT_NO_CHARGE_APPROVAL_REQUIRED');
 const context=await browser.newContext({storageState:SESSION,
  viewport:{width:1440,height:900},serviceWorkers:'block',ignoreHTTPSErrors:false});
 try{
  const page=await context.newPage(),errors=[],posts=[];
  page.on('pageerror',()=>errors.push(1));
  page.on('request',request=>{
   if(request.method()==='POST'&&
     new URL(request.url()).pathname==='/v1/autodev/ai-attempts/cancel')
    posts.push(request);
  });
  const response=await page.goto(SITE,{waitUntil:'networkidle',timeout:30000});
  check(response?.status()===200,'PWA_HTTP_NOT_200');
  const before=await realReview(page);
  const target=before.find(item=>item.runId===RUN);
  check(target?.repository==='qdip-ai/qdip-core'&&target.issueNumber===388&&
   target.status==='OUTCOME_UNKNOWN'&&target.action==='CLOSE_CLAIMED_NO_RESULT'&&
   /^rr-pilot-attempt:[0-9a-f]{64}$/.test(target.key),'EXACT_CLAIM_NOT_ELIGIBLE');
  for(const [name,width,height] of VIEWS){
   await page.setViewportSize({width,height});
   const review=page.getByRole('button',{
    name:'Звірити AI-спробу для qdip-ai/qdip-core #388'});
   await review.waitFor({state:'visible',timeout:20000});
   await review.click();
   const entry=page.locator('.portfolio__command-review-entry').filter({hasText:RUN});
   await entry.waitFor({state:'visible',timeout:15000});
   await entry.getByRole('button',{name:'Завершити завислу спробу'}).click();
   const input=entry.getByRole('textbox',{name:'Точний runId для закриття'});
   const confirm=entry.getByRole('button',{name:'Підтвердити'});
   check(await confirm.isDisabled(),'EMPTY_RUN_ENABLED');
   await input.fill('rr388-'+'0'.repeat(20));
   check(await confirm.isDisabled(),'WRONG_RUN_ENABLED');
   await input.fill(RUN);
   check(await confirm.isEnabled(),'CORRECT_RUN_DISABLED');
   check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),
    'HORIZONTAL_OVERFLOW');
   check(errors.length===0,'BROWSER_JS_ERROR');
   check(posts.length===0,'PREMATURE_CLOSURE_POST');
   await screenshot(page,'recovery-'+name);
   console.log('AUTODEV_BROWSER_RECOVERY_'+tag(name)+'=PASS');
   if(name!=='mobile-landscape')
    await entry.getByRole('button',{name:'Назад'}).click();
  }
  if(MODE==='recovery-read'){
   check(posts.length===0,'READ_ONLY_SENT_POST');
   return;
  }
  const entry=page.locator('.portfolio__command-review-entry').filter({hasText:RUN});
  const pending=page.waitForResponse(r=>
   new URL(r.url()).pathname==='/v1/autodev/ai-attempts/cancel'&&
   r.request().method()==='POST',{timeout:20000});
  await entry.getByRole('button',{name:'Підтвердити'}).click();
  const result=await pending;
  check(posts.length===1,'CLOSURE_MUST_SEND_ONE_POST');
  const sent=posts[0].postDataJSON();
  check(sent.attemptKey===target.key&&sent.runId===RUN&&
   sent.action==='CLOSE_CLAIMED_NO_RESULT'&&
   sent.confirmation==='NO_CHARGE_CONFIRMED:'+RUN&&
   sent.requestId===posts[0].headers()['idempotency-key'],
   'CLOSURE_REQUEST_INVALID');
  check(result.status()===200,'CLOSURE_HTTP_NOT_200');
  const receipt=await result.json();
  check(receipt.status==='CLOSED'&&receipt.attemptKey===target.key&&
   receipt.requestId===sent.requestId&&receipt.providerRetried===false&&
   receipt.auditPreserved===true&&receipt.operatorAssertedNoCharge===true,
   'CLOSURE_RECEIPT_INVALID');
  const remaining=await realReview(page);
  check(!remaining.some(item=>item.runId===RUN),'CLOSED_RUN_STILL_OPEN');
  check(errors.length===0,'BROWSER_JS_ERROR');
  console.log('AUTODEV_BROWSER_CLAIMED_CLOSE=PASS');
 }finally{await context.close();}
}
async function main(){
 check(['smoke','recovery-read','recovery-close','model-controls'].includes(MODE),'INVALID_MODE');
 mkdirSync(DIR,{recursive:true});
 const browser=await chromium.launch({headless:true});
 try{
  if(MODE==='smoke')await publicSmoke(browser);
  else if(MODE==='model-controls')await modelControls(browser);
  else await recovery(browser);
  console.log('AUTODEV_BROWSER_'+tag(MODE)+'=PASS');
 }finally{await browser.close();}
}
main().catch(error=>{
 console.error('AUTODEV_BROWSER_E2E=FAIL:'+safeError(error));
 process.exitCode=1;
});

/** Authenticated, READ-ONLY browser E2E for the temporary AutoDev PWA preview of qdip-autodev-mobile PR #122.
 *
 * Safety rules (this repository is PUBLIC):
 *  - Only two exact HTTPS origins are allowed: the PR #122 preview and production (baseline measurement only).
 *    Any other origin aborts before a credential is read.
 *  - Credentials are sent only to the identity-provider origin that the PWA BFF redirected to AND that equals the
 *    one production redirects to. They come from the environment and are never printed or stored.
 *  - No storageState, trace, HAR, cookie, token or response body is written. Evidence = metrics JSON (counts, paths
 *    without query, status codes, timings) and text-redacted screenshots (layout only, all text made transparent).
 *  - No request body is ever sent to /v1/autodev/*: any such POST/PUT/PATCH/DELETE fails the run.
 */
import {chromium} from '@playwright/test';
import {mkdirSync,writeFileSync,appendFileSync} from 'node:fs';
import {resolve} from 'node:path';

const PREVIEW='https://pwa-pr122-preview-staging.up.railway.app';
const PROD='https://autodev.qdip.ai';
const ALLOWED=new Set([PREVIEW,PROD]);
const MODE=process.env.QDIP_E2E_AUTODEV_MODE||'preview';           // preview | baseline
const BASE=process.env.QDIP_E2E_AUTODEV_BASE||(MODE==='baseline'?PROD:PREVIEW);
const DIR=resolve(process.env.QDIP_E2E_BROWSER_EVIDENCE_DIR||'/tmp/qdip-e2e-pr122');
const VIEWS=[['desktop',1280,900],['portrait',390,844],['landscape',844,390]];
const SCREENS=[['runs','#/runs'],['hierarchy','#/projects'],['cards','#/projects/cards'],
 ['roadmap','#/projects/roadmap'],['prs','#/prs'],['security','#/security'],['plan','#/daily/plan']];
const CARD='qdip-ai/qdip-core',FILTER='closed';
const ENTRY='/#/projects/cards?card='+encodeURIComponent(CARD)+'&filter='+FILTER;
const REDACT='*,*::before,*::after{color:transparent!important;-webkit-text-fill-color:transparent!important;'+
 'text-shadow:none!important;caret-color:transparent!important}input,textarea,select{color:transparent!important}'+
 '::placeholder{color:transparent!important}';
const check=(ok,code)=>{if(!ok)throw Error(code)};
const tag=s=>s.toUpperCase().replaceAll('-','_');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const safeError=e=>e instanceof Error&&/^[A-Z0-9_]{5,90}$/.test(e.message)?e.message:'BROWSER_FAILURE_REDACTED';
const out={mode:MODE,origin:BASE,phase:'init',steps:{},screens:[],network:{}};
const pass=(name,extra)=>{out.steps[name]='PASS';if(extra!==undefined)out.steps[name+'_DETAIL']=extra;
 console.log('AUTODEV_PR122_'+name+'=PASS');};
const issuerOrigin={value:null};

async function preflight(browser){
 check(new URL(BASE).origin===BASE&&ALLOWED.has(BASE),'ORIGIN_NOT_ALLOWLISTED');
 const context=await browser.newContext({serviceWorkers:'block',ignoreHTTPSErrors:false});
 try{
  const health=await context.request.get(BASE+'/healthz',{maxRedirects:0,timeout:20000});
  check(health.status()===200,'PWA_HEALTHZ_NOT_200');
  const authorize=async origin=>{
   const r=await context.request.get(origin+'/auth/login',{maxRedirects:0,timeout:20000});
   check([301,302,303,307].includes(r.status()),'AUTH_LOGIN_NOT_REDIRECT');
   return new URL(r.headers().location);
  };
  const target=await authorize(BASE);
  check(target.protocol==='https:'&&target.pathname==='/oauth/v2/authorize'&&
   target.searchParams.get('code_challenge_method')==='S256'&&
   target.searchParams.get('response_type')==='code'&&
   target.searchParams.get('redirect_uri')===BASE+'/auth/callback'&&
   !!target.searchParams.get('client_id'),'AUTH_REDIRECT_CONTRACT_INVALID');
  // Trust pin: the identity provider must be the one production uses.
  const reference=BASE===PROD?target:await authorize(PROD);
  check(target.origin===reference.origin,'IDP_ORIGIN_NOT_PINNED');
  issuerOrigin.value=target.origin;
  pass('AUTH_REDIRECT_CONTRACT');
  // Is the callback URI registered? Zitadel shows an error page instead of the login form when it is not.
  const page=await context.newPage();
  const response=await page.goto(target.href,{waitUntil:'domcontentloaded',timeout:30000});
  await page.waitForTimeout(2500);
  const url=new URL(page.url());
  const body=(await page.locator('body').innerText().catch(()=>'')).toLowerCase();
  const rejected=(response&&response.status()>=400)||/\/error\b/.test(url.pathname)||url.searchParams.has('error')||
   /redirect_uri|redirect uri|invalid_request|not registered|does not match|unknown client/.test(body);
  check(!rejected,'ZITADEL_CALLBACK_URI_NOT_REGISTERED');
  pass('ZITADEL_CALLBACK_REGISTERED');
 }finally{await context.close();}
}

async function login(context){
 const username=process.env.QDIP_E2E_ZITADEL_TEST_LOGIN,password=process.env.QDIP_E2E_ZITADEL_TEST_PASSWORD;
 check(!!username&&!!password,'EXISTING_OPERATOR_CREDENTIALS_REQUIRED');
 const page=await context.newPage();
 page.setDefaultTimeout(20000);
 const start=await page.goto(BASE+ENTRY,{waitUntil:'domcontentloaded',timeout:30000});
 check(start?.status()===200,'PWA_HTTP_NOT_200');
 // Callback diagnostics: status, error code, redirect path and cookie NAMES only. Never values.
 page.on('response',async r=>{
  try{const u=new URL(r.url());
   if(u.origin!==BASE||u.pathname!=='/auth/callback')return;
   const h=await r.allHeaders();
   const names=(h['set-cookie']||'').split('\n').map(c=>c.split('=')[0].trim()).filter(Boolean);
   out.callback={status:r.status(),error:u.searchParams.get('error')||null,
    hasCode:u.searchParams.has('code'),queryKeys:[...u.searchParams.keys()].sort(),
    locationPath:h.location?new URL(h.location,BASE).pathname:null,setCookieNames:names};
  }catch{}
 });
 // Controller denial class: only a fixed-shape error CODE (e.g. NOT_AUTHORIZED), never a body or token.
 page.on('response',async r=>{
  try{const u=new URL(r.url());
   if(u.origin!==BASE||u.pathname!=='/v1/autodev/monitor'||r.status()<400)return;
   let code=null;try{const b=await r.json();if(b&&typeof b.code==='string'&&/^[A-Z_]{3,40}$/.test(b.code))code=b.code;}catch{}
   (out.monitorDenials??=[]).push({status:r.status(),code});
  }catch{}
 });
 const button=page.locator('button.live-monitor__login').first();
 await button.waitFor({state:'visible',timeout:20000});
 await button.click();
 await page.waitForURL(url=>url.origin!==BASE,{timeout:30000});
 check(new URL(page.url()).origin===issuerOrigin.value,'LOGIN_ORIGIN_NOT_PINNED');   // before any credential is typed
 const find=async(selectors,timeout=13000)=>{
  const end=Date.now()+timeout;
  while(Date.now()<end){for(const s of selectors){const f=page.locator(s).first();
   if(await f.isVisible().catch(()=>false))return f;}await page.waitForTimeout(200);}
  return null;};
 const user=await find(['input[autocomplete="username"]','input[name="loginName"]','input[name="loginname"]',
  'input[type="email"]','input[type="text"]']);
 check(user,'OPERATOR_USERNAME_MISSING');
 await user.fill(username);
 let pass=await find(['input[autocomplete="current-password"]','input[type="password"]'],1200);
 if(!pass){await user.press('Enter');pass=await find(['input[autocomplete="current-password"]','input[type="password"]']);}
 check(pass,'OPERATOR_PASSWORD_MISSING');
 await pass.fill(password);
 await pass.press('Enter');                                        // one attempt, never retried
 try{await page.waitForURL(url=>url.origin===BASE,{timeout:45000});}
 catch{throw Error('OPERATOR_REAL_LOGIN_OR_CALLBACK_BLOCKED');}
 try{await page.locator('nav.bottom-nav').waitFor({state:'visible',timeout:30000});}
 catch{
  // Booleans and a route only; no page text, cookie or token.
  out.postLogin=await page.evaluate(()=>({
   hash:location.hash.split('?')[0],
   loginButton:!!document.querySelector('button.live-monitor__login'),
   status:document.querySelector('.live-monitor__status,.live-monitor__status-icon')?.className||null,
   denied:/Доступ заборонено|Access denied/.test(document.body.innerText),
   unavailable:/недоступн|unavailable|Unavailable/.test(document.body.innerText),
   stale:!!document.querySelector('.live-monitor__stale'),
   nav:!!document.querySelector('nav.bottom-nav')}));
  const sessionProbe=await page.evaluate(async()=>{
   const s=await fetch('/auth/session',{cache:'no-store',credentials:'same-origin'}).then(r=>r.status).catch(()=>0);
   const m=await fetch('/v1/autodev/monitor',{cache:'no-store',credentials:'same-origin'}).then(r=>r.status).catch(()=>0);
   return {session:s,monitor:m};});
  out.postLogin.http=sessionProbe;
  throw Error(out.postLogin.denied||sessionProbe.monitor===403?'OPERATOR_ACCESS_DENIED_BY_CONTROLLER':'OPERATOR_APP_NOT_READY');
 }
 return page;
}

const apiPath=u=>{try{const x=new URL(u);return x.origin===BASE?x.pathname:null;}catch{return null;}};
function track(page){
 const seen={};
 page.on('response',r=>{const p=apiPath(r.url());if(!p||!p.startsWith('/v1/autodev/'))return;
  const k=r.request().method()+' '+p;(seen[k]??=[]).push(r.status());});
 return {seen,count:()=>Object.values(seen).reduce((n,a)=>n+a.length,0),
  reset:()=>{for(const k of Object.keys(seen))delete seen[k];},
  paths:()=>Object.fromEntries(Object.entries(seen).map(([k,v])=>[k,v.length])),
  fails:()=>Object.values(seen).flat().filter(s=>s>=500).length};
}

async function coldStart(page,t){
 // D3: a fresh load of the default tab must not fetch hidden tabs' data.
 t.reset();
 const started=Date.now();
 await page.goto(BASE+'/#/runs',{waitUntil:'networkidle',timeout:45000});
 await page.reload({waitUntil:'networkidle',timeout:45000});
 await page.locator('nav.bottom-nav').waitFor({state:'visible',timeout:30000});
 await page.waitForTimeout(3000);
 const result={ms:Date.now()-started,total:t.count(),byPath:t.paths(),serverErrors:t.fails()};
 out.network.coldStart=result;
 return result;
}

async function screens(_context,page,t){
 const mutating=[];
 page.on('request',r=>{const p=apiPath(r.url());
  if(p&&p.startsWith('/v1/autodev/')&&r.method()!=='GET'&&r.method()!=='HEAD')mutating.push(1);});
 const errors=[];page.on('pageerror',()=>errors.push(1));
 for(const [vp,w,h] of VIEWS){
  await page.setViewportSize({width:w,height:h});
  for(const [name,hash] of SCREENS){
   t.reset();
   await page.evaluate(x=>{location.hash=x;},hash);
   await page.waitForLoadState('networkidle').catch(()=>{});
   await page.waitForTimeout(1800);
   const m=await page.evaluate(()=>({
    overflow:document.documentElement.scrollWidth>innerWidth+1,
    boundary:!!document.querySelector('.tab-error-boundary,[data-tab-error]'),
    text:(document.querySelector('main')||document.body).innerText.length,
    controls:document.querySelectorAll('button,a,select,input').length,
    skeleton:document.querySelectorAll('.skeleton').length,
    stale:!!document.querySelector('.live-monitor__stale')}));
   const entry={vp,screen:name,overflow:m.overflow,errorBoundary:m.boundary,textChars:m.text,controls:m.controls,
    skeleton:m.skeleton,stale:m.stale,requests:t.count(),serverErrors:t.fails()};
   out.screens.push(entry);
   await page.screenshot({path:resolve(DIR,`${vp}-${name}.png`),fullPage:false,style:REDACT});
   check(!m.overflow,'HORIZONTAL_OVERFLOW_'+tag(vp)+'_'+tag(name));
   check(!m.boundary,'TAB_ERROR_BOUNDARY_'+tag(vp)+'_'+tag(name));
   check(t.fails()===0,'SERVER_ERROR_'+tag(vp)+'_'+tag(name));
   check(m.text>80,'SCREEN_EMPTY_'+tag(vp)+'_'+tag(name));
  }
  console.log('AUTODEV_PR122_VIEWPORT_'+tag(vp)+'=PASS');
 }
 check(errors.length===0,'BROWSER_JS_ERROR');
 check(mutating.length===0,'READ_ONLY_RUN_SENT_MUTATION');
 pass('SEVEN_SCREENS_THREE_VIEWPORTS',out.screens.length);
 return mutating;
}

async function hiddenTabs(page,t){
 // D3/D4: Runs journal polling and other tabs' endpoints must stay silent while their tab is hidden.
 await page.setViewportSize({width:1280,height:900});
 await page.goto(BASE+'/#/runs',{waitUntil:'networkidle',timeout:45000});
 await page.reload({waitUntil:'networkidle',timeout:45000});
 const cold=out.network.coldStart.byPath;
 for(const p of ['/v1/autodev/security','/v1/autodev/roadmap','/v1/autodev/hierarchy','/v1/autodev/plan-tasks'])
  check(!Object.keys(cold).some(k=>k.endsWith(' '+p)),'HIDDEN_TAB_FETCHED_ON_START');
 pass('HIDDEN_TABS_SILENT_ON_START');
 await page.evaluate(()=>{location.hash='#/security';});
 await page.waitForTimeout(3000);
 t.reset();
 await page.waitForTimeout(20000);
 const polled=Object.keys(t.paths()).filter(k=>k.includes('/v1/autodev/manual-launch/commands'));
 out.network.runsJournalWhileHidden=polled.length;
 check(polled.length===0,'HIDDEN_RUNS_TAB_STILL_POLLING');
 pass('HIDDEN_RUNS_TAB_DOES_NOT_POLL');
}

async function staleBehaviour(page){
 await page.setViewportSize({width:1280,height:900});
 await page.goto(BASE+'/#/runs',{waitUntil:'networkidle',timeout:45000});
 const banner=page.locator('.live-monitor__stale');
 const clear=page.getByLabel(/Очистити робочий журнал AutoDev|Clear AutoDev workspace journal/);
 await clear.waitFor({state:'visible',timeout:20000});
 check(!(await clear.isDisabled()),'CLEAR_DISABLED_BEFORE_FAULT');
 const MON='**/v1/autodev/monitor';
 // D1/D2 (a): a 6 s slow answer is not a failure
 await page.route(MON,async r=>{await sleep(6000);await r.continue().catch(()=>{});});
 await page.waitForTimeout(24000);
 check(!(await banner.isVisible()),'SLOW_ANSWER_TREATED_AS_FAILURE');
 await page.unroute(MON);
 pass('SLOW_6S_NOT_A_FAILURE');
 // (b) HTTP 500: data stays, banner shows, actions are disabled
 await page.route(MON,r=>r.fulfill({status:500,contentType:'application/json',body:'{}'}));
 await banner.waitFor({state:'visible',timeout:35000});
 check(/вимкнено|disabled/i.test(await banner.innerText()),'STALE_BANNER_WITHOUT_ACTION_NOTICE');
 check(await clear.isDisabled(),'CLEAR_ENABLED_WHILE_STALE');
 await page.reload({waitUntil:'domcontentloaded'}).catch(()=>{});   // re-opening while the fault persists
 await page.locator('nav.bottom-nav').waitFor({state:'visible',timeout:30000}).catch(()=>{});
 pass('HTTP_500_STALE_AND_ACTIONS_DISABLED');
 // (c) recovery
 await page.unroute(MON);
 await banner.waitFor({state:'hidden',timeout:40000});
 check(!(await clear.isDisabled()),'CLEAR_STILL_DISABLED_AFTER_RECOVERY');
 pass('RECOVERY_ENABLES_ACTIONS');
 // (d) hang: the request never answers
 await page.route(MON,()=>{});                                      // never fulfilled
 await banner.waitFor({state:'visible',timeout:55000});
 check(await clear.isDisabled(),'CLEAR_ENABLED_AFTER_TIMEOUT');
 pass('TIMEOUT_STALE_AND_ACTIONS_DISABLED');
 await page.unroute(MON);
 await banner.waitFor({state:'hidden',timeout:40000});
 // (e) 403: data is dropped, never shown as stale
 await page.route(MON,r=>r.fulfill({status:403,contentType:'application/json',body:'{"code":"FORBIDDEN"}'}));
 await page.getByText(/Доступ заборонено|Access denied/).first().waitFor({state:'visible',timeout:40000});
 check(!(await banner.isVisible()),'FORBIDDEN_SHOWN_AS_STALE');
 check((await page.locator('nav.bottom-nav').count())===0,'NAVIGATION_VISIBLE_AFTER_403');
 pass('HTTP_403_DROPS_DATA');
 await page.unroute(MON);
}

async function main(){
 mkdirSync(DIR,{recursive:true});
 const browser=await chromium.launch({headless:true});
 try{
  out.phase='preflight';await preflight(browser);
  const context=await browser.newContext({viewport:{width:1280,height:900},serviceWorkers:'block',ignoreHTTPSErrors:false});
  try{
   out.phase='login';const page=await login(context);
   const t=track(page);
   const restored=await page.evaluate(()=>location.hash);
   const params=new URLSearchParams(restored.includes('?')?restored.slice(restored.indexOf('?')+1):'');
   check(restored.startsWith('#/projects/cards')&&params.get('card')===CARD&&params.get('filter')===FILTER,'ROUTE_NOT_RESTORED_AFTER_LOGIN');
   pass('D6_U5_ROUTE_RESTORED_AFTER_REAL_LOGIN');
   out.phase='cold-start';await coldStart(page,t);
   pass('COLD_START_MEASURED',{total:out.network.coldStart.total,ms:out.network.coldStart.ms});
   if(MODE==='preview'){
    out.phase='screens';await screens(context,page,t);
    out.phase='hidden-tabs';await hiddenTabs(page,t);
    out.phase='stale-behaviour';await staleBehaviour(page);
   }
  }finally{await context.close();}
  pass('ALL');
 }finally{
  writeFileSync(resolve(DIR,'result.json'),JSON.stringify(out,null,1));
  console.log('AUTODEV_PR122_RESULT='+JSON.stringify(out));
  if(process.env.GITHUB_STEP_SUMMARY)appendFileSync(process.env.GITHUB_STEP_SUMMARY,
   '### AutoDev PR #122 preview E2E ('+MODE+')\n```json\n'+JSON.stringify(out,null,1)+'\n```\n');
  await browser.close();
 }
}
main().catch(error=>{console.error('AUTODEV_PR122_E2E=FAIL:'+safeError(error));process.exitCode=1;});

import { chromium, request, expect } from '@playwright/test';
import { mkdirSync } from 'node:fs';
const SITE='https://mentality-1bfext7ca-taras-gezs-projects.vercel.app';
const API='https://dzvin-b2c-rc-build-qa.up.railway.app';
const LOGIN='https://mentality-web.vercel.app';
const DPL='dpl_FD4cHcaSov2Kg7vndFuCbQ1CVJ1P';
const actors=[
 {name:'QA1',email:process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN,password:process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD},
 {name:'QA2',email:process.env.QDIP_E2E_ZITADEL_TEST2_LOGIN,password:process.env.QDIP_E2E_ZITADEL_TEST2_PASSWORD},
];
let stage='BOOT';
const assert=(x,code)=>{if(!x)throw Error(code)};
async function visible(page,selectors,wait=12000){
 const until=Date.now()+wait;
 while(Date.now()<until){for(const s of selectors){const el=page.locator(s).first();if(await el.isVisible().catch(()=>false))return el}await page.waitForTimeout(250)}
 return null;
}
async function login(browser,user){
 const c=await browser.newContext({serviceWorkers:'block'});
 try{
  const page=await c.newPage();
  await page.goto(LOGIN+'/en/auth',{waitUntil:'domcontentloaded'});
  const username=await visible(page,['input[autocomplete="username"]','input[name="loginName"]','input[name="loginname"]','input[name="username"]','input[name="email"]','input[type="email"]','input[type="text"]']);
  assert(username,user.name+'_LOGIN_INPUT');
  await username.fill(user.email);
  let password=await visible(page,['input[autocomplete="current-password"]','input[type="password"]'],1500);
  if(!password){await username.press('Enter');password=await visible(page,['input[autocomplete="current-password"]','input[type="password"]'])}
  assert(password,user.name+'_PASSWORD_INPUT');
  await password.fill(user.password);await password.press('Enter');
  let session;
  for(let n=0;n<25;n++){await page.waitForTimeout(700);const r=await c.request.get(LOGIN+'/api/auth/session',{timeout:9000}).catch(()=>null);if(r?.status()===200){session=await r.json().catch(()=>null);if(session?.id)break}}
  assert(session?.id&&session.email?.toLowerCase()===user.email.toLowerCase(),user.name+'_SESSION_INVALID');
  const cookie=(await c.cookies(LOGIN)).find(z=>z.name==='auth-tokens'&&z.httpOnly&&z.secure);
  assert(cookie,user.name+'_COOKIE_MISSING');
  let tokens;try{tokens=JSON.parse(decodeURIComponent(cookie.value))}catch{throw Error('COOKIE_BAD_JSON')}
  assert(typeof tokens.accessToken==='string'&&tokens.accessToken.length>20,user.name+'_JWT_MISSING');
  console.log(user.name+'_REAL_ZITADEL_LOGIN=PASS');
  return {cookie,token:tokens.accessToken,id:session.id};
 }finally{await c.close()}
}
async function main(){
 assert(process.env.DZVIN_RAILWAY_MOOD_BROWSER_ACK==='1','APPROVAL_REQUIRED');
 assert(actors.every(x=>x.email&&x.password),'QA_CREDENTIALS_MISSING');
 const browser=await chromium.launch({headless:true});
 const clients=[];const ctxs=[];
 try{
  const identities=[];
  for(const actor of actors){
   const user=await login(browser,actor);identities.push(user);
   const api=await request.newContext({baseURL:API,extraHTTPHeaders:{Authorization:'Bearer '+user.token}});
   clients.push(api);
   const identity=await api.post('/api/auth/validate-token');
   assert([201,202].includes(identity.status()),actor.name+'_QA_BOOTSTRAP_'+identity.status());
  }
  assert(identities[0].id!==identities[1].id,'QA_SAME_SUBJECT');
  // A tag fixture lives only in disposable QA Mongo.
  const existingTags=await clients[0].get('/api/user-tags');
  assert(existingTags.status()===200,'TAGS_LIST_'+existingTags.status());
  const tags=await existingTags.json();
  if(!tags.some(t=>t.key==='qa-isolated-20261102')){
    const tag=await clients[0].post('/api/user-tags',{data:{key:'qa-isolated-20261102',name:'QA Isolated Mood'}});
    assert(tag.status()===201,'TAG_PREP_'+tag.status());
  }
  const ctx=await browser.newContext({viewport:{width:1440,height:900},timezoneId:'Europe/Warsaw',serviceWorkers:'block'});
  ctxs.push(ctx);
  const c=identities[0].cookie;
  await ctx.addCookies([{name:c.name,value:c.value,domain:new URL(SITE).hostname,path:c.path,httpOnly:true,secure:true,sameSite:c.sameSite,...(c.expires>0?{expires:c.expires}:{})}]);
  const session=await ctx.request.get(SITE+'/api/auth/session');
  assert(session.status()===200,'QA_PREVIEW_COOKIE_NOT_ACCEPTED_'+session.status());
  const list=await ctx.request.get(SITE+'/api/backend/mood-record?page=1&limit=100');
  assert(list.status()===200,'QA_PREVIEW_BFF_READ_'+list.status());
  assert(Array.isArray(await list.json())&&(await clients[0].get('/api/mood-record')).status()===200,'QA_BFF_CONTRACT');
  const before=await list.json();
  assert(before.length===0,'QA_MOOD_ALREADY_SAVED_TODAY');
  console.log('QA_PREVIEW_BFF_POINTS_TO_ISOLATED_EMPTY_MONGO=PASS');
  const page=await ctx.newPage();
  stage='MOOD_PAGE_GOTO';console.log('QA_STAGE='+stage);
  const response=await page.goto(SITE+'/en/mood-tracker',{waitUntil:'domcontentloaded',timeout:40000});
  assert(response?.status()===200,'MOOD_PAGE_HTTP_'+response?.status());
  const html=await response.text();
  assert(html.includes('data-dpl-id="'+DPL+'"'),'PREVIEW_DEPLOYMENT_CHANGED');
  stage='MOOD_BUTTON_VISIBLE';console.log('QA_STAGE='+stage);
  console.log('QA_PAGE_DOM='+JSON.stringify({path:new URL(page.url()).pathname,buttonCount:await page.locator('button[aria-pressed]').count(),sliderCount:await page.locator('[role="slider"]').count(),formCount:await page.locator('form').count()}));
  await page.locator('button[aria-pressed]').first().waitFor({state:'visible',timeout:18000});
  assert(await page.locator('button[aria-pressed]').count()>=5,'MOOD_OPTIONS_MISSING');
  stage='MOOD_BUTTON_SELECT';console.log('QA_STAGE='+stage);
  await page.locator('button[aria-pressed]').nth(3).click();
  const sliders=page.locator('[role="slider"]');
  assert(await sliders.count()>=3,'MOOD_DIMENSION_SLIDERS_MISSING');
  for(const [i,steps] of [[0,1],[1,2],[2,3]]){
   const el=sliders.nth(i);await el.focus();await el.press('Home');for(let j=0;j<steps;j++)await el.press('ArrowRight');
   await expect(el).toHaveAttribute('aria-valuenow',String(steps+1),{timeout:3500});
  }
  stage='TAG_VISIBLE';console.log('QA_STAGE='+stage);
  const tagButton=page.getByRole('button',{name:'QA Isolated Mood',exact:true});
  await tagButton.waitFor({state:'visible',timeout:18000});
  await tagButton.click();
  stage='SAVE_VISIBLE';console.log('QA_STAGE='+stage);
  const save=page.getByRole('button',{name:/save/i}).last();
  await save.waitFor({state:'visible',timeout:15000});
  assert(await save.isEnabled(),'SAVE_DISABLED');
  const createdWait=page.waitForResponse(r=>r.url().includes('/api/backend/mood-record')&&r.request().method()==='POST',{timeout:45000});
  stage='SAVE_POST';console.log('QA_STAGE='+stage);
  await save.click();
  const submitted=await createdWait;
  assert(submitted.status()===201,'MOOD_SAVE_HTTP_'+submitted.status());
  console.log('QA_DESKTOP_REAL_FORM_MOOD_TAG_DIMENSIONS_SAVE=PASS');
  let owned=[];
  for(let n=0;n<12;n++){await page.waitForTimeout(500);const z=await ctx.request.get(SITE+'/api/backend/mood-record?page=1&limit=100');if(z.status()===200){owned=await z.json();if(owned.length)break}}
  assert(owned.length===1,'MOOD_HISTORY_COUNT');
  const record=owned[0];
  assert(record.moodLevel===4&&record.stressLevel===2&&record.energyLevel===3&&record.focusLevel===4,'FORM_SAVED_WRONG_DIMENSIONS');
  assert(Array.isArray(record.tags)&&record.tags.includes('qa-isolated-20261102'),'FORM_TAG_NOT_SAVED');
  assert(Number.isFinite(Date.parse(record.createdAt)),'FORM_TIMESTAMP_MISSING');
  await page.goto(SITE+'/en/mood-tracker',{waitUntil:'domcontentloaded'});
  await page.locator('time[datetime]').first().waitFor({state:'visible',timeout:15000});
  mkdirSync('evidence',{recursive:true});
  await page.screenshot({path:'evidence/mood-desktop-1440x900.png',fullPage:true});
  console.log('QA_DESKTOP_REAL_HISTORY_DATE=PASS');
  for(const [label,width,height] of [['portrait',390,844],['landscape',844,390]]){
   const ctx2=await browser.newContext({viewport:{width,height},isMobile:true,hasTouch:true,timezoneId:'Europe/Warsaw',serviceWorkers:'block'});
   ctxs.push(ctx2);
   await ctx2.addCookies([{name:c.name,value:c.value,domain:new URL(SITE).hostname,path:c.path,httpOnly:true,secure:true,sameSite:c.sameSite,...(c.expires>0?{expires:c.expires}:{})}]);
   const q=await ctx2.newPage();
   const res=await q.goto(SITE+'/en/mood-tracker',{waitUntil:'domcontentloaded',timeout:40000});
   assert(res?.status()===200,label+'_PAGE_STATUS');
   await q.locator('time[datetime]').first().waitFor({state:'visible',timeout:15000});
   const dims=await q.evaluate(()=>({scroll:document.documentElement.scrollWidth,inner:window.innerWidth}));
   assert(dims.scroll<=dims.inner+2,label+'_OVERFLOW');
   await q.screenshot({path:'evidence/mood-'+label+'-'+width+'x'+height+'.png',fullPage:true});
   console.log('QA_MOOD_'+label.toUpperCase()+'_BROWSER_HISTORY=PASS');
  }
  const other=await browser.newContext({serviceWorkers:'block'});ctxs.push(other);
  const c2=identities[1].cookie;
  await other.addCookies([{name:c2.name,value:c2.value,domain:new URL(SITE).hostname,path:c2.path,httpOnly:true,secure:true,sameSite:c2.sameSite,...(c2.expires>0?{expires:c2.expires}:{})}]);
  const denied=await other.request.get(SITE+'/api/backend/mood-record/'+record.id);
  assert([403,404].includes(denied.status()),'FOREIGN_BFF_RECORD_EXPOSED_'+denied.status());
  console.log('QA_CROSS_USER_BFF_OWNERSHIP_DENIED=PASS');
  console.log('QA_REAL_BROWSER_MOOD_E2E=PASS');
 }finally{for(const c of ctxs)await c.close();for(const api of clients)await api.dispose();await browser.close()}
}
main().catch(e=>{console.error('QA_FAILURE_STAGE='+stage);const code=e instanceof Error&&/^[A-Z0-9_]{5,100}$/.test(e.message)?e.message:'SANITIZED_QA_BROWSER_FAILURE';console.error('QA_REAL_BROWSER_MOOD_E2E=FAIL:'+code);process.exitCode=1});

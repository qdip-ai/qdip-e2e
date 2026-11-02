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
  const bffTags=await ctx.request.get(SITE+'/api/backend/user-tags');
  assert(bffTags.status()===200,'BFF_TAG_READ_'+bffTags.status());
  const bffTagRows=await bffTags.json();
  console.log('QA_BFF_TAG_FIXTURE='+String(Array.isArray(bffTagRows)&&bffTagRows.some(x=>x.key==='qa-isolated-20261102')));
  assert(Array.isArray(bffTagRows)&&bffTagRows.some(x=>x.key==='qa-isolated-20261102'),'BFF_TAG_NOT_MAPPED');
  const page=await ctx.newPage();
  stage='MOOD_PAGE_GOTO';console.log('QA_STAGE='+stage);
  const response=await page.goto(SITE+'/en/mood-tracker',{waitUntil:'domcontentloaded',timeout:40000});
  assert(response?.status()===200,'MOOD_PAGE_HTTP_'+response?.status());
  const html=await response.text();
  assert(html.includes('data-dpl-id="'+DPL+'"'),'PREVIEW_DEPLOYMENT_CHANGED');
  // First-visit MoodInsightGuide intentionally blocks form interaction; finish it as a real user.
  const guide=page.getByRole('dialog');
  if(await guide.isVisible().catch(()=>false)){
    for(let step=0;step<4;step++){
      const next=guide.getByRole('button',{name:/next|done/i}).last();
      await next.waitFor({state:'visible',timeout:7000});
      await next.click();
    }
    await guide.waitFor({state:'hidden',timeout:7000});
    console.log('QA_FIRST_VISIT_MOOD_GUIDE_COMPLETED=PASS');
  }

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
  const tagDiagnostic=await page.evaluate(()=>({
    renderedTagText:document.body.textContent?.includes('QA Isolated Mood')??false,
    matchingButtons:[...document.querySelectorAll('button')].filter(b=>b.textContent?.includes('QA Isolated Mood')).length,
    testTagKeyRendered:document.body.innerHTML.includes('qa-isolated-20261102'),
    renderedAddNewTagButton:[...document.querySelectorAll('button')].filter(b=>b.textContent?.toLowerCase().includes('add new tag')).length,
  }));
  console.log('QA_UI_TAG_DIAGNOSTIC='+JSON.stringify(tagDiagnostic));
  const tagVisibility=await page.evaluate(()=>
    [...document.querySelectorAll('button')].filter(b=>b.textContent?.includes('QA Isolated Mood'))
      .map(b=>{
        const css=getComputedStyle(b),box=b.getBoundingClientRect();
        const parent=b.parentElement,ancestor=parent?.parentElement;
        return {
          visible:box.width>0&&box.height>0,buttonText:b.textContent?.trim().slice(0,85),
          display:css.display,visibility:css.visibility,opacity:css.opacity,
          buttonClass:b.className?.slice(0,100),parentClass:parent?.className?.slice(0,100),
          parentDisplay:parent?getComputedStyle(parent).display:null,
          ancestorDisplay:ancestor?getComputedStyle(ancestor).display:null,
        };
      })
  );
  console.log('QA_TAG_VISIBILITY='+JSON.stringify(tagVisibility));
  const tagButton=page.locator('button').filter({hasText:/^QA Isolated Mood$/}).filter({visible:true}).first();
  await tagButton.waitFor({state:'visible',timeout:5000});
  const tagBox=await tagButton.boundingBox();
  console.log('QA_TAG_CLICK_PRE='+JSON.stringify({count:await tagButton.count(),visible:await tagButton.isVisible(),enabled:await tagButton.isEnabled(),box:tagBox}));
  try {await tagButton.click({timeout:5500});} catch {
    const overlap=await page.evaluate(({x,y})=>{
      const node=document.elementFromPoint(x,y);
      return {element:node?.tagName,elementClass:typeof node?.className==='string'?node.className.slice(0,120):null};
    },{x:(tagBox?.x??0)+(tagBox?.width??0)/2,y:(tagBox?.y??0)+(tagBox?.height??0)/2});
    console.log('QA_TAG_CLICK_INTERCEPT='+JSON.stringify(overlap));
    throw Error('TAG_CLICK_BLOCKED');
  }
  stage='TAG_CLICKED';console.log('QA_STAGE='+stage);
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

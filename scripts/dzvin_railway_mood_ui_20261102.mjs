import { chromium } from '@playwright/test';
import { mkdirSync } from 'node:fs';
const LOGIN='https://mentality-web.vercel.app';
const UI='https://dzvin-b2c-web-unit-build-qa.up.railway.app';
const assert=(value,code)=>{if(!value)throw new Error(code)};
async function field(page,selectors,ms=12000){
  const end=Date.now()+ms;
  while(Date.now()<end){
    for(const selector of selectors){
      const item=page.locator(selector).first();
      if(await item.isVisible().catch(()=>false))return item;
    }
    await page.waitForTimeout(250);
  }
  throw new Error('LOGIN_FIELD_MISSING');
}
async function qaCookie(browser){
  const cx=await browser.newContext({serviceWorkers:'block'});
  try {
    const page=await cx.newPage();
    await page.goto(LOGIN+'/en/auth',{waitUntil:'domcontentloaded',timeout:30000});
    await page.waitForURL(u=>u.origin!==LOGIN,{timeout:24000});
    const user=await field(page,['input[autocomplete="username"]','input[name="loginName"]','input[name="username"]','input[type="email"]','input[type="text"]']);
    await user.fill(process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN);
    let pw=await field(page,['input[autocomplete="current-password"]','input[type="password"]'],1500).catch(()=>null);
    if(!pw){await user.press('Enter');pw=await field(page,['input[autocomplete="current-password"]','input[type="password"]']);}
    await pw.fill(process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD);await pw.press('Enter');
    let session=null;
    for(let i=0;i<20;i++){
      await page.waitForTimeout(900);
      const r=await cx.request.get(LOGIN+'/api/auth/session',{timeout:9000}).catch(()=>null);
      if(r?.status()===200){session=await r.json().catch(()=>null);if(session?.id)break;}
    }
    assert(session?.email?.toLowerCase()===process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN?.toLowerCase(),'QA_SUBJECT_NOT_VALIDATED');
    const cookie=(await cx.cookies(LOGIN)).find(c=>c.name==='auth-tokens'&&c.httpOnly&&c.secure);
    assert(cookie,'QA_SECURE_COOKIE_MISSING');
    console.log('QA1_ZITADEL_AUTH=PASS');
    return cookie;
  }finally{await cx.close();}
}
async function verifyMoodUiSubmit(browser,cookie){
  assert(process.env.DZVIN_UI_SAVE_ACK==='1','UI_WRITE_APPROVAL_REQUIRED');
  const timeZone='Europe/Warsaw';
  const cx=await browser.newContext({
    viewport:{width:1440,height:900},timezoneId:timeZone,serviceWorkers:'block'
  });
  try{
    await cx.addCookies([{
      name:cookie.name,value:cookie.value,domain:new URL(UI).hostname,path:cookie.path,
      httpOnly:true,secure:true,sameSite:cookie.sameSite,
      ...(cookie.expires>0?{expires:cookie.expires}:{})
    }]);
    const before=await cx.request.get(UI+'/api/backend/mood-record?page=1&limit=50&order=newest');
    assert(before.status()===200,'UI_PREWRITE_BACKEND_READ');
    const existing=await before.json();
    assert(Array.isArray(existing),'UI_PREWRITE_MOOD_LIST_INVALID');
    const page=await cx.newPage();
    const rendered=await page.goto(UI+'/en/mood-tracker',{waitUntil:'domcontentloaded',timeout:50000});
    assert(rendered?.status()===200,'UI_SAVE_PAGE_UNAVAILABLE');
    await page.locator('main').first().waitFor({state:'visible',timeout:12000});
    await page.waitForTimeout(1100);
    const moods=page.locator('main .grid.grid-cols-5 button[aria-pressed]');
    const firstMoodCount=await moods.count();
    await page.waitForTimeout(2000);
    const lateMoodCount=await moods.count();
    const moodVisible=await moods.nth(3).isVisible().catch(()=>false);
    const saveCount=await page.getByRole('button',{name:/^save$/i}).count();
    console.log('QA_UI_MOOD_PREFLIGHT=INITIAL_'+firstMoodCount+'_LATE_'+lateMoodCount+'_VISIBLE_'+moodVisible+'_SAVE_BUTTONS_'+saveCount+'_PREWRITE_ROWS_'+existing.length);
    await page.locator('main').first().screenshot({path:'/tmp/dzvin-mood-ui-evidence/mood-save-preflight.png'});
    assert(firstMoodCount>=5&&lateMoodCount>=5&&moodVisible,'UI_MOOD_CONTROL_DISAPPEARED_AFTER_HYDRATION');
    // First-visit onboarding is an actual modal that can intercept a visible mood button.
    // Complete the same user-facing sequence verified in browser run 41525339937.
    const guide=page.locator('[role="dialog"][aria-modal="true"]').first();
    if(await guide.isVisible().catch(()=>false)){
      console.log('QA_FIRST_VISIT_GUIDE=VISIBLE');
      for(let step=0;step<4;step++){
        const next=guide.getByRole('button',{name:/next|got it/i}).last();
        await next.waitFor({state:'visible',timeout:6000});
        await next.click();
      }
      await guide.waitFor({state:'hidden',timeout:6000});
      console.log('QA_FIRST_VISIT_GUIDE_COMPLETED=PASS');
    }
    await moods.nth(3).click({timeout:10000});
    assert(await moods.nth(3).getAttribute('aria-pressed')==='true','UI_MOOD_NOT_SELECTED');
    const sliders=page.locator('main [role="slider"]');
    assert(await sliders.count()>=3,'UI_STRESS_ENERGY_FOCUS_SLIDERS_MISSING');
    for(const index of [0,1,2]){
      await sliders.nth(index).focus();
      await page.keyboard.press('End');
      assert((await sliders.nth(index).getAttribute('aria-valuenow'))==='5',
        'UI_SLIDER_NOT_UPDATED_'+index);
    }
    const save=page.getByRole('button',{name:/^save$/i}).first();
    await save.waitFor({state:'visible',timeout:13000});
    assert(await save.isEnabled(),'UI_SAVE_DISABLED_DAILY_WINDOW');
    const responsePromise=page.waitForResponse(r=>r.url().includes('/api/backend/mood-record')&&r.request().method()==='POST',{timeout:35000});
    await save.click();
    const post=await responsePromise;
    assert(post.status()===201,'UI_SAVE_POST_'+post.status());
    const created=await post.json();
    assert(created?.moodLevel===4&&created.stressLevel===5&&created.energyLevel===5&&created.focusLevel===5,
      'UI_SAVE_PAYLOAD_OR_RESULT_INVALID');
    const after=await cx.request.get(UI+'/api/backend/mood-record?page=1&limit=50&order=newest');
    assert(after.status()===200,'UI_POSTSAVE_BACKEND_READ');
    const data=await after.json();
    assert(Array.isArray(data)&&data.length>existing.length&&data.some(r=>r.id===created.id),
      'UI_SAVE_NOT_PERSISTED');
    await page.locator('#mood-records-list time[datetime]').first().waitFor({state:'visible',timeout:15000});
    assert(await page.locator('#mood-records-list time[datetime]').count()>=1,'UI_POSTSAVE_HISTORY_EMPTY');
    console.log('QA_UI_MOOD_SELECTION_ALL_SLIDERS_POST_PERSISTED_HISTORY=PASS');
    await page.locator('main').first().screenshot({path:'/tmp/dzvin-mood-ui-evidence/mood-ui-save-nairobi.png'});
  }finally{await cx.close();}
}
async function main(){
  assert(process.env.DZVIN_RAILWAY_MOOD_UI_ACK==='1','QA_RAILWAY_APPROVAL_REQUIRED');
  assert(process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN&&process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD,'QA_SECRETS_MISSING');
  const browser=await chromium.launch({headless:true});
  try {
    const cookie=await qaCookie(browser);
    mkdirSync('/tmp/dzvin-mood-ui-evidence',{recursive:true});
    if(process.env.DZVIN_UI_SAVE_ACK==='1')await verifyMoodUiSubmit(browser,cookie);
    for(const device of [
      {name:'desktop',width:1440,height:900,mobile:false},
      {name:'mobile-portrait',width:390,height:844,mobile:true},
      {name:'mobile-landscape',width:844,height:390,mobile:true},
    ]){
      const cx=await browser.newContext({viewport:{width:device.width,height:device.height},
        isMobile:device.mobile,hasTouch:device.mobile,serviceWorkers:'block',timezoneId:'Europe/Warsaw'});
      try{
        await cx.addCookies([{
          name:cookie.name,value:cookie.value,domain:new URL(UI).hostname,path:cookie.path,
          httpOnly:true,secure:true,sameSite:cookie.sameSite,
          ...(cookie.expires>0?{expires:cookie.expires}:{}),
        }]);
        const session=await cx.request.get(UI+'/api/auth/session',{timeout:25000,maxRedirects:0});
        assert(session.status()===200,'QA_UI_SESSION_'+device.name+'_'+session.status());
        const page=await cx.newPage();
        const resp=await page.goto(UI+'/en/mood-tracker',{waitUntil:'domcontentloaded',timeout:50000});
        assert(resp?.status()===200,'MOOD_PAGE_'+device.name+'_'+resp?.status());
        assert(new URL(page.url()).pathname==='/en/mood-tracker','MOOD_PAGE_REDIRECT_'+device.name);
        const main=page.locator('main').first();
        await main.waitFor({state:'visible',timeout:18000});
        const moodApi=await cx.request.get(UI+'/api/backend/mood-record?page=1&limit=20&order=newest',{timeout:25000});
        const moodJson=await moodApi.json().catch(()=>null);
        const fixture=Array.isArray(moodJson)&&moodJson.some(x=>x.tags?.includes('qa1-isolated-20261102'));
        const cardCount=await page.locator('#mood-records-list h3').count();
        const timestampCount=await page.locator('#mood-records-list time[datetime]').count();
        const tags=Array.isArray(moodJson)?moodJson.flatMap(x=>Array.isArray(x.tags)?x.tags:[]):[];
        console.log('QA_MOOD_DIAG_'+device.name+'=HTTP_'+moodApi.status()+'_ROWS_'+(Array.isArray(moodJson)?moodJson.length:'NA')+'_FIXTURE_'+fixture+'_TAGCOUNT_'+tags.length+'_CARDS_'+cardCount+'_TIMES_'+timestampCount);
        assert(moodApi.status()===200&&Array.isArray(moodJson)&&moodJson.length>0,'QA_MOOD_ROWS_MISSING_'+device.name);
        assert(cardCount>=1&&timestampCount>=1,'QA_MOOD_HISTORY_NOT_RENDERED_'+device.name);
        if(tags.length>0)await page.getByText(tags[0],{exact:false}).first().waitFor({state:'visible',timeout:10000});
        const rendered=await main.innerText();
        assert(/stress/i.test(rendered)&&/energy/i.test(rendered)&&/focus/i.test(rendered),
          'MOOD_HISTORY_DIMENSIONS_NOT_RENDERED_'+device.name);
        const count=await main.locator('time[datetime]').count();
        assert(count>=1,'MOOD_HISTORY_DATETIME_NOT_RENDERED_'+device.name);
        const horizontal=await page.evaluate(()=>({scroll:document.documentElement.scrollWidth,width:window.innerWidth}));
        assert(horizontal.scroll<=horizontal.width+2,'MOOD_UI_HORIZONTAL_OVERFLOW_'+device.name);
        await main.screenshot({path:'/tmp/dzvin-mood-ui-evidence/'+device.name+'.png'});
        console.log('QA_MOOD_HISTORY_UI_'+device.name+'=PASS');
      }finally{await cx.close();}
    }
    console.log('DZVIN_QA_ISOLATED_UI_3_VIEWPORTS=PASS');
  }finally{await browser.close();}
}
main().catch(error=>{
  const code=String(error?.message||'UNKNOWN').replace(/[^A-Za-z0-9_]/g,'_').slice(0,100);
  console.error('DZVIN_QA_ISOLATED_UI=FAIL:'+code);process.exitCode=1;
});
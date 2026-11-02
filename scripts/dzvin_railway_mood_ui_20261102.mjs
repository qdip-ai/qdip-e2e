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
async function main(){
  assert(process.env.DZVIN_RAILWAY_MOOD_UI_ACK==='1','QA_RAILWAY_APPROVAL_REQUIRED');
  assert(process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN&&process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD,'QA_SECRETS_MISSING');
  const browser=await chromium.launch({headless:true});
  try {
    const cookie=await qaCookie(browser);
    mkdirSync('/tmp/dzvin-mood-ui-evidence',{recursive:true});
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
        console.log('QA_MOOD_DIAG_'+device.name+'=HTTP_'+moodApi.status()+'_ROWS_'+(Array.isArray(moodJson)?moodJson.length:'NA')+'_FIXTURE_'+fixture+'_CARDS_'+cardCount+'_TIMES_'+timestampCount);
        assert(moodApi.status()===200&&fixture,'QA_MOOD_FIXTURE_MISSING_'+device.name);
        await page.getByText('qa1-isolated-20261102',{exact:false}).first().waitFor({state:'visible',timeout:15000});
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
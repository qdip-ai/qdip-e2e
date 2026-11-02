/** Real, read-only Observatory admin browser regression for qdip-web #315.
 * No route mocks, test accounts, authorization changes or catalog mutations.
 * Public mode verifies denied access. Admin mode requires an EXISTING session.
 */
import {chromium} from '@playwright/test';
import {existsSync,mkdirSync} from 'node:fs';
import {resolve} from 'node:path';

const ORIGIN='https://observatory.qdip.ai';
const ROUTE=ORIGIN+'/uk/admin/plugins';
const MODE=process.env.QDIP_E2E_OBSERVATORY_MODE||'public';
const SESSION=process.env.QDIP_E2E_OBSERVATORY_STORAGE_STATE||'';
const OUT=resolve(process.env.QDIP_E2E_BROWSER_EVIDENCE_DIR||'/tmp/observatory-admin-e2e');
const VIEWS=[['DESKTOP',1440,900],['MOBILE_PORTRAIT',390,844],['MOBILE_LANDSCAPE',844,390]];
const check=(value,code)=>{if(!value)throw Error(code)};
const safe=e=>/^[A-Z0-9_]{5,100}$/.test(e?.message||'')?e.message:'OBS_BROWSER_FAILURE_REDACTED';

async function main(){
 check(['public','admin'].includes(MODE),'OBS_INVALID_MODE');
 if(MODE==='admin')check(SESSION&&existsSync(SESSION),'OBS_EXISTING_ADMIN_SESSION_REQUIRED');
 mkdirSync(OUT,{recursive:true});
 const browser=await chromium.launch({headless:true});
 try{
  for(const [name,width,height] of VIEWS){
   const context=await browser.newContext({
    viewport:{width,height},serviceWorkers:'block',ignoreHTTPSErrors:false,
    ...(MODE==='admin'?{storageState:SESSION}:{})
   });
   try{
    const page=await context.newPage(),errors=[];
    page.on('pageerror',()=>errors.push(1));
    if(MODE==='public'){
     const api=await context.request.get(ORIGIN+'/api/observatory/admin/plugins',
      {maxRedirects:0,failOnStatusCode:false,timeout:20000});
     check([401,403].includes(api.status()),'OBS_ANON_ADMIN_API_NOT_DENIED');
     const route=await context.request.get(ROUTE,
      {maxRedirects:0,failOnStatusCode:false,timeout:20000});
     check([302,303,307,308,401,403].includes(route.status()),
      'OBS_ANON_ADMIN_PAGE_NOT_DENIED');
     console.log('OBS_ANON_ACCESS_'+name+'=PASS');
     continue;
    }
    const session=await context.request.get(ORIGIN+'/api/auth/session',
      {failOnStatusCode:false,timeout:20000});
    check(session.status()===200,'OBS_ADMIN_SESSION_UNAVAILABLE');
    const user=await session.json();
    check(user?.authenticated===true&&user?.observatoryAdmin===true,
      'OBS_EXISTING_SESSION_NOT_ADMIN');
    const catalog=await context.request.get(ORIGIN+'/api/observatory/admin/plugins',
      {failOnStatusCode:false,timeout:20000});
    check(catalog.status()===200,'OBS_ADMIN_CATALOG_NOT_200');
    const data=await catalog.json();
    check(Array.isArray(data?.plugins)&&data.plugins.length>0,'OBS_ADMIN_REAL_CARD_MISSING');
    const response=await page.goto(ROUTE,{waitUntil:'domcontentloaded',timeout:30000});
    check(response?.status()===200,'OBS_ADMIN_ROUTE_NOT_200');
    await page.getByRole('heading',{name:'Керування плагінами'}).waitFor();
    const card=page.locator('article[class*="adminCard"]').first();
    await card.waitFor({state:'visible',timeout:20000});
    const version=card.getByText(/^Версія:\s/).first();
    const status=card.locator('span[data-kind="published"],span[data-kind="unpublished"]').first();
    await version.waitFor({state:'visible'});
    await status.waitFor({state:'visible'});
    const bounds=await Promise.all([card.boundingBox(),version.boundingBox(),status.boundingBox()]);
    check(bounds.every(Boolean),'OBS_ADMIN_CARD_BOUNDS_MISSING');
    const [b,v,s]=bounds;
    check(b.x>=-1&&b.x+b.width<=width+1,'OBS_ADMIN_CARD_OVERFLOW');
    check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),
      'OBS_HORIZONTAL_OVERFLOW');
    if(width<=740)check(s.y-(v.y+v.height)<64,
      'OBS_ADMIN_VERSION_STATUS_VERTICAL_GAP');
    check(errors.length===0,'OBS_ADMIN_BROWSER_JS_ERROR');
    await card.screenshot({path:resolve(OUT,'observatory-admin-'+name.toLowerCase()+'.png'),
      animations:'disabled'});
    console.log('OBS_ADMIN_LAYOUT_'+name+'=PASS');
   }finally{await context.close();}
  }
  console.log('OBSERVATORY_ADMIN_'+MODE.toUpperCase()+'_E2E=PASS');
 }finally{await browser.close();}
}
main().catch(e=>{console.error('OBSERVATORY_ADMIN_E2E=FAIL:'+safe(e));process.exitCode=1;});

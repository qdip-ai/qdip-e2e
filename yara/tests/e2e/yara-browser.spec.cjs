'use strict';
const {test,expect}=require('@playwright/test');
const path=require('node:path');

function qaState(){
  if(process.env.YARA_E2E_QA_STATE_B64){
    const state=JSON.parse(Buffer.from(process.env.YARA_E2E_QA_STATE_B64,'base64').toString('utf8'));
    if(!Array.isArray(state.cookies)||!Array.isArray(state.origins))
      throw Error('Invalid QA browser storage state');
    return state;
  }
  if(process.env.YARA_E2E_QA_STATE_FILE){
    const source=path.resolve(process.env.YARA_E2E_QA_STATE_FILE);
    const root=path.resolve(__dirname,'../..')+path.sep;
    if(source.startsWith(root))throw Error('QA browser state must not be stored in Git checkout');
    return source;
  }
  return null;
}
const authState=qaState();
async function checkOverflow(page){
  const size=await page.evaluate(()=>({viewport:window.innerWidth,
    document:document.documentElement.scrollWidth,body:document.body.scrollWidth}));
  expect(size.document,'Document overflows horizontally').toBeLessThanOrEqual(size.viewport+2);
  expect(size.body,'Body overflows horizontally').toBeLessThanOrEqual(size.viewport+2);
}
async function capture(page,info,label){
  const dest=info.outputPath(label+'.png');
  await page.screenshot({path:dest,fullPage:true,animations:'disabled'});
  await info.attach(label,{path:dest,contentType:'image/png'});
}
test('@public real login, privacy, responsive overflow',async({page},info)=>{
  const response=await page.goto('/login',{waitUntil:'domcontentloaded'});
  expect(response?.status()).toBe(200);
  await expect(page.locator('main.login.login-landing')).toBeVisible();
  await expect(page.locator('#login-heading')).toBeVisible();
  await expect(page.locator('button.login-submit')).toBeEnabled();
  await expect(page.locator('.yara-site-header')).toBeVisible();
  await checkOverflow(page);await capture(page,info,'login');
  const privacy=await page.goto('/privacy',{waitUntil:'domcontentloaded'});
  expect(privacy?.status()).toBe(200);
  await expect(page.locator('main')).toBeVisible();
  await checkOverflow(page);
});
test.describe('@auth read-only QA account',()=>{
  test.use({storageState:authState||{cookies:[],origins:[]}});
  test('@auth Today, Tasks and Plans fit the viewport',async({page},info)=>{
    if(!authState)throw Error('AUTH_E2E_BLOCKED: set YARA_E2E_QA_STATE_B64 or YARA_E2E_QA_STATE_FILE');
    if(process.env.YARA_E2E_QA_CONFIRMED!=='1')
      throw Error('AUTH_E2E_BLOCKED: set YARA_E2E_QA_CONFIRMED=1 for dedicated QA account');
    const response=await page.goto('/',{waitUntil:'domcontentloaded'});
    expect(response?.status()).toBe(200);
    await expect(page.locator('main.shell')).toBeVisible();
    await expect(page.locator('#assistant-command')).toBeVisible();
    await expect(page.locator('.yara-site-header')).toBeVisible();
    await checkOverflow(page);await capture(page,info,'today');
    const tabs=page.locator('nav.tabbar');await expect(tabs).toBeVisible();
    await tabs.getByRole('button',{name:/^(Tasks|Справи)$/}).click();
    await expect(page.locator('main.shell h1')).toContainText(/^(Tasks|Справи)$/);
    await checkOverflow(page);await capture(page,info,'tasks');
    await tabs.getByRole('button',{name:/^(Plans|Плани)$/}).click();
    await expect(page.locator('main.shell h1')).toContainText(/^(Plans|Плани)$/);
    await checkOverflow(page);await capture(page,info,'plans');
    // No calendar writes, task submissions or changes to any external provider.
  });
});

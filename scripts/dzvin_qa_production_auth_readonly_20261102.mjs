import { chromium } from '@playwright/test';
const LOGIN='https://mentality-web.vercel.app';
const PROD='https://www.dzvin.co';
const DPL='dpl_HEXPTb7ofycE36faRsEEwfAio6F2';
const accounts=[{name:'QA1',email:process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN,password:process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD},
{name:'QA2',email:process.env.QDIP_E2E_ZITADEL_TEST2_LOGIN,password:process.env.QDIP_E2E_ZITADEL_TEST2_PASSWORD}];
const assert=(v,c)=>{if(!v)throw Error(c)};
async function visible(page,selectors,ms=12000){const until=Date.now()+ms;while(Date.now()<until){for(const s of selectors){const el=page.locator(s).first();if(await el.isVisible().catch(()=>false))return el}await page.waitForTimeout(250)}return null}
async function login(browser,user){
 const ctx=await browser.newContext({serviceWorkers:'block'});
 try{
  const page=await ctx.newPage();await page.goto(LOGIN+'/en/auth',{waitUntil:'domcontentloaded',timeout:30000});
  const username=await visible(page,['input[autocomplete="username"]','input[name="loginName"]','input[name="loginname"]','input[name="username"]','input[name="email"]','input[type="email"]','input[type="text"]']);assert(username,user.name+'_NAME_FIELD');await username.fill(user.email);
  let pass=await visible(page,['input[autocomplete="current-password"]','input[type="password"]'],1500);if(!pass){await username.press('Enter');pass=await visible(page,['input[autocomplete="current-password"]','input[type="password"]'])}
  assert(pass,user.name+'_PASSWORD_FIELD');await pass.fill(user.password);await pass.press('Enter');
  let session;
  for(let n=0;n<25;n++){await page.waitForTimeout(800);const r=await ctx.request.get(LOGIN+'/api/auth/session',{timeout:9000}).catch(()=>null);if(r?.status()===200){session=await r.json().catch(()=>null);if(session?.id)break}}
  assert(session?.id&&session.email?.toLowerCase()===user.email.toLowerCase(),user.name+'_ZITADEL_LOGIN_FAIL');
  const cookie=(await ctx.cookies(LOGIN)).find(x=>x.name==='auth-tokens'&&x.httpOnly&&x.secure);assert(cookie,user.name+'_SECURE_COOKIE_MISSING');
  console.log(user.name+'_REAL_ZITADEL_LOGIN=PASS');
  return {cookie,userId:session.id};
 }finally{await ctx.close()}
}
async function main(){
 assert(process.env.DZVIN_PRODUCTION_READONLY_ACK==='1','PRODUCTION_APPROVAL_REQUIRED');
 assert(accounts.every(a=>a.email&&a.password),'TEST_SECRETS_MISSING');
 const browser=await chromium.launch({headless:true});
 try{
  const users=[];
  for(const actor of accounts){
   const id=await login(browser,actor);users.push(id.userId);
   const ctx=await browser.newContext({serviceWorkers:'block'});
   try{
    const c=id.cookie;await ctx.addCookies([{name:c.name,value:c.value,domain:'www.dzvin.co',path:c.path,httpOnly:true,secure:true,sameSite:c.sameSite,...(c.expires>0?{expires:c.expires}:{})}]);
    const ses=await ctx.request.get(PROD+'/api/auth/session',{maxRedirects:0});
    assert(ses.status()===200,actor.name+'_PROD_SESSION_'+ses.status());
    const actual=await ses.json();assert(actual.id===id.userId,actor.name+'_PROD_SUBJECT');
    const mood=await ctx.request.get(PROD+'/api/backend/mood-record?page=1&limit=20');
    assert(mood.status()===200,actor.name+'_MOOD_READ_'+mood.status());
    assert((mood.headers()['cache-control']||'').includes('no-store'),actor.name+'_MOOD_CACHE');
    assert(Array.isArray(await mood.json()),actor.name+'_MOOD_CONTRACT');
    for(const path of ['/api/backend/dip-admin/organizations','/api/backend/companies','/api/backend/research/projects']){
      const denied=await ctx.request.get(PROD+path);assert(denied.status()===404,actor.name+'_PROD_ADMIN_READ_SCOPE');
      const write=await ctx.request.post(PROD+path,{headers:{origin:PROD,'content-type':'application/json'},data:{}});
      assert(write.status()===404,actor.name+'_PROD_ADMIN_WRITE_SCOPE');
    }
    const page=await ctx.newPage();const p=await page.goto(PROD+'/en/mood-tracker',{waitUntil:'domcontentloaded',timeout:40000});
    assert(p?.status()===200,actor.name+'_PROD_PAGE');
    assert((await p.text()).includes('data-dpl-id="'+DPL+'"'),actor.name+'_DEPLOYMENT_DRIFT');
    console.log(actor.name+'_PRODUCTION_AUTH_MOOD_READ_AND_ADMIN_DENIAL=PASS');
    const logout=await ctx.request.post(PROD+'/api/auth/logout',{headers:{origin:PROD},maxRedirects:0});
    assert(logout.status()===303,actor.name+'_LOGOUT_'+logout.status());
    const after=await ctx.request.get(PROD+'/api/auth/session');assert(after.status()===401,actor.name+'_SESSION_AFTER_LOGOUT');
    console.log(actor.name+'_PRODUCTION_LOGOUT=PASS');
   }finally{await ctx.close()}
  }
  assert(users[0]!==users[1],'SAME_SUBJECTS');
  console.log('DZVIN_PRODUCTION_AUTH_READONLY_SMOKE=PASS');
 }finally{await browser.close()}
}
main().catch(err=>{const code=err instanceof Error&&/^[A-Z0-9_]{5,100}$/.test(err.message)?err.message:'SANITIZED_PRODUCTION_SMOKE_FAILURE';console.error('DZVIN_PRODUCTION_AUTH_READONLY_SMOKE=FAIL:'+code);process.exitCode=1});

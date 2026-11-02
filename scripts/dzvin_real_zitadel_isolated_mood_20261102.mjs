/** 2026-11-02 disposable Railway QA only; two existing Zitadel identities; no secrets in logs. */
import { chromium, request } from '@playwright/test';
const LOGIN='https://mentality-web.vercel.app';
const API=process.env.DZVIN_ISOLATED_QA_API;
const actors=[
  {name:'QA1',email:process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN,password:process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD},
  {name:'QA2',email:process.env.QDIP_E2E_ZITADEL_TEST2_LOGIN,password:process.env.QDIP_E2E_ZITADEL_TEST2_PASSWORD},
];
function assert(v,code){if(!v)throw Error(code)}
async function field(page,selectors,wait=12000) {
  const end=Date.now()+wait;
  do {
    for(const s of selectors){const x=page.locator(s).first(); if(await x.isVisible().catch(()=>false))return x}
    await page.waitForTimeout(250);
  }while(Date.now()<end);
  return null;
}
async function auth(browser,actor){
  const context=await browser.newContext({serviceWorkers:'block'});
  try{
    const page=await context.newPage();
    await page.goto(LOGIN+'/en/auth',{waitUntil:'domcontentloaded',timeout:30000});
    const username=await field(page,['input[autocomplete="username"]','input[name="loginName"]','input[name="loginname"]','input[name="username"]','input[name="email"]','input[type="email"]','input[type="text"]']);
    assert(username,actor.name+'_USERNAME_ABSENT');
    await username.fill(actor.email);
    let password=await field(page,['input[autocomplete="current-password"]','input[type="password"]'],1400);
    if(!password){await username.press('Enter');password=await field(page,['input[autocomplete="current-password"]','input[type="password"]'])}
    assert(password,actor.name+'_PASSWORD_ABSENT');
    await password.fill(actor.password);
    await password.press('Enter');
    let session;
    for(let i=0;i<25;i++){
      await page.waitForTimeout(700);
      const reply=await context.request.get(LOGIN+'/api/auth/session',{timeout:10000}).catch(()=>null);
      if(reply?.status()===200){session=await reply.json().catch(()=>null);if(session?.id)break}
    }
    assert(session?.id&&session.email?.toLowerCase()===actor.email.toLowerCase(),actor.name+'_IDP_LOGIN_FAILURE');
    const cookie=(await context.cookies(LOGIN)).find(c=>c.name==='auth-tokens'&&c.httpOnly&&c.secure);
    assert(cookie,actor.name+'_COOKIE_MISSING');
    let payload;try{payload=JSON.parse(decodeURIComponent(cookie.value))}catch{throw Error(actor.name+'_COOKIE_CONTRACT')}
    assert(typeof payload.accessToken==='string'&&payload.accessToken.length>20,actor.name+'_ACCESS_TOKEN_ABSENT');
    console.log(actor.name+'_ZITADEL_PKCE_LOGIN=PASS');
    return payload.accessToken;
  }finally{await context.close()}
}
async function main(){
  assert(process.env.DZVIN_ISOLATED_QA_APPROVED==='1','SCOPED_QA_APPROVAL_REQUIRED');
  assert(/^https:\/\/[a-z0-9-]+\.up\.railway\.app$/.test(API||''),'QA_API_NOT_RAILWAY_PUBLIC');
  assert(actors.every(a=>a.email&&a.password),'QA_SECRETS_MISSING');
  assert(actors[0].email.toLowerCase()!==actors[1].email.toLowerCase(),'SAME_QA_ACCOUNT');
  const browser=await chromium.launch({headless:true});
  const clients=[];
  try{
    for(const actor of actors){
      const token=await auth(browser,actor);
      const client=await request.newContext({baseURL:API,extraHTTPHeaders:{Authorization:'Bearer '+token},ignoreHTTPSErrors:false});
      clients.push(client);
      const createUser=await client.post('/api/auth/validate-token',{timeout:30000});
      assert([201,202].includes(createUser.status()),actor.name+'_USER_PROVISION_'+createUser.status());
      console.log(actor.name+'_QA_ISOLATED_USER_PROVISION=PASS');
    }
    const initial=await clients[0].get('/api/mood-record?page=1&limit=50');
    assert(initial.status()===200,'QA1_INITIAL_LIST_'+initial.status());
    const before=await initial.json();
    assert(Array.isArray(before)&&before.length===0,'QA_NOT_EMPTY');
    console.log('QA_ISOLATED_MONGO_STARTS_EMPTY=PASS');
    const records=[];
    for(let i=0;i<2;i++){
      const data={moodLevel:i?2:4,stressLevel:i?4:2,energyLevel:i?5:3,focusLevel:i?1:5,tags:['qdip-isolated-20261102']};
      const response=await clients[i].post('/api/mood-record?timeZone=Europe%2FWarsaw',{data,timeout:60000});
      assert(response.status()===201,'QA'+(i+1)+'_CREATE_'+response.status());
      const created=await response.json();
      assert(typeof created.id==='string'&&Number.isFinite(Date.parse(created.createdAt)),'CREATE_TIMESTAMP_INVALID');
      for(const key of ['moodLevel','stressLevel','energyLevel','focusLevel'])assert(created[key]===data[key],'DIMENSION_'+key);
      assert(Array.isArray(created.tags)&&created.tags.includes('qdip-isolated-20261102'),'TAGS_NOT_PERSISTED');
      records.push(created);
      console.log('QA'+(i+1)+'_MOOD_CREATE_ALL_DIMENSIONS=PASS');
    }
    for(let i=0;i<2;i++){
      const list=await clients[i].get('/api/mood-record?page=1&limit=50&order=newest');
      assert(list.status()===200,'QA'+(i+1)+'_HISTORY_STATUS_'+list.status());
      const rows=await list.json();
      assert(Array.isArray(rows)&&rows.some(x=>x.id===records[i].id),'QA'+(i+1)+'_MISSING_OWN_RECORD');
      assert(!rows.some(x=>x.id===records[1-i].id),'QA'+(i+1)+'_CROSS_TENANT_LIST_LEAK');
      const foreign=await clients[i].get('/api/mood-record/'+records[1-i].id);
      assert([403,404].includes(foreign.status()),'QA'+(i+1)+'_FOREIGN_READ_'+foreign.status());
      console.log('QA'+(i+1)+'_MOOD_HISTORY_AND_FOREIGN_DENIAL=PASS');
    }
    console.log('QA_ISOLATED_MOOD_LIFECYCLE=PASS');
    console.log('QA_TEARDOWN_REQUIRED=DELETE_ONLY_DISPOSABLE_RAILWAY_MONGO');
  }finally{
    for(const client of clients)await client.dispose();
    await browser.close();
  }
}
main().catch(err=>{const code=err instanceof Error&&/^[A-Z0-9_]{4,130}$/.test(err.message)?err.message:'REDACTED_ISOLATED_QA_FAILURE';console.error('QA_ISOLATED_MOOD_LIFECYCLE=FAIL:'+code);process.exitCode=1});

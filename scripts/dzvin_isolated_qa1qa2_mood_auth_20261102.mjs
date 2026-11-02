import { chromium } from '@playwright/test';
const LOGIN = 'https://mentality-web.vercel.app';
const BACK = 'https://dzvin-b2c-rc-build-qa.up.railway.app';
const assert = (x, code) => { if (!x) throw new Error(code); };
const users = [
  { label: 'QA1', email: process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN, password: process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD },
  { label: 'QA2', email: process.env.QDIP_E2E_ZITADEL_TEST2_LOGIN, password: process.env.QDIP_E2E_ZITADEL_TEST2_PASSWORD },
];
async function visible(page, selectors, ms=14000) {
  const end=Date.now()+ms;
  while(Date.now()<end) {
    for (const s of selectors) {
      const f=page.locator(s).first();
      if(await f.isVisible().catch(()=>false))return f;
    }
    await page.waitForTimeout(250);
  }
  throw new Error('LOGIN_INPUT_MISSING');
}
async function login(browser, user) {
  const cx=await browser.newContext({ serviceWorkers:'block' });
  try {
    const page=await cx.newPage();
    let pkce=false;
    page.on('request', req=>{
      try {
        const u=new URL(req.url());
        if(u.pathname.endsWith('/oauth/v2/authorize') && u.searchParams.get('code_challenge_method')==='S256'
          && new URL(u.searchParams.get('redirect_uri')).origin===LOGIN)pkce=true;
      }catch{}
    });
    await page.goto(LOGIN+'/en/auth',{waitUntil:'domcontentloaded',timeout:30000});
    await page.waitForURL(u=>u.origin!==LOGIN,{timeout:24000});
    assert(pkce,'PKCE_INVALID');
    const un=await visible(page,['input[autocomplete="username"]','input[name="loginName"]','input[name="username"]','input[type="email"]','input[type="text"]']);
    await un.fill(user.email);
    let pw=await visible(page,['input[autocomplete="current-password"]','input[type="password"]'],1600).catch(()=>null);
    if(!pw){await un.press('Enter');pw=await visible(page,['input[autocomplete="current-password"]','input[type="password"]']);}
    await pw.fill(user.password); await pw.press('Enter');
    let session=null;
    for(let n=0;n<23;n++){
      await page.waitForTimeout(900);
      const r=await cx.request.get(LOGIN+'/api/auth/session',{timeout:9500}).catch(()=>null);
      if(r?.status()===200){session=await r.json().catch(()=>null);if(session?.id)break;}
    }
    assert(session?.email?.toLowerCase()===user.email.toLowerCase(),'LOGIN_IDENTITY_MISMATCH');
    const cookie=(await cx.cookies(LOGIN)).find(c=>c.name==='auth-tokens' && c.httpOnly && c.secure);
    assert(cookie,'AUTH_COOKIE_MISSING');
    const parsed=JSON.parse(decodeURIComponent(cookie.value));
    assert(typeof parsed.accessToken==='string' && parsed.accessToken.length>20,'ACCESS_TOKEN_MISSING');
    console.log(user.label+'_ZITADEL_LOGIN=PASS');
    return parsed.accessToken;
  }finally{await cx.close();}
}
async function api(token,path,method='GET',body) {
  const r=await fetch(BACK+path,{
    method,headers:{authorization:'Bearer '+token,...(body?{'content-type':'application/json'}:{})},
    ...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(30000)
  });
  const result=await r.json().catch(()=>null);
  return {status:r.status,data:result};
}
async function main(){
  assert(process.env.DZVIN_MOOD_ISOLATED_ACK==='1','ISOLATED_APPROVAL_MISSING');
  assert(users.every(u=>u.email&&u.password),'QA_CREDENTIALS_MISSING');
  const health=await fetch(BACK+'/api',{signal:AbortSignal.timeout(12000)});
  assert(health.status>=200&&health.status<400,'QA_BACKEND_UNREACHABLE');
  const browser=await chromium.launch({headless:true});
  try {
    const tokens=[];
    for(const u of users)tokens.push(await login(browser,u));
    for(let i=0;i<2;i++){
      const r=await api(tokens[i],'/api/auth/validate-token','POST');
      assert([200,201,202].includes(r.status),'QA'+(i+1)+'_BACKEND_IDENTITY_'+r.status);
      console.log('QA'+(i+1)+'_ISOLATED_USER_BOUND=PASS');
    }
    const initial=await Promise.all(tokens.map(t=>api(t,'/api/mood-record?page=1&limit=20')));
    for(let i=0;i<2;i++){assert(initial[i].status===200&&Array.isArray(initial[i].data),'QA'+(i+1)+'_INITIAL_HISTORY_INVALID');}
    console.log('QA1_QA2_PRIVATE_HISTORY=PASS');
    const bodies=[
      {moodLevel:4,stressLevel:2,energyLevel:3,focusLevel:5,tags:['qa1-isolated-20261102']},
      {moodLevel:2,stressLevel:4,energyLevel:2,focusLevel:3,tags:['qa2-isolated-20261102']}
    ];
    const made=[];
    for(let i=0;i<2;i++){
      const c=await api(tokens[i],'/api/mood-record?timeZone=Europe%2FWarsaw','POST',bodies[i]);
      assert(c.status===201 && /^[a-f0-9]{24}$/i.test(c.data?.id||''),'QA'+(i+1)+'_CREATE_'+c.status);
      assert(Number.isFinite(Date.parse(c.data.createdAt)),'QA'+(i+1)+'_CREATED_DATE');
      for(const k of ['moodLevel','stressLevel','energyLevel','focusLevel'])assert(c.data[k]===bodies[i][k],'QA'+(i+1)+'_DIMENSION_'+k);
      assert(c.data.tags?.includes(bodies[i].tags[0]),'QA'+(i+1)+'_TAGS');
      made.push(c.data.id);
      console.log('QA'+(i+1)+'_CREATE_ALL_FIELDS_DATE=PASS');
    }
    for(let i=0;i<2;i++){
      const own=await api(tokens[i],'/api/mood-record?page=1&limit=50&order=newest');
      assert(own.status===200&&own.data?.some(x=>x.id===made[i]),'QA'+(i+1)+'_HISTORY_MISSING');
      assert(!own.data.some(x=>x.id===made[1-i]),'QA'+(i+1)+'_FOREIGN_LIST_LEAK');
      const foreign=await api(tokens[i],'/api/mood-record/'+made[1-i]);
      assert([403,404].includes(foreign.status),'QA'+(i+1)+'_FOREIGN_GET_'+foreign.status);
      console.log('QA'+(i+1)+'_PERSISTENCE_AND_CROSS_TENANT_DENY=PASS');
    }
    console.log('DZVIN_ISOLATED_MOOD_E2E=PASS');
    console.log('DZVIN_ISOLATED_TEARDOWN=REQUIRES_PRIVATE_DB_RESET');
  }finally{await browser.close();}
}
main().catch(e=>{
  const code=String(e?.message||'UNKNOWN').replace(/[^A-Za-z0-9_]/g,'_').slice(0,100);
  console.error('DZVIN_ISOLATED_MOOD_E2E=FAIL:'+code);
  process.exitCode=1;
});
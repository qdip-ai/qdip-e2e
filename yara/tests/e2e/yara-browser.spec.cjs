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


async function browserApi(page, url, method='GET', data){
  return page.evaluate(async ({url,method,data})=>{
    const response=await fetch(url,{
      method,credentials:'same-origin',cache:'no-store',
      headers:data===undefined?{}:{'content-type':'application/json'},
      body:data===undefined?undefined:JSON.stringify(data)
    });
    return {status:response.status,body:await response.json().catch(()=>null),
      cacheControl:response.headers.get('cache-control')};
  },{url,method,data});
}

test.describe('@delegation real authorized QA lifecycle',()=>{
  test.use({storageState:authState||{cookies:[],origins:[]}});
  test('@delegation create, replay, consent denial, cancel and durable audit via browser BFF',async({page},info)=>{
    test.setTimeout(90_000);
    if(!authState||process.env.YARA_E2E_QA_CONFIRMED!=='1')
      throw Error('DELEGATION_E2E_BLOCKED: genuine isolated QA account required');
    // This spec performs real database writes; do not aim at production or
    // an arbitrary preview. The full gate also independently attests Git SHA.
    if(new URL(process.env.YARA_E2E_BASE_URL||'').origin!==
      'https://yara-qa-web-sandbox.up.railway.app'||process.env.YARA_E2E_SCOPE!=='full')
      throw Error('DELEGATION_E2E_BLOCKED: dedicated Yara QA only');

    const response=await page.goto('/',{waitUntil:'domcontentloaded'});
    expect(response?.status()).toBe(200);
    await expect(page.locator('#assistant-command')).toBeVisible();
    const root='/api/secretary/v1/delegations';
    const clientRequestId=require('node:crypto').randomUUID();
    const actionId=require('node:crypto').randomUUID();
    const input={clientRequestId,instruction:'QA browser synthetic delegation '+clientRequestId,
      source:'typed'};
    let createdId=null,closed=false;

    // A cross-origin request must be rejected before reaching the API or DB.
    const forbidden=await page.request.post(root,{
      headers:{origin:'https://not-yara.invalid','content-type':'application/json'},
      data:input,failOnStatusCode:false
    });
    expect(forbidden.status()).toBe(403);

    try{
      const invalid=await browserApi(page,root,'POST',{...input,instruction:''});
      expect(invalid.status).toBe(400);

      const created=await browserApi(page,root,'POST',input);
      expect(created.status).toBe(201);
      expect(created.body).toMatchObject({status:'RECEIVED',revision:0,accepted:true});
      expect(created.body).not.toHaveProperty('autonomousExecutionStarted');
      expect(created.body.id).toMatch(/^[0-9a-f-]{36}$/i);
      createdId=created.body.id;

      const replay=await browserApi(page,root,'POST',input);
      expect(replay.status).toBe(201);
      expect(replay.body.id).toBe(createdId);
      expect(replay.body.status).toBe('RECEIVED');

      const conflicting=await browserApi(page,root,'POST',{
        ...input,instruction:'QA browser changed intent'
      });
      expect(conflicting.status).toBe(409);

      const all=await browserApi(page,root);
      expect(all.status).toBe(200);
      expect(all.body).toEqual(expect.arrayContaining([
        expect.objectContaining({id:createdId,status:'RECEIVED',revision:0})
      ]));
      expect(all.cacheControl).toContain('no-store');

      const detail=await browserApi(page,root+'/'+createdId);
      expect(detail.status).toBe(200);
      expect(detail.body).toMatchObject({id:createdId,status:'RECEIVED',revision:0});
      expect(detail.body.actions).toEqual([]);
      expect(detail.body.history).toEqual(expect.arrayContaining([
        expect.objectContaining({action:'DELEGATION_RECEIVED'})
      ]));

      // Consent requires a genuine, immutable executor-prepared action.
      // No browser endpoint can prepare one or execute provider writes.
      const invented=await browserApi(page,
        root+'/'+createdId+'/actions/'+actionId+'/decision','POST',
        {action:'APPROVE',expectedRevision:0});
      expect(invented.status).toBe(409);
      const rejected=await browserApi(page,
        root+'/'+createdId+'/actions/'+actionId+'/decision','POST',
        {action:'REJECT',expectedRevision:0});
      expect(rejected.status).toBe(409);
      for(const suffix of ['/start','/complete','/actions/'+actionId+'/execute',
        '/actions/'+actionId+'/propose']){
        const denied=await browserApi(page,root+'/'+createdId+suffix,'POST',{});
        expect(denied.status).toBe(404);
      }
      const invalidId=await browserApi(page,root+'/not-a-uuid');
      expect(invalidId.status).toBe(404);
      const missing=await browserApi(page,root+'/'+require('node:crypto').randomUUID());
      expect(missing.status).toBe(404);

      const stale=await browserApi(page,root+'/'+createdId+'/cancel','POST',{expectedRevision:1});
      expect(stale.status).toBe(409);
      const cancelled=await browserApi(page,root+'/'+createdId+'/cancel','POST',
        {expectedRevision:0});
      expect(cancelled.status).toBe(201);
      expect(cancelled.body).toMatchObject({id:createdId,status:'CANCELLED',
        revision:1,externalActionsAlreadyExecuted:false});
      closed=true;

      const doubleCancel=await browserApi(page,root+'/'+createdId+'/cancel','POST',
        {expectedRevision:1});
      expect(doubleCancel.status).toBe(409);
      const persisted=await browserApi(page,root+'/'+createdId);
      expect(persisted.status).toBe(200);
      expect(persisted.body).toMatchObject({id:createdId,status:'CANCELLED',revision:1});
      expect(persisted.body.history.map(x=>x.action)).toEqual(expect.arrayContaining([
        'DELEGATION_RECEIVED','DELEGATION_CANCELLED'
      ]));
      await checkOverflow(page);
      console.log('YARA_QA_DELEGATION_BROWSER_LIFECYCLE=PASS '+info.project.name);
    }finally{
      // Stop incomplete synthetic QA requests; never leave a running action.
      if(createdId&&!closed){
        const detail=await browserApi(page,root+'/'+createdId).catch(()=>null);
        if(detail?.status===200&&!['COMPLETED','CANCELLED','FAILED'].includes(detail.body?.status)){
          const cleanup=await browserApi(page,root+'/'+createdId+'/cancel','POST',
            {expectedRevision:detail.body.revision}).catch(()=>null);
          if(cleanup?.status!==201)throw Error('DELEGATION_E2E_QA_CLEANUP_FAILED');
        }
      }
    }
  });
});

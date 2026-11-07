/**
 * One-shot QA app-C provisioning on the existing Zitadel QA project only.
 * Requires a real QA21 ORG_OWNER browser login, no admin secrets and no Google.
 * The returned app/client IDs are public identifiers; no credentials printed.
 * Never touches production/main Zitadel org or other applications.
 */
import {chromium} from '@playwright/test';

const SITE='https://qdip.ai';
const ISSUER='https://mentality-rmwj0i.eu1.zitadel.cloud';
const ORG='397885387160184113';
const PROJECT=process.env.QDIP_SDK_QA_PROJECT_ID;
const OWNER='qa-21@qdip.ai';
const APP_NAME='sdk555-e2e-unrelated-qa';
const CALLBACK='http://127.0.0.1:8765/oidc/callback';
const error=(s)=>{throw Error(s);};
const check=(value,label)=>{console.log('SDK555_'+label+'='+(value?'PASS':'FAIL'));if(!value)error(label);};
async function find(page,selectors){
  for(let n=0;n<60;n++){
    for(const s of selectors){const el=page.locator(s).first();if(await el.isVisible().catch(()=>false))return el;}
    await page.waitForTimeout(250);
  }
  error('LOGIN_INPUT_UNAVAILABLE');
}
async function auth(ctx){
  const page=await ctx.newPage();
  try{
    await page.goto(SITE+'/api/auth/login?return_to='+encodeURIComponent(SITE+'/en'),{
      waitUntil:'domcontentloaded',timeout:30000});
    check(new URL(page.url()).origin===ISSUER,'REAL_ZITADEL_ORIGIN');
    const username=await find(page,['input[autocomplete="username"]','input[name="loginName"]',
      'input[name="username"]','input[name="loginname"]','input[name="email"]',
      'input[type="email"]','input[type="text"]']);
    await username.fill(OWNER);
    let pass=page.locator('input[type="password"]').first();
    if(!(await pass.isVisible().catch(()=>false))){
      await username.press('Enter');
      pass=await find(page,['input[autocomplete="current-password"]','input[type="password"]']);
    }
    const cb=page.waitForResponse(r=>{
      try{return new URL(r.url()).origin===SITE&&
        new URL(r.url()).pathname==='/api/auth/callback/zitadel';}catch{return false;}
    },{timeout:40000});
    await pass.fill(process.env.QDIP_E2E_ZITADEL_TEST21_PASSWORD);await pass.press('Enter');
    check([302,303].includes((await cb).status()),'QA21_AUTHENTICATED');
  }finally{await page.close();}
  let bearer=null;
  const consolePage=await ctx.newPage();
  consolePage.on('request',request=>{
    try{
      if(new URL(request.url()).origin!==ISSUER)return;
      void request.allHeaders().then(h=>{
        const v=h.authorization||'';
        if(v.startsWith('Bearer ')&&v.length>=24&&v.length<9000)bearer=v.slice(7);
      }).catch(()=>{});
    }catch{}
  });
  try{
    await consolePage.goto(ISSUER+'/ui/console/projects',{waitUntil:'domcontentloaded',timeout:30000});
    const until=Date.now()+20000;
    while(!bearer&&Date.now()<until)await consolePage.waitForTimeout(400);
  }finally{await consolePage.close();}
  check(typeof bearer==='string'&&bearer.length>=24,'QA21_ADMIN_CONSOLE_BEARER');
  return bearer;
}
async function request(ctx,bearer,method,body){
  const url=ISSUER+'/zitadel.application.v2.ApplicationService/'+method;
  const r=await ctx.request.post(url,{data:body,headers:{
    Authorization:'Bearer '+bearer,'Connect-Protocol-Version':'1',
    'Content-Type':'application/json',
  },timeout:20000,maxRedirects:0});
  return {status:r.status(),body:await r.json().catch(()=>null)};
}
async function main(){
  check(process.env.QDIP_E2E_ZITADEL_TEST21_LOGIN===OWNER&&
    (process.env.QDIP_E2E_ZITADEL_TEST21_PASSWORD||'').length>=8&&
    /^[0-9]{1,32}$/.test(PROJECT||'')&&
    /^[0-9]{1,32}$/.test(process.env.QDIP_SDK_MANAGED_APP_ID||''),
    'REVIEWED_QA_IDENTITY_AND_PROJECT');
  const browser=await chromium.launch({headless:true});
  const ctx=await browser.newContext({ignoreHTTPSErrors:false,
    serviceWorkers:'block',acceptDownloads:false,viewport:{width:1280,height:800}});
  let created=null;
  try{
    const bearer=await auth(ctx);
    const admin=await ctx.request.post(
      ISSUER+'/zitadel.internal_permission.v2.InternalPermissionService/ListAdministrators',{
        data:{pagination:{offset:0,limit:100},filters:[
          {resource:{organizationId:ORG}},{role:{roleKey:'ORG_OWNER'}}]},
        headers:{Authorization:'Bearer '+bearer},
        timeout:15000,maxRedirects:0});
    check(admin.status()===200,'QA_ORG_OWNER_PERMISSION_PROBE_200');
    const adminList=await admin.json().catch(()=>null);
    check(Array.isArray(adminList?.administrators)&&
      adminList.administrators.length>0,'QA_ORG_OWNER_EXISTS');
    const existing=await request(ctx,bearer,'ListApplications',{
      pagination:{limit:100},filters:[{projectIdFilter:{projectId:PROJECT}}]});
    check(existing.status===200&&Array.isArray(existing.body?.applications),
      'EXISTING_QA_PROJECT_INVENTORY');
    const qaApps=existing.body.applications.filter(x=>x.projectId===PROJECT);
    const same=qaApps.filter(x=>x.name===APP_NAME&&x.state==='APPLICATION_STATE_ACTIVE');
    check(same.length<=1,'NO_DUPLICATE_QA_THIRD_APP');
    if(same.length===1){
      created=same[0].applicationId;
      check(typeof same[0].oidcConfiguration?.clientId==='string',
        'EXISTING_QA_THIRD_OIDC');
      console.log('SDK555_QA_THIRD_APP_ID='+created);
      console.log('SDK555_QA_THIRD_CLIENT_ID='+same[0].oidcConfiguration.clientId);
      console.log('SDK555_THIRD_APP_REUSED=PASS');
      return;
    }
    const managed=await request(ctx,bearer,'GetApplication',{
      applicationId:process.env.QDIP_SDK_MANAGED_APP_ID});
    check(managed.status===200&&managed.body?.application?.projectId===PROJECT&&
      managed.body.application.name==='sdk-managed-qa',
      'VERIFIED_EXISTING_MANAGED_TEMPLATE');
    const config=managed.body.application.oidcConfiguration;
    check(config?.redirectUris?.includes(CALLBACK)&&
      config?.grantTypes?.includes('OIDC_GRANT_TYPE_AUTHORIZATION_CODE')&&
      config?.authMethodType==='OIDC_AUTH_METHOD_TYPE_NONE',
      'SAFE_NATIVE_PKCE_TEMPLATE');
    const fresh=await request(ctx,bearer,'CreateApplication',{
      projectId:PROJECT,name:APP_NAME,
      oidcConfiguration:{
        redirectUris:[CALLBACK],
        responseTypes:['OIDC_RESPONSE_TYPE_CODE'],
        grantTypes:['OIDC_GRANT_TYPE_AUTHORIZATION_CODE'],
        appType:config.appType,authMethodType:'OIDC_AUTH_METHOD_TYPE_NONE',
        devMode:true,
      },
    });
    console.log('SDK555_QA_THIRD_CREATE_STATUS='+fresh.status);
    check(fresh.status===200,'QA_THIRD_OIDC_APP_CREATED_200');
    created=fresh.body?.applicationId;
    const client=fresh.body?.oidcConfiguration?.clientId;
    check(/^[0-9]{1,32}$/.test(created||'')&&
      typeof client==='string'&&client.length>=8,'QA_THIRD_PUBLIC_CLIENT_ID');
    const checkApp=await request(ctx,bearer,'GetApplication',{applicationId:created});
    check(checkApp.status===200&&checkApp.body?.application?.projectId===PROJECT&&
      checkApp.body?.application?.name===APP_NAME&&
      checkApp.body?.application?.oidcConfiguration?.clientId===client,
      'QA_THIRD_CROSSCHECKED_ZITADEL');
    console.log('SDK555_QA_THIRD_APP_ID='+created);
    console.log('SDK555_QA_THIRD_CLIENT_ID='+client);
    console.log('SDK555_THIRD_TEST_APP_CREATED_WITH_NO_GOOGLE=PASS');
  }finally{await ctx.close();await browser.close();}
}
main().catch(e=>{
  const label=e instanceof Error&&/^[A-Z0-9_]{4,96}$/.test(e.message)?
    e.message:'SANITIZED_FAILURE';
  console.error('SDK555_QA_APP_C_PROVISIONING=BLOCKED_'+label);
  process.exitCode=1;
});

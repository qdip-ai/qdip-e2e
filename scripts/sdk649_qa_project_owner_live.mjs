import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createHash, randomBytes} from 'node:crypto';
import {chromium} from '@playwright/test';
import {validateQaApplicationVariables} from './sdk649_qa_app_vars.mjs';
const SITE='https://qdip.ai', ISSUER='https://mentality-rmwj0i.eu1.zitadel.cloud';
const ORG='397885387160184113', USER='qa-21@qdip.ai';
const CALLBACK_URI='http://127.0.0.1:8765/oidc/callback';
const STAGING_CORE='https://qdip-core-staging-staging.up.railway.app';
function check(ok,id){console.log('SDK649_'+id+'='+(ok?'PASS':'FAIL'));if(!ok)throw Error(id);}
function appOk(x,p,id,client,name){const a=x?.application;
  return a?.applicationId===id&&a?.projectId===p&&a?.name===name&&
    a?.state==='APPLICATION_STATE_ACTIVE'&&a?.oidcConfiguration?.clientId===client;}
function projectOk(x,p){return x?.project?.projectId===p&&x?.project?.organizationId===ORG&&
  x?.project?.state==='PROJECT_STATE_ACTIVE';}
function ownerOk(x,p,sub){const a=x?.administrators,m=x?.pagination??x?.details;
  return Array.isArray(a)&&a.length<=100&&Number(m?.totalResult)===a.length&&
    a.some(o=>o?.instance!==true&&o?.user?.id===sub&&
    Array.isArray(o?.roles)&&o.roles.includes('PROJECT_OWNER')&&
    o?.project?.id===p&&o?.project?.organizationId===ORG);}
async function proveCoreRejectsMissingOrForgedSdkKey(req,appId,label){
  const url=STAGING_CORE+'/api/v1/private-resource-access/applications/link';
  const body={application_id:appId};
  // Both probes MUST be rejected before introspection, ownership or a Mongo write.
  // No Authorization bearer or valid organization-scoped SDK key is sent.
  for(const [scenario,headers] of [
    ['MISSING_SDK_KEY',{}],
    ['FORGED_SDK_KEY',{'x-api-key':'sdk649-intentionally-invalid-key'}],
  ]){
    const r=await req.post(url,{
      data:body,headers,timeout:15000,maxRedirects:0,
    });
    check(r.status()===401,label+'_CORE_'+scenario+'_DENIED_401');
  }
}
async function openCallback(expectedState){
  let receive;
  const code=new Promise(resolve=>{receive=resolve;});
  let delivered=false;
  const server=createServer((req,res)=>{
    const respond=(status,body)=>{
      res.writeHead(status,{'Content-Type':'text/plain; charset=utf-8',
        'Cache-Control':'no-store','Referrer-Policy':'no-referrer',
        'X-Content-Type-Options':'nosniff'});
      res.end(body);
    };
    let url;
    try{url=new URL(req.url,CALLBACK_URI);}catch{respond(400,'Invalid callback');return;}
    if(req.method!=='GET'||url.pathname!=='/oidc/callback'){
      respond(404,'Not found');return;}
    if(url.searchParams.get('state')!==expectedState){
      respond(400,'Invalid state');return;}
    const value=url.searchParams.get('code');
    if(delivered||!value||value.length<8||value.length>2048){
      respond(400,'Invalid code');return;}
    delivered=true;
    respond(200,'QA authorization callback received');
    receive(value);
  });
  await new Promise((resolve,reject)=>{
    server.once('error',reject);
    server.listen(8765,'127.0.0.1',resolve);
  });
  return {code,close:()=>new Promise((resolve,reject)=>
    server.close(err=>err?reject(err):resolve()))};
}
async function verifyPkce(ctx,client,label,projectId,expectedSub){
  const state=randomBytes(24).toString('base64url');
  const nonce=randomBytes(24).toString('base64url');
  const verifier=randomBytes(32).toString('base64url');
  const challenge=createHash('sha256').update(verifier).digest('base64url');
  const local=await openCallback(state);
  const page=await ctx.newPage();
  let accessToken=null;
  try{
    const url=new URL(ISSUER+'/oauth/v2/authorize');
    for(const [k,v] of Object.entries({
      client_id:client,redirect_uri:CALLBACK_URI,response_type:'code',
      code_challenge:challenge,code_challenge_method:'S256',
      state,nonce,
      scope:'openid profile email urn:zitadel:iam:org:project:id:'+projectId+':aud',
    }))url.searchParams.set(k,v);
    await page.goto(url.toString(),{waitUntil:'domcontentloaded',timeout:30000});
    const timeout=new Promise((_,reject)=>{
      const t=setTimeout(()=>reject(Error('PKCE_CALLBACK_TIMEOUT')),45000);
      t.unref();
    });
    const authorizationCode=await Promise.race([local.code,timeout]);
    const response=await ctx.request.post(ISSUER+'/oauth/v2/token',{
      form:{grant_type:'authorization_code',client_id:client,
        redirect_uri:CALLBACK_URI,code:authorizationCode,code_verifier:verifier},
      timeout:15000,maxRedirects:0,
    });
    check(response.status()===200,label+'_PKCE_TOKEN_HTTP_200');
    const body=await response.json().catch(()=>null);
    accessToken=body?.access_token;
    check(body?.token_type?.toLowerCase()==='bearer'&&
      typeof accessToken==='string'&&accessToken.length>=16,
      label+'_PKCE_ACCESS_TOKEN');
    const user=await ctx.request.get(ISSUER+'/oidc/v1/userinfo',{
      headers:{Authorization:'Bearer '+accessToken},
      timeout:15000,maxRedirects:0,
    });
    check(user.status()===200,label+'_PKCE_USERINFO_HTTP_200');
    const profile=await user.json().catch(()=>null);
    check(profile?.sub===expectedSub,label+'_PKCE_EXACT_QA21_SUBJECT');
  }finally{
    accessToken=null;
    await page.close();
    await local.close();
  }
}
async function selfTest(){const p='111111111111111111',s='222222222222222222',id='333333333333333333';
  const app={application:{applicationId:id,projectId:p,name:'sdk-managed-qa',
    state:'APPLICATION_STATE_ACTIVE',oidcConfiguration:{clientId:'a'}}};
  assert(appOk(app,p,id,'a','sdk-managed-qa'));
  assert(!appOk(app,p,id,'b','sdk-managed-qa'));
  assert(projectOk({project:{projectId:p,organizationId:ORG,state:'PROJECT_STATE_ACTIVE'}},p));
  const row={user:{id:s},project:{id:p,organizationId:ORG},roles:['PROJECT_OWNER']};
  assert(ownerOk({administrators:[row],pagination:{totalResult:1}},p,s));
  assert(!ownerOk({administrators:[{user:{id:s},roles:['PROJECT_OWNER']}],
    pagination:{totalResult:1}},p,s));
  assert(!ownerOk({administrators:[{...row,roles:['ORG_OWNER']}],
    pagination:{totalResult:1}},p,s));
  assert(!ownerOk({administrators:[row],pagination:{totalResult:2}},p,s));
  console.log('SDK649_OWNER_PROOF_NEGATIVE_REGRESSIONS=PASS');
  const local=await openCallback('test-state-123');
  try{
    assert.equal((await fetch(CALLBACK_URI+'?state=wrong&code=code-sample-1234')).status,400);
    assert.equal((await fetch('http://127.0.0.1:8765/other')).status,404);
    assert.equal((await fetch(CALLBACK_URI+'?state=test-state-123&code=code-sample-1234')).status,200);
    assert.equal(await local.code,'code-sample-1234');
    assert.equal((await fetch(CALLBACK_URI+'?state=test-state-123&code=replay-code-1234')).status,400);
  }finally{await local.close();}
  console.log('SDK649_PKCE_LOOPBACK_NEGATIVE_REGRESSIONS=PASS');}
async function visible(page,selectors,ms=14000){const end=Date.now()+ms;
  while(Date.now()<end){for(const s of selectors){const n=page.locator(s).first();
    if(await n.isVisible().catch(()=>false))return n;}await page.waitForTimeout(250);}
  return null;}
async function readRpc(req,path,bearer,data,id){
  // Only Zitadel GetApplication, GetProject and ListAdministrators read RPCs.
  const r=await req.post(ISSUER+path,{data,timeout:15000,maxRedirects:0,
    headers:{Authorization:'Bearer '+bearer,Accept:'application/json'}});
  check(r.status()===200,id+'_HTTP_200');
  const json=await r.json().catch(()=>null);check(json&&typeof json==='object',id+'_JSON');
  return json;}
async function run(){validateQaApplicationVariables(process.env);
  check(process.env.QDIP_E2E_ZITADEL_TEST21_LOGIN===USER&&
    (process.env.QDIP_E2E_ZITADEL_TEST21_PASSWORD||'').length>=8,'QA21_ACCOUNT_BOUND');
  const b=await chromium.launch({headless:true}),ctx=await b.newContext({
    ignoreHTTPSErrors:false,serviceWorkers:'block',acceptDownloads:false,
    viewport:{width:1280,height:800}});
  let token=null;
  try{const page=await ctx.newPage();
    await page.goto(SITE+'/api/auth/login?return_to='+encodeURIComponent(SITE+'/en'),
      {waitUntil:'domcontentloaded',timeout:30000});
    check(new URL(page.url()).origin===ISSUER,'REAL_QA21_ISSUER');
    const login=await visible(page,['input[autocomplete="username"]','input[name="loginName"]',
      'input[name="loginname"]','input[name="username"]','input[name="email"]',
      'input[type="email"]','input[type="text"]']);check(!!login,'LOGIN_FORM');
    await login.fill(USER);
    let pass=await visible(page,['input[autocomplete="current-password"]','input[type="password"]'],1200);
    if(!pass){await login.press('Enter');
      pass=await visible(page,['input[autocomplete="current-password"]','input[type="password"]']);}
    check(!!pass,'PASSWORD_FORM');
    const cb=page.waitForResponse(r=>{try{const u=new URL(r.url());return u.origin===SITE&&
      u.pathname==='/api/auth/callback/zitadel';}catch{return false;}},{timeout:40000});
    await pass.fill(process.env.QDIP_E2E_ZITADEL_TEST21_PASSWORD);await pass.press('Enter');
    const done=await cb.catch(()=>null);check(done&&[302,303].includes(done.status()),'OIDC_CALLBACK');
    const sr=await ctx.request.get(SITE+'/api/auth/session',{timeout:15000});
    check(sr.status()===200,'SESSION_HTTP');
    const session=await sr.json();
    check(session.authenticated===true&&session.user?.email===USER,'QA21_AUTHENTICATED');
    const consolePage=await ctx.newPage();
    consolePage.on('request',req=>{try{if(new URL(req.url()).origin!==ISSUER)return;
      void req.allHeaders().then(h=>{const v=h.authorization||'';
        if(v.startsWith('Bearer ')&&v.length>=24&&v.length<9000)token=v.slice(7);
      }).catch(()=>{});}catch{}});
    await consolePage.goto(ISSUER+'/ui/console/projects',{waitUntil:'domcontentloaded',timeout:30000});
    const end=Date.now()+20000;
    while(!token&&Date.now()<end)await consolePage.waitForTimeout(500);
    check(!!token,'CONSOLE_OIDC_TOKEN_AVAILABLE');
    const ur=await ctx.request.get(ISSUER+'/oidc/v1/userinfo',{timeout:15000,
      maxRedirects:0,headers:{Authorization:'Bearer '+token}});
    check(ur.status()===200,'QA21_USERINFO_HTTP_200');
    const sub=(await ur.json().catch(()=>null))?.sub;
    check(typeof sub==='string'&&/^[0-9]{1,32}$/.test(sub),'QA21_VERIFIED_SUBJECT');
    const p=process.env.QDIP_SDK_QA_PROJECT_ID;
    const readyPkce=[];
    for(const [label,id,client,name] of [
      ['MANAGED',process.env.QDIP_SDK_MANAGED_APP_ID,
        process.env.QDIP_SDK_MANAGED_CLIENT_ID,'sdk-managed-qa'],
      ['EXTERNAL',process.env.QDIP_SDK_EXTERNAL_APP_ID,
        process.env.QDIP_SDK_EXTERNAL_CLIENT_ID,'sdk-external-qa']]){
      const app=await readRpc(ctx.request,
        '/zitadel.application.v2.ApplicationService/GetApplication',
        token,{applicationId:id},label+'_APP');
      check(appOk(app,p,id,client,name),label+'_APP_ID_PROJECT_CLIENT');
      const oidc=app?.application?.oidcConfiguration;
      const grants=Array.isArray(oidc?.grantTypes)?oidc.grantTypes:[];
      const responseTypes=Array.isArray(oidc?.responseTypes)?oidc.responseTypes:[];
      const redirects=Array.isArray(oidc?.redirectUris)?oidc.redirectUris:[];
      const hasAuthCode=grants.includes('OIDC_GRANT_TYPE_AUTHORIZATION_CODE');
      const hasCodeResponse=responseTypes.includes('OIDC_RESPONSE_TYPE_CODE');
      const validRedirects=redirects.length>0&&redirects.every(x=>{
        try{const u=new URL(x);return u.protocol==='https:'||
          (u.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(u.hostname));}
        catch{return false;}
      });
      console.log('SDK649_'+label+'_AUTH_CODE_GRANT='+(hasAuthCode?'CONFIGURED':'NOT_CONFIGURED'));
      console.log('SDK649_'+label+'_CODE_RESPONSE='+(hasCodeResponse?'CONFIGURED':'NOT_CONFIGURED'));
      console.log('SDK649_'+label+'_REGISTERED_REDIRECT_COUNT='+redirects.length);
      console.log('SDK649_'+label+'_QA_PKCE_CALLBACK='+
        (redirects.includes(CALLBACK_URI)?'REGISTERED':'MISSING'));
      if(redirects.includes(CALLBACK_URI))readyPkce.push({label,client});
      console.log('SDK649_'+label+'_REDIRECTS_HTTPS_OR_LOOPBACK='+(validRedirects?'YES':'NO'));
      console.log('SDK649_'+label+'_AUTH_METHOD_TYPE='+
        (/^OIDC_AUTH_METHOD_TYPE_[A-Z_]+$/.test(oidc?.authMethodType||'')?
          oidc.authMethodType:'NOT_REPORTED'));
      console.log('SDK649_'+label+'_OIDC_APP_TYPE='+
        (/^OIDC_APP_TYPE_[A-Z_]+$/.test(oidc?.appType||'')?
          oidc.appType:'NOT_REPORTED'));
    }
    const project=await readRpc(ctx.request,
      '/zitadel.project.v2.ProjectService/GetProject',token,{projectId:p},'QA_PROJECT');
    check(projectOk(project,p),'QA_PROJECT_ACTIVE_ORG');
    const owners=await readRpc(ctx.request,
      '/zitadel.internal_permission.v2.InternalPermissionService/ListAdministrators',
      token,{pagination:{offset:0,limit:100},filters:[
        {resource:{projectId:p}},{inUserIdsFilter:{ids:[sub]}},{role:{roleKey:'PROJECT_OWNER'}}]},
      'QA_OWNER');
    check(ownerOk(owners,p,sub),'QA21_EXACT_PROJECT_OWNER');
    // Inspect only the exact QA project. An API application is a candidate
    // resource-server client, not proof that Basic introspection is enabled.
    const catalog=await readRpc(ctx.request,
      '/zitadel.application.v2.ApplicationService/ListApplications',token,
      {pagination:{limit:100},filters:[{projectIdFilter:{projectId:p}}]},
      'QA_PROJECT_CATALOG');
    const rows=catalog?.applications??[];
    const pagination=catalog?.pagination;
    const reported=pagination?.totalResult;
    check(Array.isArray(rows)&&!!pagination&&rows.length<=100&&
      rows.every(a=>a?.projectId===p)&&
      (reported===undefined?rows.length===0:
        Number.isInteger(Number(reported))&&Number(reported)===rows.length),
      'QA_PROJECT_CATALOG_COMPLETE');
    const apis=rows.filter(a=>a?.state==='APPLICATION_STATE_ACTIVE'&&
      a?.apiConfiguration&&typeof a.apiConfiguration==='object');
    await proveCoreRejectsMissingOrForgedSdkKey(ctx.request,
      process.env.QDIP_SDK_MANAGED_APP_ID,'MANAGED');
    await proveCoreRejectsMissingOrForgedSdkKey(ctx.request,
      process.env.QDIP_SDK_EXTERNAL_APP_ID,'EXTERNAL');
    console.log('SDK649_QA_PROJECT_ACTIVE_API_APP_COUNT='+apis.length);
    // APIAuthMethodType proto enum value 0 is BASIC; ProtoJSON omits zero values.
    // Prove the exact active API application using a second read, not a bare list row.
    check(apis.length===1,'QA_PROJECT_EXACTLY_ONE_ACTIVE_API_APP');
    const apiFull=await readRpc(ctx.request,
      '/zitadel.application.v2.ApplicationService/GetApplication',token,
      {applicationId:apis[0].applicationId},'QA_INTROSPECTION_APP');
    const apiApp=apiFull?.application;
    check(apiApp?.applicationId===apis[0].applicationId&&
      apiApp?.projectId===p&&apiApp?.state==='APPLICATION_STATE_ACTIVE'&&
      apiApp?.name==='qdip-sdk-qa-introspection'&&
      typeof apiApp?.apiConfiguration?.clientId==='string'&&
      apiApp.apiConfiguration.clientId.length>0,
      'QA_INTROSPECTION_APP_EXACT_PROJECT_AND_CLIENT');
    const apiMethod=apiApp.apiConfiguration.authMethodType??
      'API_AUTH_METHOD_TYPE_BASIC';
    check(apiMethod==='API_AUTH_METHOD_TYPE_BASIC','QA_INTROSPECTION_API_BASIC');
    if(readyPkce.length===2){
      for(const app of readyPkce)
        await verifyPkce(ctx,app.client,app.label,p,sub);
      console.log('SDK649_QA_BOTH_PKCE_USER_TOKENS=PASS');
    }else console.log('SDK649_QA_BOTH_PKCE_USER_TOKENS=BLOCKED_UNREGISTERED_CALLBACK');
    console.log('SDK649_INTROSPECTION_CLIENT_SECRET_MATCH=NOT_VERIFIED');
    console.log('SDK649_INTROSPECTION_BASIC_AUTH=NOT_VERIFIED');
    console.log('SDK649_ZITADEL_READONLY_OWNER_PREFLIGHT=PASS');
    console.log('SDK649_CANONICAL_BINDING=NOT_VERIFIED');
  }finally{token=null;await ctx.close();await b.close();}
}
if(process.argv[2]==='--self-test')selfTest().catch(()=>{process.exitCode=1;});
else run().catch(e=>{const stage=e instanceof Error&&/^[A-Z0-9_]{4,100}$/.test(e.message)
  ?e.message:'SANITIZED_FAILURE';
  console.error('SDK649_ZITADEL_READONLY_OWNER_PREFLIGHT=FAIL_'+stage);
  process.exitCode=1;});

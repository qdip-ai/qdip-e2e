import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createHash, randomBytes} from 'node:crypto';
import {chromium} from '@playwright/test';
import {validateQaApplicationVariables} from './sdk649_qa_app_vars.mjs';
const SITE='https://qdip.ai', ISSUER='https://mentality-rmwj0i.eu1.zitadel.cloud';
const ORG='397885387160184113', USER='qa-21@qdip.ai';
const CALLBACK_URI='http://127.0.0.1:8765/oidc/callback';
const STAGING_CORE='https://qdip-core-staging-staging.up.railway.app';
const THIRD_APP_ID='398580544880887772'; // verified QA-only Zitadel app
const THIRD_CLIENT_ID='398580544897664988';
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
function orgOwnerOk(x,sub){const a=x?.administrators,m=x?.pagination??x?.details;
  return Array.isArray(a)&&a.length>0&&a.length<=100&&
    m?.totalResult!==undefined&&Number(m.totalResult)===a.length&&
    a.some(o=>{const r=o?.organization;
      const org=typeof r==='string'?r:
        r&&typeof r==='object'?(r.organizationId??r.id):o?.organizationId;
      return o?.instance!==true&&o?.user?.id===sub&&
        Array.isArray(o?.roles)&&o.roles.includes('ORG_OWNER')&&
        (org===undefined||org===ORG);
    });}
function exactActiveIntrospectionApps(rows){return rows.filter(a=>
  a?.state==='APPLICATION_STATE_ACTIVE'&&
  a?.name==='qdip-sdk-qa-introspection'&&
  a?.apiConfiguration&&typeof a.apiConfiguration==='object');}
function validScopedQaKeys(keys){
  return Array.isArray(keys)&&keys.length===5&&new Set(keys).size===5&&
    keys.every(k=>typeof k==='string'&&k.length>=16&&
      !/[\s\x00-\x1f\x7f]/u.test(k));
}
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
    return accessToken;
  }finally{
    accessToken=null;
    await page.close();
    await local.close();
  }
}
const QA_OIDC_AUDIENCE='qdip-sdk649-qa-caller-v1';
async function githubQaWorkloadJwt(){
  const url=process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken=process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if(typeof url!=='string'||typeof requestToken!=='string'||
     requestToken.length<20)throw Error('QA_GITHUB_OIDC_MISSING');
  let target;
  try{target=new URL(url);}catch{throw Error('QA_GITHUB_OIDC_URL_INVALID');}
  if(target.protocol!=='https:'||
     !target.hostname.endsWith('.actions.githubusercontent.com')||
     target.username||target.password)throw Error('QA_GITHUB_OIDC_URL_INVALID');
  target.searchParams.set('audience',QA_OIDC_AUDIENCE);
  let result;
  try{result=await fetch(target,{
    headers:{Authorization:'Bearer '+requestToken,Accept:'application/json'},
    redirect:'error',signal:AbortSignal.timeout(12000),
  });}catch{throw Error('QA_GITHUB_OIDC_FETCH_FAILED');}
  if(!result.ok)throw Error('QA_GITHUB_OIDC_DENIED');
  const data=await result.json().catch(()=>null);
  if(typeof data?.value!=='string'||data.value.length<50||data.value.length>8192)
    throw Error('QA_GITHUB_OIDC_MALFORMED');
  return data.value;
}
async function coreQaKeys(verifiedOwnerAccessToken){
  // The user token is already proven through browser PKCE/userinfo.
  // Core independently introspects it and requires live ORG_OWNER before
  // projecting the existing Zitadel organization. PROJECT_OWNER alone fails.
  if(typeof verifiedOwnerAccessToken!=='string'||
     verifiedOwnerAccessToken.length<16||
     /[\s\x00-\x1f\x7f]/u.test(verifiedOwnerAccessToken))
    throw Error('QA_ZITADEL_OWNER_TOKEN_MISSING');
  const identity=await githubQaWorkloadJwt();
  const url=STAGING_CORE+'/api/v1/sdk/qa/oidc-credentials';
  const result=await fetch(url,{
    method:'POST',headers:{
      Authorization:'Bearer '+identity,
      'x-zitadel-access-token':verifiedOwnerAccessToken,
    },redirect:'error',signal:AbortSignal.timeout(20000),
  }).catch(()=>{throw Error('QA_CORE_OIDC_EXCHANGE_UNAVAILABLE');});
  if(result.status!==201)throw Error('QA_CORE_OIDC_EXCHANGE_DENIED');
  const body=await result.json().catch(()=>null);
  const keys=[body?.managed_key,body?.external_key,
    body?.source_key,body?.destination_key,body?.third_key];
  check(validScopedQaKeys(keys),'DISTINCT_SCOPED_KEY_REFERENCE_SHAPE');
  const expiry=Date.parse(body?.expires_at);
  check(Number.isFinite(expiry)&&expiry>Date.now()&&
    expiry<=Date.now()+11*60*1000,'QA_SCOPED_KEYS_SHORT_TTL');
  return keys;
}
async function revokeCoreQaKeys(){
  const identity=await githubQaWorkloadJwt();
  const response=await fetch(STAGING_CORE+'/api/v1/sdk/qa/oidc-credentials/revoke',{
    method:'POST',headers:{Authorization:'Bearer '+identity},redirect:'error',
    signal:AbortSignal.timeout(20000),
  }).catch(()=>{throw Error('QA_CORE_OIDC_REVOKE_UNAVAILABLE');});
  check(response.status===204,'QA_CORE_OIDC_KEYS_REVOKED');
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
  const orgRow={user:{id:s},organization:{id:ORG},roles:['ORG_OWNER']};
  assert(orgOwnerOk({administrators:[orgRow],pagination:{totalResult:1}},s));
  assert(!orgOwnerOk({administrators:[{...orgRow,roles:['PROJECT_OWNER']}],
    pagination:{totalResult:1}},s));
  assert(!orgOwnerOk({administrators:[{...orgRow,organization:{id:'wrong-org'}}],
    pagination:{totalResult:1}},s));
  assert(!orgOwnerOk({administrators:[orgRow],pagination:{totalResult:2}},s));
  assert(!orgOwnerOk({administrators:[{...orgRow,instance:true}],
    pagination:{totalResult:1}},s));
  assert(!orgOwnerOk({pagination:{appliedLimit:100}},s));
  console.log('SDK649_ORG_OWNER_PROOF_NEGATIVE_REGRESSIONS=PASS');

  const targetApi={applicationId:'333333333333333333',
    name:'qdip-sdk-qa-introspection',state:'APPLICATION_STATE_ACTIVE',
    apiConfiguration:{clientId:'qa-api-client'}};
  const unrelatedApi={...targetApi,applicationId:'444444444444444444',name:'other-api'};
  assert.deepEqual(exactActiveIntrospectionApps([targetApi,unrelatedApi]),[targetApi]);
  assert.equal(exactActiveIntrospectionApps([unrelatedApi]).length,0);
  assert.equal(exactActiveIntrospectionApps([targetApi,{...targetApi}]).length,2);
  console.log('SDK649_EXACT_INTROSPECTION_UNIQUENESS_REGRESSIONS=PASS');

  const local=await openCallback('test-state-123');
  try{
    assert.equal((await fetch(CALLBACK_URI+'?state=wrong&code=code-sample-1234')).status,400);
    assert.equal((await fetch('http://127.0.0.1:8765/other')).status,404);
    assert.equal((await fetch(CALLBACK_URI+'?state=test-state-123&code=code-sample-1234')).status,200);
    assert.equal(await local.code,'code-sample-1234');
    assert.equal((await fetch(CALLBACK_URI+'?state=test-state-123&code=replay-code-1234')).status,400);
  }finally{await local.close();}
  console.log('SDK649_PKCE_LOOPBACK_NEGATIVE_REGRESSIONS=PASS');
  assert(validScopedQaKeys(['scoped-key-qa-001','scoped-key-qa-002',
    'scoped-key-qa-003','scoped-key-qa-004','scoped-key-qa-005']));
  assert(!validScopedQaKeys(['scoped-key-qa-001','scoped-key-qa-002',
    'scoped-key-qa-003','scoped-key-qa-004','scoped-key-qa-004']));
  assert(!validScopedQaKeys(['scoped-key-qa-001','scoped-key-qa-002',
    'scoped-key-qa-003','scoped-key-qa-004']));
  assert(!validScopedQaKeys(['scoped key-qa-001','scoped-key-qa-002']));
  assert(!validScopedQaKeys(['','scoped-key-qa-002']));
  console.log('SDK649_SCOPED_KEY_NEGATIVE_REGRESSIONS=PASS');
  // The exact QA job must never downgrade to a missing-OIDC soft skip.
  const savedUrl=process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const savedToken=process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  try{
    await assert.rejects(githubQaWorkloadJwt(),/QA_GITHUB_OIDC_MISSING/);
  }finally{
    if(savedUrl===undefined)delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
    else process.env.ACTIONS_ID_TOKEN_REQUEST_URL=savedUrl;
    if(savedToken===undefined)delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    else process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN=savedToken;
  }
  console.log('SDK649_GITHUB_OIDC_MISSING_DENIED=PASS');
  await assert.rejects(coreQaKeys(''),/QA_ZITADEL_OWNER_TOKEN_MISSING/);
  await assert.rejects(coreQaKeys('invalid token value'),/QA_ZITADEL_OWNER_TOKEN_MISSING/);
  console.log('SDK649_ORG_OWNER_TOKEN_REQUIRED=PASS');
}
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
      if(redirects.includes(CALLBACK_URI))readyPkce.push({label,client,appId:id});
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
    const orgOwners=await readRpc(ctx.request,
      '/zitadel.internal_permission.v2.InternalPermissionService/ListAdministrators',
      token,{pagination:{offset:0,limit:100},filters:[
        {resource:{organizationId:ORG}},{inUserIdsFilter:{ids:[sub]}},
        {role:{roleKey:'ORG_OWNER'}}]},
      'QA_ORG_OWNER');
    check(orgOwnerOk(orgOwners,sub),'QA21_EXACT_ORG_OWNER');

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
    const thirdApp=await readRpc(ctx.request,
      '/zitadel.application.v2.ApplicationService/GetApplication',token,
      {applicationId:THIRD_APP_ID},'THIRD_APP');
    check(appOk(thirdApp,p,THIRD_APP_ID,THIRD_CLIENT_ID,
      'sdk555-e2e-unrelated-qa'),'THIRD_APP_EXACT_ACTIVE_IDENTITY');
    check(thirdApp.application.oidcConfiguration?.redirectUris?.includes(CALLBACK_URI),
      'THIRD_APP_REAL_PKCE_CALLBACK');
    await proveCoreRejectsMissingOrForgedSdkKey(ctx.request,
      process.env.QDIP_SDK_MANAGED_APP_ID,'MANAGED');
    await proveCoreRejectsMissingOrForgedSdkKey(ctx.request,
      process.env.QDIP_SDK_EXTERNAL_APP_ID,'EXTERNAL');
    console.log('SDK649_QA_PROJECT_ACTIVE_API_APP_COUNT='+apis.length);
    // APIAuthMethodType proto enum value 0 is BASIC; ProtoJSON omits zero values.
    // Prove the exact active API application using a second read, not a bare list row.
    const introspections=exactActiveIntrospectionApps(apis);
    check(introspections.length===1,'QA_PROJECT_EXACTLY_ONE_ACTIVE_INTROSPECTION_APP');
    const apiFull=await readRpc(ctx.request,
      '/zitadel.application.v2.ApplicationService/GetApplication',token,
      {applicationId:introspections[0].applicationId},'QA_INTROSPECTION_APP');
    const apiApp=apiFull?.application;
    check(apiApp?.applicationId===introspections[0].applicationId&&
      apiApp?.projectId===p&&apiApp?.state==='APPLICATION_STATE_ACTIVE'&&
      apiApp?.name==='qdip-sdk-qa-introspection'&&
      typeof apiApp?.apiConfiguration?.clientId==='string'&&
      apiApp.apiConfiguration.clientId.length>0,
      'QA_INTROSPECTION_APP_EXACT_PROJECT_AND_CLIENT');
    const apiMethod=apiApp.apiConfiguration.authMethodType??
      'API_AUTH_METHOD_TYPE_BASIC';
    check(apiMethod==='API_AUTH_METHOD_TYPE_BASIC','QA_INTROSPECTION_API_BASIC');
    if(readyPkce.length===2){
      let tokens=[];
      let thirdToken=null;
      try{
        for(const app of readyPkce)
          tokens.push(await verifyPkce(ctx,app.client,app.label,p,sub));
        console.log('SDK649_QA_BOTH_PKCE_USER_TOKENS=PASS');
        thirdToken=await verifyPkce(ctx,THIRD_CLIENT_ID,'THIRD',p,sub);
        console.log('SDK555_THIRD_APP_REAL_QA21_PKCE=PASS');
        let qaKeys=[];
        let issued=false;
        try{
          qaKeys=await coreQaKeys(tokens[0]);
          issued=true;
          for(let i=0;i<2;i++){
            const app=readyPkce[i];
            const r=await ctx.request.post(
              STAGING_CORE+'/api/v1/private-resource-access/applications/link',{
                data:{application_id:app.appId},timeout:20000,maxRedirects:0,
                headers:{'x-api-key':qaKeys[i],Authorization:'Bearer '+tokens[i]},
              });
            check(r.status()===204,app.label+'_CORE_LINK_HTTP_204');
          }
          const thirdLink=await ctx.request.post(
            STAGING_CORE+'/api/v1/private-resource-access/applications/link',{
              data:{application_id:THIRD_APP_ID},timeout:20000,maxRedirects:0,
              headers:{'x-api-key':qaKeys[4],Authorization:'Bearer '+thirdToken},
            });
          check(thirdLink.status()===204,'THIRD_APP_CORE_LINK_HTTP_204');
          for(let i=0;i<2;i++){
            const j=1-i;
            const r=await ctx.request.post(
              STAGING_CORE+'/api/v1/private-resource-access/applications/link',{
                data:{application_id:readyPkce[i].appId},timeout:20000,
                maxRedirects:0,
                headers:{'x-api-key':qaKeys[i],Authorization:'Bearer '+tokens[j]},
              });
            check(r.status()===403,
              readyPkce[i].label+'_CROSS_APP_TOKEN_DENIED_403');
          }
          for(const mismatch of tokens){
            const wrong=await ctx.request.post(
              STAGING_CORE+'/api/v1/private-resource-access/applications/link',{
                data:{application_id:THIRD_APP_ID},timeout:20000,maxRedirects:0,
                headers:{'x-api-key':qaKeys[4],Authorization:'Bearer '+mismatch},
              });
            check(wrong.status()===403,'THIRD_APP_WRONG_CLIENT_DENIED_403');
          }
          console.log('SDK555_QA_CORE_CANONICAL_LINK=PASS_THREE_204');
          // Authoritative read-only Mongo query, separate from link_application.
          // The signed job and BOTH real PKCE tokens must match the stored
          // application/issuer/project/owner/client tuple. No row contents leak.
          const readbackHeaders={
            Authorization:'Bearer '+await githubQaWorkloadJwt(),
            'content-type':'application/json',
            'x-zitadel-managed-token':tokens[0],
            'x-zitadel-external-token':tokens[1],
            'x-zitadel-third-token':thirdToken,
          };
          const readbackUrl=STAGING_CORE+'/api/v1/sdk/qa/mongo-owners/readback';
          const readbackBody=JSON.stringify({
            managed_application_id:readyPkce[0].appId,
            external_application_id:readyPkce[1].appId,
            third_application_id:THIRD_APP_ID,
          });
          const receipt=await fetch(readbackUrl,{
            method:'POST',headers:readbackHeaders,body:readbackBody,
            redirect:'error',signal:AbortSignal.timeout(20000),
          });
          check(receipt.status===204,'QA_MONGO_OWNER_READBACK_HTTP_204');
          const swapped=await fetch(readbackUrl,{
            method:'POST',headers:{...readbackHeaders,
              'x-zitadel-managed-token':tokens[1],
              'x-zitadel-external-token':tokens[0],
            },body:readbackBody,redirect:'error',
            signal:AbortSignal.timeout(20000),
          });
          check(swapped.status===403,'QA_MONGO_SWAPPED_OWNER_TOKENS_DENIED_403');
          console.log('SDK649_QA_MONGO_READBACK=PASS_DIRECT_STAGING_DB');
          // The real grant API is exercised after creating only an isolated,
          // nonpersonal metadata fixture through the signed staging QA path.
          // Neither owner approval nor user consent is injected into Mongo.
          const qaIdentity='Bearer '+await githubQaWorkloadJwt();
          const fixtureUrl=STAGING_CORE+'/api/v1/sdk/qa/private-resource/fixture';
          const fixtureHeaders={
            Authorization:qaIdentity,
            'x-zitadel-managed-token':tokens[0],
          };
          const fixture=await fetch(fixtureUrl,{
            method:'POST',headers:fixtureHeaders,redirect:'error',
            signal:AbortSignal.timeout(20000),
          });
          check(fixture.status===201,'QA_PRIVATE_FIXTURE_HTTP_201');
          const fixturePayload=await fixture.json().catch(()=>null);
          const resourceId=fixturePayload?.resource_id;
          check(typeof resourceId==='string'&&
            /^sdk649-qa-[0-9]+-[0-9]+$/.test(resourceId),
            'QA_PRIVATE_FIXTURE_RUN_BOUND');
          try{
            const grantPath=STAGING_CORE+'/api/v1/private-resource-access/grants/';
            const checkUrl=STAGING_CORE+'/api/v1/private-resource-access/check';
            const projection='calendar.events.read';
            const purpose='sdk649_qa_decision_support';
            const checkBody={
              resource_id:resourceId,projection,purpose,
              requested_fields:['event_id','start'],
            };
            const grantBody={
              ...checkBody,destination_plugin_id:'sdk-external-qa',
              ttl_seconds:300,
            };
            const sourceHeaders={
              'x-api-key':qaKeys[2],Authorization:'Bearer '+tokens[0],
            };
            const destinationHeaders={
              'x-api-key':qaKeys[3],Authorization:'Bearer '+tokens[1],
            };
            const before=await ctx.request.post(checkUrl,{
              data:checkBody,headers:destinationHeaders,timeout:20000,maxRedirects:0,
            });
            check(before.status()===403,'QA_PRIVATE_NO_GRANTS_DENIED_403');
            const approved=await ctx.request.post(grantPath+'source',{
              data:grantBody,headers:sourceHeaders,timeout:20000,maxRedirects:0,
            });
            check(approved.status()===204,'QA_PRIVATE_SOURCE_OWNER_APPROVAL_204');
            const beforeConsent=await ctx.request.post(checkUrl,{
              data:checkBody,headers:destinationHeaders,timeout:20000,maxRedirects:0,
            });
            check(beforeConsent.status()===403,'QA_PRIVATE_WITHOUT_USER_CONSENT_DENIED_403');
            const consent=await ctx.request.post(grantPath+'consent',{
              data:grantBody,headers:sourceHeaders,timeout:20000,maxRedirects:0,
            });
            check(consent.status()===204,'QA_PRIVATE_USER_CONSENT_204');
            const allowed=await ctx.request.post(checkUrl,{
              data:checkBody,headers:destinationHeaders,timeout:20000,maxRedirects:0,
            });
            check(allowed.status()===204,'QA_PRIVATE_BOTH_GRANTS_HTTP_204');
            const deniedThird=await ctx.request.post(checkUrl,{
              data:checkBody,
              headers:{'x-api-key':qaKeys[4],Authorization:'Bearer '+thirdToken},
              timeout:20000,maxRedirects:0,
            });
            check(deniedThird.status()===403,'QA_PRIVATE_APP_C_GRANT_BLEED_DENIED_403');
            // Hard merge gate: the actual approved external SDK Worker must run.
            // A passing grant/check endpoint or an unapproved REGISTER is not
            // evidence of a Worker result. Do not soft-skip missing workers.
            const resultRequest={
              input:{event_id:'sdk649-e2e-event',start:'2026-11-07T09:00:00Z'},
              capability_version:'1',
              timeout_seconds:10,
              private_projection:{
                resource_id:resourceId,projection,purpose,
                requested_fields:['event_id','start'],
              },
            };
            const evalUrl=STAGING_CORE+'/api/v1/remote-plugins/calendar.events.read/evaluate';
            const evaluated=await ctx.request.post(evalUrl,{
              data:resultRequest,headers:destinationHeaders,
              timeout:20000,maxRedirects:0,
            });
            if(evaluated.status()!==200){
              const detail=(await evaluated.json().catch(()=>null))?.detail;
              const known=new Set([
                'Capability not authorized',
                'Private projection authorization denied',
                'Private projection authorization revoked',
                'Private projection authorization required',
                'Private projection fields not authorized',
                'Caller credential revoked or changed',
                'Worker credential revoked or changed',
                'Application binding denied',
                'remote capability unavailable',
                'remote Worker not approved',
                'worker authorization storage unavailable',
              ]);
              console.log('SDK649_QA_PRIVATE_WORKER_DENIAL_HTTP='+evaluated.status());
              const safeDetail=typeof detail==='string'&&
                /^[A-Za-z][A-Za-z ]{0,110}$/.test(detail)?detail:'REDACTED';
              console.log('SDK649_QA_PRIVATE_WORKER_DENIAL_CLASS='+
                (known.has(detail)?detail:safeDetail));
            }
            check(evaluated.status()===200,'QA_PRIVATE_WORKER_EVALUATE_HTTP_200');
            const decision=await evaluated.json().catch(()=>null);
            check(decision?.output_type==='structured_result'&&
              decision?.execution_state==='REPORTED'&&
              decision?.registered_worker?.plugin_id==='sdk-external-qa'&&
              decision?.result?.event_id==='sdk649-e2e-event'&&
              decision?.result?.start==='2026-11-07T09:00:00Z'&&
              decision?.result?.accepted===true&&
              Object.keys(decision?.result??{}).sort().join(',')==='accepted,event_id,start'&&
              decision?.verification==='NOT_INDEPENDENTLY_VERIFIED',
              'QA_PRIVATE_WORKER_MINIMAL_STRUCTURED_RESULT');

            const excess=await ctx.request.post(checkUrl,{
              data:{...checkBody,requested_fields:['event_id','start','title']},
              headers:destinationHeaders,timeout:20000,maxRedirects:0,
            });
            check(excess.status()===403,'QA_PRIVATE_UNDECLARED_FIELD_DENIED_403');
            const revoke=await ctx.request.delete(grantPath+'consent',{
              data:{
                resource_id:resourceId,destination_plugin_id:'sdk-external-qa',
                projection,purpose,
              },headers:sourceHeaders,timeout:20000,maxRedirects:0,
            });
            check(revoke.status()===204,'QA_PRIVATE_CONSENT_REVOKED_204');
            const afterRevoke=await ctx.request.post(checkUrl,{
              data:checkBody,headers:destinationHeaders,timeout:20000,maxRedirects:0,
            });
            check(afterRevoke.status()===403,'QA_PRIVATE_AFTER_REVOKE_DENIED_403');
            const revokedEval=await ctx.request.post(evalUrl,{
              data:resultRequest,headers:destinationHeaders,
              timeout:20000,maxRedirects:0,
            });
            check(revokedEval.status()===403,'QA_PRIVATE_WORKER_AFTER_REVOKE_DENIED_403');

            console.log('SDK649_QA_PRIVATE_CONSENT_GATE=PASS_LIVE_MONGO_API');
          }finally{
            const cleanup=await fetch(fixtureUrl,{
              method:'DELETE',headers:fixtureHeaders,redirect:'error',
              signal:AbortSignal.timeout(20000),
            });
            check(cleanup.status===204,'QA_PRIVATE_FIXTURE_CLEANUP_204');
          }
          console.log('SDK555_CANONICAL_BINDING=PASS_THREE_204');
        }finally{
          try{if(issued)await revokeCoreQaKeys();}
          finally{qaKeys.fill(null);qaKeys=[];}
        }
      }finally{tokens.fill(null);tokens=[];thirdToken=null;}
    }else console.log('SDK649_QA_BOTH_PKCE_USER_TOKENS=BLOCKED_UNREGISTERED_CALLBACK');
    console.log('SDK649_INTROSPECTION_CLIENT_SECRET_MATCH=NOT_VERIFIED');
    console.log('SDK649_INTROSPECTION_BASIC_AUTH=NOT_VERIFIED');
    console.log('SDK649_ZITADEL_READONLY_OWNER_PREFLIGHT=PASS');
    // Positive canonical binding is mandatory for this trusted push job.
  }finally{token=null;await ctx.close();await b.close();}
}
if(process.argv[2]==='--self-test')selfTest().catch(()=>{process.exitCode=1;});
else run().catch(e=>{const stage=e instanceof Error&&/^[A-Z0-9_]{4,100}$/.test(e.message)
  ?e.message:'SANITIZED_FAILURE';
  console.error('SDK649_ZITADEL_READONLY_OWNER_PREFLIGHT=FAIL_'+stage);
  process.exitCode=1;});

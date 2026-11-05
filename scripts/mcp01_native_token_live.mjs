/** Real owner-only Native-client PKCE probe. Not MCP/Worker acceptance.
 * Reuses QA21 login/Console read pattern independently qualified by E2E PR141.
 * All credentials, codes, tokens and claim values remain in process memory.
 * No screenshots, traces, videos, response bodies or auth URLs are persisted.
 * Explicit QA setup mode may add ONE fixed loopback callback to an empty managed Native app; no identity or scope changes.
 */
import {chromium} from '@playwright/test';
import {createHash,randomBytes} from 'node:crypto';
import {createServer} from 'node:http';
import {isDeepStrictEqual} from 'node:util';
import assert from 'node:assert/strict';
import {createRemoteJWKSet,jwtVerify} from 'jose';

const SITE='https://qdip.ai';
const ISSUER='https://mentality-rmwj0i.eu1.zitadel.cloud';
const MCP='https://qdip-mcp-sandbox.up.railway.app/mcp';
const USER='qa-21@qdip.ai';
const marker=(key,value)=>console.log('MCP01_'+key+'='+value);
function check(ok,stage){marker(stage,ok?'PASS':'FAIL');if(!ok)throw Error(stage);}
function originUrl(value){const u=new URL(value);if(u.origin!==ISSUER||u.protocol!=='https:'||u.username||u.password)throw Error('UNTRUSTED_ISSUER_ENDPOINT');return u;}
async function json(response,stage){check(response.status()===200,stage+'_HTTP_200');
 const body=await response.body();check(body.length<=131072,stage+'_BOUNDED');
 try{return JSON.parse(body.toString('utf8'));}catch{throw Error(stage+'_JSON');}}
async function visible(page,selectors,ms=14000){const end=Date.now()+ms;
 while(Date.now()<end){for(const selector of selectors){const n=page.locator(selector).first();if(await n.isVisible().catch(()=>false))return n;}await page.waitForTimeout(250);}return null;}
function callbackMatches(actual,target){return actual.origin===target.origin&&actual.pathname===target.pathname&&
 [...target.searchParams].every(([k,v])=>actual.searchParams.get(k)===v);}

// These are provider-generated read-only fields, not UpdateApplication settings.
function mutableOidc(config){const {nonCompliant,complianceProblems,allowedOrigins,...settings}=config;return settings;}
function sameOtherSettings(before,after){return isDeepStrictEqual({...mutableOidc(before),redirectUris:[]},{...mutableOidc(after),redirectUris:[]});}
function selfTest(){
 const before={clientId:'fixture',redirectUris:[],grantTypes:['code'],authMethodType:'none',allowedOrigins:[],nonCompliant:true,complianceProblems:['missing redirect']};
 const after={...before,redirectUris:['http://127.0.0.1:8765/mcp01/callback'],allowedOrigins:['http://127.0.0.1:8765'],nonCompliant:false,complianceProblems:[]};
 assert(sameOtherSettings(before,after));
 for(const changed of [{grantTypes:['implicit']},{authMethodType:'basic'},{clientId:'foreign'}])assert(!sameOtherSettings(before,{...after,...changed}));
 marker('OIDC_MUTABLE_SETTINGS_REGRESSION','PASS');
 assert(noUnrelatedStagedPatch(null));
 assert(noUnrelatedStagedPatch({id:'empty-patch',status:'STAGED',patch:{}}));
 assert(!noUnrelatedStagedPatch({id:'foreign',status:'STAGED',patch:{services:{other:{}}}}));
 assert(!noUnrelatedStagedPatch({id:'applying',status:'APPLYING',patch:{}}));
 assert(!noUnrelatedStagedPatch({id:'unknown',status:'STAGED'}));
 marker('MCP_EMPTY_STAGED_PATCH_REGRESSION','PASS');
}

async function nativeFlow(ctx,metadata,app,subject,mode,onAccess){
 const verifier=randomBytes(32).toString('base64url'),state=randomBytes(24).toString('base64url');
 const nonce=randomBytes(24).toString('base64url');
 const redirect=app.redirect;
 const authorize=originUrl(metadata.authorization_endpoint);
 const scope=['openid','profile',`urn:zitadel:iam:org:project:id:${app.project}:aud`];
 if(mode==='MCP_RESOURCE')scope.push('mcp:use');
 for(const [k,v] of Object.entries({client_id:app.client,response_type:'code',redirect_uri:redirect.href,
   scope:scope.join(' '),state,nonce,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'}))authorize.searchParams.set(k,v);
 if(mode==='MCP_RESOURCE')authorize.searchParams.set('resource',MCP);
 let callback,issuedAccess=null;
 // Real Native-app callback listener. Browser routing is not a loopback server.
 check(redirect.protocol==='http:'&&redirect.hostname==='127.0.0.1'&&redirect.port==='8765'&&
   ['/mcp01/callback','/oidc/callback'].includes(redirect.pathname),mode+'_APPROVED_LOOPBACK_CALLBACK');
 const listener=createServer((req,res)=>{
   const raw=req.url??'';
   if(raw.length>8192||req.method!=='GET'||req.headers.host!==redirect.host){res.writeHead(400);res.end();return;}
   const url=new URL(raw,redirect.origin);
   if(!callbackMatches(url,redirect)||url.searchParams.get('state')!==state||callback){res.writeHead(400);res.end();return;}
   callback=url;res.writeHead(200,{'Content-Type':'text/plain','Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'"});
   res.end('QA OAuth callback received. You may close this page.');
 });
 await new Promise((resolve,reject)=>{listener.once('error',()=>reject(Error('LOOPBACK_BIND_FAILED')));listener.listen(8765,'127.0.0.1',resolve);});
 marker(mode+'_REAL_LOOPBACK_LISTENER','PASS');
 const page=await ctx.newPage();
 page.on('requestfailed',request=>{if(!request.isNavigationRequest())return;
   const code=String(request.failure()?.errorText??'').match(/(?:net::)?(ERR_[A-Z_]+)/)?.[1];
   marker(mode+'_FAILED_NAVIGATION',code??'OTHER');
   try{const u=new URL(request.url());marker(mode+'_FAILED_NAVIGATION_IS_CALLBACK',callbackMatches(u,redirect));
     marker(mode+'_FAILED_NAVIGATION_IS_ISSUER',u.origin===ISSUER);}catch{}
 });
 try {
   // Use the existing registered callback and a listening Native client on the same runner.
   let navigation;
   try{navigation=await page.goto(authorize.href,{waitUntil:'domcontentloaded',timeout:30000});}
   catch(error){const code=String(error?.message??'').match(/net::(ERR_[A-Z_]+)/)?.[1];
     marker(mode+'_NAVIGATION_ERROR',code??(error?.name==='TimeoutError'?'TIMEOUT':'OTHER'));}
   marker(mode+'_AUTHORIZATION_HTTP',navigation?.status()??'NO_RESPONSE');
   const end=Date.now()+15000;while(!callback&&Date.now()<end)await page.waitForTimeout(250);
   if(!callback){
     // Classify only known UI states; never persist page text, URLs or hrefs containing codes.
     const text=(await page.locator('body').innerText().catch(()=>'' )).toLowerCase();
     const current=new URL(page.url());
     marker(mode+'_ISSUER_PAGE',current.origin===ISSUER);
     marker(mode+'_PAGE_SCHEME', ['http:','https:','about:','chrome-error:'].includes(current.protocol)?current.protocol.slice(0,-1):'OTHER');
     marker(mode+'_AT_REGISTERED_CALLBACK',callbackMatches(current,redirect));
     marker(mode+'_LOGIN_FORM_VISIBLE',await page.locator('input[autocomplete="username"],input[name="loginName"],input[type="password"]').first().isVisible().catch(()=>false));
     marker(mode+'_NATIVE_SUCCESS_UI',/success|close this|return to|back to|open.*app/.test(text));
     marker(mode+'_CONSENT_UI',/consent|authorize|allow access/.test(text));
     marker(mode+'_ACCESS_DENIED_UI',/access denied|not allowed|not authorized|permission denied|not permitted/.test(text));
     marker(mode+'_INVALID_REQUEST_UI',/invalid request|invalid redirect|invalid scope|request.*expired|internal error/.test(text));
     const callbackLink=await page.locator('a').evaluateAll((links,target)=>links.some(a=>{
       try{const u=new URL(a.href),t=new URL(target);return u.origin===t.origin&&u.pathname===t.pathname;}catch{return false;}
     }),redirect.href).catch(()=>false);
     marker(mode+'_REGISTERED_CALLBACK_LINK_PRESENT',callbackLink);
     marker(mode+'_CALLBACK','NOT_OBTAINED');return false;
   }
   check(callback.searchParams.get('state')===state,mode+'_STATE');
   if(callback.searchParams.has('error')){
     const allowed=new Set(['invalid_scope','invalid_target','unauthorized_client','invalid_request','access_denied','interaction_required','login_required','consent_required']);
     const error=callback.searchParams.get('error');marker(mode+'_AUTHORIZATION_ERROR',allowed.has(error)?error.toUpperCase():'OTHER');return false;
   }
   const code=callback.searchParams.get('code');check(typeof code==='string'&&code.length>12&&code.length<4096,mode+'_REAL_CODE');
   const response=await ctx.request.post(originUrl(metadata.token_endpoint).href,{timeout:15000,maxRedirects:0,
     headers:{'Content-Type':'application/x-www-form-urlencoded'},form:{grant_type:'authorization_code',code,
       client_id:app.client,redirect_uri:redirect.href,code_verifier:verifier}});
   if(response.status()!==200){marker(mode+'_TOKEN_EXCHANGE_HTTP',response.status());return false;}
   const payload=await json(response,mode+'_TOKEN');
   check(typeof payload.access_token==='string'&&payload.access_token.length>=32&&payload.access_token.length<=8192&&
     payload.token_type?.toLowerCase()==='bearer'&&Number.isFinite(payload.expires_in)&&payload.expires_in>0,mode+'_ACCESS_TOKEN');
   const access=payload.access_token;issuedAccess=access;
   marker(mode+'_RESPONSE_SCOPE_PRESENT',typeof payload.scope==='string');
   marker(mode+'_RESPONSE_MCP_SCOPE',typeof payload.scope==='string'&&payload.scope.split(' ').includes('mcp:use'));
   const userinfo=await json(await ctx.request.get(originUrl(metadata.userinfo_endpoint).href,{timeout:15000,maxRedirects:0,
     headers:{Authorization:'Bearer '+access}}),mode+'_USERINFO');
   check(userinfo.sub===subject,mode+'_SAME_OWNER_SUBJECT');
   if(access.split('.').length===3){
     const keys=createRemoteJWKSet(originUrl(metadata.jwks_uri),{timeoutDuration:5000});
     const verified=(await jwtVerify(access,keys,{issuer:ISSUER,audience:app.project,algorithms:['RS256'],requiredClaims:['iss','aud','sub','exp']})).payload;
     check(verified.sub===subject&&verified.azp===app.client,mode+'_SIGNED_NATIVE_CLIENT_OWNER');
     const aud=Array.isArray(verified.aud)?verified.aud:[verified.aud];
     marker(mode+'_JWT_AUDIENCE_HAS_MCP_URL',aud.includes(MCP));
     marker(mode+'_JWT_AUDIENCE_HAS_QA_PROJECT',aud.includes(app.project));
     marker(mode+'_JWT_SCOPE_PRESENT',typeof verified.scope==='string');
     marker(mode+'_JWT_MCP_SCOPE',typeof verified.scope==='string'&&verified.scope.split(' ').includes('mcp:use'));
   }else marker(mode+'_JWT_SIGNATURE_AND_CLIENT_BINDING','NOT_VERIFIED_OPAQUE');
   if(onAccess)await onAccess(access);
   if(mode==='MCP_RESOURCE'){
     const mcp=await ctx.request.post(MCP,{timeout:15000,maxRedirects:0,
       headers:{Authorization:'Bearer '+access,'Content-Type':'application/json',Accept:'application/json, text/event-stream',
         'MCP-Protocol-Version':'2026-07-28','Mcp-Method':'server/discover'},
       data:{jsonrpc:'2.0',id:1,method:'server/discover',params:{_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28',
         'io.modelcontextprotocol/clientCapabilities':{},'io.modelcontextprotocol/clientInfo':{name:'mcp01-real-native-probe',version:'1'}}}}});
     marker('REAL_NATIVE_MCP_DISCOVER_HTTP',mcp.status());
   }
   marker(mode+'_NATIVE_PKCE','PASS');return true;
 }finally{
   // Revoke only the disposable access token minted by this flow, never the Console/site session token.
   if(issuedAccess&&metadata.revocation_endpoint){
     try{
       const revoke=await ctx.request.post(originUrl(metadata.revocation_endpoint).href,{timeout:15000,maxRedirects:0,
         form:{token:issuedAccess,token_type_hint:'access_token',client_id:app.client}});
       marker(mode+'_DISPOSABLE_TOKEN_REVOCATION_HTTP',revoke.status());
       const after=await ctx.request.get(originUrl(metadata.userinfo_endpoint).href,{timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+issuedAccess}});
       marker(mode+'_AFTER_REVOCATION_USERINFO_HTTP',after.status());
     }catch{marker(mode+'_DISPOSABLE_TOKEN_REVOCATION','NOT_VERIFIED');}
   }
   issuedAccess=null;callback=null;await page.close();await new Promise(resolve=>listener.close(resolve));
 }

}

// Railway can return STAGED with an empty patch when there are no pending changes.
// Reject APPLYING and any non-empty/unknown patch before credential provisioning.
function noUnrelatedStagedPatch(stage){
 return stage==null||(typeof stage==='object'&&!Array.isArray(stage)&&stage.status==='STAGED'&&
   stage.patch!==null&&typeof stage.patch==='object'&&!Array.isArray(stage.patch)&&Object.keys(stage.patch).length===0);
}

// Uses the same sealed EnvironmentConfig delivery contract as Core's SDK
// reconciler. Never exports a secret or creates a public provisioning endpoint.
const RAILWAY={project:'b4c18e5e-9ae8-461c-921c-0ac97049be2e',environment:'73a05860-cec4-4678-b3bf-1d32ac363a85',service:'ba13c2d1-6150-4d95-9a73-793ec2ed1228'};
async function railwayQuery(ctx,query,variables={}){
 const token=process.env.RAILWAY_MCP_QA_PROJECT_TOKEN;
 check(typeof token==='string'&&token.length>=20,'MCP_QA_DELIVERY_TOKEN_PRESENT');
 const result=await json(await ctx.request.post('https://backboard.railway.com/graphql/v2',{
   timeout:15000,maxRedirects:0,headers:{'Project-Access-Token':token},data:{query,variables}}),'RAILWAY_OPERATION');
 check(!result.errors&&result.data&&typeof result.data==='object','RAILWAY_OPERATION_ACK');
 return result.data;
}
async function deliveryPreflight(ctx){
 const identity=(await railwayQuery(ctx,'query { projectToken { projectId environmentId } }')).projectToken;
 check(identity?.projectId===RAILWAY.project&&identity?.environmentId===RAILWAY.environment,'MCP_QA_DELIVERY_TOKEN_EXACT_SCOPE');
 const data=await railwayQuery(ctx,'query($p:String!,$e:String!){ project(id:$p){id services{edges{node{id name}}} environments{edges{node{id name}}}} environment(id:$e,projectId:$p){variables(first:10000){edges{node{name serviceId isSealed}}}} environmentStagedChanges(environmentId:$e){id status patch} }',{p:RAILWAY.project,e:RAILWAY.environment});
 check(data.project?.services?.edges?.some(x=>x.node?.id===RAILWAY.service&&x.node?.name==='qdip-mcp')&&
   data.project?.environments?.edges?.some(x=>x.node?.id===RAILWAY.environment&&x.node?.name==='sandbox'),'MCP_QA_DELIVERY_TARGET');
 check(noUnrelatedStagedPatch(data.environmentStagedChanges),'MCP_QA_NO_UNRELATED_STAGED_PATCH');
 const variables=data.environment?.variables?.edges;
 check(Array.isArray(variables),'MCP_QA_VARIABLE_METADATA_AVAILABLE');
 const own=variables.map(x=>x.node).filter(x=>x?.serviceId===RAILWAY.service);
 check(!own.some(x=>['ZITADEL_INTROSPECTION_CLIENT_ID','ZITADEL_INTROSPECTION_CLIENT_SECRET'].includes(x.name)),
   'MCP_QA_NO_EXISTING_INTROSPECTION_OVERWRITE');
}
async function provisionIntrospection(ctx,consoleToken,project,client){
 await deliveryPreflight(ctx); // Must succeed BEFORE any AS write or new secret.
 const projectData=await json(await ctx.request.post(ISSUER+'/zitadel.project.v2.ProjectService/GetProject',{
   timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},data:{projectId:project}}),'MCP_QA_PROJECT');
 check(projectData.project?.projectId===project&&projectData.project?.organizationId==='397885387160184113','MCP_QA_PROJECT_EXACT_ORGANIZATION');
 const name='qdip-mcp-qa-introspection';
 const list=await json(await ctx.request.post(ISSUER+'/zitadel.application.v2.ApplicationService/ListApplications',{
   timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},
   data:{pagination:{limit:10},filters:[{projectIdFilter:{projectId:project}},{nameFilter:{name}}]}}),'MCP_API_APPLICATION_INVENTORY');
 check(Array.isArray(list.applications??[])&&(list.applications??[]).length===0,'MCP_API_NO_EXISTING_APP_OR_SECRET_ROTATION');
 // Only a dedicated API introspection application; never duplicate SDK Native A/B.
 const created=await json(await ctx.request.post(ISSUER+'/zitadel.application.v2.ApplicationService/CreateApplication',{
   timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},
   data:{projectId:project,name,apiConfiguration:{authMethodType:'API_AUTH_METHOD_TYPE_BASIC'}}}),'MCP_API_APPLICATION_CREATE');
 const id=created.applicationId,api=created.apiConfiguration;
 check(typeof id==='string'&&/^[0-9]{1,32}$/.test(id)&&typeof api?.clientId==='string'&&api.clientId.length<256&&
   typeof api?.clientSecret==='string'&&api.clientSecret.length>=16&&api.clientSecret.length<4096,'MCP_API_ONE_TIME_SECRET_COMPLETE');
 // From this point any ambiguous delivery stops; do not retry issuance or reset/delete a secret.
 const read=await json(await ctx.request.post(ISSUER+'/zitadel.application.v2.ApplicationService/GetApplication',{
   timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},data:{applicationId:id}}),'MCP_API_APPLICATION_READBACK');
 check(read.application?.applicationId===id&&read.application?.projectId===project&&read.application?.name===name&&
   read.application?.state==='APPLICATION_STATE_ACTIVE'&&read.application?.apiConfiguration?.clientId===api.clientId&&
   (!read.application.apiConfiguration.authMethodType||read.application.apiConfiguration.authMethodType==='API_AUTH_METHOD_TYPE_BASIC'),
   'MCP_API_APPLICATION_EXACT_READBACK');
 await deliveryPreflight(ctx);
 const variables={
   ZITADEL_INTROSPECTION_CLIENT_ID:{value:api.clientId,isSealed:true},
   ZITADEL_INTROSPECTION_CLIENT_SECRET:{value:api.clientSecret,isSealed:true},
   MCP_ALLOWED_CLIENT_IDS:{value:client,isSealed:false},
   MCP_INTROSPECTION_APPLICATION_ID:{value:id,isSealed:false},
   MCP_EXECUTION_ENABLED:{value:'false',isSealed:false}
 };
 const staged=await railwayQuery(ctx,'mutation($e:String!,$input:EnvironmentConfig!,$merge:Boolean){environmentStageChanges(environmentId:$e,input:$input,merge:$merge){id status}}',
   {e:RAILWAY.environment,input:{services:{[RAILWAY.service]:{variables}}},merge:false});
 check(typeof staged.environmentStageChanges?.id==='string','MCP_SEALED_CONFIGURATION_STAGED');
 const committed=await railwayQuery(ctx,'mutation($e:String!){environmentPatchCommitStaged(environmentId:$e)}',{e:RAILWAY.environment});
 check(committed.environmentPatchCommitStaged!=null&&committed.environmentPatchCommitStaged!==false,'MCP_SEALED_CONFIGURATION_COMMITTED');
 const metadata=await railwayQuery(ctx,'query($p:String!,$e:String!){environment(id:$e,projectId:$p){variables(first:10000){edges{node{name serviceId isSealed}}}}}',{p:RAILWAY.project,e:RAILWAY.environment});
 const own=metadata.environment?.variables?.edges?.map(x=>x.node).filter(x=>x?.serviceId===RAILWAY.service)??[];
 check(['ZITADEL_INTROSPECTION_CLIENT_ID','ZITADEL_INTROSPECTION_CLIENT_SECRET'].every(name=>own.filter(x=>x.name===name&&x.isSealed===true).length===1),'MCP_INTROSPECTION_DELIVERED_SEALED');
 return {clientId:api.clientId,clientSecret:api.clientSecret};
}
async function inspectOpaque(ctx,metadata,credential,token,app,subject){
 const auth=Buffer.from(encodeURIComponent(credential.clientId)+':'+encodeURIComponent(credential.clientSecret)).toString('base64');
 const active=await json(await ctx.request.post(originUrl(metadata.introspection_endpoint).href,{
   timeout:15000,maxRedirects:0,headers:{Authorization:'Basic '+auth},form:{token,token_type_hint:'access_token'}}),'REAL_INTROSPECTION');
 check(active.active===true,'REAL_INTROSPECTION_ACTIVE');
 check(active.iss===ISSUER&&active.sub===subject&&active.exp>Date.now()/1000,'REAL_INTROSPECTION_ISSUER_OWNER_EXPIRY');
 const ids=[active.client_id,active.azp].filter(x=>x!==undefined);
 check(ids.length>0&&ids.every(x=>x===app.client),'REAL_INTROSPECTION_SAME_NATIVE_CLIENT');
 const aud=Array.isArray(active.aud)?active.aud:[active.aud];
 marker('REAL_INTROSPECTION_MCP_RESOURCE_AUDIENCE',aud.includes(MCP));
 marker('REAL_INTROSPECTION_DEDICATED_API_AUDIENCE',aud.includes(credential.clientId));
 marker('REAL_INTROSPECTION_QA_PROJECT_AUDIENCE',aud.includes(app.project));
 marker('REAL_INTROSPECTION_SCOPE_PRESENT',typeof active.scope==='string');
 marker('REAL_INTROSPECTION_MCP_USE_GRANTED',typeof active.scope==='string'&&active.scope.split(' ').includes('mcp:use'));
}

async function main(){
 check(process.env.QDIP_E2E_ZITADEL_TEST21_LOGIN===USER&&(process.env.QDIP_E2E_ZITADEL_TEST21_PASSWORD||'').length>=8,'QA21_ACCOUNT_BOUND');
 const project=process.env.QDIP_SDK_QA_PROJECT_ID,application=process.env.QDIP_SDK_MANAGED_APP_ID,client=process.env.QDIP_SDK_MANAGED_CLIENT_ID;
 check([project,application].every(x=>typeof x==='string'&&/^[0-9]{1,32}$/.test(x))&&typeof client==='string'&&client.length>0&&client.length<=256,'EXISTING_MANAGED_REFERENCES_PRESENT');
 const browser=await chromium.launch({headless:true});const ctx=await browser.newContext({ignoreHTTPSErrors:false,serviceWorkers:'block',acceptDownloads:false});
 let consoleToken=null,introspection=null;
 const provision=process.env.MCP01_PROVISION_OAUTH==='true';
 try{
   if(provision)await deliveryPreflight(ctx);
   const metadata=await json(await ctx.request.get(ISSUER+'/.well-known/openid-configuration',{timeout:15000,maxRedirects:0}),'DISCOVERY');
   check(metadata.issuer===ISSUER&&metadata.code_challenge_methods_supported?.includes('S256'),'ISSUER_S256');
   const page=await ctx.newPage();await page.goto(SITE+'/api/auth/login?return_to='+encodeURIComponent(SITE+'/en'),{waitUntil:'domcontentloaded',timeout:30000});
   check(new URL(page.url()).origin===ISSUER,'LOGIN_ISSUER');
   const login=await visible(page,['input[autocomplete="username"]','input[name="loginName"]','input[name="loginname"]','input[name="username"]','input[name="email"]','input[type="email"]','input[type="text"]']);check(!!login,'LOGIN_FORM');await login.fill(USER);
   let pass=await visible(page,['input[autocomplete="current-password"]','input[type="password"]'],1200);
   if(!pass){await login.press('Enter');pass=await visible(page,['input[autocomplete="current-password"]','input[type="password"]']);}
   check(!!pass,'PASSWORD_FORM');const callback=page.waitForResponse(r=>{try{const u=new URL(r.url());return u.origin===SITE&&u.pathname==='/api/auth/callback/zitadel';}catch{return false;}},{timeout:40000});
   await pass.fill(process.env.QDIP_E2E_ZITADEL_TEST21_PASSWORD);await pass.press('Enter');
   const done=await callback.catch(()=>null);check(done&&[302,303].includes(done.status()),'QA21_LOGIN_CALLBACK');
   const consolePage=await ctx.newPage();consolePage.on('request',request=>{try{if(new URL(request.url()).origin!==ISSUER)return;void request.allHeaders().then(h=>{const value=h.authorization||'';if(value.startsWith('Bearer ')&&value.length>=24&&value.length<9000)consoleToken=value.slice(7);}).catch(()=>{});}catch{}});
   await consolePage.goto(ISSUER+'/ui/console/projects',{waitUntil:'domcontentloaded',timeout:30000});
   const end=Date.now()+20000;while(!consoleToken&&Date.now()<end)await consolePage.waitForTimeout(250);check(!!consoleToken,'CONFIG_READ_AUTHORITY');
   const owner=await json(await ctx.request.get(ISSUER+'/oidc/v1/userinfo',{timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken}}),'CONFIG_READER_USERINFO');
   check(typeof owner.sub==='string'&&/^[0-9]{1,32}$/.test(owner.sub),'EXPECTED_OWNER_SUBJECT');
   const data=await json(await ctx.request.post(ISSUER+'/zitadel.application.v2.ApplicationService/GetApplication',{
     timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},data:{applicationId:application}}),'MANAGED_APP_CONFIG');
   let app=data.application;check(app?.applicationId===application&&app?.projectId===project&&app?.name==='sdk-managed-qa'&&
     app?.state==='APPLICATION_STATE_ACTIVE'&&app?.oidcConfiguration?.clientId===client,'EXACT_MANAGED_APP_CONFIG');
   let oidc=app.oidcConfiguration;
   if((oidc.redirectUris??[]).length===0&&process.env.MCP01_REGISTER_QA_CALLBACK==='true'){
     // Task-authorized minimal QA setup using the real project owner's session, not Agent/Controller keys.
     check(oidc.applicationType==='OIDC_APP_TYPE_NATIVE'&&oidc.authMethodType==='OIDC_AUTH_METHOD_TYPE_NONE'&&
       oidc.grantTypes?.includes('OIDC_GRANT_TYPE_AUTHORIZATION_CODE')&&oidc.responseTypes?.includes('OIDC_RESPONSE_TYPE_CODE'),'CALLBACK_WRITE_PUBLIC_NATIVE_PRECONDITIONS');
     const qaProject=await json(await ctx.request.post(ISSUER+'/zitadel.project.v2.ProjectService/GetProject',{
       timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},data:{projectId:project}}),'CALLBACK_WRITE_PROJECT');
     check(qaProject.project?.projectId===project&&qaProject.project?.organizationId==='397885387160184113','CALLBACK_WRITE_EXACT_QA_PROJECT');
     const registered='http://127.0.0.1:8765/mcp01/callback';
     await json(await ctx.request.post(ISSUER+'/zitadel.application.v2.ApplicationService/UpdateApplication',{
       timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},
       data:{applicationId:application,projectId:project,oidcConfiguration:{redirectUris:[registered]}}}),'CALLBACK_OWNER_WRITE');
     const after=await json(await ctx.request.post(ISSUER+'/zitadel.application.v2.ApplicationService/GetApplication',{
       timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},data:{applicationId:application}}),'CALLBACK_READBACK');
     check(after.application?.applicationId===application&&after.application?.projectId===project&&
       after.application?.oidcConfiguration?.clientId===client&&after.application?.name==='sdk-managed-qa','CALLBACK_READBACK_IDENTITY');
     const updated=after.application.oidcConfiguration;
     check(sameOtherSettings(oidc,updated)&&
       isDeepStrictEqual(updated.redirectUris,[registered]),'ONLY_APPROVED_QA_CALLBACK_CHANGED');
     app=after.application;oidc=updated;
   }
   // Config read only; this does not repeat project-owner listing/qualification.
   const uris=oidc.redirectUris;
   check(Array.isArray(uris)&&uris.length>0&&uris.length<=50,'REGISTERED_REDIRECTS_PRESENT');
   const redirect=uris.map(value=>{try{return new URL(value);}catch{return null;}}).find(u=>u&&(u.protocol==='https:'||(u.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(u.hostname)))&&!u.username&&!u.password&&!u.hash);
   check(!!redirect,'REGISTERED_HTTP_REDIRECT_AVAILABLE');
   marker('REGISTERED_REDIRECT_URI_NOT_LOGGED','PASS');
   if(provision)introspection=await provisionIntrospection(ctx,consoleToken,project,client);
   consoleToken=null;await consolePage.close();
   const baseline=await nativeFlow(ctx,metadata,{project,client,redirect},owner.sub,'PROJECT_BASELINE');
   check(baseline,'MATCHED_NATIVE_BASELINE');
   const requested=await nativeFlow(ctx,metadata,{project,client,redirect},owner.sub,'MCP_RESOURCE',introspection?token=>inspectOpaque(ctx,metadata,introspection,token,{project,client},owner.sub):undefined);
   marker('MCP_RESOURCE_PKCE_RESULT',requested?'TOKEN_OBTAINED':'DENIED_OR_INTERACTION_BLOCKED');
   if(!introspection)marker('REAL_INTROSPECTION','NOT_RUN_NO_RUNNER_CREDENTIAL_CUSTODY');
   marker('REAL_MCP_OAUTH_ACCEPTANCE','NOT_QUALIFIED');
   marker('CANONICAL_LINK_AND_WORKER_EXECUTION','NOT_RUN');
   marker('NATIVE_TOKEN_CONTRACT_PROBE','COMPLETED');
 }finally{consoleToken=null;introspection=null;await ctx.close();await browser.close();}
}
if(process.argv.includes('--self-test'))selfTest();else main().catch(error=>{const stage=error instanceof Error&&/^[A-Z0-9_]{4,100}$/.test(error.message)?error.message:'SANITIZED_FAILURE';
 marker('NATIVE_TOKEN_CONTRACT_PROBE','FAIL_'+stage);process.exitCode=1;});

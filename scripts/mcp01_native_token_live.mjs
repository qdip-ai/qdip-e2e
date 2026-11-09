/** Real owner-only Native PKCE and opt-in MCP decision execution.
 * Reuses QA21 login/Console read pattern independently qualified by E2E PR141.
 * All credentials, codes, tokens and claim values remain in process memory.
 * No screenshots, traces, videos, response bodies or auth URLs are persisted.
 * Explicit QA setup mode may add ONE fixed loopback callback to an empty managed Native app; no identity or scope changes.
 */
import {chromium} from '@playwright/test';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {createHash,createHmac,randomBytes} from 'node:crypto';
import {createServer} from 'node:http';
import {isDeepStrictEqual} from 'node:util';
import assert from 'node:assert/strict';
import {createRemoteJWKSet,jwtVerify} from 'jose';

const SITE='https://qdip.ai';
const ISSUER='https://mentality-rmwj0i.eu1.zitadel.cloud';
const MCP='https://qdip-mcp-sandbox.up.railway.app/mcp';
const USER='qa-21@qdip.ai';
const executionMode=process.argv.includes('--mcp-execution');
const multiCapabilityMode=process.argv.includes('--mcp-two-capabilities');
const discoveryPreflightMode=process.argv.includes('--mcp-discovery-preflight');
// Explicit QA-only B owner-link acceptance; the protected operator retains the B key.
const secondAppLinkMode=process.argv.includes('--mcp-application-b-link');
const workerUnavailableMode=process.argv.includes('--mcp-worker-unavailable');
const workerTimeoutMode=process.argv.includes('--mcp-worker-timeout');
const delegationMode=process.argv.includes('--mcp-delegation');
const crossOrgMode=process.argv.includes('--mcp-authz-cross-org');
const qa23ReadOnlyMode=process.argv.includes('--mcp-authz-qa23-readonly');
const QA23='qa-23@qdip.ai';
const unassignedRoleMode=process.argv.includes('--mcp-authz-unassigned');
let delegationPhase='not-started';
let qa23ReadPhase='before';
const realDecisionMode=executionMode||multiCapabilityMode||discoveryPreflightMode||workerUnavailableMode||workerTimeoutMode||secondAppLinkMode||delegationMode||crossOrgMode||unassignedRoleMode||qa23ReadOnlyMode;
const ownerBootstrapMode=process.argv.includes('--mcp-owner-bootstrap');
const applicationLinkMode=process.argv.includes('--mcp-application-link');
const QA_GATEWAY='https://mcp652-gateway-qa-staging.up.railway.app';
const QA_ZITADEL_ORG='397885387160184113';
const ownerPreviewSetup=process.argv.includes('--configure-owner-preview');
const ownerPreviewCallback='https://qdip-web-git-feat-425-core-backed-zi-6de08f-taras-gezs-projects.vercel.app/api/auth/callback/zitadel';
const marker=(key,value)=>console.log('MCP01_'+key+'='+value);
function check(ok,stage){marker(stage,ok?'PASS':'FAIL');if(!ok)throw Error(stage);}
function originUrl(value){const u=new URL(value);if(u.origin!==ISSUER||u.protocol!=='https:'||u.username||u.password)throw Error('UNTRUSTED_ISSUER_ENDPOINT');return u;}
async function json(response,stage){check(response.status()===200,stage+'_HTTP_200');
 const body=await response.body();check(body.length<=131072,stage+'_BOUNDED');
 try{return JSON.parse(body.toString('utf8'));}catch{throw Error(stage+'_JSON');}}
async function visible(page,selectors,ms=14000){const end=Date.now()+ms;
 while(Date.now()<end){for(const selector of selectors){const n=page.locator(selector).first();if(await n.isVisible().catch(()=>false))return n;}await page.waitForTimeout(250);}return null;}
// RFC 6238 / SHA-1, fixed 30-second step and 6 digits. QA-only seed, never logged.
function totpAt(secret,epochMs){
 if(typeof secret!=='string'||!/^[A-Z2-7]{16,128}={0,6}$/.test(secret.toUpperCase()))
   throw Error('AUTHZ01_QA23_TOTP_SEED_INVALID');
 const base32=secret.toUpperCase().replace(/=+$/,'');
 let bits=0,value=0,bytes=[];
 for(const c of base32){value=(value<<5)|'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);bits+=5;
   if(bits>=8){bits-=8;bytes.push((value>>>bits)&255);}}
 if(bytes.length<10)throw Error('AUTHZ01_QA23_TOTP_SEED_INVALID');
 const key=Buffer.from(bytes);
 const counter=Buffer.alloc(8);
 counter.writeBigUInt64BE(BigInt(Math.floor(epochMs/30_000)));
 const digest=createHmac('sha1',key).update(counter).digest();
 key.fill(0);counter.fill(0);bytes.fill(0);
 const offset=digest[digest.length-1]&15;
 const value31=(digest.readUInt32BE(offset)&0x7fffffff);
 digest.fill(0);
 return String(value31%1_000_000).padStart(6,'0');
}
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
 const names=['ZITADEL_INTROSPECTION_CLIENT_ID','ZITADEL_INTROSPECTION_CLIENT_SECRET'];
 const config={services:{[RAILWAY.service]:{variables:Object.fromEntries(names.map(n=>[n,{isSealed:true}]))}}};
 const rendered=Object.fromEntries(names.map(n=>[n,null]));
 assert(sealedReadback(JSON.stringify(config),rendered));
 assert(!sealedReadback(config,{}));
 delete config.services[RAILWAY.service].variables[names[0]].isSealed;
 assert(sealedReadback(config,rendered));
 assert(!sealedReadback(config,{...rendered,[names[0]]:'readable-value'}));
 marker('SEALED_READBACK_REGRESSION','PASS');
 assert(noUnrelatedStagedPatch(null));
 assert(noUnrelatedStagedPatch({id:'empty-patch',status:'STAGED',patch:{}}));
 assert(!noUnrelatedStagedPatch({id:'foreign',status:'STAGED',patch:{services:{other:{}}}}));
 assert(!noUnrelatedStagedPatch({id:'applying',status:'APPLYING',patch:{}}));
 assert(!noUnrelatedStagedPatch({id:'unknown',status:'STAGED'}));
 assert.equal(totpAt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',59000),'287082');
 assert.throws(()=>totpAt('badseed',59000),/AUTHZ01_QA23_TOTP_SEED_INVALID/);
 marker('QA23_TOTP_RFC6238_REGRESSION','PASS');
 marker('MCP_EMPTY_STAGED_PATCH_REGRESSION','PASS');
}

async function loginToSite(ctx,user,password,stage){
 // Browser context owns page lifetime; closing during OAuth redirect hung Actions.
 const page=await ctx.newPage();
 await page.goto(SITE+'/api/auth/login?return_to='+encodeURIComponent(SITE+'/en'),{waitUntil:'domcontentloaded',timeout:30000});
 check(new URL(page.url()).origin===ISSUER,stage+'_LOGIN_ISSUER');
 const login=await visible(page,['input[autocomplete="username"]','input[name="loginName"]','input[name="loginname"]','input[name="username"]','input[name="email"]','input[type="email"]','input[type="text"]']);
 check(!!login,stage+'_LOGIN_FORM');await login.fill(user);
 let pass=await visible(page,['input[autocomplete="current-password"]','input[type="password"]'],1200);
 if(!pass){await login.press('Enter');pass=await visible(page,['input[autocomplete="current-password"]','input[type="password"]']);}
 check(!!pass,stage+'_PASSWORD_FORM');
 let callbackReceived=false;
 const qa23IssuerPostStatuses=[];
 if(stage==='AUTHZ01_QA23'){
   page.on('response',response=>{
     try{
       if(new URL(response.url()).origin!==ISSUER||response.request().method()!=='POST')return;
       if(qa23IssuerPostStatuses.length<16)qa23IssuerPostStatuses.push(response.status());
     }catch{}
   });
 }
 const callback=page.waitForResponse(r=>{try{const u=new URL(r.url());return u.origin===SITE&&u.pathname==='/api/auth/callback/zitadel';}catch{return false;}},{timeout:40000})
   .then(r=>{callbackReceived=true;return r;}).catch(()=>null);
 await pass.fill(password);
 if(stage==='AUTHZ01_QA23'){
   // ZITADEL Login V2 binds handleSubmit to the button onClick (not form onSubmit).
   // Pressing Enter may perform a native form POST without executing the login action.
   const submit=page.locator('button[type="submit"]').first();
   check(await submit.isVisible(),'AUTHZ01_QA23_REAL_SUBMIT_BUTTON_VISIBLE');
   await submit.click({timeout:12000});
   marker('AUTHZ01_QA23_REACT_SUBMIT_CLICKED','PASS');
 }else await pass.press('Enter');
 if(stage==='AUTHZ01_QA23'){
   // Let the real ZITADEL policy decide: no MFA challenge means no TOTP seed needed.
   const fieldSelectors=['input[autocomplete="one-time-code"]','input[name="code"]',
     'input[inputmode="numeric"]','input[type="tel"]'];
   let totp=null,methodSelected=false;
   const deadline=Date.now()+12000;
   while(!callbackReceived&&Date.now()<deadline){
     totp=await visible(page,fieldSelectors,350);
     if(totp)break;
     if(!methodSelected){
       const authenticator=page.getByRole('button',{name:/authenticator|totp|verification app/i}).first();
       if(await authenticator.isVisible().catch(()=>false)){
         await authenticator.click();
         methodSelected=true;
       }
     }
   }
   if(totp){
     const seed=process.env.QDIP_E2E_ZITADEL_TEST23_TOTP_SEED;
     check(typeof seed==='string'&&seed.length>=16,'AUTHZ01_QA23_TOTP_SEALED_SEED_PRESENT');
     const untilNextStep=30000-(Date.now()%30000);
     if(untilNextStep<5000)await page.waitForTimeout(untilNextStep+700);
     await totp.fill(totpAt(seed,Date.now()));
     await totp.press('Enter');
     marker('AUTHZ01_QA23_TOTP_SUBMITTED','PASS');
   }else if(callbackReceived)marker('AUTHZ01_QA23_NO_MFA_CHALLENGE','PASS');
 }
 const done=await callback;
 if(!done){
   if(stage==='AUTHZ01_QA23'){
     marker(stage+'_ISSUER_POST_COUNT',qa23IssuerPostStatuses.length);
     marker(stage+'_ISSUER_POST_STATUS_CODES',JSON.stringify(qa23IssuerPostStatuses));
     const passwordInput=page.locator('input[type="password"]').first();
     marker(stage+'_PASSWORD_ARIA_INVALID',await passwordInput.getAttribute('aria-invalid').catch(()=>null)==='true');
     marker(stage+'_VISIBLE_ALERT',await page.getByRole('alert').first().isVisible().catch(()=>false));
     marker(stage+'_VISIBLE_VALIDATION_ERROR',
       await page.locator('[data-state="error"],[role="alert"],[aria-live="assertive"]').first().isVisible().catch(()=>false));
     marker(stage+'_SUBMIT_BUTTON_VISIBLE',await page.locator('button[type="submit"]').first().isVisible().catch(()=>false));
     marker(stage+'_SUBMIT_BUTTON_DISABLED',await page.locator('button[type="submit"]').first().isDisabled().catch(()=>false));
   }
   // Booleans only: never output the login page, response, URL, user, or credentials.
   const location=new URL(page.url());
   marker(stage+'_LOGIN_STALLED_ORIGIN',location.origin===ISSUER?'ISSUER':location.origin===SITE?'SITE':'OTHER');
   const body=(await page.locator('body').innerText().catch(()=>'' )).slice(0,12000).toLowerCase();
   const signs={
     invalid_credentials:/invalid.*(password|credentials|login)|incorrect.*(password|credentials)|wrong password|login failed|falsches passwort|nieprawidłowe hasło/.test(body),
     password_reset:/reset password|change password|new password|password expired|passwort ändern/.test(body),
     email_verification:/verify.*(email|address)|confirm.*email|email not verified|verify your account/.test(body),
     second_factor:/authentication code|authenticator|one.time password|two.factor|mfa|passkey|verify.*(identity|login)|sms code/.test(body),
     consent:/approve|grant access|authorize application|consent/.test(body)
   };
   for(const [key,value] of Object.entries(signs))marker(stage+'_LOGIN_STATE_'+key.toUpperCase(),value);
   marker(stage+'_LOGIN_PASSWORD_FIELD_VISIBLE',await page.locator('input[type="password"]').first().isVisible().catch(()=>false));
   marker(stage+'_LOGIN_OTP_FIELD_VISIBLE',await page.locator('input[autocomplete="one-time-code"]').first().isVisible().catch(()=>false));
 }
 check(done&&[302,303].includes(done.status()),stage+'_LOGIN_CALLBACK');
}

async function nativeFlow(ctx,metadata,app,subject,mode,onAccess){
 const verifier=randomBytes(32).toString('base64url'),state=randomBytes(24).toString('base64url');
 const nonce=randomBytes(24).toString('base64url');
 const redirect=app.redirect;
 const authorize=originUrl(metadata.authorization_endpoint);
 const scope=['openid','profile',`urn:zitadel:iam:org:project:id:${app.project}:aud`];
 if(mode==='MCP_RESOURCE'){
   if(process.env.MCP01_OAUTH_PROFILE==='zitadel_project_roles'||process.env.MCP01_CONFIGURE_ROLE_CONTRACT==='true')scope.push('urn:zitadel:iam:org:projects:roles',(crossOrgMode||unassignedRoleMode||qa23ReadOnlyMode)?'urn:zitadel:iam:org:project:role:mcp:read':'urn:zitadel:iam:org:project:role:mcp:use');
   else scope.push('mcp:use');
 }
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
   check(subject===null?typeof userinfo.sub==='string'&&/^[0-9]{1,32}$/.test(userinfo.sub):userinfo.sub===subject,mode+'_SAME_OWNER_SUBJECT');
   if(access.split('.').length===3){
     const keys=createRemoteJWKSet(originUrl(metadata.jwks_uri),{timeoutDuration:5000});
     const verified=(await jwtVerify(access,keys,{issuer:ISSUER,audience:app.project,algorithms:['RS256'],requiredClaims:['iss','aud','sub','exp']})).payload;
     check(verified.sub===userinfo.sub&&verified.azp===app.client,mode+'_SIGNED_NATIVE_CLIENT_OWNER');
     const aud=Array.isArray(verified.aud)?verified.aud:[verified.aud];
     marker(mode+'_JWT_AUDIENCE_HAS_MCP_URL',aud.includes(MCP));
     marker(mode+'_JWT_AUDIENCE_HAS_QA_PROJECT',aud.includes(app.project));
     // Audience is a public resource/client identifier, never an access token.
     check(aud.length>0&&aud.length<=12&&aud.every(x=>typeof x==='string'&&x.length<256&&/^[A-Za-z0-9:/._-]+$/.test(x)),
       'OAUTH_AUDIENCE_BOUNDED');
     marker('OAUTH01_ACTUAL_AUD',JSON.stringify(aud));
     marker('OAUTH02_PR6_EXACT_MCP_RESOURCE_AUDIENCE',aud.includes(MCP)?'PASS':'CONTRACT_FAIL');
     if(crossOrgMode||unassignedRoleMode||qa23ReadOnlyMode){
       const roles=verified[`urn:zitadel:iam:org:project:${app.project}:roles`];
       if(qa23ReadOnlyMode){
         check(typeof roles?.['mcp:read']?.[QA_ZITADEL_ORG]==='string' &&
           !roles?.['mcp:use']?.[QA_ZITADEL_ORG],'AUTHZ01_QA23_REAL_EXCLUSIVE_READ_ROLE');
       }else{
         check(!roles?.['mcp:read']?.[QA_ZITADEL_ORG],
           crossOrgMode?'AUTHZ05_FOREIGN_SUBJECT_HAS_NO_QA_READ_ROLE':'AUTHZ06_NO_ASSIGNED_READ_ROLE');
       }
       if(crossOrgMode)check(!roles?.['mcp:use']?.[QA_ZITADEL_ORG],'AUTHZ05_FOREIGN_SUBJECT_HAS_NO_QA_USE_ROLE');
     }
     marker(mode+'_JWT_SCOPE_PRESENT',typeof verified.scope==='string');
     marker(mode+'_JWT_MCP_SCOPE',typeof verified.scope==='string'&&verified.scope.split(' ').includes('mcp:use'));
   }else{
     // ZITADEL may issue opaque access tokens; their audience/roles cannot be inferred
     // from ID tokens, requested scopes, or a successful userinfo request.
     marker(mode+'_JWT_SIGNATURE_AND_CLIENT_BINDING','NOT_VERIFIED_OPAQUE');
     marker('OAUTH01_ACTUAL_AUD','NOT_VERIFIED_OPAQUE_ACCESS_TOKEN');
     marker('OAUTH02_PR6_EXACT_MCP_RESOURCE_AUDIENCE','NOT_VERIFIED_OPAQUE_ACCESS_TOKEN');
     if(crossOrgMode)marker('AUTHZ05_ROLE_EVIDENCE','LIVE_MCP_DENIAL_REQUIRED');
     if(unassignedRoleMode)marker('AUTHZ06_ROLE_EVIDENCE','EXISTING_ZITADEL_ASSIGNMENT_READBACK');
     if(qa23ReadOnlyMode)marker('AUTHZ01_QA23_ROLE_EVIDENCE','VERIFIED_ZITADEL_ASSIGNMENT_READBACK');
   }
   if(onAccess)await onAccess(access,userinfo.sub);
   if(crossOrgMode||unassignedRoleMode){
     const stage=crossOrgMode?'AUTHZ05_CROSS_ORG':'AUTHZ06_UNASSIGNED_ROLE';
     const denied=await ctx.request.post(MCP,{timeout:15000,maxRedirects:0,
       headers:{Authorization:'Bearer '+access,'Content-Type':'application/json',Accept:'application/json, text/event-stream',
         'MCP-Protocol-Version':'2026-07-28','Mcp-Method':'server/discover'},
       data:{jsonrpc:'2.0',id:501,method:'server/discover',params:{}}});
     marker(stage+'_MCP_HTTP',denied.status());
     check([401,403].includes(denied.status()),stage+'_DENIED');
     marker(stage,'PASS');
     return true;
   }
   if(qa23ReadOnlyMode){
     // Exercise actual MCP initialize + tools/call; server/discover is not a
     // valid MCP method and HTTP 400 cannot establish token acceptance.
     await assertQa23ReadOnly(access);
     return true;
   }
   if(mode==='MCP_RESOURCE'&&!secondAppLinkMode){
     const mcp=await ctx.request.post(MCP,{timeout:15000,maxRedirects:0,
       headers:{Authorization:'Bearer '+access,'Content-Type':'application/json',Accept:'application/json, text/event-stream',
         'MCP-Protocol-Version':'2026-07-28','Mcp-Method':'server/discover'},
       data:{jsonrpc:'2.0',id:1,method:'server/discover',params:{_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28',
         'io.modelcontextprotocol/clientCapabilities':{},'io.modelcontextprotocol/clientInfo':{name:'mcp01-real-native-probe',version:'1'}}}}});
     marker('REAL_NATIVE_MCP_DISCOVER_HTTP',mcp.status());
     check(mcp.status()===200,'REAL_MCP_AUTHENTICATION');
     await realMcpClient(access);
   }
   marker(mode+'_NATIVE_PKCE','PASS');return true;
 }finally{
   // Revoke only the disposable access token minted by this flow, never the Console/site session token.
   let revocationFailed=false;
   if(issuedAccess&&metadata.revocation_endpoint){
     try{
       const revoke=await ctx.request.post(originUrl(metadata.revocation_endpoint).href,{timeout:15000,maxRedirects:0,
         form:{token:issuedAccess,token_type_hint:'access_token',client_id:app.client}});
       marker(mode+'_DISPOSABLE_TOKEN_REVOCATION_HTTP',revoke.status());
       const after=await ctx.request.get(originUrl(metadata.userinfo_endpoint).href,{timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+issuedAccess}});
       marker(mode+'_AFTER_REVOCATION_USERINFO_HTTP',after.status());
       if(executionMode||delegationMode){
         check(revoke.status()===200&&after.status()===401,'DISPOSABLE_TOKEN_REVOCATION_ENFORCED');
         const denied=await ctx.request.post(MCP,{timeout:15000,maxRedirects:0,
           headers:{Authorization:'Bearer '+issuedAccess,'Content-Type':'application/json',Accept:'application/json, text/event-stream',
             'MCP-Protocol-Version':'2026-07-28','Mcp-Method':'server/discover'},
           data:{jsonrpc:'2.0',id:99,method:'server/discover',params:{}}});
         check([401,403].includes(denied.status()),'REVOKED_TOKEN_MCP_DENIED');
       }
     }catch{marker(mode+'_DISPOSABLE_TOKEN_REVOCATION','NOT_VERIFIED');revocationFailed=executionMode;}
   }
   issuedAccess=null;callback=null;await page.close();await new Promise(resolve=>listener.close(resolve));
   if(revocationFailed)throw Error('DISPOSABLE_TOKEN_REVOCATION_UNVERIFIED');
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

function sealedReadback(config,rendered){
 const applied=typeof config==='string'?JSON.parse(config):config;
 const own=applied?.services?.[RAILWAY.service]?.variables;
 return ['ZITADEL_INTROSPECTION_CLIENT_ID','ZITADEL_INTROSPECTION_CLIENT_SECRET'].every(name=>
   Object.hasOwn(own??{},name)&&Object.hasOwn(rendered??{},name)&&rendered[name]===null);
}
async function verifyExistingDelivery(ctx){
 const identity=(await railwayQuery(ctx,'query { projectToken { projectId environmentId } }')).projectToken;
 check(identity?.projectId===RAILWAY.project&&identity?.environmentId===RAILWAY.environment,'MCP_QA_DELIVERY_TOKEN_EXACT_SCOPE');
 // Official CLI GetEnvironmentConfig / VariablesForServiceDeployment contracts.
 // decryptVariables:false never requests plaintext sealed values; rendered null
 // means installed-but-unreadable, not absent.
 const data=await railwayQuery(ctx,'query($p:String!,$e:String!,$s:String!){environment(id:$e){id name config(decryptVariables:false) variables(first:10000){edges{node{name serviceId isSealed}}}} variablesForServiceDeployment(projectId:$p,environmentId:$e,serviceId:$s)}',
   {p:RAILWAY.project,e:RAILWAY.environment,s:RAILWAY.service});
 check(data.environment?.id===RAILWAY.environment&&data.environment?.name==='sandbox','MCP_QA_EXISTING_ENVIRONMENT');
 const raw=data.environment.config,config=typeof raw==='string'?JSON.parse(raw):raw;
 const names=['ZITADEL_INTROSPECTION_CLIENT_ID','ZITADEL_INTROSPECTION_CLIENT_SECRET'];
 marker('MCP_APPLIED_SECRET_ENTRIES_PRESENT',names.every(n=>Object.hasOwn(config?.services?.[RAILWAY.service]?.variables??{},n)));
 marker('MCP_APPLIED_SEAL_FLAG_FIELDS_PRESENT',names.every(n=>Object.hasOwn(config?.services?.[RAILWAY.service]?.variables?.[n]??{},'isSealed')));
 marker('MCP_DEPLOYMENT_SECRET_NAMES_PRESENT',names.every(n=>Object.hasOwn(data.variablesForServiceDeployment??{},n)));
 marker('MCP_DEPLOYMENT_SECRET_VALUES_UNREADABLE',names.every(n=>data.variablesForServiceDeployment?.[n]===null));
 check(sealedReadback(config,data.variablesForServiceDeployment),'MCP_INTROSPECTION_DELIVERED_SEALED');
 marker('MCP_EXISTING_SECRET_VALUES_NOT_READ','PASS');
 const own=(data.environment.variables?.edges??[]).map(x=>x.node).filter(x=>x?.serviceId===RAILWAY.service);
 const callerEntries=own.filter(x=>x.name==='QDIP_API_KEY');
 check(callerEntries.length===1&&callerEntries[0].isSealed===true,'MCP_QA_CALLER_SEALED_METADATA');
 const v=data.variablesForServiceDeployment??{};
 check(v.QDIP_API_KEY===null&&typeof v.QDIP_API_KEY_ID==='string'&&
   /^[a-f0-9-]{36}$/.test(v.QDIP_API_KEY_ID),'MCP_QA_CALLER_KEY_ID_READBACK');
 check(v.QDIP_GATEWAY_URL===QA_GATEWAY&&v.MCP_APPROVED_CAPABILITY_ID==='mcp.qa.choice'&&
   v.MCP_APPROVED_CAPABILITY_VERSION==='1'&&['true','false'].includes(v.MCP_EXECUTION_ENABLED),
   'MCP_QA_CALLER_PROTECTED_CONTRACT_EXACT');
 marker('MCP_QA_SEALED_CALLER_KEY_ID',v.QDIP_API_KEY_ID);
 marker('MCP_QA_SEALED_DELIVERY','PASS');
}
async function realMcpClient(access){
 const client=new Client({name:'independent-mcp01-native-client',version:'1'},{
   versionNegotiation:{mode:{pin:'2026-07-28'}},supportedProtocolVersions:['2026-07-28']});
 const transport=new StreamableHTTPClientTransport(new URL(MCP),{
   requestInit:{headers:{authorization:'Bearer '+access}}});
 try{
   await client.connect(transport);
   const tools=await client.listTools();
   check(isDeepStrictEqual(tools.tools.map(t=>t.name).sort(),['qdip_describe_capability','qdip_invoke_decision','qdip_list_capabilities']),'REAL_MCP_THREE_TOOLS');
   marker('REAL_MCP_TOOLS_LIST','PASS');
   if(discoveryPreflightMode){
     const list=await client.callTool({name:'qdip_list_capabilities',arguments:{}},{timeout:20000});
     check(list.isError!==true&&Array.isArray(list.structuredContent?.capabilities),'MCP02_REAL_DISCOVERY_READ_ONLY');
     const items=list.structuredContent.capabilities;
     marker('MCP02_REAL_AUTHORIZED_COUNT',items.length);
     marker('MCP02_REAL_AUTHORIZED_IDENTITIES',JSON.stringify(items.slice(0,16).map(x=>({id:x.capability_id,version:x.capability_version}))));
   }
   else if(workerUnavailableMode)await assertWorkerUnavailable(client);
   else if(workerTimeoutMode)await assertWorkerTimeout(client);
   else if(multiCapabilityMode)await executeMcpMultiCapability(client);
   else if(delegationMode)await assertExternalDelegation(client);

   else if(executionMode)await executeMcpDecision(client);
 }finally{await client.close();}
}

async function assertQa23ReadOnly(access){
 const client=new Client({name:'independent-qa23-read-only',version:'1'},{
   versionNegotiation:{mode:{pin:'2026-07-28'}},supportedProtocolVersions:['2026-07-28']});
 const transport=new StreamableHTTPClientTransport(new URL(MCP),{
   requestInit:{headers:{authorization:'Bearer '+access}}});
 try{
   await client.connect(transport);
   const list=await client.callTool({name:'qdip_list_capabilities',arguments:{}},{timeout:20000});
   const described=await client.callTool({name:'qdip_describe_capability',
     arguments:{capability_id:'mcp.qa.choice',capability_version:'1'}},{timeout:20000});
   const invoked=await client.callTool({name:'qdip_invoke_decision',
     arguments:{capability_id:'mcp.qa.choice',capability_version:'1',
       input:{first_value:7,second_value:3},timeout_seconds:10}},{timeout:20000});
   check(invoked.isError===true&&invoked.structuredContent?.error?.code==='UNAUTHORIZED'&&
     !('execution_id' in (invoked.structuredContent??{})),
     'AUTHZ_XUSER_'+qa23ReadPhase.toUpperCase()+'_INVOKE_DENIED');
   const listOk=list.isError!==true&&Array.isArray(list.structuredContent?.capabilities)&&
     list.structuredContent.capabilities.length===1&&
     list.structuredContent.capabilities[0].capability_id==='mcp.qa.choice'&&
     list.structuredContent.capabilities[0].capability_version==='1';
   const describeOk=described.isError!==true&&described.structuredContent?.capability_id==='mcp.qa.choice'&&
     described.structuredContent?.capability_version==='1';
   if(qa23ReadPhase==='granted'){
     check(listOk&&describeOk,'AUTHZ_XUSER_GRANTED_EXACT_READ');
   }else{
     check(list.isError===true&&described.isError===true&&!listOk&&!describeOk,
       'AUTHZ_XUSER_'+qa23ReadPhase.toUpperCase()+'_READ_DENIED');
   }
 }finally{await client.close();}
}

async function qa23ReadAudit(ctx,token){
 const response=await ctx.request.get(QA_GATEWAY+'/api/v1/qa/mcp652/decision-audit',{
   timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+token}});
 check(response.status()===200,'AUTHZ_XUSER_CORE_AUDIT_AVAILABLE');
 const body=await json(response,'AUTHZ_XUSER_CORE_AUDIT_RESPONSE');
 check(Number.isSafeInteger(body.execution_events)&&body.execution_events>=0,
   'AUTHZ_XUSER_CORE_AUDIT_RECORD_COUNT_VALID');
 return body.execution_events;
}

// QA fault-injection qualification. Run ONLY while the reviewed QA worker is
// deliberately offline; never treat a normal positive invocation as this proof.
async function assertWorkerUnavailable(client){
 const args={capability_id:'mcp.qa.choice',capability_version:'1'};
 const list=await client.callTool({name:'qdip_list_capabilities',arguments:{}},{timeout:20000});
 check(!list.isError&&Array.isArray(list.structuredContent?.capabilities)&&
   list.structuredContent.capabilities.length===0,'UNAVAILABLE_CAPABILITY_REMOVED_FROM_DISCOVERY');
 const started=Date.now();
 const denied=await client.callTool({name:'qdip_invoke_decision',arguments:{
   ...args,input:{first_value:7,second_value:3},timeout_seconds:2
 }},{timeout:12000});
 const code=denied.structuredContent?.error?.code;
 marker('WORKER_OUTAGE_ERROR_CODE',typeof code==='string'&&/^[A-Z_]{3,80}$/.test(code)?code:'UNKNOWN');
 check(denied.isError===true&&['WORKER_UNAVAILABLE','INVALID_REQUEST'].includes(code)&&
   denied.structuredContent?.error?.retryable===false &&
   !('execution_id' in (denied.structuredContent??{})),
   'REAL_WORKER_UNAVAILABLE_FAIL_CLOSED');
 check(Date.now()-started<12000,'WORKER_UNAVAILABLE_BOUNDED_DEADLINE');
 marker('REAL_WORKER_UNAVAILABLE_QA','PASS');
}

// Actual delayed registered SDK-02 Worker; Core's 504 is mapped by SDK
// to GATEWAY_TIMEOUT and redacted by MCP to INDETERMINATE without retry.
async function assertWorkerTimeout(client){
 const args={capability_id:'mcp.qa.choice',capability_version:'1'};
 const started=Date.now();
 const result=await client.callTool({name:'qdip_invoke_decision',arguments:{
   ...args,input:{first_value:7,second_value:3},timeout_seconds:1
 }},{timeout:15000});
 const code=result.structuredContent?.error?.code;
 marker('QA_WORKER_TIMEOUT_CODE',typeof code==='string'&&/^[A-Z_]{3,80}$/.test(code)?code:'UNKNOWN');
 check(result.isError===true&&code==='INDETERMINATE'&&
   result.structuredContent?.error?.retryable===false&&
   !('execution_id' in (result.structuredContent??{})),
   'REAL_WORKER_TIMEOUT_FAILS_CLOSED_NO_RETRY');
 check(Date.now()-started<15000,'REAL_WORKER_TIMEOUT_BOUNDED');
 marker('REAL_WORKER_TIMEOUT_QA','PASS');
}


/** MCP-02 live qualification: use the existing independent MCP client and Native token.
 * The second QA workload's exact published manifest and expected Kernel result
 * are pinned to the reviewed SDK-02 fixture; missing publication fails closed.
 */
async function executeMcpMultiCapability(client){
 const first={capability_id:'mcp.qa.choice',capability_version:'1'};
 const identity={capability_id:'mcp.qa.bonus',capability_version:'2'};
 const input={first_value:7,second_value:3,second_bonus:6};
 const expectedSchema={type:'object',properties:{
   first_value:{type:'integer',minimum:0,maximum:1000000},
   second_value:{type:'integer',minimum:0,maximum:1000000},
   second_bonus:{type:'integer',minimum:0,maximum:1000000}},
   required:['first_value','second_value','second_bonus'],additionalProperties:false};
 const expectedSolution={first:'0',second:'1'};
 const expectedObjective='9';
 const requested=async (name,args)=>{
   const result=await client.callTool({name,arguments:args},{timeout:20000});
   const diagnostic=result.structuredContent?.error?.code;
   if(result.isError&&typeof diagnostic==='string'&&/^[A-Z_]{1,80}$/.test(diagnostic))
     marker('MCP02_TOOL_DIAGNOSTIC',diagnostic);
   check(result.isError!==true&&!!result.structuredContent,'MCP02_'+name.toUpperCase()+'_SUCCESS');
   check(JSON.stringify(result.structuredContent).length<=131072,'MCP02_RESPONSE_BOUNDED');
   return result.structuredContent;
 };
 const list=await requested('qdip_list_capabilities',{});
 check(Array.isArray(list.capabilities)&&list.capabilities.length>=2&&
   list.capabilities.some(x=>x.capability_id===first.capability_id&&x.capability_version===first.capability_version)&&
   list.capabilities.some(x=>x.capability_id===identity.capability_id&&x.capability_version===identity.capability_version),
   'MCP02_TWO_REAL_AUTHORIZED_CAPABILITIES');
 const keys=list.capabilities.map(x=>[x.plugin_id,x.capability_id,x.capability_version].join(':'));
 check(keys.length===new Set(keys).size,'MCP02_AUTHORIZED_LIST_UNIQUE');
 const a=await requested('qdip_describe_capability',first);
 const b=await requested('qdip_describe_capability',identity);
 const firstSchema={type:'object',properties:{
   first_value:{type:'integer',minimum:0,maximum:1000000},
   second_value:{type:'integer',minimum:0,maximum:1000000}},
   required:['first_value','second_value'],additionalProperties:false};
 check(a.plugin_id==='sdk-managed-qa'&&a.capability_id===first.capability_id&&
   a.capability_version==='1'&&a.execution_mode==='managed_kernel'&&
   isDeepStrictEqual(a.input_schema,firstSchema),'MCP02_CHOICE_V1_TRUSTED_MANIFEST');
 check(b.plugin_id==='sdk-managed-qa'&&b.capability_id===identity.capability_id&&
   b.capability_version===identity.capability_version&&b.execution_mode==='managed_kernel'&&
   isDeepStrictEqual(b.input_schema,expectedSchema)&&
   !isDeepStrictEqual(b.input_schema,a.input_schema),'MCP02_SECOND_EXACT_TRUSTED_MANIFEST');
 for(const [capability_id,capability_version] of [['mcp.qa.unknown','1'],[identity.capability_id,'__wrong_version__']]){
   const denied=await client.callTool({name:'qdip_invoke_decision',
     arguments:{capability_id,capability_version,input}},{timeout:20000});
   check(denied.isError===true&&denied.structuredContent?.error?.code==='FORBIDDEN'&&
     !('execution_id' in (denied.structuredContent??{})),'MCP02_UNKNOWN_OR_WRONG_VERSION_DENIED');
 }
 const invalid=await client.callTool({name:'qdip_invoke_decision',arguments:{
   ...identity,input:{...input,__unexpected_mcp02:true},timeout_seconds:10}},{timeout:20000});
 check(invalid.isError===true&&invalid.structuredContent?.error?.code==='INVALID_REQUEST'&&
   !('execution_id' in (invalid.structuredContent??{})),'MCP02_INVALID_SCHEMA_DENIED');
 const firstResult=await requested('qdip_invoke_decision',{...first,input:{first_value:7,second_value:3},timeout_seconds:10});
 const secondResult=await requested('qdip_invoke_decision',{...identity,input,timeout_seconds:10});
 const normalizeDecimal=(value)=>{
   if(typeof value!=='string'||!/^-?(0|[1-9][0-9]*)(\.[0-9]+)?$/.test(value))return null;
   const [integer,fraction='']=value.split('.');
   const remainder=fraction.replace(/0+$/,'');
   return (integer==='-0'?'0':integer)+(remainder?'.'+remainder:'');
 };
 const sameDecimal=(actual,expected)=>normalizeDecimal(actual)!==null&&normalizeDecimal(actual)===normalizeDecimal(expected);
 const sameSolution=(actual,expected)=>actual&&typeof actual==='object'&&!Array.isArray(actual)&&
   isDeepStrictEqual(Object.keys(actual).sort(),Object.keys(expected).sort())&&
   Object.keys(expected).every(key=>sameDecimal(actual[key],expected[key]));
 const validEvidence=(result,solution,objective)=>{
   const manifest=result.manifest,replay=result.replay_contract;
   return typeof result.execution_id==='string'&&/^[A-Za-z0-9_.:-]{1,128}$/.test(result.execution_id)&&
     result.semantic_status==='EXACT'&&result.backend_status==='OPTIMAL'&&result.actionable===true&&
     sameSolution(result.solution,solution)&&sameDecimal(result.objective_value,objective)&&
     manifest?.execution_id===result.execution_id&&manifest?.backend_id==='ortools-cp-sat'&&
     manifest?.semantic_version==='1.0.0'&&replay?.semantic_version==='1.0.0'&&
     ['decision_id','decision_spec_hash','ir_hash','compiler_version'].every(k=>typeof manifest[k]==='string'&&manifest[k]===replay[k])&&
     ['decision_spec_hash','ir_hash'].every(k=>/^[a-f0-9]{64}$/.test(manifest[k]))&&
     isDeepStrictEqual(result.diagnostics,{redacted:true});
 };
 check(validEvidence(firstResult,{first:'1',second:'0'},'7'),'MCP02_CHOICE_V1_REAL_KERNEL_RESULT');
 check(validEvidence(secondResult,expectedSolution,expectedObjective),'MCP02_SECOND_REAL_KERNEL_RESULT');
 check(firstResult.execution_id!==secondResult.execution_id,'MCP02_DISTINCT_REAL_EXECUTIONS');
 marker('MCP02_EXECUTION_IDS',JSON.stringify([firstResult.execution_id,secondResult.execution_id]));
 marker('MCP02_TWO_REAL_CAPABILITIES_E2E','PASS');
}


async function assertExternalDelegation(client){
 const args={capability_id:'mcp.qa.choice',capability_version:'1'};
 if(delegationPhase==='granted'){
   await executeMcpDecision(client);
   marker('MCP03_INDEPENDENT_CLIENT_MANAGED_KERNEL','PASS');
   return;
 }
 check(['revoked','ungranted'].includes(delegationPhase),'MCP03_NEGATIVE_PHASE_EXPECTED');
 const label=delegationPhase==='ungranted'?'UNGRANTED':'REVOKED';
 const listed=await client.callTool({name:'qdip_list_capabilities',arguments:{}},{timeout:20000});
 check(listed.isError!==true&&isDeepStrictEqual(listed.structuredContent?.capabilities,[]),
   'MCP03_'+label+'_DISCOVERY_EMPTY');
 for(const [name,arguments_] of [
   ['qdip_describe_capability',args],
   ['qdip_invoke_decision',{...args,input:{first_value:7,second_value:3}}]]){
   const result=await client.callTool({name,arguments:arguments_},{timeout:20000});
   check(result.isError===true&&result.structuredContent?.error?.code==='FORBIDDEN'&&
     !('execution_id' in (result.structuredContent??{})),
     'MCP03_'+label+'_'+name.toUpperCase()+'_DENIED');
 }
 marker('MCP03_'+label+'_REAL_MCP','PASS');
}

async function executeMcpDecision(client){
 const args={capability_id:'mcp.qa.choice',capability_version:'1'};
 const call=async(name,arguments_)=>{
   // One request only: never replay an invoke after timeout/unknown outcome.
   const response=await client.callTool({name,arguments:arguments_},{timeout:20000});
   const code=response.structuredContent?.error?.code;
   if(response.isError&&typeof code==='string'&&/^[A-Z_]{1,80}$/.test(code))marker('TOOL_DIAGNOSTIC',code);
   check(!response.isError&&response.structuredContent&&typeof response.structuredContent==='object','TOOL_'+name.toUpperCase());
   check(JSON.stringify(response.structuredContent).length<=131072,'TOOL_RESULT_BOUNDED');
   return response.structuredContent;
 };
 const listed=await call('qdip_list_capabilities',{});
 marker('AUTHORIZED_CAPABILITY_COUNT',Array.isArray(listed.capabilities)?listed.capabilities.length:'INVALID');
 check(isDeepStrictEqual(listed.capabilities,[{plugin_id:'sdk-managed-qa',...args}]),'AUTHORIZED_CAPABILITY_EXACT');
 const manifest=await call('qdip_describe_capability',args);
 check(manifest.plugin_id==='sdk-managed-qa'&&manifest.capability_id===args.capability_id&&
   manifest.capability_version==='1'&&manifest.execution_mode==='managed_kernel'&&
   isDeepStrictEqual(manifest.required_scopes,['plugins:execute']),'AUTHORIZED_MANIFEST_EXACT');
 check(isDeepStrictEqual(manifest.input_schema,{type:'object',properties:{
   first_value:{type:'integer',minimum:0,maximum:1000000},second_value:{type:'integer',minimum:0,maximum:1000000}},
   required:['first_value','second_value'],additionalProperties:false}),'PUBLISHED_WORKER_SCHEMA_EXACT');
 // A different capability or version must not be discoverable by a valid QA21 caller.
 for(const [capability_id,capability_version] of [
   ['foreign.qa.choice','1'],['mcp.qa.choice','2']
 ]){
   const denied=await client.callTool({name:'qdip_describe_capability',
     arguments:{capability_id,capability_version}},{timeout:20000});
   check(denied.isError===true&&denied.structuredContent?.error?.code==='FORBIDDEN',
     'FOREIGN_CAPABILITY_OR_VERSION_DENIED');
 }
 const result=await call('qdip_invoke_decision',{...args,input:{first_value:7,second_value:3},timeout_seconds:10});
 check(typeof result.execution_id==='string'&&/^[A-Za-z0-9_.:-]{1,128}$/.test(result.execution_id),'REAL_KERNEL_EXECUTION_ID');
 check(result.semantic_status==='EXACT'&&result.backend_status==='OPTIMAL'&&result.actionable===true,'KERNEL_EXACT_OPTIMAL');
 // Compare decimal strings without converting them to JavaScript floats.
 const integer=(value,expected)=>typeof value==='string'&&/^-?(0|[1-9][0-9]*)(\.0+)?$/.test(value)&&BigInt(value.split('.')[0])===expected;
 check(isDeepStrictEqual(Object.keys(result.solution??{}).sort(),['first','second'])&&
   integer(result.solution.first,1n)&&integer(result.solution.second,0n)&&integer(result.objective_value,7n),'KERNEL_CHOICE_CONSTRAINTS_AND_OBJECTIVE');
 const m=result.manifest,r=result.replay_contract;
 check(m?.semantic_version==='1.0.0'&&r?.semantic_version==='1.0.0'&&m.execution_id===result.execution_id&&
   m.backend_id==='ortools-cp-sat'&&m.runtime_version==='qdip-runtime-kernel.v1'&&m.compiler_version==='qdip-runtime-compiler.v1'&&
   /^[A-Za-z0-9_.:-]{1,128}$/.test(m.decision_id)&&
   ['decision_id','decision_spec_hash','ir_hash','compiler_version'].every(k=>typeof m[k]==='string'&&m[k]===r[k])&&
   ['decision_spec_hash','ir_hash'].every(k=>/^[a-f0-9]{64}$/.test(m[k])),'MANIFEST_REPLAY_BOUND_TO_EXECUTION');
 check(isDeepStrictEqual(result.diagnostics,{redacted:true}),'DIAGNOSTICS_REDACTED');
 // Only this bounded, known QA result is written; no raw diagnostics or auth material.
 marker('REAL_MCP_DECISION',JSON.stringify({execution_id:result.execution_id,semantic_status:result.semantic_status,
   backend_status:result.backend_status,actionable:result.actionable,solution:result.solution,objective_value:result.objective_value,
   manifest:{execution_id:m.execution_id,decision_id:m.decision_id,decision_spec_hash:m.decision_spec_hash,ir_hash:m.ir_hash,
     semantic_version:m.semantic_version,compiler_version:m.compiler_version,runtime_version:m.runtime_version,backend_id:m.backend_id},
   replay_contract:{semantic_version:r.semantic_version,decision_id:r.decision_id,decision_spec_hash:r.decision_spec_hash,
     ir_hash:r.ir_hash,compiler_version:r.compiler_version}}));
 const invalid=await client.callTool({name:'qdip_invoke_decision',arguments:{...args,input:{first_value:'7',second_value:3},timeout_seconds:10}},{timeout:20000});
 check(invalid.isError===true&&invalid.structuredContent?.error?.code==='INVALID_REQUEST','INVALID_SCHEMA_DENIED');
 // Validate hard timeout budget at the externally exposed MCP boundary.
 // These are rejected before dispatch: NOT a substitute for a real delayed Worker.
 for(const timeout_seconds of [0,31]){
   const denied=await client.callTool({name:'qdip_invoke_decision',
     arguments:{...args,input:{first_value:7,second_value:3},timeout_seconds}},{timeout:20000});
   check(denied.isError===true,'INVALID_TIMEOUT_BOUNDS_DENIED');
 }
 marker('REAL_WORKER_TIMEOUT_INJECTION','NOT_RUN');

 marker('REAL_MCP_POSITIVE_VERTICAL_SLICE','PASS');
 marker('REMAINING_TENANT_KEY_WORKER_TIMEOUT_QUALIFICATION','NOT_RUN');
}


async function configureRoleContract(ctx,consoleToken,project,subject){
 const org='397885387160184113',role='mcp:use';
 const rpc=async(service,method,data,stage)=>json(await ctx.request.post(ISSUER+'/'+service+'/'+method,{
   timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},data}),stage);
 const found=await rpc('zitadel.project.v2.ProjectService','GetProject',{projectId:project},'ROLE_PROJECT');
 check(found.project?.projectId===project&&found.project?.organizationId===org,'ROLE_EXACT_QA_PROJECT');
 const roles=await rpc('zitadel.project.v2.ProjectService','ListProjectRoles',{
   projectId:project,pagination:{limit:10},filters:[{roleKeyFilter:{key:role}}]},'MCP_ROLE_READ');
 check(Array.isArray(roles.projectRoles??[])&&(roles.projectRoles??[]).length<=1,'MCP_ROLE_UNAMBIGUOUS');
 if(!(roles.projectRoles??[]).length){
   await rpc('zitadel.project.v2.ProjectService','AddProjectRole',{
     projectId:project,roleKey:role,displayName:'Use QDIP MCP in isolated QA',group:'MCP QA'},'MCP_ROLE_CREATE');
 }else check(roles.projectRoles[0].key===role&&roles.projectRoles[0].projectId===project,'MCP_ROLE_EXACT_EXISTING');
 const filters=[{projectId:{id:project}},{organizationId:{id:org}},{inUserIds:{ids:[subject]}}];
 const read=()=>rpc('zitadel.authorization.v2.AuthorizationService','ListAuthorizations',{pagination:{limit:10},filters},'MCP_ROLE_ASSIGNMENT_READ');
 const grants=await read(),existing=grants.authorizations??[];
 check(Array.isArray(existing)&&existing.length<=1,'MCP_ROLE_ASSIGNMENT_UNAMBIGUOUS');
 if(!existing.length){
   await rpc('zitadel.authorization.v2.AuthorizationService','CreateAuthorization',{
     userId:subject,projectId:project,organizationId:org,roleKeys:[role]},'MCP_ROLE_ASSIGNMENT_CREATE');
 }else{
   const grant=existing[0];
   check(grant.project?.id===project&&grant.project?.organizationId===org&&grant.organization?.id===org&&
     grant.user?.id===subject&&grant.state==='STATE_ACTIVE','MCP_ROLE_ASSIGNMENT_EXACT_ACTIVE');
   const keys=grant.roles?.map(x=>x.key)??[];
   check(keys.every(x=>typeof x==='string')&&keys.length<50,'MCP_EXISTING_ROLE_KEYS_BOUNDED');
   if(!keys.includes(role))await rpc('zitadel.authorization.v2.AuthorizationService','UpdateAuthorization',{
     id:grant.id,roleKeys:[...keys,role]},'MCP_ROLE_ASSIGNMENT_ADD_ONLY');
 }
 const after=(await read()).authorizations??[];
 check(after.length===1&&after[0].user?.id===subject&&after[0].project?.id===project&&
   after[0].organization?.id===org&&after[0].state==='STATE_ACTIVE'&&after[0].roles?.some(x=>x.key===role),'MCP_ROLE_ASSIGNMENT_VERIFIED');
 const staged=(await railwayQuery(ctx,'query($e:String!){environmentStagedChanges(environmentId:$e){id status patch}}',{e:RAILWAY.environment})).environmentStagedChanges;
 check(noUnrelatedStagedPatch(staged),'MCP_ROLE_PROFILE_NO_UNRELATED_PATCH');
 const variables={
   MCP_OAUTH_PROFILE:{value:'zitadel_project_roles',isSealed:false},
   MCP_ZITADEL_PROJECT_ID:{value:project,isSealed:false},
   MCP_ZITADEL_ORGANIZATION_ID:{value:org,isSealed:false},
   MCP_EXECUTION_ENABLED:{value:'false',isSealed:false}
 };
 await railwayQuery(ctx,'mutation($e:String!,$input:EnvironmentConfig!,$merge:Boolean){environmentStageChanges(environmentId:$e,input:$input,merge:$merge){id status}}',
   {e:RAILWAY.environment,input:{services:{[RAILWAY.service]:{variables}}},merge:false});
 const committed=await railwayQuery(ctx,'mutation($e:String!){environmentPatchCommitStaged(environmentId:$e)}',{e:RAILWAY.environment});
 check(committed.environmentPatchCommitStaged!=null&&committed.environmentPatchCommitStaged!==false,'MCP_ROLE_PROFILE_CONFIGURED');
 const expected='urn:zitadel:iam:org:project:id:'+project+':aud';
 let ready=false;
 for(let attempt=0;attempt<18;attempt++){
   const response=await ctx.request.get(new URL('/.well-known/oauth-protected-resource/mcp',MCP).href,{timeout:5000,maxRedirects:0});
   const metadata=response.status()===200?await response.json().catch(()=>null):null;
   if(metadata?.resource===MCP&&metadata.scopes_supported?.includes(expected)&&
     metadata.scopes_supported.includes('urn:zitadel:iam:org:project:role:mcp:use')){ready=true;break;}
   await new Promise(resolve=>setTimeout(resolve,5000));
 }
 check(ready,'MCP_ROLE_PROFILE_RUNTIME_READY');
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
 await verifyExistingDelivery(ctx);
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


// Exact QA-only credential boundary; no Vercel, no admin API key in GitHub.
// Owner-bound, zero-key-exposure application linking through isolated QA Core.
async function linkQaApplication(ctx,token,application){
 const endpoint=QA_GATEWAY+'/api/v1/qa/mcp652/application-link';
 const body={application_id:application};
 if(!secondAppLinkMode){
 const anonymous=await ctx.request.post(endpoint,{timeout:15000,maxRedirects:0,
   headers:{'Content-Type':'application/json'},data:body});
 check(anonymous.status()===403,'QA_APP_LINK_ANONYMOUS_DENIED');
 const foreign=await ctx.request.post(endpoint,{timeout:15000,maxRedirects:0,
   headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
   data:{application_id:'123456789012345678'}});
 check(foreign.status()===403,'QA_APP_LINK_FOREIGN_APPLICATION_DENIED');
 }
 const response=await ctx.request.post(endpoint,{timeout:15000,maxRedirects:0,
   headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},data:body});
 marker('QA_APP_LINK_HTTP',response.status());
 check(response.status()===204,'QA_APP_LINK_VERIFIED_OWNER_HTTP_204');
 marker('QA_APP_LINK_PERSISTED','PASS');
}

async function bootstrapQaOwner(ctx,token){
 const endpoint=QA_GATEWAY+'/api/v1/qa/mcp652/owner-bootstrap';
 const unauthorized=await ctx.request.post(endpoint,{timeout:15000,maxRedirects:0,
   headers:{'Content-Type':'application/json'},data:{organization_id:QA_ZITADEL_ORG}});
 check(unauthorized.status()===403,'QA_OWNER_MISSING_TOKEN_DENIED');
 const foreign=await ctx.request.post(endpoint,{timeout:15000,maxRedirects:0,
   headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
   data:{organization_id:'123456789012345678'}});
 check(foreign.status()===403,'QA_OWNER_FOREIGN_ORG_DENIED');
 const result=await ctx.request.post(endpoint,{timeout:15000,maxRedirects:0,
   headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
   data:{organization_id:QA_ZITADEL_ORG}});
 marker('QA_OWNER_CANONICAL_LINK_HTTP',result.status());
 check(result.status()===201,'QA_OWNER_CANONICAL_LINK_HTTP_201');
 const raw=await result.body();
 check(raw.length<16384,'QA_OWNER_CANONICAL_LINK_BOUNDED');
 const linked=JSON.parse(raw.toString('utf8'));
 check(typeof linked.id==='string'&&/^[0-9a-f-]{36}$/i.test(linked.id)&&
       linked.identity_provider==='zitadel'&&linked.zitadel_organization_id===QA_ZITADEL_ORG&&
       linked.zitadel_issuer===ISSUER,'QA_OWNER_CANONICAL_LINK_IDENTITY');
 marker('QA_OWNER_CANONICAL_LINK','PASS');
}

async function main(){
 const modes=[executionMode,multiCapabilityMode,discoveryPreflightMode,secondAppLinkMode,ownerPreviewSetup,ownerBootstrapMode,applicationLinkMode,workerUnavailableMode,workerTimeoutMode,delegationMode,crossOrgMode,unassignedRoleMode,qa23ReadOnlyMode].filter(Boolean).length;
 check(process.argv.slice(2).every(arg=>['--mcp-execution','--mcp-application-b-link','--configure-owner-preview','--mcp-owner-bootstrap','--mcp-application-link','--mcp-worker-unavailable','--mcp-worker-timeout','--mcp-two-capabilities','--mcp-discovery-preflight','--mcp-delegation','--mcp-authz-cross-org','--mcp-authz-unassigned','--mcp-authz-qa23-readonly'].includes(arg))&&
   modes<=1,'CLI_MODE_SUPPORTED');
 check(process.env.QDIP_E2E_ZITADEL_TEST21_LOGIN===USER&&(process.env.QDIP_E2E_ZITADEL_TEST21_PASSWORD||'').length>=8,'QA21_ACCOUNT_BOUND');
 const project=process.env.QDIP_SDK_QA_PROJECT_ID,
   application=secondAppLinkMode?process.env.QDIP_SDK_EXTERNAL_APP_ID:process.env.QDIP_SDK_MANAGED_APP_ID,
   client=secondAppLinkMode?process.env.QDIP_SDK_EXTERNAL_CLIENT_ID:process.env.QDIP_SDK_MANAGED_CLIENT_ID;
 check([project,application].every(x=>typeof x==='string'&&/^[0-9]{1,32}$/.test(x))&&typeof client==='string'&&client.length>0&&client.length<=256,'EXISTING_QA_APPLICATION_REFERENCES_PRESENT');
 const browser=await chromium.launch({headless:true});const ctx=await browser.newContext({ignoreHTTPSErrors:false,serviceWorkers:'block',acceptDownloads:false});
 let consoleToken=null,introspection=null;
 const provision=process.env.MCP01_PROVISION_OAUTH==='true';
 const verifyExisting=process.env.MCP01_VERIFY_EXISTING_OAUTH==='true';
 check(!(provision&&verifyExisting),'MCP_OAUTH_MODES_EXCLUSIVE');
 if(realDecisionMode||ownerBootstrapMode||applicationLinkMode)check(!provision&&!verifyExisting&&process.env.MCP01_CONFIGURE_ROLE_CONTRACT!=='true'&&
   process.env.MCP01_REGISTER_QA_CALLBACK!=='true','EXECUTION_HAS_NO_PROVISIONING_AUTHORITY');
 try{
   if(provision)await deliveryPreflight(ctx);
   if(verifyExisting)await verifyExistingDelivery(ctx);
   const metadata=await json(await ctx.request.get(ISSUER+'/.well-known/openid-configuration',{timeout:15000,maxRedirects:0}),'DISCOVERY');
   check(metadata.issuer===ISSUER&&metadata.code_challenge_methods_supported?.includes('S256'),'ISSUER_S256');
   if(executionMode||secondAppLinkMode||ownerBootstrapMode||applicationLinkMode||delegationMode)check(typeof metadata.revocation_endpoint==='string','REVOCATION_ENDPOINT_REQUIRED');
   await loginToSite(ctx,USER,process.env.QDIP_E2E_ZITADEL_TEST21_PASSWORD,'QA21');
   const consolePage=await ctx.newPage();consolePage.on('request',request=>{try{if(new URL(request.url()).origin!==ISSUER)return;void request.allHeaders().then(h=>{const value=h.authorization||'';if(value.startsWith('Bearer ')&&value.length>=24&&value.length<9000)consoleToken=value.slice(7);}).catch(()=>{});}catch{}});
   await consolePage.goto(ISSUER+'/ui/console/projects',{waitUntil:'domcontentloaded',timeout:30000});
   const end=Date.now()+20000;while(!consoleToken&&Date.now()<end)await consolePage.waitForTimeout(250);check(!!consoleToken,'CONFIG_READ_AUTHORITY');
   const owner=await json(await ctx.request.get(ISSUER+'/oidc/v1/userinfo',{timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken}}),'CONFIG_READER_USERINFO');
   check(typeof owner.sub==='string'&&/^[0-9]{1,32}$/.test(owner.sub),'EXPECTED_OWNER_SUBJECT');
   const data=await json(await ctx.request.post(ISSUER+'/zitadel.application.v2.ApplicationService/GetApplication',{
     timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},data:{applicationId:application}}),'MANAGED_APP_CONFIG');
   let app=data.application;check(app?.applicationId===application&&app?.projectId===project&&app?.name===(secondAppLinkMode?'sdk-external-qa':'sdk-managed-qa')&&
     app?.state==='APPLICATION_STATE_ACTIVE'&&app?.oidcConfiguration?.clientId===client,'EXACT_MANAGED_APP_CONFIG');
   let oidc=app.oidcConfiguration;
   if(realDecisionMode){
     // Match Core's live PROJECT_OWNER application-binding policy before any key issue.
     const owned=await json(await ctx.request.post(ISSUER+'/zitadel.internal_permission.v2.InternalPermissionService/ListAdministrators',{
       timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},
       data:{pagination:{offset:0,limit:100},filters:[
         {resource:{projectId:project}},{inUserIdsFilter:{ids:[owner.sub]}},{role:{roleKey:'PROJECT_OWNER'}}
       ]}}),'MCP_QA_PROJECT_ADMIN_READ');
     const entries=owned.administrators;
     check(Array.isArray(entries)&&entries.length<=100,'MCP_QA_PROJECT_ADMIN_BOUNDED');
     const exact=entries.filter(row=>row&&row.instance!==true&&row.user?.id===owner.sub&&
       row.project?.id===project&&row.project?.organizationId==='397885387160184113'&&
       Array.isArray(row.roles)&&row.roles.includes('PROJECT_OWNER'));
     marker('MCP_QA_PROJECT_OWNER_EXACT',exact.length===1);
     check(exact.length===1,'MCP_QA_PROJECT_OWNER_REQUIRED_FOR_CANONICAL_SDK_BINDING');
   }
   if(ownerPreviewSetup){
     check(oidc.applicationType==='OIDC_APP_TYPE_NATIVE'&&oidc.authMethodType==='OIDC_AUTH_METHOD_TYPE_NONE'&&
       oidc.grantTypes?.includes('OIDC_GRANT_TYPE_AUTHORIZATION_CODE'),'OWNER_PREVIEW_PUBLIC_NATIVE_CLIENT');
     const qa=await json(await ctx.request.post(ISSUER+'/zitadel.project.v2.ProjectService/GetProject',{
       timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},data:{projectId:project}}),'OWNER_PREVIEW_PROJECT');
     check(qa.project?.projectId===project&&qa.project.organizationId==='397885387160184113','OWNER_PREVIEW_EXACT_ORGANIZATION');
     check(Array.isArray(oidc.redirectUris)&&oidc.redirectUris.length<50,'OWNER_PREVIEW_REDIRECTS_BOUNDED');
     const desired=oidc.redirectUris.includes(ownerPreviewCallback)?oidc.redirectUris:[...oidc.redirectUris,ownerPreviewCallback];
     if(!oidc.redirectUris.includes(ownerPreviewCallback))await json(await ctx.request.post(ISSUER+'/zitadel.application.v2.ApplicationService/UpdateApplication',{
       timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},
       data:{applicationId:application,projectId:project,oidcConfiguration:{redirectUris:desired}}}),'OWNER_PREVIEW_CALLBACK_ADD');
     const read=await json(await ctx.request.post(ISSUER+'/zitadel.application.v2.ApplicationService/GetApplication',{
       timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},data:{applicationId:application}}),'OWNER_PREVIEW_CALLBACK_READ');
     const observed=read.application?.oidcConfiguration;
     if(observed&&!sameOtherSettings(oidc,observed)){
       const beforeMutable=mutableOidc(oidc),afterMutable=mutableOidc(observed);
       const fields=[...new Set([...Object.keys(beforeMutable),...Object.keys(afterMutable)])]
         .filter(key=>!isDeepStrictEqual(beforeMutable[key],afterMutable[key]))
         .filter(key=>/^[a-zA-Z][a-zA-Z0-9]{0,63}$/.test(key)).slice(0,30);
       marker('OWNER_PREVIEW_CHANGED_FIELD_NAMES',fields.join(',')||'NONE');
     }
     check(read.application?.applicationId===application&&read.application?.projectId===project&&
       sameOtherSettings(oidc,read.application.oidcConfiguration)&&isDeepStrictEqual(read.application.oidcConfiguration.redirectUris,desired),
       'OWNER_PREVIEW_ONLY_EXACT_CALLBACK_ADDED');
     marker('OWNER_PREVIEW_CALLBACK_CONFIGURED','PASS');
     const loginEntry=new URL('/api/auth/login',ownerPreviewCallback);
     const loginResponse=await ctx.request.get(loginEntry.href,{maxRedirects:0,timeout:15000});
     marker('OWNER_PREVIEW_LOGIN_ENTRY_HTTP',loginResponse.status());
     const next=loginResponse.headers()['location'];
     let issuerRedirect=false;
     try{
       const target=new URL(next);
       issuerRedirect=loginResponse.status()===302&&target.origin===ISSUER&&target.pathname.startsWith('/oauth/v2/authorize');
     }catch{}
     marker('OWNER_PREVIEW_LOGIN_ISSUER_REDIRECT',issuerRedirect);
     check(issuerRedirect,'OWNER_PREVIEW_LOGIN_AT_APPROVED_ISSUER');
     return;
   }
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

   let agentApplication=null;
   if(delegationMode){
     const agentId=process.env.QDIP_SDK_EXTERNAL_APP_ID;
     const agentClient=process.env.QDIP_SDK_EXTERNAL_CLIENT_ID;
     check(typeof agentId==='string'&&/^[0-9]{1,32}$/.test(agentId)&&
       typeof agentClient==='string'&&agentClient.length>0&&agentClient!==client,
       'MCP03_INDEPENDENT_OAUTH_CLIENT_PRECHECK');
     const info=await json(await ctx.request.post(
       ISSUER+'/zitadel.application.v2.ApplicationService/GetApplication',{
         timeout:15000,maxRedirects:0,headers:{Authorization:'Bearer '+consoleToken},
         data:{applicationId:agentId}}),'MCP03_AGENT_APPLICATION_READ');
     const agent=info.application;
     check(agent?.applicationId===agentId&&agent.projectId===project&&
       agent.name==='sdk-external-qa'&&agent.state==='APPLICATION_STATE_ACTIVE'&&
       agent.oidcConfiguration?.clientId===agentClient,'MCP03_AGENT_APP_VERIFIED');
     const agentRedirect=(agent.oidcConfiguration.redirectUris??[])
       .map(value=>{try{return new URL(value);}catch{return null;}})
       .find(u=>u&&u.protocol==='http:'&&u.hostname==='127.0.0.1'&&
         u.port==='8765'&&['/mcp01/callback','/oidc/callback'].includes(u.pathname));
     check(!!agentRedirect,'MCP03_AGENT_REGISTERED_NATIVE_CALLBACK');
     agentApplication={project,client:agentClient,redirect:agentRedirect,applicationId:agentId};
   }
   const uris=oidc.redirectUris;
   check(Array.isArray(uris)&&uris.length>0&&uris.length<=50,'REGISTERED_REDIRECTS_PRESENT');
   const redirect=uris.map(value=>{try{return new URL(value);}catch{return null;}}).find(u=>u&&(u.protocol==='https:'||(u.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(u.hostname)))&&!u.username&&!u.password&&!u.hash);
   check(!!redirect,'REGISTERED_HTTP_REDIRECT_AVAILABLE');
   marker('REGISTERED_REDIRECT_URI_NOT_LOGGED','PASS');
   if(provision)introspection=await provisionIntrospection(ctx,consoleToken,project,client);
   if(process.env.MCP01_CONFIGURE_ROLE_CONTRACT==='true')await configureRoleContract(ctx,consoleToken,project,owner.sub);
   if(unassignedRoleMode){
     const headers={Authorization:'Bearer '+consoleToken};
     const projectRoles=await json(await ctx.request.post(ISSUER+'/zitadel.project.v2.ProjectService/ListProjectRoles',{
       timeout:15000,maxRedirects:0,headers,data:{projectId:project,pagination:{limit:10},
         filters:[{roleKeyFilter:{key:'mcp:read'}}]}}),'AUTHZ06_REAL_PROJECT_ROLE');
     const readRoles=(projectRoles.projectRoles??[]).filter(x=>x.key==='mcp:read'&&x.projectId===project);
     check(readRoles.length<=1,'AUTHZ06_READ_ROLE_UNAMBIGUOUS');
     marker('AUTHZ01_READ_ROLE_REGISTERED',readRoles.length===1?'PASS':'BLOCKED_MISSING_ROLE');
     const assignments=await json(await ctx.request.post(ISSUER+'/zitadel.authorization.v2.AuthorizationService/ListAuthorizations',{
       timeout:15000,maxRedirects:0,headers,data:{pagination:{limit:10},filters:[
         {projectId:{id:project}},{organizationId:{id:QA_ZITADEL_ORG}},{inUserIds:{ids:[owner.sub]}}
       ]}}),'AUTHZ06_REAL_ROLE_ASSIGNMENTS');
     const items=assignments.authorizations??[];
     check(Array.isArray(items)&&items.length===1&&items[0].user?.id===owner.sub&&
       items[0].project?.id===project&&items[0].organization?.id===QA_ZITADEL_ORG&&
       items[0].state==='STATE_ACTIVE','AUTHZ06_EXACT_QA_OWNER_ASSIGNMENT');
     const keys=items[0].roles?.map(x=>x.key)??[];
     check(keys.includes('mcp:use')&&!keys.includes('mcp:read'),'AUTHZ06_USE_ASSIGNED_READ_UNASSIGNED');
   }
   let qa23Subject=null;
   if(qa23ReadOnlyMode){
     check((process.env.QDIP_E2E_ZITADEL_TEST23_PASSWORD??'').length>=8,
       'AUTHZ01_QA23_SEALED_LOGIN_CONFIGURED');
     const qaApp={project,client,redirect};
     const readCtx=await browser.newContext({ignoreHTTPSErrors:false,serviceWorkers:'block',acceptDownloads:false});
     let mustClean=false,before=null;
     const action=async(method,token)=>{
       const result=await ctx.request.fetch(QA_GATEWAY+'/api/v1/qa/mcp652/read-delegation',{
         method,timeout:15000,maxRedirects:0,
         headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
         data:{recipient_subject:qa23Subject}});
       check(result.status()===204,'AUTHZ_XUSER_'+(method==='POST'?'GRANT':'REVOKE')+'_CORE_HTTP_204');
     };
     const asOwner=async callback=>check(await nativeFlow(ctx,metadata,qaApp,owner.sub,
       'PROJECT_BASELINE',callback),'AUTHZ_XUSER_OWNER_NATIVE_PKCE');
     try{
       await loginToSite(readCtx,QA23,process.env.QDIP_E2E_ZITADEL_TEST23_PASSWORD,'AUTHZ01_QA23');
       // Clean an abandoned QA-only grant before checking the no-grant path.
       await asOwner(token=>action('DELETE',token));
       qa23ReadPhase='before';
       check(await nativeFlow(readCtx,metadata,qaApp,qa23Subject,'MCP_RESOURCE'),
         'AUTHZ_XUSER_BEFORE_GRANT_FLOW');
       await asOwner(async token=>{
         before=await qa23ReadAudit(ctx,token);
         mustClean=true; // ensure finally revokes even if Core commits and response fails
         await action('POST',token);
       });
       qa23ReadPhase='granted';
       check(await nativeFlow(readCtx,metadata,qaApp,qa23Subject,'MCP_RESOURCE'),
         'AUTHZ_XUSER_GRANTED_FLOW');
     }finally{
       if(mustClean){
         await asOwner(async token=>{
           await action('DELETE',token);
           const after=await qa23ReadAudit(ctx,token);
           check(before!==null&&after===before,'AUTHZ_XUSER_ZERO_NEW_KERNEL_EXECUTION_RECORDS');
         });
       }
       await readCtx.close();
     }
     qa23ReadPhase='revoked';
     const revokedCtx=await browser.newContext({ignoreHTTPSErrors:false,serviceWorkers:'block',acceptDownloads:false});
     try{
       await loginToSite(revokedCtx,QA23,process.env.QDIP_E2E_ZITADEL_TEST23_PASSWORD,'AUTHZ01_QA23');
       check(await nativeFlow(revokedCtx,metadata,qaApp,qa23Subject,'MCP_RESOURCE'),
         'AUTHZ_XUSER_REVOKED_FLOW');
     }finally{await revokedCtx.close();}
     marker('AUTHZ_XUSER_CROSS_USER_LIVE_E2E','PASS');
     return;
   }
   if(unassignedRoleMode){
     check(await nativeFlow(ctx,metadata,{project,client,redirect},owner.sub,'MCP_RESOURCE'),
       'AUTHZ06_LIVE_REQUESTED_BUT_UNASSIGNED_ROLE_DENIAL');
     return;
   }
   if(delegationMode){
     // A distinct B OAuth client is not authorized solely by shared user/org.
     // Prove live denial *before* A grants B any capability.
     delegationPhase='ungranted';
     check(await nativeFlow(ctx,metadata,agentApplication,owner.sub,'MCP_RESOURCE'),
       'MCP03_FOREIGN_UNGRANTED_AGENT_DENIED_FLOW');
     let granted=false;
     const action=async(method,token)=>{
       const response=await ctx.request.fetch(QA_GATEWAY+'/api/v1/qa/mcp652/agent-delegation',{
         method,timeout:15000,maxRedirects:0,
         headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
         data:{agent_application_id:agentApplication.applicationId}});
       check(response.status()===204,
         method==='POST'?'MCP03_EXPLICIT_OWNER_GRANT':'MCP03_OWNER_REVOKE');
       if(method==='POST')granted=true;
     };
     try{
       check(await nativeFlow(ctx,metadata,{project,client,redirect},owner.sub,
         'PROJECT_BASELINE',token=>action('POST',token)),'MCP03_OWNER_AUTHORIZED_GRANT_FLOW');
       delegationPhase='granted';
       check(await nativeFlow(ctx,metadata,agentApplication,owner.sub,'MCP_RESOURCE'),
         'MCP03_INDEPENDENT_AGENT_DECISION_FLOW');
     }finally{
       if(granted){
         check(await nativeFlow(ctx,metadata,{project,client,redirect},owner.sub,
           'PROJECT_BASELINE',token=>action('DELETE',token)),'MCP03_OWNER_REVOKE_FLOW');
       }
     }
     delegationPhase='revoked';
     check(await nativeFlow(ctx,metadata,agentApplication,owner.sub,'MCP_RESOURCE'),
       'MCP03_INDEPENDENT_AGENT_REVOKED_FLOW');
     marker('MCP03_INDEPENDENT_AGENT_E2E','PASS');
     return;
   }
   if(!verifyExisting&&!realDecisionMode&&!ownerBootstrapMode){
     const baseline=await nativeFlow(ctx,metadata,{project,client,redirect},owner.sub,'PROJECT_BASELINE');
     check(baseline,'MATCHED_NATIVE_BASELINE');
   }
   const requested=await nativeFlow(ctx,metadata,{project,client,redirect},owner.sub,'MCP_RESOURCE',
     async token=>{
       if(introspection)await inspectOpaque(ctx,metadata,introspection,token,{project,client},owner.sub);
       if(ownerBootstrapMode)await bootstrapQaOwner(ctx,token);
       if(applicationLinkMode||secondAppLinkMode)await linkQaApplication(ctx,token,application);
     });
   marker('MCP_RESOURCE_PKCE_RESULT',requested?'TOKEN_OBTAINED':'DENIED_OR_INTERACTION_BLOCKED');
   check(requested===true,'MCP_RESOURCE_FLOW_COMPLETED');
   if(!introspection)marker('REAL_INTROSPECTION','PERFORMED_IN_MCP_RUNTIME');
   marker('REAL_MCP_OAUTH_ACCEPTANCE','PASS');
   if(!executionMode&&!ownerBootstrapMode&&!applicationLinkMode&&!secondAppLinkMode)marker('CANONICAL_LINK_AND_WORKER_EXECUTION','NOT_RUN');
   if(ownerBootstrapMode)marker('CANONICAL_OWNER_LINK','PASS');
   if(applicationLinkMode)marker('CANONICAL_APPLICATION_LINK','PASS');
   if(secondAppLinkMode)marker('B_APP_CANONICAL_LINK','PASS');
   marker('NATIVE_TOKEN_CONTRACT_PROBE','COMPLETED');
 }finally{consoleToken=null;introspection=null;await ctx.close();await browser.close();}
}
if(process.argv.includes('--self-test'))selfTest();else main().catch(error=>{const stage=error instanceof Error&&/^[A-Z0-9_]{4,100}$/.test(error.message)?error.message:'SANITIZED_FAILURE';
 marker('NATIVE_TOKEN_CONTRACT_PROBE','FAIL_'+stage);process.exitCode=1;});

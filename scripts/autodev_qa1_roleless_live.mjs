/** Real AutoDev QA1 negative authorization, one password attempt, no mutation.
 * Proves a real Zitadel OAuth PKCE login, a valid signed access token with
 * NO autodev_operator in the QDIP organization, and live API HTTP 403.
 * Never prints/captures access tokens, cookies, auth codes, email, screenshots,
 * traces or credentials. Fails closed if token is opaque or role unexpectedly exists.
 */
import { chromium } from '@playwright/test';
import { createPublicKey, verify } from 'node:crypto';

// Canonical domain of the *same* Railway staging PWA; registered OIDC callback.
const SITE='https://autodev.qdip.ai';
const ISSUER='https://mentality-rmwj0i.eu1.zitadel.cloud';
const PROJECT='394565917515719957';
const ORG='368555767923594379';
const CLIENT='395658023814660262';
const MODE=process.env.QDIP_AUTODEV_PROOF_MODE||'roleless';
if(!['roleless','operator'].includes(MODE))throw Error('PROOF_TEST_MODE_INVALID');
const USER=MODE==='operator'?process.env.QDIP_AUTODEV_OPERATOR_LOGIN:'qa1@qdip.ai';
const PASS=MODE==='operator'?process.env.QDIP_AUTODEV_OPERATOR_PASSWORD:process.env.QDIP_AUTODEV_QA1_PASSWORD;
function require_(ok,stage){if(!ok)throw new Error(stage)}
async function field(page,selectors,wait=12000){
 const until=Date.now()+wait;
 while(Date.now()<until){
  for(const selector of selectors){
   const locator=page.locator(selector).first();
   if(await locator.isVisible().catch(()=>false))return locator;
  }
  await page.waitForTimeout(250);
 }
 return null;
}
function parseJwt(token){
 require_(typeof token==='string'&&token.length<8192,'QA1_ACCESS_TOKEN_ABSENT');
 const p=token.split('.');
 require_(p.length===3,'QA1_ACCESS_TOKEN_NOT_JWT');
 const header=JSON.parse(Buffer.from(p[0],'base64url').toString());
 const claims=JSON.parse(Buffer.from(p[1],'base64url').toString());
 require_((header.alg==='RS256'||header.alg==='RS384')&&typeof header.kid==='string','QA1_JWT_UNEXPECTED_ALG');
 return {p,header,claims};
}
async function verifiedClaims(token){
 const {p,header,claims}=parseJwt(token);
 const response=await fetch(ISSUER+'/oauth/v2/keys',{redirect:'error',signal:AbortSignal.timeout(9000)});
 require_(response.ok,'QA1_REAL_JWKS_UNAVAILABLE');
 const jwks=await response.json();
 const key=(Array.isArray(jwks.keys)?jwks.keys:[]).find(x=>x.kid===header.kid&&x.kty==='RSA');
 require_(Boolean(key),'QA1_JWKS_KID_NOT_FOUND');
 const publicKey=createPublicKey({key,format:'jwk'});
 const signed=Buffer.from(p[0]+'.'+p[1]);
 const signature=Buffer.from(p[2],'base64url');
 require_(verify(header.alg==='RS384'?'RSA-SHA384':'RSA-SHA256',signed,publicKey,signature),'QA1_JWT_SIGNATURE_INVALID');
 const now=Math.floor(Date.now()/1000);
 require_(claims.iss===ISSUER&&claims.sub&&typeof claims.sub==='string'&&
   claims.exp>now&&claims.iat<=now+20&&
   (claims.aud===PROJECT||Array.isArray(claims.aud)&&claims.aud.includes(PROJECT)),
   'QA1_LIVE_JWT_ISSUER_AUDIENCE_OR_EXPIRY_INVALID');
 const projectRoles=claims['urn:zitadel:iam:org:project:'+PROJECT+':roles'];
 require_(!projectRoles || typeof projectRoles==='object','QA1_LIVE_ROLES_INVALID');
 if(MODE==='operator'){
  require_(typeof projectRoles?.autodev_operator?.[ORG]==='string' &&
    projectRoles.autodev_operator[ORG].length>0,'PROOF_OPERATOR_ROLE_MISSING');
 }else{
  require_(!projectRoles?.autodev_operator?.[ORG], 'QA1_ACCOUNT_HAS_AUTODEV_OPERATOR_ROLE');
 }
 return claims;
}
async function main(){
 require_(typeof PASS==='string'&&PASS.length>0,
  MODE==='operator'?'PROOF_OPERATOR_PASSWORD_UNAVAILABLE':'QA1_PASSWORD_SECRET_MISSING');
 require_(typeof USER==='string'&&USER.length>0,
  MODE==='operator'?'PROOF_OPERATOR_LOGIN_UNAVAILABLE':'QA1_LOGIN_UNAVAILABLE');
 const browser=await chromium.launch({headless:true});
 const context=await browser.newContext({
  ignoreHTTPSErrors:false,serviceWorkers:'block',acceptDownloads:false,
  viewport:{width:390,height:844},
 });
 try{
  // Assert the actual Railway PWA → private Controller route even if Zitadel
  // subsequently fails before presenting a sign-in form.
  const route=SITE+'/v1/autodev/proof-cycle';
  const publicRead=await context.request.get(route,{
   headers:{'Accept':'application/json'},
   maxRedirects:0,failOnStatusCode:false,timeout:15000,
  });
  require_(publicRead.status()===403,'PROOF_ANONYMOUS_PROXY_HTTP_NOT_403');
  const publicBody=await publicRead.json().catch(()=>null);
  if(publicBody?.code!=='NOT_AUTHORIZED')
   console.error('PROOF_PUBLIC_READ_CODE='+String(publicBody?.code||'NON_JSON'));
  require_(publicBody?.code==='NOT_AUTHORIZED','PROOF_ANONYMOUS_PROXY_NOT_CONTROLLER');
  console.log('PROOF_RAILWAY_CADDY_CONTROLLER_ANONYMOUS_HTTP_403=PASS');
  const page=await context.newPage();
  page.setDefaultTimeout(12000);
  const response=await page.goto(SITE,{waitUntil:'domcontentloaded',timeout:30000});
  require_(response?.status()===200,'QA1_PWA_UNAVAILABLE');
  const entry=page.locator('button.live-monitor__login');
  await entry.waitFor({state:'visible',timeout:15000});
  require_(!(await entry.isDisabled()),'QA1_ZITADEL_SIGNIN_DISABLED');
  let pkce=null;
  let authorizeStatus=null;
  page.on('response', response=>{
   try{
    const url=new URL(response.url());
    if(url.origin===ISSUER && url.pathname==='/oauth/v2/authorize'){
     authorizeStatus=response.status();
    }
   }catch{}
  });
  page.on('request', request=>{
   try{
    const url=new URL(request.url());
    if(url.origin===ISSUER && url.pathname==='/oauth/v2/authorize'){
     pkce={
      client:url.searchParams.get('client_id'),
      challenge:url.searchParams.get('code_challenge_method'),
      redirect:url.searchParams.get('redirect_uri'),
      scope:url.searchParams.get('scope')||'',
     };
    }
   }catch{}
  });
  await entry.click();
  await page.waitForURL(url=>url.origin===ISSUER,{timeout:30000});
  require_(pkce?.client===CLIENT && pkce?.challenge==='S256' &&
   pkce?.redirect===SITE+'/auth/callback' && pkce?.scope.includes(PROJECT),
   'QA1_PKCE_APPLICATION_MISMATCH');
  console.log(MODE==='operator'?'PROOF_OPERATOR_REAL_ZITADEL_PKCE=PASS':'AUTODEV_QA1_REAL_ZITADEL_PKCE=PASS');

  const username=await field(page,[
   'input[autocomplete="username"]','input[name="loginName"]',
   'input[name="loginname"]','input[name="username"]',
   'input[name="email"]','input[type="email"]','input[type="text"]'
  ]);
  if(!username){
   // Public login DOM only. Never print URL query, form values, credentials,
   // cookies, tokens, PKCE state, full body text, or screenshots.
   const diag=await page.evaluate(()=>({
    path:location.pathname,
    host:location.host,
    title:document.title,
    readyState:document.readyState,
    visibleTextLength:(document.body?.innerText||'').length,
    errorTextHint:/error|invalid|not found|unauthorized|unavailable/i.test(document.body?.innerText||''),
    safeErrorExcerpt:(document.body?.innerText||'').slice(0,400)
     .replace(/https?:\/\/\S+/g,'[URL]')
     .replace(/[A-Za-z0-9_\-]{24,}/g,'[REDACTED]')
     .slice(0,240),

    inputs:[...document.querySelectorAll('input')].slice(0,12).map(e=>({
     type:e.type||'',name:e.name||'',autocomplete:e.autocomplete||'',
     placeholder:e.getAttribute('placeholder')||'',
     visible:!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length),
    })),
    iframes:document.querySelectorAll('iframe').length,
    buttons:document.querySelectorAll('button').length,
   }));
   console.error('PROOF_PUBLIC_LOGIN_DOM_DIAG='+JSON.stringify({...diag,authorizeStatus}));
  }
  require_(Boolean(username),'QA1_LOGIN_FORM_MISSING');
  await username.fill(USER);
  let password=await field(page,['input[autocomplete="current-password"]','input[type="password"]'],1000);
  if(!password){
   await username.press('Enter');
   password=await field(page,['input[autocomplete="current-password"]','input[type="password"]'],12000);
  }
  if(!password){
   const authUi=await page.evaluate(()=>({
    host:location.host,
    path:location.pathname,
    visibleInputs:[...document.querySelectorAll('input')].filter(e=>
     e.offsetWidth||e.offsetHeight||e.getClientRects().length).slice(0,10)
     .map(e=>({type:e.type||'',name:e.name||'',autocomplete:e.autocomplete||''})),
    visibleButtons:[...document.querySelectorAll('button')].filter(e=>
     e.offsetWidth||e.offsetHeight||e.getClientRects().length).length,
    providerHint:/google|microsoft|external|sso|identity provider/i.test(document.body?.innerText||''),
    safeText:(document.body?.innerText||'').slice(0,350)
     .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,'[EMAIL]')
     .replace(/https?:\/\/\S+/g,'[URL]')
     .replace(/[A-Za-z0-9_\-]{24,}/g,'[REDACTED]'),
   }));
   console.error('PROOF_PASSWORD_UI_DIAG='+JSON.stringify(authUi));
  }
  require_(Boolean(password),'QA1_PASSWORD_FORM_MISSING');
  await password.fill(PASS);
  await password.press('Enter');
  // Exactly one password attempt. MFA or consent is a genuine blocker.
  try{
   await page.waitForURL(url=>url.origin===SITE,{timeout:42000});
   await page.waitForFunction(()=>{
     for(let i=0;i<localStorage.length;i++){
       const key=localStorage.key(i);
       if(key?.startsWith('oidc.user:')){
        try{const user=JSON.parse(localStorage.getItem(key)||'{}');
          if(typeof user.access_token==='string'&&user.access_token.length>0)return true;}catch{}
       }
     }
     return false;
   },null,{timeout:18000});
  }catch{throw Error('QA1_REAL_LOGIN_MFA_OR_CALLBACK_BLOCKED');}
  const token=await page.evaluate(()=>{
   for(let i=0;i<localStorage.length;i++){
    const key=localStorage.key(i);
    if(key?.startsWith('oidc.user:')){
     try{const user=JSON.parse(localStorage.getItem(key)||'{}');
      if(typeof user.access_token==='string')return user.access_token;}catch{}
    }
   }
   return null;
  });
  require_(Boolean(token),'QA1_SESSION_TOKEN_MISSING');
  const claims=await verifiedClaims(token);
  // If the ID token does contain email, it must match the real test account.
  // Some access tokens do not include email even when the OAuth login succeeded.
  if(typeof claims.email==='string')require_(claims.email.toLowerCase()===USER,'QA1_SUBJECT_EMAIL_MISMATCH');
  console.log(MODE==='operator'?'PROOF_OPERATOR_SIGNED_ACCESS_TOKEN=PASS':'AUTODEV_QA1_SIGNED_ACCESS_TOKEN_NO_OPERATOR_ROLE=PASS');
  // The PWA's existing Caddy reverse-proxy forwards this exact route to the
  // private Railway Controller. No Controller public domain or extra token.
  const requestHeaders={'Authorization':'Bearer '+token,'Accept':'application/json'};
  const anonymous=await context.request.get(route,{
   headers:{'Accept':'application/json'},
   maxRedirects:0,failOnStatusCode:false,timeout:15000,
  });
  require_(anonymous.status()===403,'PROOF_ANONYMOUS_HTTP_NOT_403');
  const anonymousBody=await anonymous.json().catch(()=>null);
  require_(anonymousBody?.code==='NOT_AUTHORIZED','PROOF_ANONYMOUS_DENIAL_NOT_CONTROLLER');
  const answer=await context.request.get(route,{
   headers:requestHeaders,maxRedirects:0,failOnStatusCode:false,timeout:20000,
  });
  const proof=await answer.json().catch(()=>null);
  require_((answer.headers()['cache-control']||'').includes('no-store'),
   'PROOF_RESPONSE_CACHE_UNSAFE');
  if(MODE==='operator'){
   require_(answer.status()===200,'PROOF_OPERATOR_HTTP_NOT_200');
   require_(proof?.schemaVersion===1 && proof?.readOnly===true &&
    proof?.source==='github_proof_cycle' &&
    proof?.repository==='qdip-ai/qdip-core' &&
    proof?.canMerge===false && proof?.mergeReason==='NOT_EVALUATED',
    'PROOF_OPERATOR_RESPONSE_CONTRACT_INVALID');
   require_(Array.isArray(proof.items) && typeof proof.coverage==='object' &&
    ['Kernel','SDK','MCP','AutoDev','Yara'].every(x=>proof.coverage[x]),
    'PROOF_PRODUCT_COVERAGE_INVALID');
   require_(proof.items.every(item=>
    typeof item.id==='string' && typeof item.repository==='string' &&
    typeof item.url==='string' && item.url.startsWith('https://github.com/') &&
    item.canMerge===false && Array.isArray(item.evidence) &&
    typeof item.verification==='string'),
    'PROOF_EVIDENCE_IDENTITY_INVALID');
   require_(proof.items.length>0 || proof.partial===true,'PROOF_EMPTY_UNEXPLAINED');
   const invalidScope=await context.request.get(route+'?repository=attacker/example&page=1',{
    headers:requestHeaders,maxRedirects:0,failOnStatusCode:false,timeout:15000,
   });
   require_(invalidScope.status()===400,'PROOF_UNSCOPED_REPOSITORY_NOT_400');
   console.log('PROOF_OPERATOR_REAL_ZITADEL_HTTP_200_AND_SCOPE_400=PASS');
   console.log('AUTODEV_PROOF_CYCLE_OPERATOR_E2E=PASS');
   return;
  }
  require_(answer.status()===403 && proof?.code==='NOT_AUTHORIZED',
   'PROOF_ROLELESS_HTTP_NOT_403');
  const wrongOrigin=await context.request.get(route,{
   headers:{...requestHeaders,Origin:'https://attacker.invalid'},
   maxRedirects:0,failOnStatusCode:false,timeout:15000,
  });
  require_(wrongOrigin.status()===403 &&
   (await wrongOrigin.json().catch(()=>null))?.code==='FORBIDDEN',
   'PROOF_CROSS_ORIGIN_HTTP_NOT_FORBIDDEN');
  console.log('PROOF_ANONYMOUS_ROLELESS_CROSS_ORIGIN_HTTP_403=PASS');

  const denied=await context.request.get(SITE+'/v1/autodev/monitor',{
   headers:{'Authorization':'Bearer '+token,'Accept':'application/json'},
   maxRedirects:0,failOnStatusCode:false,timeout:15000,
  });
  require_(denied.status()===403,'QA1_NO_OPERATOR_HTTP_NOT_403');
  const body=await denied.json().catch(()=>null);
  require_(body?.code==='NOT_AUTHORIZED','QA1_NO_OPERATOR_DENIAL_NOT_BACKEND');
  require_((denied.headers()['cache-control']||'').includes('no-store'),'QA1_DENIAL_CACHE_UNSAFE');
  console.log('AUTODEV_QA1_REAL_NO_OPERATOR_API_403=PASS');
  // The PWA shows 'access-denied' before it revokes the local OIDC session.
  // Reloading after revocation legitimately shows the login state instead.
  await page.waitForSelector('.live-monitor__warning',{timeout:18000});
  require_((await page.locator('.mission-home').count())===0,'QA1_FIXTURE_DATA_LEAKED_TO_DENIED_USER');
  console.log('AUTODEV_QA1_NO_FAKE_RUNS_OR_COMMANDS=PASS');
  console.log('AUTODEV_QA1_LIVE_NEGATIVE_ZITADEL_E2E=PASS');
 }finally{
  await context.close();await browser.close();
 }
}
main().catch(err=>{
 const stage=err instanceof Error&&/^[A-Z0-9_]{5,100}$/.test(err.message)
   ?err.message:'QA1_BROWSER_FAILURE_REDACTED';
 console.error((MODE==='operator'?'AUTODEV_PROOF_CYCLE_OPERATOR_E2E=FAIL:':
 'AUTODEV_QA1_LIVE_NEGATIVE_ZITADEL_E2E=FAIL:')+stage);
 process.exitCode=1;
});

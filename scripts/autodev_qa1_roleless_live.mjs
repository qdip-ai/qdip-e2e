/** Real AutoDev QA1 negative authorization, one password attempt, no mutation.
 * Proves a real Zitadel OAuth PKCE login, a valid signed access token with
 * NO autodev_operator in the QDIP organization, and live API HTTP 403.
 * Never prints/captures access tokens, cookies, auth codes, email, screenshots,
 * traces or credentials. Fails closed if token is opaque or role unexpectedly exists.
 */
import { chromium } from '@playwright/test';
import { createPublicKey, verify } from 'node:crypto';

const SITE='https://autodev-mission-control-pwa-staging.up.railway.app';
const ISSUER='https://mentality-rmwj0i.eu1.zitadel.cloud';
const PROJECT='394565917515719957';
const ORG='368555767923594379';
const CLIENT='395658023814660262';
const USER='qa1@qdip.ai';
const PASS=process.env.QDIP_AUTODEV_QA1_PASSWORD;
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
 require_(!projectRoles?.autodev_operator?.[ORG], 'QA1_ACCOUNT_HAS_AUTODEV_OPERATOR_ROLE');
 return claims;
}
async function main(){
 require_(typeof PASS==='string'&&PASS.length>0,'QA1_PASSWORD_SECRET_MISSING');
 const browser=await chromium.launch({headless:true});
 const context=await browser.newContext({
  ignoreHTTPSErrors:false,serviceWorkers:'block',acceptDownloads:false,
  viewport:{width:390,height:844},
 });
 try{
  const page=await context.newPage();
  page.setDefaultTimeout(12000);
  const response=await page.goto(SITE,{waitUntil:'domcontentloaded',timeout:30000});
  require_(response?.status()===200,'QA1_PWA_UNAVAILABLE');
  const entry=page.locator('button.live-monitor__login');
  await entry.waitFor({state:'visible',timeout:15000});
  require_(!(await entry.isDisabled()),'QA1_ZITADEL_SIGNIN_DISABLED');
  await entry.click();
  await page.waitForURL(url=>url.origin===ISSUER,{timeout:30000});
  const url=new URL(page.url());
  require_(url.origin===ISSUER && url.searchParams.get('client_id')===CLIENT &&
   url.searchParams.get('code_challenge_method')==='S256' &&
   url.searchParams.get('redirect_uri')===SITE+'/auth/callback' &&
   (url.searchParams.get('scope')||'').includes(PROJECT),
   'QA1_PKCE_APPLICATION_MISMATCH');
  console.log('AUTODEV_QA1_REAL_ZITADEL_PKCE=PASS');

  const username=await field(page,[
   'input[autocomplete="username"]','input[name="loginName"]',
   'input[name="loginname"]','input[name="username"]',
   'input[name="email"]','input[type="email"]','input[type="text"]'
  ]);
  require_(Boolean(username),'QA1_LOGIN_FORM_MISSING');
  await username.fill(USER);
  let password=await field(page,['input[autocomplete="current-password"]','input[type="password"]'],1000);
  if(!password){
   await username.press('Enter');
   password=await field(page,['input[autocomplete="current-password"]','input[type="password"]'],12000);
  }
  require_(Boolean(password),'QA1_PASSWORD_FORM_MISSING');
  await password.fill(PASS);
  await password.press('Enter');
  // Exactly one password attempt. MFA or consent is a genuine blocker.
  try{
   await page.waitForURL(url=>url.origin===SITE,{timeout:42000});
   await page.waitForFunction(()=>{
     for(let i=0;i<sessionStorage.length;i++){
       const key=sessionStorage.key(i);
       if(key?.startsWith('oidc.user:')){
        try{const user=JSON.parse(sessionStorage.getItem(key)||'{}');
          if(typeof user.access_token==='string'&&user.access_token.length>0)return true;}catch{}
       }
     }
     return false;
   },{timeout:18000});
  }catch{throw Error('QA1_REAL_LOGIN_MFA_OR_CALLBACK_BLOCKED');}
  const token=await page.evaluate(()=>{
   for(let i=0;i<sessionStorage.length;i++){
    const key=sessionStorage.key(i);
    if(key?.startsWith('oidc.user:')){
     try{const user=JSON.parse(sessionStorage.getItem(key)||'{}');
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
  console.log('AUTODEV_QA1_SIGNED_ACCESS_TOKEN_NO_OPERATOR_ROLE=PASS');

  const denied=await context.request.get(SITE+'/v1/autodev/monitor',{
   headers:{'Authorization':'Bearer '+token,'Origin':SITE,'Accept':'application/json'},
   maxRedirects:0,failOnStatusCode:false,timeout:15000,
  });
  require_(denied.status()===403,'QA1_NO_OPERATOR_HTTP_NOT_403');
  const body=await denied.json().catch(()=>null);
  require_(body?.code==='NOT_AUTHORIZED','QA1_NO_OPERATOR_DENIAL_NOT_BACKEND');
  require_((denied.headers()['cache-control']||'').includes('no-store'),'QA1_DENIAL_CACHE_UNSAFE');
  console.log('AUTODEV_QA1_REAL_NO_OPERATOR_API_403=PASS');
  await page.goto(SITE,{waitUntil:'domcontentloaded'});
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
 console.error('AUTODEV_QA1_LIVE_NEGATIVE_ZITADEL_E2E=FAIL:'+stage);
 process.exitCode=1;
});

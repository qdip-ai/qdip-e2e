/**
 * One-shot QA app-C provisioning on the existing Zitadel QA project only.
 * Requires a real QA21 ORG_OWNER browser login, no admin secrets and no Google.
 * The returned app/client IDs are public identifiers; no credentials printed.
 * Never touches production/main Zitadel org or other applications.
 */
import {chromium} from '@playwright/test';
import {createServer} from 'node:http';
import {randomBytes,createHash,createHmac} from 'node:crypto';

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

// RFC6238: create an actual second factor for this disposable QA principal.
// No shared factor, plaintext secret logging, MFA skip or provider configuration change.
function makeTotp(secret,instant=Date.now()){
  if(!/^[A-Z2-7]{16,128}={0,6}$/i.test(secret))throw Error('TOTP_SECRET_MALFORMED');
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let buffer=0,bits=0,bytes=[];
  for(const letter of secret.replace(/=+$/,'').toUpperCase()){
    buffer=(buffer<<5)|alphabet.indexOf(letter);
    bits+=5;
    if(bits>=8){bits-=8;bytes.push((buffer>>bits)&255);}
    buffer&=(1<<bits)-1;
  }
  const count=Buffer.alloc(8);
  count.writeBigUInt64BE(BigInt(Math.floor(instant/30000)));
  const mac=createHmac('sha1',Buffer.from(bytes)).update(count).digest();
  const offset=mac[mac.length-1]&15;
  const numeric=(
    ((mac[offset]&127)<<24) | ((mac[offset+1]&255)<<16) |
    ((mac[offset+2]&255)<<8) | (mac[offset+3]&255)
  )>>>0;
  return String(numeric%1000000).padStart(6,'0');
}
async function registerQaTotp(ctx,adminBearer,userId){
  const url=ISSUER+'/v2/users/'+encodeURIComponent(userId)+'/totp';
  const headers={Authorization:'Bearer '+adminBearer,'Content-Type':'application/json'};
  const request=await ctx.request.post(url,{
    headers,data:{},timeout:15000,maxRedirects:0});
  check(request.status()===200,'QA_SECOND_REAL_TOTP_REGISTRATION_200');
  const response=await request.json().catch(()=>null);
  let secret=response?.secret;
  check(typeof secret==='string'&&secret.length>=16,
    'QA_SECOND_REAL_TOTP_SECRET_RECEIVED_PRIVATELY');
  const confirmation=await ctx.request.post(url+'/verify',{
    headers,data:{code:makeTotp(secret)},timeout:15000,maxRedirects:0});
  check(confirmation.status()===200,'QA_SECOND_REAL_TOTP_VERIFIED_200');
  const factors=await ctx.request.get(
    ISSUER+'/v2/users/'+encodeURIComponent(userId)+'/authentication_methods',{
      headers,timeout:15000,maxRedirects:0});
  const methods=await factors.json().catch(()=>null);
  check(factors.status()===200&&Array.isArray(methods?.authMethodTypes)&&
    methods.authMethodTypes.some(x=>typeof x==='string'&&x.includes('TOTP')),
    'QA_SECOND_REGISTERED_TOTP_READBACK');
  // Held in the process only until a real browser signs in; never persisted.
  return secret;
}

async function proveEphemeralSecondQaUser(browser,adminContext,bearer){
  const stamp=process.env.GITHUB_RUN_ID;
  check(/^[0-9]{5,24}$/.test(stamp||''),'QA_SECOND_RUN_ISOLATED_ID');
  const email='sdk555-qa-user-'+stamp+'@example.com';
  const password=randomBytes(32).toString('base64url')+'!Aa9';
  let userId=null;
  try{
    const creation=await adminContext.request.post(ISSUER+'/v2/users/new',{
      data:{organizationId:ORG,username:email,human:{
        profile:{givenName:'SDK555',familyName:'QA',displayName:'SDK555 test user'},
        email:{email,isVerified:true},
        password:{password,changeRequired:false},
      }},
      headers:{Authorization:'Bearer '+bearer,'Content-Type':'application/json'},
      timeout:20000,maxRedirects:0,
    });
    console.log('SDK555_QA_SECOND_CREATE_STATUS='+creation.status());
    check(creation.status()===200,'QA_SECOND_USER_CREATED_200');
    const created=await creation.json().catch(()=>null);
    userId=created?.id;
    check(typeof userId==='string'&&/^[0-9]{1,32}$/.test(userId),
      'QA_SECOND_REAL_USER_ID');
    const who=await adminContext.request.get(
      ISSUER+'/v2/users/'+encodeURIComponent(userId),{
        headers:{Authorization:'Bearer '+bearer},timeout:15000,maxRedirects:0});
    const record=await who.json().catch(()=>null);
    check(who.status()===200&&record?.user?.userId===userId&&
      record?.user?.details?.resourceOwner===ORG,
      'QA_SECOND_CANONICAL_SAME_ORG');
    check(record?.user?.human?.email?.isVerified===true,
      'QA_SECOND_EMAIL_VERIFIED_BY_IDENTITY_PROVIDER');
    check(record?.user?.human?.passwordChangeRequired!==true,
      'QA_SECOND_PASSWORD_CHANGE_NOT_REQUIRED');
    const factors=await adminContext.request.get(
      ISSUER+'/v2/users/'+encodeURIComponent(userId)+'/authentication_methods',{
        headers:{Authorization:'Bearer '+bearer},timeout:15000,maxRedirects:0});
    console.log('SDK555_QA_SECOND_AUTH_METHODS_HTTP='+factors.status());
    if(factors.status()===200){
      const methods=await factors.json().catch(()=>null);
      const types=methods?.authMethodTypes??[];
      for(const method of ['PASSWORD','TOTP','OTP_EMAIL','OTP_SMS']){
        console.log('SDK555_QA_SECOND_FACTOR_'+method+'='+
          (Array.isArray(types)&&types.some(x=>typeof x==='string'&&x.includes(method))
           ?'PRESENT':'ABSENT'));
      }
    }
    const totpSecret=await registerQaTotp(adminContext,bearer,userId);
    const callbackUri='http://127.0.0.1:8765/oidc/callback';
    const state=randomBytes(24).toString('base64url');
    const verifier=randomBytes(32).toString('base64url');
    const challenge=createHash('sha256').update(verifier).digest('base64url');
    let receiver;
    const code=new Promise(resolve=>receiver=resolve);
    const server=createServer((req,res)=>{
      let url;
      try{url=new URL(req.url,callbackUri);}catch{res.writeHead(400).end();return;}
      const authCode=url.searchParams.get('code');
      if(req.method!=='GET'||url.pathname!=='/oidc/callback'||
         url.searchParams.get('state')!==state||!authCode||
         authCode.length<8||authCode.length>2048){
        res.writeHead(400).end();return;
      }
      res.writeHead(200,{'Cache-Control':'no-store','Referrer-Policy':'no-referrer'});
      res.end('QA test callback');
      receiver(authCode);
    });
    await new Promise((resolve,reject)=>{
      server.once('error',reject);server.listen(8765,'127.0.0.1',resolve);
    });
    const ctx=await browser.newContext({ignoreHTTPSErrors:false,
      acceptDownloads:false,serviceWorkers:'block',viewport:{width:1280,height:800}});
    try{
      const page=await ctx.newPage();
      const authorize=new URL(ISSUER+'/oauth/v2/authorize');
      for(const [k,v] of Object.entries({
        client_id:process.env.QDIP_SDK_MANAGED_CLIENT_ID,
        redirect_uri:callbackUri,response_type:'code',
        code_challenge:challenge,code_challenge_method:'S256',
        state,nonce:randomBytes(24).toString('base64url'),
        scope:'openid profile email urn:zitadel:iam:org:project:id:'+
          process.env.QDIP_SDK_QA_PROJECT_ID+':aud',
      }))authorize.searchParams.set(k,v);
      await page.goto(authorize.toString(),{waitUntil:'domcontentloaded',timeout:30000});
      const name=await find(page,['input[autocomplete="username"]','input[name="loginName"]',
        'input[name="username"]','input[name="loginname"]','input[name="email"]',
        'input[type="email"]','input[type="text"]']);
      await name.fill(email);
      let pass=page.locator('input[type="password"]').first();
      if(!(await pass.isVisible().catch(()=>false))){
        await name.press('Enter');
        pass=await find(page,['input[autocomplete="current-password"]','input[type="password"]']);
      }
      await pass.fill(password);await pass.press('Enter');
      // The QA organization requires MFA enrollment. Authenticate with
      // this user's real, independently registered TOTP second factor.
      const otpSelector='input[autocomplete="one-time-code"],input[name="code"],'+
        'input[name*="otp"],input[id*="otp"],input[id*="code"],'+
        'input[inputmode="numeric"]';
      let otpEntered=false;
      for(let n=0;n<70;n++){
        const otp=page.locator(otpSelector).first();
        if(await otp.isVisible().catch(()=>false)){
          await otp.fill(makeTotp(totpSecret));
          await otp.press('Enter');
          otpEntered=true;
          break;
        }
        await page.waitForTimeout(200);
      }
      console.log('SDK555_SECOND_TOTP_PROMPT='+
        (otpEntered?'REAL_BROWSER_CODE_ENTERED':'NOT_VISIBLE'));
      let authCode;
      try{
        authCode=await Promise.race([code,new Promise((_,reject)=>
          setTimeout(()=>reject(Error('QA_SECOND_OIDC_CALLBACK_TIMEOUT')),40000))]);
      }catch(error){
        // Diagnostic labels only. No URL query, email, form values or token.
        const terminal=new URL(page.url());
        const pageBody=(await page.locator('body').innerText().catch(()=>''))||'';
        const lower=pageBody.toLowerCase();
        const categories={
          issuerOrigin:terminal.origin===ISSUER,
          passwordFieldVisible:await page.locator('input[type="password"]').first()
            .isVisible().catch(()=>false),
          emailVerification:/verify your email|verify email|email verification|email code/.test(lower),
          passwordChange:/change password|set password|password change|new password/.test(lower),
          codeChallenge:/verification code|one-time code|otp|authenticator|two-factor|mfa/.test(lower),
          errorAlert:await page.locator('[role="alert"]').count()>0,
          loginDenied:/invalid|not found|failed|denied|locked|inactive|error/.test(lower),
          verifyUser:/verify user|verify your account|confirm user|verify identity/.test(lower),
          codeProvidedInEmail:/code provided in the verification email/.test(lower),
          enterCode:/enter the code|enter code|type the code/.test(lower),
          sentToEmail:/sent to your email|sent to email|email address/.test(lower),
          authenticator:/authenticator app|authenticator code|totp/.test(lower),
          setupAuthenticator:/setup authenticator|set up authenticator/.test(lower),
          otpOnEmail:/email one-time|one-time password via email|email otp/.test(lower),
          recoveryCode:/recovery code/.test(lower),
        };
        for(const [key,value] of Object.entries(categories))
          console.log('SDK555_SECOND_LOGIN_DIAGNOSTIC_'+key.toUpperCase()+
            '='+String(value).toUpperCase());
        const headings=(await page.locator('h1,h2,[role="heading"]').allTextContents().catch(()=>[]))
          .map(x=>x.trim().toLowerCase());
        for(const [name,regex] of Object.entries({
          VERIFY_USER:/verify user/,
          VERIFY_EMAIL:/verify.*email|email.*verification/,
          MFA:/multi.factor|authenticator|two.factor/,
          LOGIN:/sign in|log in/,
          AUTHENTICATION:/authentication/,
        }))console.log('SDK555_SECOND_LOGIN_HEADING_'+name+'='+
          (headings.some(x=>regex.test(x))?'PRESENT':'ABSENT'));
        // Redact all data-bearing text before reporting the visible screen;
        // no email, token, auth code, state, password or ID may leave CI.
        const visibleText=(await page.locator('body').innerText().catch(()=>''))||'';
        const neutralized=visibleText
          .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,'[EMAIL]')
          .replace(/https?:\/\/\S+/g,'[URL]')
          .replace(/[A-Za-z0-9_-]{18,}/g,'[VALUE]')
          .replace(/\b\d{4,}\b/g,'[ID]')
          .replace(/\s+/g,' ').slice(0,350);
        console.log('SDK555_SECOND_LOGIN_PATH='+
          (new URL(page.url()).pathname.replace(/[0-9]{5,}/g,'[ID]')));
        console.log('SDK555_SECOND_LOGIN_VISIBLE_TEXT_REDACTED='+
          JSON.stringify(neutralized));
        console.log('SDK555_SECOND_LOGIN_INPUT_COUNT='+
          await page.locator('input:visible').count());
        throw error;
      }
      const tokenResponse=await ctx.request.post(ISSUER+'/oauth/v2/token',{
        form:{grant_type:'authorization_code',
          client_id:process.env.QDIP_SDK_MANAGED_CLIENT_ID,
          redirect_uri:callbackUri,code:authCode,code_verifier:verifier},
        timeout:15000,maxRedirects:0});
      check(tokenResponse.status()===200,'QA_SECOND_PKCE_TOKEN_HTTP_200');
      const body=await tokenResponse.json().catch(()=>null);
      const token=body?.access_token;
      check(typeof token==='string'&&token.length>=16,
        'QA_SECOND_REAL_SCOPED_ACCESS_TOKEN');
      const user=await ctx.request.get(ISSUER+'/oidc/v1/userinfo',{
        headers:{Authorization:'Bearer '+token},timeout:15000,maxRedirects:0});
      const data=await user.json().catch(()=>null);
      check(user.status()===200&&data?.sub===userId,'QA_SECOND_EXACT_SUBJECT');
      console.log('SDK555_QA_SECOND_USER_REAL_PKCE_SAME_ORG=PASS');
    }finally{
      await ctx.close();
      await new Promise(resolve=>server.close(resolve));
    }
  }finally{
    if(userId){
      const deletion=await adminContext.request.delete(
        ISSUER+'/v2/users/'+encodeURIComponent(userId),{
          headers:{Authorization:'Bearer '+bearer},timeout:20000,maxRedirects:0});
      check(deletion.status()===200,'QA_SECOND_DELETED_AFTER_TEST_200');
      const checkGone=await adminContext.request.get(
        ISSUER+'/v2/users/'+encodeURIComponent(userId),{
          headers:{Authorization:'Bearer '+bearer},timeout:15000,maxRedirects:0});
      check(checkGone.status()===404,'QA_SECOND_CLEANUP_INDEPENDENT_READBACK_404');
    }
  }
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
      await proveEphemeralSecondQaUser(browser,ctx,bearer);
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
        appType:'OIDC_APP_TYPE_NATIVE',authMethodType:'OIDC_AUTH_METHOD_TYPE_NONE',
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
    await proveEphemeralSecondQaUser(browser,ctx,bearer);
  }finally{await ctx.close();await browser.close();}
}
main().catch(e=>{
  const label=e instanceof Error&&/^[A-Z0-9_]{4,96}$/.test(e.message)?
    e.message:'SANITIZED_FAILURE';
  console.error('SDK555_QA_APP_C_PROVISIONING=BLOCKED_'+label);
  process.exitCode=1;
});

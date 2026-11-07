/**
 * Read-only preflight for #555's *real* same-org two-user/three-app matrix.
 * Uses existing QA21/QA1/QA2 secrets and the existing QA project. Never
 * creates accounts, apps, orgs, keys or test data. Never logs identities.
 * Fails closed when the required principals/apps are not available.
 */
import {chromium} from '@playwright/test';
import {createServer} from 'node:http';
import {createHash, randomBytes} from 'node:crypto';

const SITE='https://qdip.ai';
const ISSUER='https://mentality-rmwj0i.eu1.zitadel.cloud';
const ORG='397885387160184113';
const PROJECT=process.env.QDIP_SDK_QA_PROJECT_ID;
const CLIENT=process.env.QDIP_SDK_MANAGED_CLIENT_ID;
const CALLBACK='http://127.0.0.1:8765/oidc/callback';
function check(value,code){
  console.log('SDK555_'+code+'='+(value?'PASS':'FAIL'));
  if(!value)throw Error(code);
}
async function find(page,selectors,timeout=14000){
  const limit=Date.now()+timeout;
  while(Date.now()<limit){
    for(const selector of selectors){
      const node=page.locator(selector).first();
      if(await node.isVisible().catch(()=>false))return node;
    }
    await page.waitForTimeout(250);
  }
  throw Error('LOGIN_FIELD_UNAVAILABLE');
}
async function logIn(browser,username,password){
  if(typeof username!=='string'||username.length<5||
     typeof password!=='string'||password.length<8)
    throw Error('EXISTING_SEALED_ACCOUNT_REQUIRED');
  const ctx=await browser.newContext({ignoreHTTPSErrors:false,
    acceptDownloads:false,serviceWorkers:'block',viewport:{width:1280,height:800}});
  try{
    const page=await ctx.newPage();
    await page.goto(SITE+'/api/auth/login?return_to='+encodeURIComponent(SITE+'/en'),{
      waitUntil:'domcontentloaded',timeout:30000});
    check(new URL(page.url()).origin===ISSUER,'LOGIN_ZITADEL_ISSUER');
    const user=await find(page,['input[autocomplete="username"]','input[name="loginName"]',
      'input[name="loginname"]','input[name="username"]','input[name="email"]',
      'input[type="email"]','input[type="text"]']);
    await user.fill(username);
    let pass;
    try{pass=await find(page,['input[autocomplete="current-password"]','input[type="password"]'],1200);}
    catch{await user.press('Enter');
      pass=await find(page,['input[autocomplete="current-password"]','input[type="password"]']);}
    const callback=page.waitForResponse(r=>{
      try{return new URL(r.url()).origin===SITE&&
        new URL(r.url()).pathname==='/api/auth/callback/zitadel';}
      catch{return false;}
    },{timeout:40000});
    await pass.fill(password);
    await pass.press('Enter');
    check([302,303].includes((await callback).status()),'REAL_ZITADEL_CALLBACK');
    const response=await ctx.request.get(SITE+'/api/auth/session',{timeout:15000});
    check(response.status()===200,'SESSION_HTTP_200');
    const session=await response.json().catch(()=>null);
    check(session?.authenticated===true&&
      session?.user?.email?.toLowerCase()===username.toLowerCase(),
      'EXACT_EXISTING_TEST_LOGIN');
    return ctx;
  }catch(error){await ctx.close();throw error;}
}
async function tokenForExistingQaProject(ctx){
  const state=randomBytes(20).toString('base64url');
  const verifier=randomBytes(32).toString('base64url');
  const challenge=createHash('sha256').update(verifier).digest('base64url');
  let resolveCode;
  const code=new Promise(resolve=>resolveCode=resolve);
  const server=createServer((req,res)=>{
    let url;
    try{url=new URL(req.url,CALLBACK);}catch{res.writeHead(400).end();return;}
    const auth=url.searchParams.get('code');
    if(req.method!=='GET'||url.pathname!=='/oidc/callback'||
       url.searchParams.get('state')!==state||!auth||
       auth.length<8||auth.length>2048){res.writeHead(400).end();return;}
    res.writeHead(200,{'Cache-Control':'no-store','Referrer-Policy':'no-referrer'});
    res.end('Authorized test callback');
    resolveCode(auth);
  });
  await new Promise((res,rej)=>server.once('error',rej).listen(8765,'127.0.0.1',res));
  const page=await ctx.newPage();
  try{
    const url=new URL(ISSUER+'/oauth/v2/authorize');
    for(const [k,v] of Object.entries({
      client_id:CLIENT,redirect_uri:CALLBACK,response_type:'code',
      code_challenge:challenge,code_challenge_method:'S256',state,
      nonce:randomBytes(20).toString('base64url'),
      scope:'openid profile email urn:zitadel:iam:org:project:id:'+PROJECT+':aud',
    }))url.searchParams.set(k,v);
    await page.goto(url.toString(),{waitUntil:'domcontentloaded',timeout:30000});
    const authCode=await Promise.race([
      code,new Promise((_,rej)=>setTimeout(()=>rej(Error('PKCE_CALLBACK_TIMEOUT')),40000)),
    ]);
    const response=await ctx.request.post(ISSUER+'/oauth/v2/token',{
      form:{grant_type:'authorization_code',client_id:CLIENT,
        redirect_uri:CALLBACK,code:authCode,code_verifier:verifier},
      timeout:15000,maxRedirects:0});
    check(response.status()===200,'QA_APP_PKCE_200');
    const body=await response.json().catch(()=>null);
    const token=body?.access_token;
    check(typeof token==='string'&&token.length>=16,'QA_APP_TOKEN');
    const info=await ctx.request.get(ISSUER+'/oidc/v1/userinfo',{
      headers:{Authorization:'Bearer '+token},timeout:15000,maxRedirects:0});
    check(info.status()===200,'QA_APP_USERINFO_200');
    const user=await info.json().catch(()=>null);
    check(typeof user?.sub==='string'&&user.sub.length>=5,'REAL_USER_SUBJECT');
    return {token,subject:user.sub,resourceOrg:
      user['urn:zitadel:iam:user:resourceowner:id']??null};
  }finally{
    await page.close();
    await new Promise(res=>server.close(res));
  }
}
async function readCatalog(ctx,token){
  const response=await ctx.request.post(
    ISSUER+'/zitadel.application.v2.ApplicationService/ListApplications',{
      data:{pagination:{limit:100},
        filters:[{projectIdFilter:{projectId:PROJECT}}]},
      headers:{Authorization:'Bearer '+token},timeout:15000,maxRedirects:0});
  check(response.status()===200,'QA_OWNER_APP_INVENTORY_200');
  const json=await response.json().catch(()=>null);
  const rows=json?.applications??[];
  const total=json?.pagination?.totalResult;
  check(Array.isArray(rows)&&Number(total)===rows.length&&
    rows.every(x=>x?.projectId===PROJECT&&
      x?.state==='APPLICATION_STATE_ACTIVE'),'QA_PROJECT_INVENTORY_EXACT');
  const oidc=rows.filter(x=>x?.oidcConfiguration);
  const third=oidc.filter(x=>x.name!=='sdk-managed-qa'&&x.name!=='sdk-external-qa');
  console.log('SDK555_QA_PROJECT_DISTINCT_USER_APPS='+oidc.length);
  check(third.length>=1,'THIRD_EXISTING_OIDC_APPLICATION');
}
async function main(){
  check(typeof PROJECT==='string'&&/^[0-9]{1,32}$/.test(PROJECT)&&
    typeof CLIENT==='string'&&CLIENT.length>=8,'QA_PROJECT_CONFIG_PRESENT');
  const identities=[
    ['QA21',process.env.QDIP_E2E_ZITADEL_TEST21_LOGIN,
      process.env.QDIP_E2E_ZITADEL_TEST21_PASSWORD],
    ['QA1',process.env.QDIP_E2E_ZITADEL_TEST1_LOGIN,
      process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD],
    ['QA2',process.env.QDIP_E2E_ZITADEL_TEST2_LOGIN,
      process.env.QDIP_E2E_ZITADEL_TEST2_PASSWORD],
  ];
  const browser=await chromium.launch({headless:true});
  const info=[];
  try{
    for(const [name,username,password] of identities){
      const ctx=await logIn(browser,username,password);
      try{
        const principal=await tokenForExistingQaProject(ctx);
        info.push({name,resourceOrg:principal.resourceOrg,subject:principal.subject});
        if(name==='QA21')await readCatalog(ctx,principal.token);
        // Do not print token, subject, org IDs or response body.
        console.log('SDK555_'+name+'_SIGNED_PKCE=PASS');
      }finally{await ctx.close();}
    }
    check(info.length===3&&new Set(info.map(x=>x.subject)).size===3,
      'THREE_DISTINCT_REAL_QA_USERS');
    const same=info.filter(x=>x.resourceOrg===ORG);
    console.log('SDK555_EXISTING_USERS_IN_QA_ORG='+same.length);
    check(same.length>=2,'TWO_EXISTING_USERS_IN_SAME_QA_ORG');
    console.log('SDK555_SAME_ORG_MATRIX_PREFLIGHT=PASS');
  }finally{await browser.close();}
}
main().catch(err=>{
  const label=err instanceof Error&&/^[A-Z0-9_]{6,96}$/.test(err.message)?
    err.message:'SANITIZED_BROWSER_FAILURE';
  console.error('SDK555_SAME_ORG_MATRIX_PREFLIGHT=BLOCKED_'+label);
  process.exitCode=1;
});

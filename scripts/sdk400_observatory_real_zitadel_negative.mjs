/**
 * #400 real browser authorization probe against the already deployed Observatory.
 * Uses existing sealed QA identities; every security POST is guaranteed
 * non-mutating (invalid revision/identity or wrong Origin).
 * Do not log credentials, cookies, storage state, response bodies or token URLs.
 */
import { chromium, request } from '@playwright/test';
const SITE='https://qdip.ai';
const OBS='https://observatory.qdip.ai';
const YARA='remote-3b25f5ae494aa7bf-secretary';
const BAD='sdk400-nonexistent-negative-fixture';
const body={
  expected_revision:-1,plugin_version:'0.1.0',
  reason:'Read-only security authorization QA; invalid revision intentionally',
  review_reference:'SDK400-ROLE-NEGATIVE-20261102',
  risk_acknowledged:true
};
function check(ok,tag){if(!ok)throw Error(tag);}
async function find(page,select,ms=14000){
  const end=Date.now()+ms;
  while(Date.now()<end){
    for(const s of select){
      const el=page.locator(s).first();
      if(await el.isVisible().catch(()=>false))return el;
    }
    await page.waitForTimeout(200);
  }
  throw Error('LOGIN_FORM_MISSING');
}
async function login(browser,account,password,admin){
  check(typeof password==='string'&&password.length>0,'SEALED_PASSWORD_ABSENT');
  const context=await browser.newContext({
    serviceWorkers:'block',ignoreHTTPSErrors:false,acceptDownloads:false
  });
  try{
    const page=await context.newPage();
    await page.goto(SITE+'/api/auth/login?return_to='+encodeURIComponent(OBS+'/uk/admin/plugins'),{
      waitUntil:'domcontentloaded',timeout:30000
    });
    const username=await find(page,[
      'input[autocomplete="username"]','input[name="loginName"]','input[name="loginname"]',
      'input[name="username"]','input[name="email"]','input[type="email"]','input[type="text"]'
    ]);
    await username.fill(account);
    let pass;
    try{pass=await find(page,['input[autocomplete="current-password"]','input[type="password"]'],1100);}
    catch{await username.press('Enter');pass=await find(page,['input[autocomplete="current-password"]','input[type="password"]']);}
    const callback=page.waitForResponse(x=>{
      try{const url=new URL(x.url());return url.origin===SITE&&url.pathname==='/api/auth/callback/zitadel'}
      catch{return false}
    },{timeout:40000});
    await pass.fill(password);
    await pass.press('Enter');
    check([302,303].includes((await callback).status()),'ZITADEL_CALLBACK_DENIED');
    const sessionResponse=await context.request.get(OBS+'/api/auth/session',{timeout:20000});
    check(sessionResponse.status()===200,'SESSION_HTTP_DENIED');
    const session=await sessionResponse.json();
    check(session.authenticated===true&&session.observatoryAdmin===admin,'AUTH_ROLE_INCORRECT');
    console.log('SDK400_REAL_ZITADEL_'+(admin?'ADMIN':'ROLELESS')+'_SESSION=PASS');
    // Owner discovery is authorized separately from Observatory administrator role.
    // Read-only exact founder-org lookup; never log identities, tokens or org records.
    const owned=await context.request.get(OBS+'/api/observatory/organizations',{timeout:20000});
    check(owned.status()===200,'OWNER_DISCOVERY_DENIED');
    const ownedResponse=await owned.json();
    check(Array.isArray(ownedResponse.organizations),'OWNER_DISCOVERY_INVALID');
    const founderOwner=ownedResponse.organizations.some(item=>
      item && item.id==='368555767923594379' && item.state==='active'
    );
    console.log('SDK400_'+(admin?'ADMIN':'ROLELESS')+'_FOUNDER_ORG_OWNER='+
      (founderOwner?'VERIFIED':'NOT_VERIFIED'));


    const list=await context.request.get(OBS+'/api/observatory/admin/plugins',{timeout:20000});
    check(list.status()===(admin?200:403),'ADMIN_CATALOG_ROLE_BYPASS');
    const endpoint=OBS+'/api/observatory/admin/plugins/'+YARA+'/security/approve';
    const neg=await context.request.post(endpoint,{
      headers:{Origin:OBS,'content-type':'application/json'},data:body,timeout:20000
    });
    check(neg.status()===(admin?422:403),'INVALID_REVIEW_CONTRACT_NOT_REJECTED');
    if(admin){
      const foreign=await context.request.post(
        OBS+'/api/observatory/admin/plugins/'+BAD+'/security/approve',{
        headers:{Origin:OBS,'content-type':'application/json'},data:body,timeout:20000
      });
      check(foreign.status()===403,'UNTRUSTED_PLUGIN_REVIEW_EXPOSED');
      const cross=await context.request.post(endpoint,{
        headers:{Origin:'https://attacker.invalid','content-type':'application/json'},data:body,timeout:20000
      });
      check(cross.status()===403,'CSRF_ORIGIN_BYPASS');
      console.log('SDK400_ADMIN_UNTRUSTED_REVIEW_AND_CSRF_DENY=PASS');
    }else{
      console.log('SDK400_ROLELESS_DIRECT_SECURITY_POST_DENY=PASS');
    }
  }finally{await context.close();}
}
async function main(){
  const credentials=[
    ['qa@qdip.ai',process.env.QDIP_E2E_ZITADEL_TEST_PASSWORD,true],
    ['qa1@qdip.ai',process.env.QDIP_E2E_ZITADEL_TEST1_PASSWORD,false],
    ['qa2@qdip.ai',process.env.QDIP_E2E_ZITADEL_TEST2_PASSWORD,false]
  ];
  const anon=await request.newContext({ignoreHTTPSErrors:false});
  try{
    const endpoint=OBS+'/api/observatory/admin/plugins/'+YARA+'/security/approve';
    const req=await anon.post(endpoint,{
      headers:{Origin:OBS,'content-type':'application/json'},data:body
    });
    check(req.status()===401,'ANONYMOUS_SECURITY_POST_NOT_DENIED');
    console.log('SDK400_ANONYMOUS_SECURITY_POST_DENY=PASS');
  }finally{await anon.dispose();}
  const browser=await chromium.launch({headless:true});
  try{for(const [user,pass,admin] of credentials)await login(browser,user,pass,admin)}
  finally{await browser.close()}
  console.log('SDK400_ZITADEL_OBSERVATORY_NEGATIVE_BROWSER=PASS');
  console.log('SDK400_OWNER_POSITIVE_APPROVE_REVOKE=NOT_RUN');
}
main().catch(e=>{
  const code=e instanceof Error&&/^[A-Z0-9_]{6,100}$/.test(e.message)?e.message:'REDACTED_BROWSER_FAILURE';
  console.error('SDK400_ZITADEL_OBSERVATORY_NEGATIVE_BROWSER=FAIL:'+code);
  process.exitCode=1;
});

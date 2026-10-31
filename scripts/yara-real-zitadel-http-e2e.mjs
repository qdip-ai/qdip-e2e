/**
 * Yara candidate real-user HTTP E2E against an isolated Railway QA API.
 * Uses the existing public QDIP Zitadel OIDC client with genuine code+PKCE.
 * No synthetic identity, no production API mutation, no token/cookie outputs.
 */
import {chromium} from '@playwright/test';
import {createHash, randomBytes, randomUUID} from 'node:crypto';

const SITE='https://qdip.ai';
const API='https://yara-qa-api-sandbox.up.railway.app';
const EXPECTED_CLIENT='394566248211424533';
const EXPECTED_AUDIENCE='394565917515719957';
const QA_WEB='https://yara-qa-web-sandbox.up.railway.app';
const LOGIN=process.env.QDIP_E2E_ZITADEL_TEST_LOGIN;
const PASSWORD=process.env.QDIP_E2E_ZITADEL_TEST_PASSWORD;
function gate(ok,stage){if(!ok)throw Error(stage);}
async function visible(page,selectors,timeout=12000){
  const end=Date.now()+timeout;
  while(Date.now()<end){
    for(const s of selectors){const f=page.locator(s).first();if(await f.isVisible().catch(()=>false))return f;}
    await page.waitForTimeout(250);
  }
  return null;
}
async function run(){
  gate(Boolean(LOGIN)&&Boolean(PASSWORD),'YARA_EXISTING_ZITADEL_TEST_ACCOUNT_NOT_BOUND');
  const browser=await chromium.launch({headless:true});
  const context=await browser.newContext({ignoreHTTPSErrors:false,serviceWorkers:'block',acceptDownloads:false});
  try{
    const plain=await context.request.get(API+'/health/ready',{maxRedirects:0,timeout:15000});
    gate(plain.status()===200,'YARA_QA_API_HEALTH_NOT_200');
    const noAuth=await context.request.get(API+'/v1/delegations',{maxRedirects:0,timeout:15000});
    gate(noAuth.status()===401,'YARA_QA_UNAUTHENTICATED_READ_NOT_401');
    console.log('YARA_QA_REAL_API_HEALTH_AND_ANON_DENIAL=PASS');

    const start=await context.request.get(SITE+'/api/auth/login',{maxRedirects:0,timeout:15000});
    gate(start.status()===302,'QDIP_EXISTING_OIDC_CLIENT_START_FAILED');
    const target=new URL(start.headers()['location']||'');
    gate(target.protocol==='https:'&&target.searchParams.get('client_id')===EXPECTED_CLIENT,
      'QDIP_EXISTING_PUBLIC_CLIENT_ID_MISMATCH');
    gate(target.searchParams.get('code_challenge_method')==='S256'&&
      target.searchParams.get('redirect_uri')===SITE+'/api/auth/callback/zitadel',
      'QDIP_EXISTING_PKCE_REDIRECT_MISMATCH');
    const scope=target.searchParams.get('scope')||'';
    gate(scope.includes(EXPECTED_AUDIENCE),'QDIP_EXISTING_CLIENT_AUDIENCE_MISMATCH');

    const metadata=await context.request.get(target.origin+'/.well-known/openid-configuration',{timeout:15000});
    gate(metadata.status()===200,'QDIP_ZITADEL_DISCOVERY_FAILED');
    const oidc=await metadata.json();
    gate(oidc.issuer===target.origin&&new URL(oidc.token_endpoint).origin===target.origin&&
      new URL(oidc.authorization_endpoint).origin===target.origin,
      'QDIP_ZITADEL_DISCOVERY_ORIGIN_MISMATCH');

    const verifier=randomBytes(32).toString('base64url');
    const state=randomBytes(24).toString('base64url');
    const auth=new URL(oidc.authorization_endpoint);
    const params={
      client_id:EXPECTED_CLIENT,response_type:'code',
      redirect_uri:SITE+'/api/auth/callback/zitadel',
      scope,state,nonce:randomBytes(24).toString('base64url'),
      code_challenge:createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method:'S256'
    };
    for(const [key,value] of Object.entries(params))auth.searchParams.set(key,value);

    // Never submit the callback to the production Web: it has no matching state.
    // Intercept the one-time authorization code in the browser request itself.
    await context.route(SITE+'/api/auth/callback/zitadel**',route=>route.abort());
    const page=await context.newPage();
    await page.goto(auth.toString(),{waitUntil:'domcontentloaded',timeout:30000});
    const username=await visible(page,[
      'input[autocomplete="username"]','input[name="loginName"]','input[name="loginname"]',
      'input[name="username"]','input[name="email"]','input[type="email"]','input[type="text"]'
    ]);
    gate(Boolean(username),'YARA_REAL_ZITADEL_EXISTING_CLIENT_LOGIN_FORM_MISSING');
    await username.fill(LOGIN);
    let password=await visible(page,['input[autocomplete="current-password"]','input[type="password"]'],1200);
    if(!password){await username.press('Enter');password=await visible(page,[
      'input[autocomplete="current-password"]','input[type="password"]'
    ]);}
    gate(Boolean(password),'YARA_REAL_ZITADEL_EXISTING_CLIENT_PASSWORD_FIELD_MISSING');
    const callbackPromise=page.waitForRequest(req=>{
      try{const u=new URL(req.url());return u.origin===SITE&&
        u.pathname==='/api/auth/callback/zitadel'&&u.searchParams.get('state')===state;
      }catch{return false;}
    },{timeout:30000});
    await password.fill(PASSWORD);
    await password.press('Enter');
    const req=await callbackPromise;
    const callback=new URL(req.url());
    gate(!callback.searchParams.has('error'),'YARA_REAL_ZITADEL_EXISTING_CLIENT_OIDC_ERROR');
    const code=callback.searchParams.get('code');
    gate(typeof code==='string'&&code.length>12,'YARA_REAL_ZITADEL_EXISTING_CLIENT_NO_CODE');
    const tokenResponse=await context.request.post(oidc.token_endpoint,{
      headers:{'Content-Type':'application/x-www-form-urlencoded'},maxRedirects:0,timeout:15000,
      data:new URLSearchParams({
        grant_type:'authorization_code',code,client_id:EXPECTED_CLIENT,
        redirect_uri:SITE+'/api/auth/callback/zitadel',code_verifier:verifier
      }).toString()
    });
    gate(tokenResponse.status()===200,'YARA_REAL_ZITADEL_EXISTING_CLIENT_TOKEN_EXCHANGE_DENIED');
    const token=await tokenResponse.json().catch(()=>null);
    gate(token?.token_type?.toLowerCase()==='bearer'&&typeof token.access_token==='string',
      'YARA_REAL_ZITADEL_EXISTING_CLIENT_ACCESS_TOKEN_UNAVAILABLE');
    console.log('YARA_REAL_ZITADEL_EXISTING_CLIENT_PKCE_TOKEN=PASS');

    const headers={Authorization:'Bearer '+token.access_token};
    const list=await context.request.get(API+'/v1/delegations',{headers,timeout:15000});
    gate(list.status()===200,'YARA_QA_REAL_AUTH_READ_NOT_200');
    const data=await list.json().catch(()=>null);
    gate(Array.isArray(data),'YARA_QA_REAL_AUTH_READ_SHAPE');
    console.log('YARA_QA_AUTHENTICATED_DELEGATIONS_READ=PASS');

    // All writes stay in isolated QA Postgres; no external/provider execution.
    const clientRequestId=randomUUID();
    const instruction='QA E2E synthetic delegation '+clientRequestId;
    const payload={clientRequestId,instruction,source:'typed'};
    const create=await context.request.post(API+'/v1/delegations',{
      headers:{...headers,Origin:QA_WEB},data:payload,timeout:15000
    });
    gate(create.status()===201,'YARA_QA_REAL_AUTH_CREATE_NOT_201');
    const created=await create.json().catch(()=>null);
    gate(created?.status==='RECEIVED'&&created.revision===0&&created.accepted===true&&
      typeof created.id==='string','YARA_QA_REAL_AUTH_CREATE_BODY_INVALID');
    const replay=await context.request.post(API+'/v1/delegations',{
      headers:{...headers,Origin:QA_WEB},data:payload,timeout:15000
    });
    gate(replay.status()===201&&(await replay.json()).id===created.id,
      'YARA_QA_REAL_AUTH_IDEMPOTENCY_FAILED');
    const conflict=await context.request.post(API+'/v1/delegations',{
      headers:{...headers,Origin:QA_WEB},data:{...payload,instruction:'Changed QA request'},timeout:15000
    });
    gate(conflict.status()===409,'YARA_QA_REAL_AUTH_REPLAY_CONFLICT_NOT_409');
    const notFound=await context.request.get(API+'/v1/delegations/'+randomUUID(),{
      headers,timeout:15000
    });
    gate(notFound.status()===404,'YARA_QA_REAL_AUTH_MISSING_RESOURCE_NOT_404');
    const cancel=await context.request.post(API+'/v1/delegations/'+created.id+'/cancel',{
      headers:{...headers,Origin:QA_WEB},data:{expectedRevision:0},timeout:15000
    });
    gate(cancel.status()===201,'YARA_QA_REAL_AUTH_CANCEL_NOT_201');
    const cancelled=await cancel.json().catch(()=>null);
    gate(cancelled?.status==='CANCELLED'&&cancelled.revision===1,
      'YARA_QA_REAL_AUTH_CANCEL_BODY_INVALID');
    const stale=await context.request.post(API+'/v1/delegations/'+created.id+'/cancel',{
      headers:{...headers,Origin:QA_WEB},data:{expectedRevision:0},timeout:15000
    });
    gate(stale.status()===409,'YARA_QA_REAL_AUTH_STALE_REVISION_NOT_409');
    const detail=await context.request.get(API+'/v1/delegations/'+created.id,{headers,timeout:15000});
    gate(detail.status()===200,'YARA_QA_REAL_AUTH_DETAIL_NOT_200');
    const stateAfter=await detail.json().catch(()=>null);
    gate(stateAfter?.status==='CANCELLED'&&
      stateAfter.history?.some(x=>x.action==='DELEGATION_CANCELLED'),
      'YARA_QA_REAL_AUTH_DURABLE_AUDIT_MISSING');
    console.log('YARA_QA_REAL_ZITADEL_HTTP_LIFECYCLE=PASS');
    console.log('YARA_QA_REAL_HTTP_NEGATIVE_GATES=PASS');
    console.log('YARA_QA_BROWSER_UI_SESSION=NOT_TESTED');
  }finally{await context.close();await browser.close();}
}
run().catch(e=>{const stage=e instanceof Error&&/^[A-Z0-9_]{5,100}$/.test(e.message)
  ?e.message:'YARA_QA_REAL_HTTP_E2E_REDACTED_FAILURE';
  console.error('YARA_QA_REAL_ZITADEL_HTTP_LIFECYCLE=FAIL:'+stage);
  process.exitCode=1;
});

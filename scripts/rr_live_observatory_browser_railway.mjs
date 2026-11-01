// Read-only LIVE deployed Observatory browser smoke: no synthetic login.
import { chromium } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';

const target = 'https://observatory.qdip.ai/en/readiness-recovery';
if (process.env.RAILWAY_PROJECT_ID !== 'b4c18e5e-9ae8-461c-921c-0ac97049be2e'
 || process.env.RAILWAY_ENVIRONMENT_ID !== '73a05860-cec4-4678-b3bf-1d32ac363a85'
 || process.env.RAILWAY_SERVICE_ID !== '4eedd306-8438-4255-af64-997547697057') {
 console.error('RR_BROWSER_WRONG_SANDBOX'); process.exit(2);
}
const viewports = [
 { label: 'desktop', width: 1440, height: 900 },
 { label: 'mobile-portrait', width: 390, height: 844 },
 { label: 'mobile-landscape', width: 844, height: 390 },
];
const report=[];
await mkdir('/tmp/rr-browser-evidence', { recursive:true });
const browser = await chromium.launch({headless:true, args:['--no-sandbox']});
try {
  for (const viewport of viewports) {
    const context = await browser.newContext({viewport:{width:viewport.width,height:viewport.height},isMobile:viewport.label!=='desktop',hasTouch:viewport.label!=='desktop',ignoreHTTPSErrors:false});
    const page = await context.newPage();
    const info = {viewport:viewport.label,size:viewport.width+'x'+viewport.height,tests:[]};
    try {
      const response = await page.goto(target,{waitUntil:'domcontentloaded',timeout:45000});
      const status=response?.status()??0;
      info.documentStatus=status;
      if(status !== 200) throw new Error('RR_ROUTE_HTTP_'+status);
      await page.getByTestId('qdip-access-gate').waitFor({state:'visible',timeout:15000});
      info.tests.push('anonymous_access_gate_visible');
      const title=await page.locator('h1,h2,h3').allTextContents();
      const workspaceCount=await page.getByTestId('rr-production-operator').count();
      const plannerCount=await page.getByTestId('rr-kernel-only-workspace').count();
      if (workspaceCount!==0 || plannerCount!==0) throw new Error('ANONYMOUS_RR_WORKSPACE_EXPOSED');
      info.tests.push('no_anonymous_operator_workspace');
      const bodyWidth=await page.evaluate(()=>document.documentElement.scrollWidth);
      info.scrollWidth=bodyWidth;
      if(bodyWidth>viewport.width+1) throw new Error('HORIZONTAL_OVERFLOW_'+bodyWidth);
      info.tests.push('no_horizontal_overflow');
      const [session,preflight,raw,verified] = await Promise.all([
        page.request.get('https://observatory.qdip.ai/api/rr-operator/session'),
        page.request.post('https://observatory.qdip.ai/api/rr-operator/kernel/preflight',{data:{}}),
        page.request.get('https://observatory.qdip.ai/api/rr-operator/kernel/executions/denied/presentation'),
        page.request.get('https://observatory.qdip.ai/api/rr-operator/kernel/decisions/denied/history/verified-export-page'),
      ]);
      info.authStatus=[session.status(),preflight.status(),raw.status(),verified.status()];
      if(session.status()!==200 || preflight.status()!==401 || raw.status()!==401 || verified.status()!==401) {
        throw new Error('RR_ANONYMOUS_HTTP_GATE_'+info.authStatus.join('_'));
      }
      const body=await session.json();
      if(body.authenticated!==false)throw new Error('RR_GUEST_AUTHENTICATED');
      info.tests.push('anonymous_BFF_401_read_write_verified_export');
      const signIn = page.getByRole('link',{name:/sign in|увійти|zaloguj/i}).first();
      if(await signIn.count()===0)throw new Error('RR_SIGNIN_LINK_MISSING');
      info.tests.push('sign_in_link_visible');
      info.status='PASS';
    } catch(e) {
      info.status='FAIL';info.failure=String(e).slice(0,200);
    } finally {
      const filename='/tmp/rr-browser-evidence/rr-'+viewport.label+'-history.png';
      await page.screenshot({path:filename,fullPage:true,timeout:10000}).catch(()=>{});
      info.screenshot=filename;
      console.log('RR_BROWSER_VIEWPORT='+JSON.stringify(info));
      report.push(info);
      await context.close();
    }
  }
} finally {await browser.close()}
await writeFile('/tmp/rr-browser-evidence/report.json',JSON.stringify(report));
const failed=report.filter(x=>x.status!=='PASS');
console.log('RR_BROWSER_DEPLOYED_ANONYMOUS='+ (failed.length?'FAIL':'PASS')+' '+(viewports.length-failed.length)+'/'+viewports.length);
console.log('RR_LIVE_ZITADEL_OPERATOR=NOT_TESTED');
console.log('RR_STANDALONE_PRODUCTION_CUTOVER=NOT_TESTED');
if(failed.length)process.exitCode=1;

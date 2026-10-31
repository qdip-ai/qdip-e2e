import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync,readFileSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';

const root=resolve(import.meta.dirname,'..');
const sha='a'.repeat(40);
function invoke(name,args,env={}){
  return spawnSync(process.execPath,[join(root,'scripts',name),...args],{
    encoding:'utf8',env:{...process.env,...env},timeout:5000,
  });
}
function report(scope,mutation=()=>{}){
  const projects=['desktop-chromium','mobile-portrait-chromium','mobile-landscape-chromium',
    'desktop-webkit','mobile-portrait-webkit','mobile-landscape-webkit'];
  const cases=(title)=>({title,tests:projects.map(p=>({
    projectName:p,status:'expected',results:[{status:'passed'}],
  }))});
  const specs=[cases('@public login')];
  if(scope==='full')specs.push(cases('@auth Today'));
  const fixture={suites:[{specs}],stats:{
    expected:scope==='full'?12:6,unexpected:0,skipped:0,
  }};
  mutation(fixture);
  const tmp=mkdtempSync(join(tmpdir(),'yara-test-'));
  try{
    const file=join(tmp,'report.json');
    writeFileSync(file,JSON.stringify(fixture));
    return invoke('yara-browser-report.mjs',[file,scope]);
  }finally{rmSync(tmp,{recursive:true,force:true})}
}
test('Yara browser report requires all six public browsers',()=>{
  const p=report('public');
  assert.equal(p.status,0,p.stderr);
  assert.match(p.stdout,/6\/6/);
  assert.match(p.stdout,/CANDIDATE_AUTH=NOT_TESTED/);
});
test('Yara browser report requires twelve public and authenticated browsers',()=>{
  const p=report('full');
  assert.equal(p.status,0,p.stderr);
  assert.match(p.stdout,/12\/12/);
});
test('Yara browser report rejects missing, skipped or duplicated cases',()=>{
  assert.notEqual(report('public',x=>x.suites[0].specs[0].tests.pop()).status,0);
  assert.notEqual(report('public',x=>{x.stats.skipped=1}).status,0);
  assert.notEqual(report('public',x=>x.suites[0].specs[0].tests.push(x.suites[0].specs[0].tests[0])).status,0);
});
test('Yara full gate never qualifies production or untrusted HTTP',()=>{
  const base={YARA_E2E_EXPECTED_SHA:sha,YARA_E2E_SCOPE:'full'};
  assert.notEqual(invoke('yara-browser-gate.mjs',['validate'],{
    ...base,YARA_E2E_BASE_URL:'https://yara.qdip.ai',
  }).status,0);
  assert.notEqual(invoke('yara-browser-gate.mjs',['validate'],{
    ...base,YARA_E2E_BASE_URL:'http://yara-qa.up.railway.app',
  }).status,0);
  assert.equal(invoke('yara-browser-gate.mjs',['validate'],{
    ...base,YARA_E2E_BASE_URL:'https://yara-qa.up.railway.app',
  }).status,0);
});
test('Yara live Zitadel step fails closed without sealed QA credentials',()=>{
  const r=invoke('yara-browser-gate.mjs',['login'],{
    YARA_E2E_EXPECTED_SHA:sha,YARA_E2E_SCOPE:'full',
    YARA_E2E_BASE_URL:'https://yara-qa.up.railway.app',
    QDIP_E2E_ZITADEL_TEST_LOGIN:'',QDIP_E2E_ZITADEL_TEST_PASSWORD:'',
  });
  assert.notEqual(r.status,0);
  assert.match(r.stderr,/YARA_ZITADEL_TEST_IDENTITY_MISSING/);
});


test('Yara runner executes centralized browser matrix without private checkout',()=>{
  const workflow=readFileSync(join(root,'.github','workflows','yara-browser-e2e.yml'),'utf8');
  assert.doesNotMatch(workflow,/QDIP_READ_TOKEN|repository:\s*qdip-ai\/qdip-personal-secretary/);
  assert.match(workflow,/suite\/yara\/tests\/e2e\/yara-browser\.spec\.cjs/);
  assert.match(workflow,/node_modules\/\.bin\/playwright test/);
  assert.match(workflow,/yara-browser-gate\.mjs attest/);
  assert.match(workflow,/yara-browser-report\.mjs/);
  assert.ok(existsSync(join(root,'yara','playwright.config.cjs')));
  assert.ok(existsSync(join(root,'yara','tests','e2e','yara-browser.spec.cjs')));
});

test('Yara public PR browser smoke needs no Yara source SHA',()=>{
  const r=invoke('yara-browser-gate.mjs',['validate'],{
    YARA_E2E_EXPECTED_SHA:'',YARA_E2E_SCOPE:'public',
    YARA_E2E_BASE_URL:'https://yara.qdip.ai',
  });
  assert.equal(r.status,0,r.stderr);
});

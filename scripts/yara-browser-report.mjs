/** Sanitized fail-closed Playwright evidence for public qdip-e2e logs. */
import fs from 'node:fs';
const file=process.argv[2], scope=process.argv[3];
if(!['public','full'].includes(scope||''))throw Error('YARA_REPORT_INVALID_SCOPE');
let data;
try{data=JSON.parse(fs.readFileSync(file,'utf8'))}catch{throw Error('YARA_BROWSER_JSON_REPORT_MISSING_OR_INVALID')}
function allSpecs(groups){
  const specs=[];
  for(const s of groups||[]){
    specs.push(...(s.specs||[]));
    specs.push(...allSpecs(s.suites||[]));
  }
  return specs;
}
const specs=allSpecs(data.suites);
const tests=specs.flatMap(s=>(s.tests||[]).map(t=>({name:s.title,project:t.projectName,status:t.status,result:t.results?.[0]?.status})));
const projects=['desktop-chromium','mobile-portrait-chromium','mobile-landscape-chromium',
  'desktop-webkit','mobile-portrait-webkit','mobile-landscape-webkit'];
const expected=scope==='full'?18:6;
const seen=new Set();
for(const t of tests){
  const type=t.name.includes('@public')?'public':t.name.includes('@delegation')?'delegation':t.name.includes('@auth')?'auth':'unexpected';
  const key=type+':'+t.project;
  if(!projects.includes(t.project)||type==='unexpected'||seen.has(key) ||
    (scope==='public'&&type!=='public') ||
    t.status!=='expected'||t.result!=='passed')
    throw Error('YARA_BROWSER_REQUIRED_MATRIX_FAILED');
  seen.add(key);
}
for(const name of projects){
  if(!seen.has('public:'+name)||(scope==='full'&&(!seen.has('auth:'+name)||!seen.has('delegation:'+name))))
    throw Error('YARA_BROWSER_REQUIRED_CASE_MISSING');
}
if(tests.length!==expected || data.stats?.unexpected!==0 ||
  data.stats?.skipped!==0 || data.stats?.expected!==expected)
  throw Error('YARA_BROWSER_COUNTS_OR_SKIPS_INVALID');
console.log('YARA_BROWSER_MATRIX=PASS ('+expected+'/'+expected+' real browser cases)');
console.log('YARA_BROWSER_MODE='+scope.toUpperCase());
if(scope==='public')console.log('YARA_BROWSER_CANDIDATE_AUTH=NOT_TESTED');

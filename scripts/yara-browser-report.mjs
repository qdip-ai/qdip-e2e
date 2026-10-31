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
const tests=specs.flatMap(s=>(s.tests||[]).map(t=>({
  name:s.title,project:t.projectName,status:t.status,result:t.results?.[0]?.status,
  // Source line number only, never assertion text or authenticated response.
  errorLine:(()=>{const stack=t.results?.[0]?.error?.stack||'';
    const match=/yara-browser\.spec\.cjs:(\d+):\d+/.exec(stack);
    return match?Number(match[1]):null;})(),
  errorClass:(()=>{const name=t.results?.[0]?.error?.name||'';
    return name==='TimeoutError'?'timeout':name==='Error'?'error':'other';})()
})));
const projects=['desktop-chromium','mobile-portrait-chromium','mobile-landscape-chromium',
  'desktop-webkit','mobile-portrait-webkit','mobile-landscape-webkit'];
const expected=scope==='full'?18:6;
const seen=new Set();
function failMatrix(reason){
  // Only authored test-class names, bounded project IDs and status enums.
  // No authenticated page output, response bodies, cookies or token metadata.
  console.error('YARA_BROWSER_CASE_STATUSES='+JSON.stringify(tests.map(t=>({
    type:t.name.includes('@public')?'public':t.name.includes('@delegation')?'delegation':
      t.name.includes('@auth')?'auth':'unexpected',
    project:projects.includes(t.project)?t.project:'unexpected',
    status:['expected','unexpected','skipped'].includes(t.status)?t.status:'other',
    result:['passed','failed','timedOut','skipped','interrupted'].includes(t.result)?t.result:'other',
    line:t.errorLine,errorClass:t.errorClass
  }))));
  throw Error(reason);
}
for(const t of tests){
  const type=t.name.includes('@public')?'public':t.name.includes('@delegation')?'delegation':t.name.includes('@auth')?'auth':'unexpected';
  const key=type+':'+t.project;
  if(!projects.includes(t.project)||type==='unexpected'||seen.has(key) ||
    (scope==='public'&&type!=='public') ||
    t.status!=='expected'||t.result!=='passed')
    failMatrix('YARA_BROWSER_REQUIRED_MATRIX_FAILED');
  seen.add(key);
}
for(const name of projects){
  if(!seen.has('public:'+name)||(scope==='full'&&(!seen.has('auth:'+name)||!seen.has('delegation:'+name))))
    failMatrix('YARA_BROWSER_REQUIRED_CASE_MISSING');
}
if(tests.length!==expected || data.stats?.unexpected!==0 ||
  data.stats?.skipped!==0 || data.stats?.expected!==expected)
  failMatrix('YARA_BROWSER_COUNTS_OR_SKIPS_INVALID');
console.log('YARA_BROWSER_MATRIX=PASS ('+expected+'/'+expected+' real browser cases)');
console.log('YARA_BROWSER_MODE='+scope.toUpperCase());
if(scope==='public')console.log('YARA_BROWSER_CANDIDATE_AUTH=NOT_TESTED');

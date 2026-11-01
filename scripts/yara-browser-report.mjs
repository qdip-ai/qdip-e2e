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
const expected=scope==='full'?24:6;
const seen=new Set();
function reportSafeFailureDiagnostic(){
  for(const spec of specs)for(const t of spec.tests||[]){
    if(t.status!=='unexpected')continue;
    const result=t.results?.[0]||{};
    const chunks=[...(result.stdout||[]),...(result.stderr||[])];
    const output=chunks.map(x=>typeof x==='string'?x:(typeof x?.text==='string'?x.text:'')).join('');
    for(const line of output.split('\n')){
      for(const kind of ['YARA_VIEWPORT_OVERFLOW','YARA_QA_UI_NO_POST_DIAGNOSTIC']){
        const marker=kind+'=';
        const offset=line.indexOf(marker);
        if(offset<0)continue;
        let value;
        try{value=JSON.parse(line.slice(offset+marker.length));}catch{continue;}
        if(kind==='YARA_VIEWPORT_OVERFLOW'){
          const phase=['public-login','public-privacy','today','tasks','plans','delegation-api','delegation-ui'].includes(value?.phase)?value.phase:'unknown';
          const size=value?.size||{};
          const nums={viewport:Number(size.viewport)||0,document:Number(size.document)||0,body:Number(size.body)||0};
          const outside=(Array.isArray(value?.outside)?value.outside:[]).slice(0,6).map(x=>({
            tag:/^[A-Z]{1,12}$/.test(x?.tag)?x.tag:'OTHER',
            className:/^[a-zA-Z0-9_-]{1,48}$/.test(x?.className)?x.className:'other',
            right:Number.isFinite(x?.right)?Math.round(x.right):0
          }));
          console.error('YARA_SAFE_OVERFLOW='+JSON.stringify({project:t.projectName,phase,size:nums,outside}));
        }else{
          const flags=value?.flags||{};
          const safe={};
          for(const key of ['inputHasValue','buttonPresent','buttonDisabled','alertVisible',
            'delegationVisible','serviceWorkerActive','pathIsRoot','hasRandomUUID','secureContext'])
            safe[key]=typeof flags[key]==='boolean'?flags[key]:null;
          const errors=(Array.isArray(value?.failures)?value.failures:[]).slice(0,3)
            .map(x=>['RANDOM_UUID_EXCEPTION','CRYPTO_EXCEPTION','TYPE_ERROR','OTHER_PAGE_ERROR'].includes(x)?x:'OTHER_PAGE_ERROR');
          const touch=value?.touch||{};
          const taps={};
          for(const key of ['down','up','click','buttonDown','buttonUp','buttonClick'])
            taps[key]=Number.isSafeInteger(touch[key])&&touch[key]>=0&&touch[key]<20?touch[key]:null;
          taps.centerButton=typeof touch.centerButton==='boolean'?touch.centerButton:null;
          for(const kind of ['down','up']){
            const state=touch[kind+'State']||{};
            taps[kind+'State']={
              buttonTop:Number.isFinite(state.buttonTop)?Math.round(state.buttonTop):null,
              buttonBottom:Number.isFinite(state.buttonBottom)?Math.round(state.buttonBottom):null,
              scrollY:Number.isFinite(state.scrollY)?Math.round(state.scrollY):null,
              tabbarPosition:['static','fixed','sticky','absent'].includes(state.tabbarPosition)?state.tabbarPosition:'other',
              textareaFocused:typeof state.textareaFocused==='boolean'?state.textareaFocused:null,
              targetIsButton:typeof state.targetIsButton==='boolean'?state.targetIsButton:null
            };
          }
          console.error('YARA_SAFE_UI_NO_POST='+JSON.stringify({project:t.projectName,flags:safe,errors,taps}));
        }
      }
    }
  }
}
function failMatrix(reason){
  // Only authored test-class names, bounded project IDs and status enums.
  // No authenticated page output, response bodies, cookies or token metadata.
  console.error('YARA_BROWSER_CASE_STATUSES='+JSON.stringify(tests.map(t=>({
    type:t.name.includes('@public')?'public':t.name.includes('@delegation-ui')?'delegation-ui':t.name.includes('@delegation')?'delegation':
      t.name.includes('@auth')?'auth':'unexpected',
    project:projects.includes(t.project)?t.project:'unexpected',
    status:['expected','unexpected','skipped'].includes(t.status)?t.status:'other',
    result:['passed','failed','timedOut','skipped','interrupted'].includes(t.result)?t.result:'other',
    line:t.errorLine,errorClass:t.errorClass
  }))));
  reportSafeFailureDiagnostic();
  throw Error(reason);
}
for(const t of tests){
  const type=t.name.includes('@public')?'public':t.name.includes('@delegation-ui')?'delegation-ui':t.name.includes('@delegation')?'delegation':t.name.includes('@auth')?'auth':'unexpected';
  const key=type+':'+t.project;
  if(!projects.includes(t.project)||type==='unexpected'||seen.has(key) ||
    (scope==='public'&&type!=='public') ||
    t.status!=='expected'||t.result!=='passed')
    failMatrix('YARA_BROWSER_REQUIRED_MATRIX_FAILED');
  seen.add(key);
}
for(const name of projects){
  if(!seen.has('public:'+name)||(scope==='full'&&(!seen.has('auth:'+name)||!seen.has('delegation:'+name)||!seen.has('delegation-ui:'+name))))
    failMatrix('YARA_BROWSER_REQUIRED_CASE_MISSING');
}
if(tests.length!==expected || data.stats?.unexpected!==0 ||
  data.stats?.skipped!==0 || data.stats?.expected!==expected)
  failMatrix('YARA_BROWSER_COUNTS_OR_SKIPS_INVALID');
console.log('YARA_BROWSER_MATRIX=PASS ('+expected+'/'+expected+' real browser cases)');
console.log('YARA_BROWSER_MODE='+scope.toUpperCase());
if(scope==='public')console.log('YARA_BROWSER_CANDIDATE_AUTH=NOT_TESTED');

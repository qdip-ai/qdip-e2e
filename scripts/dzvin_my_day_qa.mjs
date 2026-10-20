import { chromium } from '@playwright/test';
import { expect } from '@playwright/test';
const ORIGIN = 'https://www.dzvin.co';
const ZONE = '?timeZone=Europe%2FWarsaw';
const API = '/api/backend/daily-habits';
const KINDS = ['breathing','movement','journaling','screenBreak'];
const fail = (code) => { throw new Error(code); };
async function read(ctx) {
  const r = await ctx.request.get(ORIGIN+API+ZONE);
  if(r.status()!==200) fail('LIST_HTTP_'+r.status());
  const rows = await r.json();
  if(!Array.isArray(rows)) fail('LIST_CONTRACT');
  return rows;
}
async function main(){
  if(process.env.DZVIN_QA_MUTATION_RUN_ACK!=='1') fail('QA_SCOPE_NOT_APPROVED');
  const browser=await chromium.launch({headless:true});
  const contexts=[];
  const created=[];
  try {
    for(const file of ['b2c-a.json','b2c-b.json']){
      const ctx=await browser.newContext({storageState:'playwright/.auth/'+file,timezoneId:'Europe/Warsaw',serviceWorkers:'block'});
      contexts.push(ctx);
      const s=await ctx.request.get(ORIGIN+'/api/auth/session');
      if(s.status()!==200) fail('AUTH_SESSION_HTTP_'+s.status());
    }
    const [a,b]=contexts;
    const oldA=await read(a),oldB=await read(b);
    const kind=KINDS.find(x=>!oldA.some(r=>r.kind===x)&&!oldB.some(r=>r.kind===x));
    if(!kind) fail('NO_SAFE_FREE_TEST_HABIT');
    const mutate=(ctx,method,path,data)=>ctx.request.fetch(ORIGIN+API+path,{method,headers:{Origin:ORIGIN},...(data?{data}:{})});
    const choose=await mutate(a,'PUT','/'+kind+ZONE);
    if(choose.status()!==200) fail('CHOOSE_HTTP_'+choose.status());
    created.push([a,kind]);
    if((await read(a)).find(x=>x.kind===kind)?.doneToday!==false) fail('CHOOSE_NOT_PERSISTED');
    if((await read(b)).some(x=>x.kind===kind)) fail('OTHER_USER_LEAK');
    const cross=await mutate(b,'PATCH','/'+kind+'/today'+ZONE,{completed:true});
    if(cross.status()!==404) fail('FOREIGN_MUTATION_'+cross.status());
    const done=await mutate(a,'PATCH','/'+kind+'/today'+ZONE,{completed:true});
    if(done.status()!==200||(await read(a)).find(x=>x.kind===kind)?.doneToday!==true) fail('DONE_NOT_PERSISTED');
    const undo=await mutate(a,'PATCH','/'+kind+'/today'+ZONE,{completed:false});
    if(undo.status()!==200||(await read(a)).find(x=>x.kind===kind)?.doneToday!==false) fail('UNDO_NOT_PERSISTED');
    const del=await mutate(a,'DELETE','/'+kind);
    if(del.status()!==200||(await read(a)).some(x=>x.kind===kind)) fail('REMOVE_NOT_PERSISTED');
    created.pop();
    if(JSON.stringify(await read(a))!==JSON.stringify(oldA)||JSON.stringify(await read(b))!==JSON.stringify(oldB)) fail('QA_STATE_CHANGED');

    console.log('MY_DAY_SEEDED_API_PERSISTENCE_AND_OWNER_ISOLATION=PASS');

    // Run the same seeded scenario through real hydrated My Day controls.
    // Register cleanup before any UI write, so partial browser failures
    // never leave test fixtures behind.
    const titles = {
      breathing: 'A short breathing break',
      movement: 'A little movement',
      journaling: 'Write down one thought',
      screenBreak: 'Take a screen break',
    };
    const page = await a.newPage();
    created.push([a,kind]);
    try {
      const response = await page.goto(ORIGIN+'/en/my-day',{waitUntil:'domcontentloaded',timeout:45000});
      if(response?.status()!==200) fail('MY_DAY_PAGE_HTTP_'+response?.status());
      await expect(page.getByRole('heading',{name:'Your optional daily habits'})).toBeVisible({timeout:25000});
      const row=page.locator('li').filter({has:page.getByRole('heading',{name:titles[kind],exact:true})}).first();
      await expect(row.getByRole('button',{name:'Add to my day'})).toBeVisible({timeout:25000});
      await row.getByRole('button',{name:'Add to my day'}).click();
      await expect(row.getByText('Selected — available today')).toBeVisible({timeout:15000});
      if((await read(a)).find(x=>x.kind===kind)?.doneToday!==false) fail('BROWSER_SELECT_NOT_PERSISTED');
      await page.reload({waitUntil:'domcontentloaded',timeout:45000});
      await expect(page.locator('li').filter({has:page.getByRole('heading',{name:titles[kind],exact:true})}).getByText('Selected — available today')).toBeVisible({timeout:25000});
      console.log('MY_DAY_UI_SELECT_AND_RELOAD=PASS');

      const row2=page.locator('li').filter({has:page.getByRole('heading',{name:titles[kind],exact:true})}).first();
      await row2.getByRole('button',{name:'I did this today'}).click();
      await expect(row2.getByText('Marked for today')).toBeVisible({timeout:15000});
      await page.reload({waitUntil:'domcontentloaded',timeout:45000});
      const row3=page.locator('li').filter({has:page.getByRole('heading',{name:titles[kind],exact:true})}).first();
      await expect(row3.getByText('Marked for today')).toBeVisible({timeout:25000});
      if((await read(a)).find(x=>x.kind===kind)?.doneToday!==true) fail('BROWSER_DONE_NOT_PERSISTED');
      console.log('MY_DAY_UI_DONE_AND_RELOAD=PASS');

      await row3.getByRole('button',{name:"Undo today's mark"}).click();
      await expect(row3.getByText('Selected — available today')).toBeVisible({timeout:15000});
      if((await read(a)).find(x=>x.kind===kind)?.doneToday!==false) fail('BROWSER_UNDO_NOT_PERSISTED');
      await row3.getByRole('button',{name:'Remove from my day'}).click();
      await expect(row3.getByRole('button',{name:'Add to my day'})).toBeVisible({timeout:15000});
      if((await read(a)).some(x=>x.kind===kind)) fail('BROWSER_REMOVE_NOT_PERSISTED');
      created.pop();
      console.log('MY_DAY_UI_UNDO_REMOVE_AND_CLEANUP=PASS');
    } finally {
      await page.close();
    }

  } finally {
    for(const [ctx,kind] of created) {
      const d=await ctx.request.delete(ORIGIN+API+'/'+kind,{headers:{Origin:ORIGIN}}).catch(()=>null);
      if(d?.status()!==200) { console.error('QA_FIXTURE_CLEANUP_FAILED');process.exitCode=1; }
    }
    await Promise.all(contexts.map(x=>x.close()));
    await browser.close();
  }
}
main().catch(e=>{console.error('MY_DAY_QA='+(/^[A-Z0-9_]{4,80}$/.test(e.message)?e.message:'FAIL'));process.exitCode=1;});
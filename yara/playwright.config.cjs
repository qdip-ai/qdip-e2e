'use strict';
const {defineConfig,devices}=require('@playwright/test');
const baseURL=process.env.YARA_E2E_BASE_URL;
if(!baseURL)throw Error('YARA_E2E_BASE_URL required: point to deployed QA at the tested SHA');
const url=new URL(baseURL);
if(url.protocol!=='https:'&&!(url.protocol==='http:'&&['127.0.0.1','localhost'].includes(url.hostname)))
  throw Error('YARA_E2E_BASE_URL must be HTTPS except for loopback');
module.exports=defineConfig({
  testDir:'./tests/e2e',testMatch:'*.spec.cjs',
  timeout:30_000,expect:{timeout:10_000},fullyParallel:false,workers:1,retries:0,
  reporter:[['list'],['html',{open:'never',outputFolder:'playwright-report'}]],
  outputDir:'test-results',
  use:{baseURL:url.origin,headless:true,screenshot:'on',trace:'off',video:'off',
    actionTimeout:10_000,navigationTimeout:20_000},
  projects:[
    {name:'desktop-chromium',use:{...devices['Desktop Chrome'],viewport:{width:1440,height:900}}},
    {name:'mobile-portrait-chromium',use:{...devices['Desktop Chrome'],viewport:{width:390,height:844},isMobile:true,hasTouch:true}},
    {name:'mobile-landscape-chromium',use:{...devices['Desktop Chrome'],viewport:{width:844,height:390},isMobile:true,hasTouch:true}},
    {name:'desktop-webkit',use:{...devices['Desktop Safari'],viewport:{width:1440,height:900}}},
    {name:'mobile-portrait-webkit',use:{...devices['iPhone 13'],viewport:{width:390,height:844}}},
    {name:'mobile-landscape-webkit',use:{...devices['iPhone 13'],viewport:{width:844,height:390},isMobile:true,hasTouch:true}},
  ],
});

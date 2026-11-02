import { chromium } from '@playwright/test';
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
let captured = false;
page.on('request', req => {
  try {
    const url = new URL(req.url());
    if (url.pathname.endsWith('/oauth/v2/authorize')) {
      if (!url.searchParams.get('client_id')) throw Error('MISSING_PUBLIC_CLIENT_ID');
      console.log('QA_PUBLIC_ISSUER=' + url.origin);
      console.log('QA_PUBLIC_CLIENT_ID=' + url.searchParams.get('client_id'));
      captured = true;
    }
  } catch { }
});
try {
  await page.goto('https://mentality-web.vercel.app/en/auth', { waitUntil: 'domcontentloaded' });
  await page.waitForURL(url => url.origin !== 'https://mentality-web.vercel.app', { timeout: 25000 });
  if (!captured) throw Error('OAUTH_REQUEST_NOT_CAPTURED');
  console.log('QA_PUBLIC_IDP_BOOTSTRAP=PASS');
} finally {
  await browser.close();
}

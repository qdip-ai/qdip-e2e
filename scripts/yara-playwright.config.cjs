'use strict';
const path = require('node:path');
const { defineConfig } = require('@playwright/test');

const cases = [
  ['desktop', { width: 1440, height: 900 }, false],
  ['mobile-portrait', { width: 390, height: 844 }, true],
  ['mobile-landscape', { width: 844, height: 390 }, true],
];
const browsers = ['chromium', 'webkit'];

module.exports = defineConfig({
  testDir: __dirname,
  testMatch: 'yara-browser.spec.cjs',
  timeout: 45_000,
  expect: { timeout: 15_000 },
  retries: 0,
  workers: 1,
  outputDir: path.resolve(__dirname, '../test-results'),
  reporter: 'json',
  use: {
    baseURL: process.env.YARA_E2E_BASE_URL,
    ignoreHTTPSErrors: false,
    serviceWorkers: 'block',
    trace: 'off',
    screenshot: 'off',
  },
  projects: browsers.flatMap(browserName =>
    cases.map(([name, viewport, isMobile]) => ({
      name: name + '-' + browserName,
      use: { browserName, viewport, isMobile, hasTouch: isMobile },
    })),
  ),
});

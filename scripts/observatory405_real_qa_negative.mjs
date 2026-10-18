/**
 * QDIP #405 real Zitadel QA1/QA2 production negative authorization acceptance.
 * Uses GitHub Actions encrypted credentials. Exactly one password attempt.
 * No screenshots, traces, tokens, cookies, login URLs or PII in logs.
 * Does NOT create, publish, modify, or revoke any plugin.
 */
import { chromium, request } from "@playwright/test";

const SITE = "https://qdip.ai";
const OBS = "https://observatory.qdip.ai";
const ACCOUNT = process.env.QDIP_405_TEST_LOGIN;
const PASSWORD = process.env.QDIP_405_TEST_PASSWORD;
const LABEL = process.env.QDIP_405_TEST_LABEL;
const TEST_PLUGIN = "e2e-405-nonexistent-never-published";
const SAFE_BODY = {
  published: true,
  capability_id: "secretary.plan",
  expected_revision: 0,
  application_launch_url: "https://vhv.qdip.ai",
  launch_url_verified: true,
};
function check(condition, stage) {
  if (!condition) throw Error(stage);
}
async function field(page, selectors, timeout = 14000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) {
    for (const selector of selectors) {
      const candidate = page.locator(selector).first();
      if (await candidate.isVisible().catch(() => false)) return candidate;
    }
    await page.waitForTimeout(200);
  }
  return null;
}
async function main() {
  check(LABEL === "QA1" || LABEL === "QA2", "BAD_TEST_LABEL");
  check(ACCOUNT === LABEL.toLowerCase() + "@qdip.ai", "TEST_ACCOUNT_BINDING_INVALID");
  check(typeof PASSWORD === "string" && PASSWORD.length > 0, "TEST_PASSWORD_NOT_BOUND");
  const prefix = "OBS405_" + LABEL;
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    ignoreHTTPSErrors: false, serviceWorkers: "block",
    viewport: { width: 1280, height: 800 }, acceptDownloads: false,
  });
  const anon = await request.newContext({ ignoreHTTPSErrors: false });
  try {
    const path = "/api/observatory/admin/plugins";
    const unauth = await anon.get(OBS + path, { timeout: 20000 });
    check(unauth.status() === 401, "ANONYMOUS_ADMIN_READ_NOT_DENIED");
    const unauthWrite = await anon.put(OBS + path + "/" + TEST_PLUGIN, {
      headers: { Origin: OBS, "Content-Type": "application/json" },
      data: SAFE_BODY, timeout: 20000,
    });
    check(unauthWrite.status() === 401, "ANONYMOUS_ADMIN_WRITE_NOT_DENIED");
    console.log(prefix + "_ANONYMOUS_ADMIN_DENIAL=PASS");

    const initial = await anon.get(SITE + "/api/auth/login?return_to=" +
      encodeURIComponent(OBS + "/uk/admin/plugins"), { maxRedirects: 0 });
    check(initial.status() === 302, "SITE_OIDC_REDIRECT_MISSING");
    const target = new URL(initial.headers()["location"] || "");
    check(target.protocol === "https:" &&
      target.searchParams.get("code_challenge_method") === "S256" &&
      target.searchParams.get("redirect_uri") === SITE + "/api/auth/callback",
      "OIDC_PKCE_CONTRACT_INVALID");
    console.log(prefix + "_PKCE_START=PASS");

    const page = await context.newPage();
    page.setDefaultTimeout(15000);
    await page.goto(SITE + "/api/auth/login?return_to=" +
      encodeURIComponent(OBS + "/uk/admin/plugins"), {
      waitUntil: "domcontentloaded", timeout: 30000,
    });
    const user = await field(page, [
      'input[autocomplete="username"]','input[name="loginName"]',
      'input[name="loginname"]','input[name="username"]',
      'input[name="email"]','input[type="email"]','input[type="text"]',
    ]);
    check(Boolean(user), "ZITADEL_USERNAME_INPUT_MISSING");
    await user.fill(ACCOUNT);
    let pass = await field(page, [
      'input[autocomplete="current-password"]', 'input[type="password"]',
    ], 1400);
    if (!pass) {
      await user.press("Enter");
      pass = await field(page, [
        'input[autocomplete="current-password"]', 'input[type="password"]',
      ]);
    }
    check(Boolean(pass), "ZITADEL_PASSWORD_INPUT_MISSING");
    const callback = page.waitForResponse(response => {
      try { return new URL(response.url()).origin === SITE &&
                   new URL(response.url()).pathname === "/api/auth/callback"; }
      catch { return false; }
    }, { timeout: 40000 });
    await pass.fill(PASSWORD);
    await pass.press("Enter");
    let response;
    try { response = await callback; }
    catch { throw Error("ZITADEL_LOGIN_NO_CALLBACK"); }
    check(response.status() === 302 || response.status() === 303,
      "ZITADEL_CALLBACK_DENIED");
    // Browser shares an HttpOnly domain-scoped session across qdip.ai and Observatory.
    const sessionResponse = await context.request.get(SITE + "/api/auth/session");
    check(sessionResponse.status() === 200, "SITE_SESSION_HTTP_FAILED");
    const session = await sessionResponse.json();
    check(session.authenticated === true && session.observatoryAdmin === false,
      "TEST_IDENTITY_ADMIN_ROLE_UNEXPECTED_OR_SESSION_INVALID");
    console.log(prefix + "_REAL_ZITADEL_LOGIN_NONADMIN=PASS");

    const observable = await context.request.get(OBS + "/api/auth/session");
    check(observable.status() === 200, "OBSERVATORY_SESSION_HTTP_FAILED");
    const obsSession = await observable.json();
    check(obsSession.authenticated === true && obsSession.observatoryAdmin === false,
      "OBSERVATORY_SESSION_ROLE_MISMATCH");
    console.log(prefix + "_OBSERVATORY_SHARED_SESSION=PASS");

    const adminPage = await context.request.get(OBS + "/uk/admin/plugins", {
      maxRedirects: 0,
    });
    check(adminPage.status() === 200 || adminPage.status() === 403,
      "ADMIN_PAGE_HTTP_UNEXPECTED");
    const denied = await context.request.get(OBS + path, { timeout: 20000 });
    check(denied.status() === 403, "REAL_NONADMIN_ADMIN_LIST_EXPOSED");
    const write = await context.request.put(OBS + path + "/" + TEST_PLUGIN, {
      headers: { Origin: OBS, "Content-Type": "application/json" },
      data: SAFE_BODY, timeout: 20000,
    });
    check(write.status() === 403, "REAL_NONADMIN_PLUGIN_WRITE_EXPOSED");
    const wrongOrigin = await context.request.put(OBS + path + "/" + TEST_PLUGIN, {
      headers: { Origin: "https://attacker.invalid", "Content-Type": "application/json" },
      data: SAFE_BODY, timeout: 20000,
    });
    check(wrongOrigin.status() === 403, "REAL_NONADMIN_CROSS_ORIGIN_WRITE_EXPOSED");
    console.log(prefix + "_REAL_PLUGIN_405_READ_WRITE_DENIED=PASS");
    console.log(prefix + "_REAL_ZITADEL_PLUGIN_405_NEGATIVE=PASS");
  } finally {
    await anon.dispose(); await context.close(); await browser.close();
  }
}
main().catch(error => {
  const stage = error instanceof Error && /^[A-Z0-9_]{5,100}$/.test(error.message)
    ? error.message : "BROWSER_FAILURE_REDACTED";
  console.error("OBS405_" + (LABEL === "QA1" || LABEL === "QA2" ? LABEL : "UNKNOWN") +
    "_REAL_ZITADEL_PLUGIN_405_NEGATIVE=FAIL:" + stage);
  process.exitCode = 1;
});

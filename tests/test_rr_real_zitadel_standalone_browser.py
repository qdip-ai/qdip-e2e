"""Real Zitadel -> standalone RR BFF browser acceptance (no mocked sessions).

Execute only against a deployed standalone pair verified out of band:
RR_BROWSER_URL, RR_ZITADEL_USERNAME, RR_ZITADEL_PASSWORD,
RR_E2E_VALID_EXECUTION_ID. No session injection or credential logging.
One real-account login per run to avoid account lockout across viewports.
"""
from __future__ import annotations

import os
import time
from urllib.parse import urlparse

import pytest
from playwright.sync_api import sync_playwright


VIEWPORTS = ((1440, 900), (390, 844), (844, 390))


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.fail(f"RR_BROWSER_E2E_MISSING_{name}", pytrace=False)
    return value


def _visible_input(page, selectors: tuple[str, ...], timeout: float):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for selector in selectors:
            field = page.locator(selector).first
            if field.is_visible():
                return field
        page.wait_for_timeout(200)
    pytest.fail("RR_ZITADEL_LOGIN_FORM_UNAVAILABLE", pytrace=False)


def test_real_zitadel_standalone_rr_bff(tmp_path):
    base = _required("RR_BROWSER_URL").rstrip("/")
    username = _required("RR_ZITADEL_USERNAME")
    password = _required("RR_ZITADEL_PASSWORD")
    execution_id = _required("RR_E2E_VALID_EXECUTION_ID")
    assert urlparse(base).scheme == "https", "RR_BROWSER_E2E_REQUIRES_TLS"
    assert "/" not in execution_id and "?" not in execution_id
    api = base + "/api/rr-operator/kernel/executions/" + execution_id

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            context = browser.new_context(ignore_https_errors=False)
            page = context.new_page()
            anonymous = page.request.get(api)
            assert anonymous.status == 401, f"RR_ANONYMOUS_HTTP_{anonymous.status}"

            page.goto(base, wait_until="domcontentloaded")
            login = page.get_by_role("button", name="Sign in with Zitadel")
            assert login.is_visible(), "RR_REAL_LOGIN_ENTRY_NOT_FOUND"
            login.click()
            page.wait_for_url(lambda url: "zitadel" in str(url).lower(), timeout=30000)
            user = _visible_input(page, (
                'input[autocomplete="username"]', 'input[name="loginName"]',
                'input[name="loginname"]', 'input[name="username"]',
                'input[name="email"]', 'input[type="email"]',
            ), 12)
            user.fill(username)
            passwd = None
            for selector in ('input[autocomplete="current-password"]', 'input[type="password"]'):
                field = page.locator(selector).first
                if field.is_visible():
                    passwd = field
                    break
            if passwd is None:
                user.press("Enter")
                passwd = _visible_input(page, (
                    'input[autocomplete="current-password"]', 'input[type="password"]',
                ), 12)
            passwd.fill(password)
            passwd.press("Enter")
            # Never make a second password attempt; MFA/consent is a hard blocker.
            page.wait_for_url(lambda url: str(url).startswith(base), timeout=45000)

            for width, height in VIEWPORTS:
                page.set_viewport_size({"width": width, "height": height})
                page.goto(base, wait_until="domcontentloaded")
                panel = page.get_by_test_id("rr-production-operator")
                assert panel.is_visible(), f"RR_OPERATOR_PANEL_MISSING_{width}x{height}"
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), (
                    f"RR_HORIZONTAL_OVERFLOW_{width}x{height}"
                )
                page.screenshot(
                    path=str(tmp_path / f"rr-{width}x{height}.png"),
                    full_page=True,
                )

            # Cookies are created through the real OIDC flow. Never call Core
            # directly or inject a platform or organization API key.
            authorized = page.request.get(api)
            assert authorized.status == 200, f"RR_STANDALONE_READ_HTTP_{authorized.status}"
            assert authorized.json()["result"]["workflow"]["execution_id"] == execution_id

            invalid = page.request.post(
                base + "/api/rr-operator/kernel/executions", data="{}",
                headers={"content-type": "application/json", "origin": urlparse(base).scheme + "://" + urlparse(base).netloc},
            )
            assert invalid.status == 422, f"RR_STANDALONE_WRITE_PREFLIGHT_HTTP_{invalid.status}"
            wrong_origin = page.request.post(
                base + "/api/rr-operator/kernel/executions", data="{}",
                headers={"content-type": "application/json", "origin": "https://invalid.example"},
            )
            assert wrong_origin.status == 403, f"RR_CROSS_ORIGIN_HTTP_{wrong_origin.status}"
            context.close()
        finally:
            browser.close()

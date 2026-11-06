"""Real Zitadel -> RR BFF -> browser acceptance. No mocked sessions.

Run in the existing secret-bound browser QA job with:
 RR_BROWSER_URL, RR_ZITADEL_USERNAME, RR_ZITADEL_PASSWORD,
 RR_E2E_VALID_EXECUTION_ID (a real execution belonging to the operator org).
The deployed Web BFF must have RR_STANDALONE_ENABLED=1 and a verified
RR_ORGANIZATION_ID/RR_ORG_API_KEY binding. Never print credentials.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest
from playwright.sync_api import sync_playwright


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.fail(f"RR_BROWSER_E2E_MISSING_{name}", pytrace=False)
    return value


@pytest.mark.parametrize("viewport", [
    {"width": 1440, "height": 900},
    {"width": 390, "height": 844},
    {"width": 844, "height": 390},
])
def test_real_zitadel_standalone_rr_bff(viewport, tmp_path):
    base = _required("RR_BROWSER_URL").rstrip("/")
    username = _required("RR_ZITADEL_USERNAME")
    password = _required("RR_ZITADEL_PASSWORD")
    execution_id = _required("RR_E2E_VALID_EXECUTION_ID")
    assert urlparse(base).scheme == "https", "RR_BROWSER_E2E_REQUIRES_TLS"
    assert "/" not in execution_id and "?" not in execution_id
    api = base + "/api/rr-operator/kernel/executions/" + execution_id

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(viewport=viewport, ignore_https_errors=False)
        page = context.new_page()
        # An anonymous request must not reach the privileged standalone RR BFF.
        anonymous = page.request.get(api)
        assert anonymous.status == 401, f"RR_ANONYMOUS_HTTP_{anonymous.status}"

        page.goto(base, wait_until="domcontentloaded")
        # Use the actual product login link; do not inject session cookies or tokens.
        login = page.get_by_role("link", name="Sign in").or_(
            page.get_by_role("button", name="Sign in")
        )
        assert login.count() > 0, "RR_REAL_LOGIN_ENTRY_NOT_FOUND"
        login.first.click()
        page.wait_for_url(lambda url: "zitadel" in url.lower(), timeout=30000)
        page.get_by_role("textbox").first.fill(username)
        page.get_by_role("button", name="Next").or_(
            page.get_by_role("button", name="Continue")
        ).first.click()
        page.locator('input[type="password"]').fill(password)
        page.get_by_role("button", name="Login").or_(
            page.get_by_role("button", name="Sign in")
        ).first.click()
        page.wait_for_url(lambda url: url.startswith(base), timeout=45000)

        # Browser requests share real OIDC cookies with the BFF; never call Core
        # directly or inject an API key. This must return the known org's record.
        authorized = page.request.get(api)
        assert authorized.status == 200, f"RR_STANDALONE_READ_HTTP_{authorized.status}"
        assert authorized.json()["result"]["workflow"]["execution_id"] == execution_id

        # Invalid write must fail validation, not authorization or upstream routing.
        invalid = page.request.post(
            base + "/api/rr-operator/kernel/executions",
            data="{}",
            headers={"content-type": "application/json", "origin": base},
        )
        assert invalid.status == 422, f"RR_STANDALONE_WRITE_PREFLIGHT_HTTP_{invalid.status}"
        wrong_origin = page.request.post(
            base + "/api/rr-operator/kernel/executions",
            data="{}",
            headers={"content-type": "application/json", "origin": "https://invalid.example"},
        )
        assert wrong_origin.status == 403
        page.screenshot(path=str(tmp_path / f"rr-{viewport['width']}x{viewport['height']}.png"), full_page=True)
        context.close()
        browser.close()

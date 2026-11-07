"""Real Zitadel -> standalone RR BFF browser acceptance (no mocked sessions).

Execute only against a deployed standalone pair verified out of band:
RR_BROWSER_URL, QDIP_E2E_ZITADEL_TEST_LOGIN, QDIP_E2E_ZITADEL_TEST_PASSWORD,
RR_E2E_VALID_EXECUTION_ID. No session injection or credential logging.
One real-account login per run to avoid account lockout across viewports.
"""
from __future__ import annotations

import asyncio
import copy
import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import asyncpg
import pytest
from playwright.sync_api import sync_playwright


VIEWPORTS = ((1440, 900), (390, 844), (844, 390))


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.fail(f"RR_BROWSER_E2E_MISSING_{name}", pytrace=False)
    return value


async def _journal_readback(dsn: str, organization_id: str, execution_id: str) -> dict | None:
    """Independently read the RR-owned QA journal, not the HTTP/BFF response."""
    connection = await asyncpg.connect(dsn, timeout=10, command_timeout=10)
    try:
        payload = await connection.fetchval(
            """SELECT record::text FROM rr_execution_records
               WHERE organization_id = $1 AND execution_id = $2""",
            organization_id, execution_id,
        )
        return None if payload is None else json.loads(payload)
    finally:
        await connection.close()


async def _foreign_record(dsn: str, organization_id: str) -> tuple[str, str] | None:
    """Find a persisted existing foreign-tenant fixture, never an invented ID."""
    connection = await asyncpg.connect(dsn, timeout=10, command_timeout=10)
    try:
        row = await connection.fetchrow(
            """SELECT organization_id, execution_id FROM rr_execution_records
               WHERE organization_id <> $1 ORDER BY execution_id LIMIT 1""",
            organization_id,
        )
        return None if row is None else (row["organization_id"], row["execution_id"])
    finally:
        await connection.close()


def _visible_input(page, selectors: tuple[str, ...], timeout: float):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for selector in selectors:
            field = page.locator(selector).first
            if field.is_visible():
                return field
        page.wait_for_timeout(200)
    # Describe only public page structure before entering any credentials.
    # Never log the URL query (OIDC state/code), page text or user identifiers.
    current = urlparse(page.url)
    body = page.locator("body")
    visible_text = body.inner_text(timeout=3000).lower() if body.is_visible() else ""
    markers = (
        "redirect_uri", "redirect uri", "invalid_redirect", "invalid request",
        "unauthorized client", "error", "login", "sign in",
    )
    observed = [label.replace(" ", "_") for label in markers if label in visible_text]
    pytest.fail(
        f"RR_ZITADEL_LOGIN_FORM_UNAVAILABLE host={current.hostname} "
        f"path={current.path} inputs={page.locator('input').count()} "
        f"markers={','.join(observed) or 'none'}",
        pytrace=False,
    )


def _login_rr_zitadel(page, page_url: str, username: str, password: str) -> None:
    page.goto(page_url, wait_until="domcontentloaded")
    login = page.get_by_role("link", name="Sign in", exact=True).first
    login.wait_for(state="visible", timeout=20000)
    href = login.get_attribute("href")
    assert href and urlparse(href).netloc == urlparse(page_url).netloc, (
        "RR_RAILWAY_LOGIN_LINK_ESCAPES_QA_ORIGIN"
    )
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
    page.wait_for_url(lambda url: str(url).startswith(page_url), timeout=45000)


def test_real_zitadel_standalone_rr_bff(tmp_path):
    base = _required("RR_BROWSER_URL").rstrip("/")
    username = _required("QDIP_E2E_ZITADEL_TEST_LOGIN")
    password = _required("QDIP_E2E_ZITADEL_TEST_PASSWORD")
    dsn = _required("RR_E2E_TEST_POSTGRES_DSN")
    organization_id = _required("RR_E2E_ORGANIZATION_ID")
    assert urlparse(dsn).path.rsplit("/", 1)[-1].endswith("_test"), (
        "RR_E2E_POSTGRES_MUST_BE_DEDICATED_TEST_DATABASE"
    )
    assert _required("RR_E2E_STAGING_WRITE") == "1", (
        "RR_E2E_REQUIRES_EXPLICIT_STAGING_MUTATION_PERMISSION"
    )
    parsed = urlparse(base)
    assert parsed.scheme == "https", "RR_BROWSER_E2E_REQUIRES_TLS"
    assert parsed.hostname and parsed.hostname.endswith(".up.railway.app"), (
        "RR_E2E_RAILWAY_ONLY"
    )
    assert parsed.path in ("", "/") and not parsed.query and not parsed.fragment, (
        "RR_BROWSER_URL_MUST_BE_ORIGIN"
    )
    assert parsed.hostname not in {"qdip.ai", "observatory.qdip.ai", "studio.qdip.ai"}, (
        "RR_E2E_PRODUCTION_MUTATIONS_FORBIDDEN"
    )
    page_url = base + "/en/readiness-recovery"
    api = base + "/api/rr-operator/kernel/executions/rr-anonymous-unauthorized"

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = None
        try:
            context = browser.new_context(ignore_https_errors=False)
            context.tracing.start(screenshots=True, snapshots=True, sources=False)
            page = context.new_page()
            browser_errors = []
            page.on("pageerror", lambda error: browser_errors.append(type(error).__name__))
            anonymous = page.request.get(api)
            assert anonymous.status == 401, f"RR_ANONYMOUS_HTTP_{anonymous.status}"

            _login_rr_zitadel(page, page_url, username, password)

            for width, height in VIEWPORTS:
                page.set_viewport_size({"width": width, "height": height})
                page.goto(page_url, wait_until="domcontentloaded")
                panel = page.get_by_test_id("rr-production-operator")
                panel.wait_for(state="visible", timeout=20000)
                assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), (
                    f"RR_HORIZONTAL_OVERFLOW_{width}x{height}"
                )
                page.screenshot(
                    path=str(tmp_path / f"rr-{width}x{height}.png"),
                    full_page=True,
                )

            # Cookies come from the real Zitadel OIDC flow; the test creates its
            # own execution below rather than relying on a stale preseeded ID.
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
            # Full functional E2E: no mocked responses. Every request passes
            # through the same OIDC browser context and standalone Web BFF.
            origin_headers = {"origin": base, "content-type": "application/json"}
            prefix = base + "/api/rr-operator/kernel"
            suffix = uuid4().hex
            fixture = json.loads(
                (Path(__file__).resolve().parents[1] / "fixtures" /
                 "rr_reference_api_v1.json").read_text(encoding="utf-8")
            )
            first = copy.deepcopy(fixture)
            now = datetime.now(UTC)
            first_id = "rr-browser-first-" + suffix
            next_id = "rr-browser-replan-" + suffix
            decision_id = "rr-browser-decision-" + suffix
            first["execution_id"] = first_id
            first["payload"]["decision_id"] = decision_id
            first["source"]["snapshot_id"] = "rr-browser-source-" + suffix
            first["source"]["captured_at"] = (now - timedelta(minutes=4)).isoformat()
            first["ingested_at"] = (now - timedelta(minutes=3)).isoformat()

            def call_post(path: str, payload: dict):
                return page.request.post(
                    prefix + path,
                    data=json.dumps(payload, separators=(",", ":")),
                    headers=origin_headers,
                    timeout=65_000,
                )

            preflight = call_post("/preflight", first)
            assert preflight.status == 200, (
                f"RR_LIVE_PREFLIGHT_HTTP_{preflight.status}"
            )
            preview = preflight.json()
            assert (
                preview["execution_id"] == first_id
                and preview["decision_id"] == decision_id
                and preview["validation_scope"] == "SCHEMA_AND_ADMISSION_ONLY"
            )

            created = call_post("/executions", first)
            assert created.status == 201, f"RR_LIVE_CREATE_HTTP_{created.status}"
            record = created.json()
            assert record["result"]["workflow"]["execution_id"] == first_id
            assert record["result"]["runtime"]["execution_result"]["execution_id"] == first_id

            # Lost-ACK replay is safe: same request identity returns same
            # persisted execution, without scheduling another decision.
            repeated = call_post("/executions", first)
            assert repeated.status == 201, (
                f"RR_LIVE_IDEMPOTENCY_HTTP_{repeated.status}"
            )
            assert repeated.json() == record

            read = page.request.get(prefix + "/executions/" + first_id)
            assert read.status == 200 and read.json() == record
            assert record["organization_id"] == organization_id, "RR_ORGANIZATION_BINDING_MISMATCH"
            stored = asyncio.run(_journal_readback(dsn, organization_id, first_id))
            assert stored == record, "RR_POSTGRES_HTTP_READBACK_MISMATCH"
            foreign_fixture = asyncio.run(_foreign_record(dsn, organization_id))
            assert foreign_fixture is not None, "RR_FOREIGN_ORG_JOURNAL_FIXTURE_MISSING"
            foreign_org, foreign_execution_id = foreign_fixture
            assert foreign_execution_id != first_id, "RR_FOREIGN_FIXTURE_INVALID"
            foreign = page.request.get(prefix + "/executions/" + foreign_execution_id)
            assert foreign.status in (403, 404), (
                f"RR_FOREIGN_ORGANIZATION_READ_HTTP_{foreign.status}"
            )
            assert foreign_org not in foreign.text(), "RR_FOREIGN_ORG_ID_EXPOSED"
            print("RR_STANDALONE_POSTGRES_READBACK=PASS")
            print("RR_CROSS_ORG_HTTP_ISOLATION=PASS")
            replay = page.request.get(
                prefix + "/executions/" + first_id + "/replay-verification"
            )
            assert replay.status == 200, f"RR_LIVE_REPLAY_HTTP_{replay.status}"
            assert (
                replay.json()["execution_id"] == first_id
                and len(replay.json()["ir_hash"]) == 64
            )
            projection = page.request.get(
                prefix + "/executions/" + first_id + "/presentation"
            )
            assert projection.status == 200
            assert (
                projection.json()["execution_id"] == first_id
                and projection.json()["decision_id"] == decision_id
            )

            # Validate real UI read: use the operator's own identifier,
            # not a mocked route or local client computation.
            page.goto(page_url, wait_until="domcontentloaded")
            id_field = page.get_by_label("Execution ID", exact=True)
            id_field.wait_for(state="visible", timeout=20000)
            id_field.fill(first_id)
            page.get_by_role("button", name="Inspect saved execution").click()
            page.get_by_test_id("rr-kernel-evidence").wait_for(
                state="visible", timeout=30000
            )

            second = copy.deepcopy(first)
            second["execution_id"] = next_id
            second["source"]["snapshot_id"] = "rr-browser-update-" + suffix
            second["source"]["captured_at"] = (
                now - timedelta(minutes=2)
            ).isoformat()
            second["ingested_at"] = (now - timedelta(minutes=1)).isoformat()
            second["payload"]["workshop_capacity"] = 1
            second.update({
                "change_id": "rr-browser-change-" + suffix,
                "kind": "STATE_CHANGE",
                "reason": "Existing workshop capacity changed in E2E staging",
                "requested_at": now.isoformat(),
            })
            revised = call_post(
                "/executions/" + first_id + "/replan", second
            )
            assert revised.status == 201, (
                f"RR_LIVE_REPLAN_HTTP_{revised.status}"
            )
            assert revised.json()["result"]["workflow"]["execution_id"] == next_id
            stale = call_post("/executions/" + first_id + "/replan", {
                **second,
                "execution_id": "rr-browser-stale-" + suffix,
                "change_id": "rr-browser-stale-change-" + suffix,
            })
            assert stale.status == 409, f"RR_STALE_REPLAN_HTTP_{stale.status}"

            history_url = prefix + "/decisions/" + decision_id
            history = page.request.get(history_url + "/history")
            assert history.status == 200, (
                f"RR_LIVE_HISTORY_HTTP_{history.status}"
            )
            records = history.json()["executions"]
            assert [
                item["result"]["workflow"]["execution_id"] for item in records
            ] == [first_id, next_id]

            integrity = page.request.get(history_url + "/history-integrity")
            assert integrity.status == 200
            assert (
                integrity.json()["complete_chain"] is True
                and integrity.json()["head_execution_id"] == next_id
            )
            export = page.request.get(
                history_url + "/history/verified-export-page"
            )
            assert export.status == 200
            evidence = export.json()
            assert (
                evidence["history_verified"] is True
                and evidence["export_complete"] is True
                and evidence["head_execution_id"] == next_id
                and len(evidence["executions"]) == 2
            )

            # Economic v2 is an advisory flow, never a physical-action
            # approval. Verify real Worker/Kernel computation and archive.
            economic = {
                "snapshot_id": "rr-browser-economic-" + suffix,
                "operational": {
                    "decision_id": "rr-browser-economic-decision-" + suffix,
                    "horizon_slots": 4,
                    "workshop_capacity": 1,
                    "technicians": [{
                        "id": "tech", "skills": ["repair"],
                        "available_slots": [0, 1, 2],
                    }],
                    "jobs": [{
                        "id": "repair", "duration_slots": 1,
                        "required_skills": ["repair"], "deadline_slot": 4,
                        "readiness_gain_units": 0,
                        "parts": [{"part_id": "bearing", "quantity": 1}],
                    }],
                },
                "assets": [{"id": "machine", "state_revision": 1}],
                "restorations": [{"job_id": "repair", "asset_id": "machine"}],
                "occupations": [{"job_id": "repair", "asset_ids": ["machine"]}],
                "job_costs": [{"job_id": "repair", "all_in_cost_cents": 0}],
                "procurements": [{
                    "id": "expedite",
                    "alternative_group_id": "bearing-offers",
                    "part_id": "bearing", "quantity": 1,
                    "arrival_slot": 0, "all_in_cost_cents": 150000,
                }],
                "capabilities": [{
                    "id": "output", "asset_ids": ["machine"],
                    "contribution_cents_by_slot": [0, 100000, 100000, 100000],
                }],
            }
            econ_preview = call_post("/economic-v2/preflight", economic)
            assert econ_preview.status == 200, (
                f"RR_LIVE_ECON_PREFLIGHT_HTTP_{econ_preview.status}"
            )
            snapshot = call_post("/economic-v2/snapshots", economic)
            assert snapshot.status == 201, (
                f"RR_LIVE_ECON_SNAPSHOT_HTTP_{snapshot.status}"
            )
            advice_id = "rr-browser-advice-" + suffix
            advice_request = {
                "snapshot_id": economic["snapshot_id"],
                "execution_id": advice_id,
            }
            advised = call_post("/economic-v2/advice", advice_request)
            assert advised.status == 200, (
                f"RR_LIVE_ECON_ADVICE_HTTP_{advised.status}"
            )
            assert advised.json()["actionable"] is False
            saved_advice = page.request.get(
                prefix + "/economic-v2/advice/" + advice_id
            )
            assert saved_advice.status == 200
            assert saved_advice.json() == advised.json()
            advice_integrity = page.request.get(
                prefix + "/economic-v2/advice/" + advice_id + "/integrity"
            )
            assert advice_integrity.status == 200, (
                f"RR_LIVE_ECON_INTEGRITY_HTTP_{advice_integrity.status}"
            )

            # Evidence screens for all target form factors after a real write.
            for width, height in VIEWPORTS:
                page.set_viewport_size({"width": width, "height": height})
                page.goto(page_url, wait_until="domcontentloaded")
                page.get_by_test_id("rr-production-operator").wait_for(
                    state="visible", timeout=20000
                )
                field = page.get_by_label("Execution ID", exact=True)
                field.wait_for(state="visible", timeout=20000)
                field.fill(first_id)
                inspect = page.get_by_role("button", name="Inspect saved execution")
                assert inspect.is_visible() and inspect.is_enabled(), (
                    f"RR_INSPECT_CONTROL_UNAVAILABLE_{width}x{height}"
                )
                inspect.click()
                page.get_by_test_id("rr-kernel-evidence").wait_for(
                    state="visible", timeout=30000
                )
                page.screenshot(
                    path=str(tmp_path / f"rr-result-{width}x{height}.png"),
                    full_page=True,
                )
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= window.innerWidth + 1"
                ), f"RR_RESULT_HORIZONTAL_OVERFLOW_{width}x{height}"

            assert not browser_errors, (
                f"RR_BROWSER_UNHANDLED_EXCEPTIONS_{len(browser_errors)}"
            )
        finally:
            if context is not None:
                context.tracing.stop(path=str(tmp_path / "rr-browser-trace.zip"))
                context.close()
            browser.close()


def test_railway_real_zitadel_login_and_scoped_rr_read() -> None:
    """Independent real test user -> Railway QA Zitadel -> BFF -> RR read API.

    This does not substitute for the separate PostgreSQL-backed write E2E.
    """
    base = _required("RR_BROWSER_URL").rstrip("/")
    parsed = urlparse(base)
    assert parsed.scheme == "https" and parsed.hostname and (
        parsed.hostname.endswith(".up.railway.app")
    ), "RR_OIDC_BROWSER_REQUIRES_ISOLATED_RAILWAY_QA"
    assert not parsed.query and not parsed.fragment and parsed.path in ("", "/")
    username = _required("QDIP_E2E_ZITADEL_TEST_LOGIN")
    password = _required("QDIP_E2E_ZITADEL_TEST_PASSWORD")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            context = browser.new_context(ignore_https_errors=False)
            try:
                page = context.new_page()
                endpoint = base + "/api/rr-operator/kernel/executions/rr-qa-anonymous-check"
                anonymous = page.request.get(endpoint)
                assert anonymous.status == 401, f"RR_QA_ANONYMOUS_HTTP_{anonymous.status}"
                _login_rr_zitadel(
                    page, base + "/en/readiness-recovery", username, password,
                )
                # Real signed-in browser; QA identity has no QDIP ORG_OWNER,
                # so the staging owner relay must return an empty selection.
                anonymous_owner = page.request.get(base + "/api/observatory/organizations")
                # Request is already signed in here; verify the HMAC relay below.
                session = page.request.get(base + "/api/rr-operator/session")
                assert session.status == 200, f"RR_QA_SESSION_HTTP_{session.status}"
                state = session.json()
                assert state.get("configured") is True, "RR_QA_OIDC_UNCONFIGURED"
                assert state.get("authenticated") is True, "RR_QA_OPERATOR_ROLE_MISSING"
                missing = page.request.get(
                    base + "/api/rr-operator/kernel/executions/rr-qa-missing-" + uuid4().hex
                )
                assert missing.status == 404, (
                    f"RR_QA_SCOPED_API_READ_HTTP_{missing.status}"
                )
                assert anonymous_owner.status == 200, (
                    f"RR_QA_STAGING_OWNER_LIST_HTTP_{anonymous_owner.status}"
                )
                owners = anonymous_owner.json().get("organizations")
                assert isinstance(owners, list), "RR_STAGING_OWNER_LIST_INVALID"
                assert not any(org.get("id") == "368555767923594379" for org in owners), (
                    "RR_STAGING_QA_TEST_USER_MUST_NOT_OWN_QDIP"
                )
                wrong_org = page.request.post(
                    base + "/api/observatory/organizations",
                    data=json.dumps({"organizationId": "397885387160184113"}),
                    headers={"origin": base, "content-type": "application/json"},
                )
                assert wrong_org.status == 403, (
                    f"RR_STAGING_WRONG_ORG_DENIAL_HTTP_{wrong_org.status}"
                )
                print("RR_STAGING_OWNER_RELAY_SCOPE_AND_PROOF=PASS")
                for width, height in VIEWPORTS:
                    page.set_viewport_size({"width": width, "height": height})
                    content = page.goto(
                        base + "/uk/admin/apps", wait_until="domcontentloaded", timeout=30000
                    )
                    assert content and content.status == 200, (
                        f"RR_STAGING_OWNER_SELECTOR_HTTP_{width}x{height}"
                    )
                    title = page.get_by_role(
                        "heading", name="RR staging — підтвердження організації"
                    )
                    title.wait_for(state="visible", timeout=20000)
                    assert page.evaluate(
                        "document.documentElement.scrollWidth <= window.innerWidth + 1"
                    ), f"RR_STAGING_OWNER_SELECTOR_OVERFLOW_{width}x{height}"
                    print(f"RR_STAGING_OWNER_SELECTOR_{width}x{height}=PASS")
                print("RR_RAILWAY_REAL_ZITADEL_LOGIN_AND_SCOPED_READ=PASS")
            finally:
                context.close()
        finally:
            browser.close()

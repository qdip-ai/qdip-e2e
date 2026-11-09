"""Real Zitadel -> standalone RR BFF browser acceptance (no mocked sessions).

Execute only against a deployed standalone pair verified out of band:
RR_BROWSER_URL, QDIP_E2E_ZITADEL_TEST_LOGIN, QDIP_E2E_ZITADEL_TEST_PASSWORD,
RR_QA_RAILWAY_TOKEN. No session injection, public DSN or credential logging.
One real-account login per run to avoid account lockout across viewports.
"""
from __future__ import annotations

import copy
import hashlib
from decimal import Decimal
import json
import os
import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import pytest
from playwright.sync_api import sync_playwright

from scripts.rr_qa_railway_private_readback import readback_from_ci, scenario_readback_from_ci


VIEWPORTS = ((1440, 900), (390, 844), (844, 390))


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.fail(f"RR_BROWSER_E2E_MISSING_{name}", pytrace=False)
    return value


def _rr_failure_code(response) -> str:
    """Expose only a small explicit RR error code, never token or response text."""
    try:
        detail = response.json().get("detail", {})
        code = detail.get("code", "") if isinstance(detail, dict) else ""
    except (TypeError, ValueError, AttributeError):
        return "UNKNOWN"
    return code if isinstance(code, str) and re.fullmatch(r"[a-z0-9_]{1,80}", code) else "UNKNOWN"


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
    organization_id = _required("RR_E2E_ORGANIZATION_ID")
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
            assert created.status == 201, f"RR_LIVE_CREATE_HTTP_{created.status}:CODE_{_rr_failure_code(created)}"
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
            # Independent verifier executes INSIDE existing Railway PostgreSQL QA,
            # returns only a pass/fail and a REAL foreign journal identifier.
            # A public, non-sensitive fingerprint permits an independent QA
            # PostgreSQL verifier to check the same execution out of band.
            # This does not replace the mandatory protected in-job verifier.
            record_sha = hashlib.sha256(json.dumps(
                record, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
            print(
                f"RR_SQL_READBACK_PROBE_KIND=scheduling ORG={organization_id} "
                f"EXECUTION={first_id} SHA256={record_sha}",
                flush=True,
            )
            foreign_org, foreign_execution_id = readback_from_ci(record)
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
            readback_from_ci(revised.json())  # Also prove durable replan record.
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
                signed_owner = page.request.get(base + "/api/observatory/organizations")
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
                # Read-only real-session preflight: test the activated BFF -> RR
                # scheduling boundary without executing Kernel or writing PostgreSQL.
                sample = json.loads(
                    (Path(__file__).resolve().parents[1] / "fixtures" /
                     "rr_reference_api_v1.json").read_text(encoding="utf-8")
                )
                proof_id = "rr-qa-preflight-" + uuid4().hex
                now = datetime.now(UTC)
                sample["execution_id"] = proof_id
                sample["payload"]["decision_id"] = proof_id
                sample["source"]["snapshot_id"] = proof_id
                sample["source"]["captured_at"] = (now - timedelta(minutes=2)).isoformat()
                sample["ingested_at"] = (now - timedelta(minutes=1)).isoformat()
                preview_response = page.request.post(
                    base + "/api/rr-operator/kernel/preflight",
                    data=json.dumps(sample, separators=(",", ":")),
                    headers={"origin": base, "content-type": "application/json"},
                    timeout=30_000,
                )
                assert preview_response.status == 200, (
                    f"RR_QA_AUTHENTICATED_SCHEDULING_PREFLIGHT_HTTP_{preview_response.status}"
                )
                preview = preview_response.json()
                assert (
                    preview.get("execution_id") == proof_id
                    and preview.get("validation_scope") == "SCHEMA_AND_ADMISSION_ONLY"
                    and preview.get("accepted_for_kernel_submission") is True
                ), "RR_QA_AUTHENTICATED_SCHEDULING_PREFLIGHT_CONTRACT"
                print("RR_QA_AUTHENTICATED_SCHEDULING_PREFLIGHT=PASS")
                assert signed_owner.status == 200, (
                    f"RR_QA_STAGING_OWNER_LIST_HTTP_{signed_owner.status}"
                )
                owners = signed_owner.json().get("organizations")
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
                    evidence = Path("test-results/rr-staging-owner") / f"owner-{width}x{height}.png"
                    evidence.parent.mkdir(parents=True, exist_ok=True)
                    page.get_by_role(
                        "region", name="Мої організації Zitadel"
                    ).screenshot(path=str(evidence))
                    print(f"RR_STAGING_OWNER_VIEWPORT_SCREENSHOT_{width}x{height}=PASS")
                    assert page.evaluate(
                        "document.documentElement.scrollWidth <= window.innerWidth + 1"
                    ), f"RR_STAGING_OWNER_SELECTOR_OVERFLOW_{width}x{height}"
                    print(f"RR_STAGING_OWNER_SELECTOR_{width}x{height}=PASS")
                print("RR_RAILWAY_REAL_ZITADEL_LOGIN_AND_SCOPED_READ=PASS")
            finally:
                context.close()
        finally:
            browser.close()


def test_real_zitadel_rr_cvar_staging() -> None:
    """Browser->Zitadel->BFF->RR->SDK Worker->Core CVaR->PostgreSQL/replay.

    Deliberately separate from scheduling qualification: a scheduling 503
    cannot mask the scenario-specific result. Never use a mock session or DB.
    """
    base = _required("RR_BROWSER_URL").rstrip("/")
    organization_id = _required("RR_E2E_ORGANIZATION_ID")
    assert _required("RR_E2E_STAGING_WRITE") == "1"
    location = urlparse(base)
    assert location.scheme == "https" and location.hostname
    assert location.hostname.endswith(".up.railway.app")
    assert location.path in ("", "/") and not location.query and not location.fragment
    username = _required("QDIP_E2E_ZITADEL_TEST_LOGIN")
    password = _required("QDIP_E2E_ZITADEL_TEST_PASSWORD")
    suffix = uuid4().hex
    economic = json.loads(
        (Path(__file__).resolve().parents[1] / "fixtures" /
         "rr_cvar_two_stage_v1.json").read_text(encoding="utf-8")
    )
    economic["snapshot_id"] = "rr-cvar-live-" + suffix
    economic["operational"]["decision_id"] = "rr-cvar-decision-" + suffix
    early = copy.deepcopy(economic)
    late = copy.deepcopy(economic)
    # Only an after-reveal delivery delay differs. The submitted current
    # physical state and pre-reveal commitments must remain authoritative.
    late["procurements"][0]["arrival_slot"] = 3
    scenario = {
        "snapshot_id": economic["snapshot_id"],
        "execution_id": "rr-cvar-risk-" + suffix,
        "reveal_slot": 1,
        "scenarios": [
            {
                "id": "early", "probability_bps": 7000,
                "probability_basis": "ASSUMED", "projected_request": early,
            },
            {
                "id": "late", "probability_bps": 3000,
                "probability_basis": "ASSUMED", "projected_request": late,
            },
        ],
        "deferred_procurement_ids": [],
        "risk": {
            "loss_floor_cents": 300000,
            "alpha_bps": 9000,
            "aversion_bps": 3500,
        },
    }

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            context = browser.new_context(ignore_https_errors=False)
            try:
                page = context.new_page()
                prefix = base + "/api/rr-operator/kernel"
                assert page.request.get(
                    prefix + "/economic-v2/scenario-advice/rr-cvar-unknown"
                ).status == 401
                _login_rr_zitadel(
                    page, base + "/en/readiness-recovery", username, password,
                )
                headers = {"origin": base, "content-type": "application/json"}

                def post(path: str, value: dict):
                    return page.request.post(
                        prefix + path, data=json.dumps(value),
                        headers=headers, timeout=180_000,
                    )

                created = post("/economic-v2/snapshots", economic)
                assert created.status == 201, (
                    f"RR_CVAR_SOURCE_REGISTER_HTTP_{created.status}:CODE_{_rr_failure_code(created)}"
                )
                assert created.json()["snapshot_id"] == economic["snapshot_id"]
                # Core scenario model must be reached; ordinary economic-v2
                # scheduling/advice evidence is insufficient for CVaR.
                risk_result = post("/economic-v2/scenario-advice", scenario)
                assert risk_result.status == 200, (
                    f"RR_CVAR_RISK_HTTP_{risk_result.status}:CODE_{_rr_failure_code(risk_result)}"
                )
                output = risk_result.json()
                assert output["schema_version"] == (
                    "readiness-recovery.economic-scenario-preview.v1"
                )
                assert output["execution_id"] == scenario["execution_id"]
                assert output["decision_id"] == economic["operational"]["decision_id"]
                assert output["actionable"] is False
                assert output["supply_source_verified"] is False
                result = output["execution_result"]
                replay = output["replay_contract"]
                manifest = result["manifest"]
                assert result["backend_status"] == "OPTIMAL"
                assert result["semantic_status"] == "EXACT"
                assert result["execution_id"] == scenario["execution_id"]
                assert len(manifest["ir_hash"]) == 64
                assert result["ir_hash"] == replay["ir_hash"] == manifest["ir_hash"]
                assert replay["decision_spec_hash"] == manifest["decision_spec_hash"]
                recommendation = output["recommendation"]
                assert recommendation["status"] == "OPTIMAL"
                assert recommendation["actionable"] is False
                assert recommendation["reveal_slot"] == 1
                assert [world["scenario_id"] for world in recommendation["scenarios"]] == [
                    "early", "late"
                ]
                assert [world["probability_bps"] for world in recommendation["scenarios"]] == [
                    7000, 3000
                ]
                expected = sum(
                    Decimal(str(world["incremental_margin_cents"]))
                    * world["probability_bps"]
                    for world in recommendation["scenarios"]
                ) / Decimal(10000)
                assert Decimal(str(recommendation["expected_incremental_margin_cents"])) == expected
                tail = Decimal(str(recommendation["cvar_loss_cents"]))
                assert tail >= 0
                penalty = tail * Decimal(3500) / Decimal(10000)
                assert Decimal(str(recommendation["risk_penalty_cents"])) == penalty
                assert Decimal(str(recommendation["risk_adjusted_objective_cents"])) == (
                    expected - penalty
                )
                # The joint model's first-stage assignments cannot depend on
                # the future scenario. Recourse may differ after reveal.
                first_stage = recommendation["first_stage_scheduled_jobs"]
                assert all(job["start_slot"] < 1 for job in first_stage)
                for world in recommendation["scenarios"]:
                    realized = [
                        job for job in world["scheduled_jobs"] if job["start_slot"] < 1
                    ]
                    assert realized == first_stage
                    assert set(recommendation["first_stage_procurement_ids"]).issubset(
                        set(world["selected_procurement_ids"])
                    )

                saved = page.request.get(
                    prefix + "/economic-v2/scenario-advice/" + scenario["execution_id"],
                    timeout=60_000,
                )
                assert saved.status == 200, f"RR_CVAR_READ_HTTP_{saved.status}"
                assert saved.json() == output
                replayed = post("/economic-v2/scenario-advice", scenario)
                assert replayed.status == 200 and replayed.json() == output
                # Independent PostgreSQL query runs in existing private Railway,
                # comparing the response JSONB for this exact org/execution.
                scenario_sha = hashlib.sha256(json.dumps(
                    output, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                ).encode("utf-8")).hexdigest()
                print(
                    f"RR_SQL_READBACK_PROBE_KIND=scenario ORG={organization_id} "
                    f"EXECUTION={scenario['execution_id']} SHA256={scenario_sha}",
                    flush=True,
                )
                scenario_readback_from_ci(output, organization_id)
                print("RR_CVAR_REAL_PERSISTENCE_AND_REPLAY=PASS")

                neutral = {**scenario, "execution_id": "rr-cvar-neutral-" + suffix}
                neutral.pop("risk")
                zero = copy.deepcopy(scenario)
                zero["execution_id"] = "rr-cvar-zero-" + suffix
                zero["risk"]["aversion_bps"] = 0
                neutral_response = post("/economic-v2/scenario-advice", neutral)
                zero_response = post("/economic-v2/scenario-advice", zero)
                assert neutral_response.status == 200, (
                    f"RR_CVAR_NEUTRAL_HTTP_{neutral_response.status}"
                )
                assert zero_response.status == 200, (
                    f"RR_CVAR_ZERO_HTTP_{zero_response.status}"
                )
                a = neutral_response.json()["recommendation"]
                z = zero_response.json()["recommendation"]
                assert a["expected_incremental_margin_cents"] == z[
                    "expected_incremental_margin_cents"
                ]
                assert a["first_stage_procurement_ids"] == z[
                    "first_stage_procurement_ids"
                ]
                assert Decimal(str(z["risk_penalty_cents"])) == 0

                bad_prob = copy.deepcopy(scenario)
                bad_prob["execution_id"] = "rr-cvar-bad-prob-" + suffix
                bad_prob["scenarios"][0]["probability_bps"] = 6000
                assert post("/economic-v2/scenario-advice", bad_prob).status == 422
                bad_alpha = copy.deepcopy(scenario)
                bad_alpha["execution_id"] = "rr-cvar-bad-alpha-" + suffix
                bad_alpha["risk"]["alpha_bps"] = 10000
                assert post("/economic-v2/scenario-advice", bad_alpha).status == 422
                tampered_history = copy.deepcopy(scenario)
                tampered_history["execution_id"] = "rr-cvar-history-" + suffix
                # Tampering nested projections is rejected even when IDs look valid.
                tampered_history["scenarios"][1]["projected_request"]["operational"][
                    "decision_id"
                ] = "forged"
                assert post("/economic-v2/scenario-advice", tampered_history).status == 422
                stale = {**scenario, "snapshot_id": "rr-cvar-missing-" + suffix,
                         "execution_id": "rr-cvar-stale-" + suffix}
                assert post("/economic-v2/scenario-advice", stale).status == 404
                conflict = copy.deepcopy(scenario)
                conflict["risk"]["aversion_bps"] = 0
                assert post("/economic-v2/scenario-advice", conflict).status == 409
                print("RR_CVAR_NEGATIVE_CONTRACTS=PASS")
            finally:
                context.close()
        finally:
            browser.close()

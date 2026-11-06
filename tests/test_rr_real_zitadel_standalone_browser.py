"""Real Zitadel -> standalone RR BFF browser acceptance (no mocked sessions).

Execute only against a deployed standalone pair verified out of band:
RR_BROWSER_URL, QDIP_E2E_ZITADEL_TEST_LOGIN, QDIP_E2E_ZITADEL_TEST_PASSWORD,
RR_E2E_VALID_EXECUTION_ID. No session injection or credential logging.
One real-account login per run to avoid account lockout across viewports.
"""
from __future__ import annotations

import copy
import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

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
    username = _required("QDIP_E2E_ZITADEL_TEST_LOGIN")
    password = _required("QDIP_E2E_ZITADEL_TEST_PASSWORD")
    execution_id = _required("RR_E2E_VALID_EXECUTION_ID")
    assert _required("RR_E2E_STAGING_WRITE") == "1", (
        "RR_E2E_REQUIRES_EXPLICIT_STAGING_MUTATION_PERMISSION"
    )
    parsed = urlparse(base)
    assert parsed.scheme == "https", "RR_BROWSER_E2E_REQUIRES_TLS"
    assert parsed.path in ("", "/") and not parsed.query and not parsed.fragment, (
        "RR_BROWSER_URL_MUST_BE_ORIGIN"
    )
    assert parsed.hostname not in {"qdip.ai", "observatory.qdip.ai", "studio.qdip.ai"}, (
        "RR_E2E_PRODUCTION_MUTATIONS_FORBIDDEN"
    )
    assert "/" not in execution_id and "?" not in execution_id
    page_url = base + "/en/readiness-recovery"
    api = base + "/api/rr-operator/kernel/executions/" + execution_id

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            context = browser.new_context(ignore_https_errors=False)
            page = context.new_page()
            anonymous = page.request.get(api)
            assert anonymous.status == 401, f"RR_ANONYMOUS_HTTP_{anonymous.status}"

            page.goto(page_url, wait_until="domcontentloaded")
            login = page.get_by_role("button", name="Sign in with Zitadel")
            login.wait_for(state="visible", timeout=20000)
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
                page.screenshot(
                    path=str(tmp_path / f"rr-result-{width}x{height}.png"),
                    full_page=True,
                )
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= window.innerWidth + 1"
                ), f"RR_RESULT_HORIZONTAL_OVERFLOW_{width}x{height}"

            context.close()
        finally:
            browser.close()

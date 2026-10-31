"""Pure contract tests: no GitHub credentials or real source repositories."""
from __future__ import annotations

import base64
import unittest
from pathlib import Path
from unittest.mock import patch

import check_browser_report
import watch_core
import verify_dispatch


def report(mode: str) -> dict:
    required = check_browser_report.MATRIX[mode]
    return {
        "suites": [{"specs": [{"title": title + " full test", "ok": True} for title in required]}],
        "stats": {"skipped": 0, "unexpected": 0, "expected": len(required)},
    }


class BrowserGateTests(unittest.TestCase):
    def test_both_positive_matrices(self) -> None:
        for mode in check_browser_report.MATRIX:
            with self.subTest(mode=mode):
                self.assertTrue(check_browser_report.validate(report(mode), mode))

    def test_missing_browser_case_is_not_pass(self) -> None:
        item = report("rr-plugin-v1")
        item["suites"][0]["specs"].pop()
        self.assertFalse(check_browser_report.validate(item, "rr-plugin-v1"))

    def test_failure_is_not_pass(self) -> None:
        item = report("rr-plugin-v1")
        item["suites"][0]["specs"][0]["ok"] = False
        self.assertFalse(check_browser_report.validate(item, "rr-plugin-v1"))

    def test_skipped_or_extra_cases_are_not_pass(self) -> None:
        item = report("rr-plugin-v1")
        item["stats"]["skipped"] = 1
        self.assertFalse(check_browser_report.validate(item, "rr-plugin-v1"))
        item = report("rr-plugin-v1")
        item["suites"][0]["specs"].append({"title": "irrelevant test", "ok": True})
        self.assertFalse(check_browser_report.validate(item, "rr-plugin-v1"))

    def test_unknown_contract_never_falls_back(self) -> None:
        self.assertFalse(check_browser_report.validate(report("legacy"), "unknown"))


class IndependentBrowserConfigurationTests(unittest.TestCase):
    def test_browser_uses_suiteshared_secret_and_no_default_auth_cookies(self) -> None:
        root = Path(__file__).parent
        runner = (root / "run_real_e2e.sh").read_text(encoding="utf-8")
        config = (root / "rr_real_playwright.config.ts").read_text(encoding="utf-8")
        default_web_config = "playwright.config.ts"
        self.assertIn("--config=playwright.rr-real.config.ts", runner)
        self.assertIn('pnpm exec playwright test "$SPEC" "${BROWSER_CONFIG_ARGS[@]}"', runner)
        self.assertNotIn("oidcTestCookies", config)
        self.assertNotIn("oidcTestConfig", config)
        self.assertNotIn("import './" + default_web_config, config)
        self.assertIn("storageState: { cookies: [], origins: [] }", config)
        self.assertIn("'QDIP_AUTH_COOKIE_SECRET'", config)
        self.assertIn("reuseExistingServer: false", config)

    def test_browser_contract_asserts_dedicated_config(self) -> None:
        root = Path(__file__).parent
        guard = (root / "check_oidc_session_contract.py").read_text(encoding="utf-8")
        self.assertIn("independent browser config is mandatory", guard)
        self.assertIn("browser starts anonymous", guard)
        self.assertIn("browser server signs with the same isolated secret", guard)


class IsolatedOidcFixtureTests(unittest.TestCase):
    @staticmethod
    def source(name: str) -> str:
        return (Path(__file__).parent / name).read_text(encoding="utf-8")

    def test_e2e_session_fixture_uses_current_role_bound_web_contract(self) -> None:
        provision = self.source("provision_tenants.py")
        browser = self.source("rr_oidc_session_browser.spec.ts")
        current = {
            "QDIP_AUTH_COOKIE_SECRET",
            "ZITADEL_QDIP_PROJECT_ID",
            "ZITADEL_QDIP_ORGANIZATION_ID",
            "QDIP_RR_ZITADEL_ROLE_KEY",
            "QDIP_STUDIO_ZITADEL_ROLE_KEY",
        }
        for key in current:
            with self.subTest(name=key):
                self.assertIn(key, provision)
                self.assertIn(key, browser)
        for retired in (
            "QDIP_WEB_SESSION_SIGNING_SECRET",
            "QDIP_RR_ALLOWED_ZITADEL_USER_IDS",
            "QDIP_STUDIO_ALLOWED_ZITADEL_USER_IDS",
            "QDIP_AUTH_ALLOWED_SUBJECTS",
            "QDIP_AUTH_OPERATOR_SUBJECTS",
        ):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, provision)
                self.assertNotIn(retired, browser)

    def test_studio_only_subject_is_a_required_negative_browser_case(self) -> None:
        provision = self.source("provision_tenants.py")
        browser = self.source("rr_oidc_session_browser.spec.ts")
        self.assertIn('"qdip-e2e-operator"', provision)
        self.assertIn('"qdip-e2e-studio-only"', provision)
        self.assertIn("isolated signed Studio-only role cannot access RR operator", browser)
        required = check_browser_report.MATRIX["rr-oidc-session-v1"]
        self.assertEqual(len(required), 14)
        self.assertIn("isolated signed Studio-only role cannot access RR operator", required)
        self.assertEqual(
            len([x for x in required if "isolated signed-session browser → real Core" in x]),
            3,
        )
        test_report = report("rr-oidc-session-v1")
        self.assertTrue(check_browser_report.validate(test_report, "rr-oidc-session-v1"))
        test_report["suites"][0]["specs"] = [
            spec for spec in test_report["suites"][0]["specs"]
            if not spec["title"].startswith("isolated signed Studio-only role")
        ]
        self.assertFalse(check_browser_report.validate(test_report, "rr-oidc-session-v1"))


class EconomicV2BrowserMatrixTests(unittest.TestCase):
    def test_real_core_economic_preflight_is_a_mandatory_case(self) -> None:
        source = (Path(__file__).parent / "rr_oidc_session_browser.spec.ts").read_text(encoding="utf-8")
        required = check_browser_report.MATRIX["rr-oidc-session-v1"]
        self.assertEqual(len(required), 14)
        label = "economic-v2 preview reaches real Core but cannot execute"
        self.assertIn(label, required)
        self.assertIn("test('" + label, source)
        self.assertIn("economic-v2/preflight", source)
        self.assertIn("economic-zero-executions", source)
        self.assertIn("supply_source_verified: false", source)
        fixture = report("rr-oidc-session-v1")
        self.assertTrue(check_browser_report.validate(fixture, "rr-oidc-session-v1"))
        fixture["suites"][0]["specs"] = [
            spec for spec in fixture["suites"][0]["specs"]
            if not spec["title"].startswith(label)
        ]
        self.assertFalse(check_browser_report.validate(fixture, "rr-oidc-session-v1"))


class ActiveQualificationRefTests(unittest.TestCase):
    def test_watcher_only_qualifies_canonical_merged_dev_pair(self) -> None:
        self.assertEqual(watch_core.BRANCHES, ("dev",))
        self.assertEqual(watch_core.OBS_BRANCHES, {"dev": "dev"})
        self.assertNotIn("feat/rr-plugin-computation-ownership", watch_core.BRANCHES)

    def test_dispatch_refuses_cross_product_branch_pair_before_any_network(self) -> None:
        environment = {
            "BACKEND_SHA": "a" * 40,
            "BACKEND_BRANCH": "feat/rr-plugin-computation-ownership",
            "OBSERVATORY_REF": "dev",
            "OBSERVATORY_SHA": "b" * 40,
            "E2E_SUITE_SHA": "c" * 40,
            "QUALIFICATION_KEY": "d" * 64,
            "RR_E2E_CONTRACT_MODE": "rr-oidc-session-v1",
            "QDIP_READ_TOKEN": "not-a-real-token",
        }
        with patch.dict("os.environ", environment), patch.object(verify_dispatch, "get") as remote:
            with self.assertRaisesRegex(RuntimeError, "mismatched Core/Web"):
                verify_dispatch.main()
            remote.assert_not_called()


class DashboardPairWatcherTests(unittest.TestCase):
    def test_unmerged_core_plugin_is_not_tested_as_retired_password_dashboard(self) -> None:
        # A missing Core presentation in a hypothetical old checkout must
        # fail closed even if Web/dev uses Zitadel. Canonical dev has merged
        # the plugin in reality, and its actual E2E must be tested separately.
        ledger = {"version": 1, "branches": {}}
        with (
            patch.dict("os.environ", {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": watch_core.TARGET,
                "QDIP_READ_TOKEN": "read-only-test",
                "GITHUB_TOKEN": "public-test",
                "GITHUB_SHA": "e" * 40,
            }),
            patch.object(watch_core, "fingerprint", return_value="test-suite"),
            patch.object(watch_core, "read_ledger", return_value=(ledger, None)),
            patch.object(watch_core, "head", side_effect=lambda repo, branch, token:
                ("a" if repo == watch_core.CORE else "b") * 40),
            patch.object(watch_core, "rr_contract_mode", return_value="legacy"),
            patch.object(watch_core, "supported", return_value=False),
            patch.object(watch_core, "dispatch") as dispatch,
            patch.object(watch_core, "write_ledger") as saved,
        ):
            self.assertEqual(watch_core.main(), 0)
            dispatch.assert_not_called()
            written = saved.call_args.args[0]["branches"]
            self.assertEqual(written["dev"]["status"], "RR_PLUGIN_NOT_MERGED")
            self.assertNotEqual(written["dev"]["status"], "PASS")


class ContractDiscoveryTests(unittest.TestCase):
    CORE = "a" * 40
    WEB = "b" * 40

    @staticmethod
    def web_source(code: str) -> dict:
        return {"type": "file", "content": base64.b64encode(code.encode()).decode()}

    def test_password_reference_operator_is_detected_by_real_web_source(self) -> None:
        results = [
            {"type": "file"},
            self.web_source("createOperatorSession() and verifyOperatorPassword()"),
        ]
        with patch.object(watch_core, "api", side_effect=results) as mock:
            self.assertEqual(
                watch_core.rr_contract_mode(self.CORE, self.WEB, "opaque"), "rr-plugin-v1"
            )
            self.assertIn("presentation.py", mock.call_args_list[0].args[0])
            self.assertIn(self.WEB, mock.call_args_list[1].args[0])

    def test_signed_oidc_session_contract_has_dedicated_required_mode(self) -> None:
        results = [
            {"type": "file"},
            self.web_source("Password authentication retired; use Zitadel OIDC"),
        ]
        with patch.object(watch_core, "api", side_effect=results):
            self.assertEqual(
                watch_core.rr_contract_mode(self.CORE, self.WEB, "opaque"), "rr-oidc-session-v1"
            )

    def test_old_backend_selects_legacy_only_on_actual_404(self) -> None:
        with patch.object(watch_core, "api", side_effect=FileNotFoundError):
            self.assertEqual(watch_core.rr_contract_mode(self.CORE, self.WEB, "opaque"), "legacy")

    def test_unknown_web_contract_fails_closed(self) -> None:
        results = [{"type": "file"}, self.web_source("unknown login implementation")]
        with patch.object(watch_core, "api", side_effect=results):
            with self.assertRaises(RuntimeError):
                watch_core.rr_contract_mode(self.CORE, self.WEB, "opaque")

    def test_network_or_auth_error_does_not_silently_downgrade(self) -> None:
        with patch.object(watch_core, "api", side_effect=RuntimeError("GitHub authentication denied")):
            with self.assertRaises(RuntimeError):
                watch_core.rr_contract_mode(self.CORE, self.WEB, "opaque")


if __name__ == "__main__":
    unittest.main()

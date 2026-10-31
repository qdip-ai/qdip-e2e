"""Evidence-safe coverage counts never imply a production E2E PASS."""
import unittest

from scripts.case_coverage import ROOT, SCOPE, browser_titles, requirements, summary


class CaseCoverageTests(unittest.TestCase):
    def test_current_required_matrix_has_unique_mapped_browser_specs(self):
        matrix = requirements((ROOT / "scripts/check_browser_report.py")
                              .read_text(encoding="utf-8"))
        titles = browser_titles((ROOT / "scripts/rr_oidc_session_browser.spec.ts")
                               .read_text(encoding="utf-8"))
        result = summary(matrix, titles)
        self.assertEqual(result["scope"], SCOPE)
        self.assertEqual((result["requiredCases"], result["mappedCases"]), (14, 14))
        self.assertEqual(result["executionOutcome"], "NOT_EVALUATED")
        self.assertEqual(result["productionReadiness"], "NOT_EVALUATED")
        self.assertIn("NOT_GLOBAL_QDIP", result["scopeKind"])

    def test_missing_case_never_counts_as_covered(self):
        result = summary(("expected case must exist",), ["unrelated"])
        self.assertEqual(result["mappedCases"], 0)
        self.assertEqual(result["coveragePercent"], 0)

    def test_duplicate_case_titles_are_ambiguous_not_complete(self):
        result = summary(("first required case",),
                         ["first required case suffix", "first required case suffix"])
        self.assertEqual(result["mappedCases"], 0)
        self.assertTrue(result["cases"][0]["ambiguous"])

    def test_reject_duplicate_or_empty_required_cases(self):
        for required in ((), ("duplicate required test", "duplicate required test")):
            with self.subTest(required=required), self.assertRaises(ValueError):
                summary(required, [])

    def test_browser_parser_rejects_comments_without_test_call(self):
        result = browser_titles("// test('comment')\n"
                                "test('real browser case', async ({page}) => {})")
        # The limited source scan is only a mapping sanity check, not
        # proof that an executable Playwright run passed.
        self.assertEqual(result, ["real browser case"])
        block_comment = "/*\ntest('fake case in comment', async () => {})\n*/"
        self.assertEqual(browser_titles(block_comment), [])
        self.assertEqual(summary(("fake case in comment",),
                                 browser_titles(block_comment))["mappedCases"], 0)


if __name__ == "__main__":
    unittest.main()

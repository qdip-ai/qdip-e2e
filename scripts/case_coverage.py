"""Evidence-safe test-case mapping coverage for the existing RR OIDC contract.

Does not claim ALL QDIP E2E scope, execution PASS, or production Zitadel
qualification. This checks whether each independently required browser-case
prefix in check_browser_report.py has one implementation in the Playwright spec.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MATRIX_FILE = ROOT / "scripts" / "check_browser_report.py"
SPEC_FILE = ROOT / "scripts" / "rr_oidc_session_browser.spec.ts"
SCOPE = "rr-oidc-session-v1"
_TEST = re.compile(r"\btest\s*\(\s*'([^']+)'")


def requirements(source: str, mode: str = SCOPE) -> tuple[str, ...]:
    """Parse the actual Python MATRIX data without evaluating arbitrary code."""
    tree = ast.parse(source)
    entries = [node.value for node in tree.body
               if isinstance(node, ast.AnnAssign)
               and isinstance(node.target, ast.Name)
               and node.target.id == "MATRIX"]
    if len(entries) != 1:
        raise ValueError("Missing unique E2E case matrix")
    value = ast.literal_eval(entries[0])
    cases = value.get(mode)
    if (type(cases) is not tuple or not cases or len(cases) > 1000
            or any(type(x) is not str or len(x) < 10 or len(x) > 240
                   for x in cases) or len(set(cases)) != len(cases)):
        raise ValueError("Invalid E2E case catalog")
    return cases


def browser_titles(source: str) -> list[str]:
    return [match.group(1) for match in _TEST.finditer(source)]


def summary(required: tuple[str, ...], actual_titles: list[str]) -> dict:
    """Only uniquely matched required cases count as covered."""
    if not required or len(set(required)) != len(required):
        raise ValueError("Missing or duplicate requirements")
    details = []
    for index, prefix in enumerate(required, 1):
        matches = [title for title in actual_titles if title.startswith(prefix)]
        details.append({"caseId": f"{SCOPE}-{index:02d}",
                        "mapped": len(matches) == 1,
                        "ambiguous": len(matches) > 1})
    covered = sum(int(x["mapped"]) for x in details)
    return {"schemaVersion": 1, "scope": SCOPE,
            "scopeKind": "SINGLE_RR_BROWSER_CONTRACT_NOT_GLOBAL_QDIP",
            "requiredCases": len(required), "mappedCases": covered,
            "coveragePercent": round(100 * covered / len(required)),
            "executionOutcome": "NOT_EVALUATED",
            "productionReadiness": "NOT_EVALUATED",
            "cases": details}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="Fail if any required case lacks a unique test")
    parser.add_argument("--output", default="",
                        help="Optional machine-readable JSON report destination")
    args = parser.parse_args()
    catalog = requirements(MATRIX_FILE.read_text(encoding="utf-8"))
    result = summary(catalog, browser_titles(SPEC_FILE.read_text(encoding="utf-8")))
    data = json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(data, encoding="utf-8")
    print(data, end="")
    return 0 if not args.check or result["mappedCases"] == result["requiredCases"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

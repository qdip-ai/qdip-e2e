"""Run private-source build/test commands without exposing raw output publicly.

Raw subprocess stdout/stderr stays in the ephemeral hosted runner's private temp
directory and is NEVER uploaded. Prints only an allowlisted stage status.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ALLOWED = {
    "backend-install", "mongodb-integration", "mongodb-recovery",
    "backend-start", "backend-http", "rr-plugin-http", "backend-restart", "backend-restart-verify",
    "observatory-install", "observatory-lint", "observatory-typecheck",
    "observatory-unit", "observatory-build", "browser-install", "browser-e2e",
    "sdk-install", "sdk-admission-restart", "sdk-admission", "sdk-e2e", "sdk-negative", "rr-auth-revocation", "test-report",
    "rr-actor-unit", "rr-actor-ruff", "core-quality", "observatory-format", "rr-replay-load",
}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=sorted(ALLOWED))
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--cwd", default=".")
    parser.add_argument("--output", default="")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command or args.timeout < 1 or args.timeout > 1800:
        return 2
    temp = os.environ.get("RUNNER_TEMP")
    if not temp or os.environ.get("GITHUB_ACTIONS") != "true":
        print("SAFE_STAGE=REJECTED", file=sys.stderr)
        return 2
    path = Path(temp) / f"qdip-{args.stage}.log"
    try:
        with path.open("wb") as log:
            completed = subprocess.run(
                command,
                cwd=args.cwd,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=args.timeout,
                check=False,
                env=os.environ.copy(),
            )
        status = "PASS" if completed.returncode == 0 else "FAIL"
    except subprocess.TimeoutExpired:
        status = "TIMEOUT"
    except (OSError, ValueError):
        status = "INFRA_FAIL"
    if args.output:
        # Only the audited Chromium JSON result is copied into RUNNER_TEMP;
        # never upload it or echo its content to public Actions logs.
        try:
            if path.exists():
                Path(args.output).write_bytes(path.read_bytes())
        except OSError:
            status = "INFRA_FAIL"
    if args.stage == "mongodb-recovery" and status == "PASS":
        # This specific runner restores only an invented database on a loopback
        # native Mongo replica. Publish bounded numbers/statuses, never the
        # private backup, signing keys, application stdout or stack traces.
        source = path.read_text(encoding="utf-8", errors="replace")
        rto_values = re.findall(
            r"^RR_NATIVE_DISPOSABLE_RESTORE_RTO_MS=([0-9]{1,9})$",
            source,
            flags=re.MULTILINE,
        )
        accepted = (
            len(rto_values) == 1
            and source.count(
                "RR_NATIVE_DISPOSABLE_RPO_LOST_RECORDS=0 "
                "(fixed synthetic five-collection fixture only)"
            ) == 1
            and "RR_RECOVERY_ECONOMIC_HMAC_TAMPER=PASS" in source
            and "RR_NATIVE_REAL_BACKUP_RESTORE=PASS " in source
        )
        if not accepted:
            # No silent scope-limited PASS if RTO/RPO or HMAC drill metrics
            # disappear, become ambiguous, or are not independently verified.
            status = "FAIL"
            print("QDIP_RECOVERY_METRICS=FAIL")
        else:
            print("RR_DISPOSABLE_RESTORE_RTO_MS=" + rto_values[0])
            print("RR_DISPOSABLE_RPO_LOST_RECORDS=0")
            print("RR_DISPOSABLE_HMAC_ARCHIVE_INTEGRITY=PASS")
            print("QDIP_RECOVERY_METRICS=PASS")
    if args.stage == "rr-replay-load" and status == "PASS":
        # Backend raw output remains local. Only bounded synthetic replay
        # latency and successful read count may leave this runner.
        source = path.read_text(encoding="utf-8", errors="replace")
        p95 = re.findall(
            r"^RR_LOAD_P95_MS=([0-9]{1,8}\.[0-9]{2})$",
            source,
            flags=re.MULTILINE,
        )
        accepted = (
            len(p95) == 1
            and source.count("RR_LOAD_REQUESTS=40 CONCURRENCY=4") == 1
            and source.count("RR_LOAD_NON_200=0") == 1
            and source.count(
                "RR_LOAD_RESULT=MEASURED (SLO acceptance must be decided separately)"
            ) == 1
        )
        if not accepted:
            status = "FAIL"
            print("RR_REPLAY_LATENCY_EVIDENCE=FAIL")
        else:
            print("RR_SYNTHETIC_REPLAY_REQUESTS=40")
            print("RR_SYNTHETIC_REPLAY_CONCURRENCY=4")
            print("RR_SYNTHETIC_REPLAY_NON_200=0")
            print("RR_SYNTHETIC_REPLAY_P95_MS=" + p95[0])
            print("RR_REPLAY_LATENCY_EVIDENCE=MEASURED_NOT_SLO")
    # Separate sanitized phase ledger for final TEST_FAIL vs INFRA_FAIL status.
    with (Path(temp) / "qdip-stage-results.jsonl").open("a", encoding="utf-8") as out:
        out.write(json.dumps({"stage": args.stage, "status": status}) + chr(10))
    if args.stage == "core-quality" and status != "PASS" and path.exists():
        # Core's canonical quality entrypoint prints only the selected command
        # before running it. Public evidence may name its fixed category, never
        # relay private Ruff/mypy/pytest output, test names, traceback or paths.
        source = path.read_text(encoding="utf-8", errors="replace")
        categories = (
            (r"^\$ .* -m ruff check \.$", "RUFF"),
            (r"^\$ .* -m mypy app$", "MYPY_APP"),
            (r"^\$ .* -m mypy tests$", "MYPY_TESTS"),
            (r"^\$ .* -m pytest$", "PYTEST"),
            (r"^\$ .* -m app\.runtime\.freeze_evidence$", "FREEZE"),
        )
        last = "UNKNOWN"
        positions = [
            (match.start(), label)
            for pattern, label in categories
            for match in re.finditer(pattern, source, flags=re.MULTILINE)
        ]
        if positions:
            last = max(positions, key=lambda item: item[0])[1]
        print("QDIP_CORE_QUALITY_FAILED_PHASE=" + last)
        if last == "RUFF":
            # An ordinal over the ephemeral private checkout lets the owner's
            # authorized GitHub reader resolve affected files out of band.
            # Never emit private paths, source lines, content or raw errors.
            candidates = sorted(
                entry.as_posix()
                for entry in Path(".").rglob("*.py")
                if entry.is_file()
                and not any(part.startswith(".") for part in entry.parts)
            )
            by_path = {name.removeprefix("./"): i + 1 for i, name in enumerate(candidates)}
            print("QDIP_RUFF_FILE_INDEX_SIZE=" + str(len(candidates)))
            findings: set[tuple[int, str]] = set()
            lines = source.splitlines()
            for i, line in enumerate(lines):
                compact = re.match(
                    r"^([a-zA-Z0-9_./-]+\.py):\d+:\d+:\s+([A-Z][0-9]{3})\b",
                    line,
                )
                if compact:
                    index = by_path.get(compact.group(1).removeprefix("./"))
                    if index is not None:
                        findings.add((index, compact.group(2)))
                code = re.match(r"^([A-Z][0-9]{3})\b", line)
                if code:
                    for location in lines[i + 1 : i + 4]:
                        match = re.search(
                            r"--?>\s+([a-zA-Z0-9_./-]+\.py):\d+:\d+",
                            location,
                        )
                        if match:
                            index = by_path.get(match.group(1).removeprefix("./"))
                            if index is not None:
                                findings.add((index, code.group(1)))
                            break
            print("QDIP_RUFF_FINDING_COUNT=" + str(len(findings)))
            for index, code in sorted(findings)[:20]:
                print(f"QDIP_RUFF_FILE_ORDINAL={index} RULE={code}")
            if len(findings) > 20:
                print("QDIP_RUFF_FINDINGS_TRUNCATED=true")
    if args.stage == "mongodb-recovery" and status != "PASS" and path.exists():
        # Safe only for the synthetic hard-coded local RR restore verifier.
        # Never release unfiltered backend stderr or payloads into public Actions.
        source = path.read_text(encoding="utf-8", errors="replace")
        phases = re.findall(
            r"^RR_RECOVERY_PHASE=(SEED_START|BASE_SEED|ECONOMIC_SEED_OLD|"
            r"ECONOMIC_SEED_ROTATED|BASE_VERIFY|ECONOMIC_VERIFY|"
            r"VERIFY_START|TAMPER_START)$",
            source,
            flags=re.MULTILINE,
        )
        kinds = re.findall(
            r"^RR_RECOVERY_ERROR_CLASS=(ValidationError|TypeError|ValueError|"
            r"RuntimeError|ImportError|ModuleNotFoundError|AssertionError|"
            r"KeyError|AttributeError|OperationFailure|OTHER)$",
            source,
            flags=re.MULTILINE,
        )
        print("QDIP_RECOVERY_LAST_PHASE=" + (phases[-1] if phases else "UNKNOWN"))
        print("QDIP_RECOVERY_ERROR_CLASS=" + (kinds[-1] if kinds else "UNKNOWN"))
    print(f"QDIP_STAGE_{args.stage.upper().replace('-', '_')}={status}")
    return 0 if status == "PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())

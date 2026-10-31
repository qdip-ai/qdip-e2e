"""Isolated SDK credentials must be policy-valid before expensive native E2E."""
from __future__ import annotations

import contextlib
import io
import os
import runpy
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


class FixturePolicyTests(unittest.TestCase):
    def test_rr_worker_and_caller_keys_are_distinct_and_scoped(self) -> None:
        rows: list[dict] = []

        class Keys:
            def count_documents(self, query: dict) -> int:
                return len(rows)

            def insert_one(self, value: dict) -> None:
                rows.append(value)

        class Database:
            name = "qdip_e2e"

            def get_default_database(self):
                return self

            def __getitem__(self, name: str):
                self_test.assertEqual(name, "org_api_keys")
                return Keys()

            def close(self) -> None:
                pass

        self_test = self
        client = Database()
        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / "github-env"
            env_path.touch()
            env = {
                "GITHUB_ACTIONS": "true",
                "MONGODB_URL": "mongodb://127.0.0.1:27019/qdip_e2e?replicaSet=rrtest",
                "GITHUB_ENV": str(env_path),
            }
            with (
                patch.dict(os.environ, env),
                patch.dict(sys.modules, {"pymongo": types.SimpleNamespace(MongoClient=lambda _: client)}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                runpy.run_path(str(ROOT / "scripts/provision_tenants.py"), run_name="__main__")
            names = set(line.split("=", 1)[0] for line in env_path.read_text().splitlines())
            self.assertTrue({"E2E_KEY_A", "E2E_KEY_B", "E2E_WORKER_KEY", "E2E_CALLER_KEY"} <= names)

        by_id = {r["id"]: r for r in rows}
        self.assertEqual(len(by_id), 4)
        self.assertEqual(
            by_id["rr-e2e-key-a"]["scopes"],
            ["decisions:execute", "decisions:read", "audit:read"],
        )
        self.assertEqual(by_id["rr-e2e-key-b"]["org_id"], "rr-e2e-org-b")
        self.assertEqual(by_id["rr-e2e-worker-a"]["scopes"], ["plugins:register"])
        self.assertEqual(by_id["rr-e2e-caller-a"]["scopes"], ["plugins:read", "plugins:execute"])
        self.assertEqual(by_id["rr-e2e-worker-a"]["org_id"], by_id["rr-e2e-caller-a"]["org_id"])
        for key in ("rr-e2e-worker-a", "rr-e2e-caller-a"):
            self.assertEqual(by_id[key]["plugin_id"], "staffing")
            self.assertEqual(by_id[key]["allowed_capabilities"], ["staffing.plan"])
        for key in ("rr-e2e-key-a", "rr-e2e-key-b"):
            self.assertNotIn("plugin_id", by_id[key])
            self.assertFalse(any(scope.startswith("plugins:") for scope in by_id[key]["scopes"]))
        self.assertEqual(len({record["key_hash"] for record in rows}), 4)


if __name__ == "__main__":
    unittest.main()

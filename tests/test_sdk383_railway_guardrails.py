"""Fast fail-closed guardrails for the *independent* live SDK #383 E2E scripts.

These are local regression checks, NOT substitutes for real Railway E2E.
"""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from sdk383_sealed_railway_e2e import (
    KEY_ID_NAME, SECRET_NAME, GateError, Railway, assert_sealed, main as canary_main,
)
from sdk383_sealed_worker_lifecycle_e2e import main as worker_main


class SealedRailwayGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.id = "2d1473e4-0ad5-44bd-83f7-5e6f2680119e"
        self.nodes = [
            {"name": SECRET_NAME, "isSealed": True},
            {"name": KEY_ID_NAME, "isSealed": False},
        ]
        self.values = {KEY_ID_NAME: self.id}

    def test_exact_write_only_secret_and_public_id_accepted(self) -> None:
        assert_sealed(self.nodes, self.values, self.id)

    def test_readable_secret_is_rejected(self) -> None:
        self.nodes[0]["isSealed"] = False
        with self.assertRaisesRegex(GateError, "unsealed"):
            assert_sealed(self.nodes, self.values, self.id)

    def test_sealed_public_id_is_rejected(self) -> None:
        self.nodes[1]["isSealed"] = True
        with self.assertRaisesRegex(GateError, "sealed"):
            assert_sealed(self.nodes, self.values, self.id)

    def test_missing_metadata_is_rejected(self) -> None:
        with self.assertRaises(GateError):
            assert_sealed(self.nodes[:1], self.values, self.id)

    def test_wrong_id_is_rejected(self) -> None:
        with self.assertRaisesRegex(GateError, "does not match"):
            assert_sealed(self.nodes, {KEY_ID_NAME: "different"}, self.id)

    def test_pending_query_requests_environment_patch_fields(self) -> None:
        client = object.__new__(Railway)
        calls = []
        def query(document, variables):
            calls.append((document, variables))
            return {"environmentStagedChanges": None}
        client.query = query
        client.pending()
        self.assertEqual(len(calls), 1)
        self.assertIn("environmentStagedChanges(environmentId: $e) { id status }", calls[0][0])

    def test_pending_unrelated_railway_patch_blocks_delivery(self) -> None:
        client = object.__new__(Railway)
        client.query = lambda document, variables: {
            "environmentStagedChanges": {"id": "unrelated", "status": "STAGED"},
        }
        with self.assertRaisesRegex(GateError, "Railway staged patch requires inspection"):
            client.pending()

    def test_no_project_token_fails_closed(self) -> None:
        with self.assertRaisesRegex(GateError, "Missing scoped"):
            Railway("invalid")

    def test_canary_denied_without_explicit_qa_approval(self) -> None:
        with patch.dict(os.environ, {"QDIP_SDK383_E2E_APPROVED": ""}):
            with self.assertRaisesRegex(GateError, "approval"):
                canary_main()

    def test_worker_denied_without_explicit_qa_approval(self) -> None:
        with patch.dict(os.environ, {"QDIP_SDK383_E2E_APPROVED": ""}):
            with self.assertRaisesRegex(GateError, "approval"):
                worker_main()


if __name__ == "__main__":
    unittest.main()

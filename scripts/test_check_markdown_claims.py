#!/usr/bin/env python3
"""Mutation proofs for the whole-tree Markdown claim checks."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_markdown_claims as checker

PROTO = """
// service Commented {
syntax = "proto3";
service Alpha { rpc A(Req) returns (Resp); }
/* service Hidden { */
service Beta {
  option note = "service Quoted {";
}
"""
GNMI = "service gNMI { rpc Get(Req) returns (Resp); }\n"
GRPC_DOC = "The gRPC surface across three services.\n\nTwo native rustbgpd v1 services plus gNMI.\n"


class EvpnBumTests(unittest.TestCase):
    def test_current_document_with_stale_posture_fails(self) -> None:
        errors = checker.evpn_bum_errors(
            {"docs/how-to/evpn.md": "BUM enforcement is an\noperator-facing opt-in.\n"}
        )
        self.assertEqual(
            errors, ["docs/how-to/evpn.md: stale EVPN BUM posture claim (operator_facing_opt_in)"]
        )

    def test_history_and_unrelated_blocks_pass(self) -> None:
        stale = "`apply_bum_enforcement` (default: false).\n"
        self.assertEqual(
            checker.evpn_bum_errors(
                {
                    "CHANGELOG.md": stale,
                    "docs/adr/0001-x.md": stale,
                    "tests/interop/m1-receipt.md": stale,
                    "docs/guide.md": "An operator-facing opt-in unrelated to flooding.\n",
                }
            ),
            [],
        )
        self.assertEqual(len(checker.evpn_bum_errors({"docs/guide.md": stale})), 1)


class GrpcCountTests(unittest.TestCase):
    def test_proto_tokens_skip_comments_and_strings(self) -> None:
        self.assertEqual(checker.service_names(PROTO), ["Alpha", "Beta"])

    def test_matching_counts_pass(self) -> None:
        self.assertEqual(checker.grpc_count_errors({"a.md": GRPC_DOC}, PROTO, GNMI, (1, 1)), [])

    def test_stale_counts_fail(self) -> None:
        stale = GRPC_DOC.replace("three", "four").replace("Two", "3")
        errors = checker.grpc_count_errors({"a.md": stale}, PROTO, GNMI, (1, 1))
        self.assertEqual(
            errors,
            [
                "a.md: observed 4, classification total, proto-derived expected 3",
                "a.md: observed 3, classification native, proto-derived expected 2",
            ],
        )

    def test_bare_native_count_is_a_claim_only_beside_a_total(self) -> None:
        paragraph = "The gRPC surface across three services: two native plus gNMI.\n"
        self.assertEqual(checker.grpc_count_errors({"a.md": paragraph}, PROTO, GNMI, (1, 1)), [])
        self.assertIn(
            "classification native",
            checker.grpc_count_errors(
                {"a.md": paragraph.replace("two", "five")}, PROTO, GNMI, (1, 1)
            )[0],
        )
        orphan = "Two native builds.\n"
        self.assertEqual(checker.grpc_count_errors({"a.md": orphan}, PROTO, GNMI, (0, 0)), [])

    def test_claim_count_drift_fails(self) -> None:
        errors = checker.grpc_count_errors({"a.md": GRPC_DOC}, PROTO, GNMI, (2, 1))
        self.assertIn("found 1 total-service and 1 native-service claims", errors[0])

    def test_unexpected_gnmi_services_fail(self) -> None:
        errors = checker.grpc_count_errors({}, PROTO, GNMI + "service Extra {}\n", (0, 0))
        self.assertIn("expected exactly the gNMI service", errors[0])


class AddNeighborTests(unittest.TestCase):
    def sources(self) -> dict[str, str]:
        return {
            path: f"curl {checker.ADD_NEIGHBOR} {intent} {' '.join([mask] * count)}\n"
            for path, (intent, mask, count) in checker.ADD_NEIGHBOR_SOURCES.items()
        }

    def test_intent_payloads_pass(self) -> None:
        self.assertEqual(checker.add_neighbor_errors(self.sources()), [])

    def test_new_or_missing_caller_fails(self) -> None:
        sources = self.sources()
        sources["docs/new.md"] = checker.ADD_NEIGHBOR
        self.assertIn("callers are", checker.add_neighbor_errors(sources)[0])
        del sources["docs/new.md"], sources["docs/interop.md"]
        self.assertIn("callers are", checker.add_neighbor_errors(sources)[0])

    def test_config_payload_and_mask_drift_fail(self) -> None:
        sources = self.sources()
        sources["docs/interop.md"] = f"{checker.ADD_NEIGHBOR} -d '{{\"config\": {{}}}}'\n"
        errors = " ".join(checker.add_neighbor_errors(sources))
        self.assertIn("is not the intent form", errors)
        self.assertIn("mask(s), found 0", errors)
        self.assertIn("still sends the config form", errors)


class RepositoryTests(unittest.TestCase):
    def test_repository_passes(self) -> None:
        self.assertEqual(checker.check(checker.ROOT), [])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Readiness must cover Alice's independently refreshed neighbor cache."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "alice_consumer", Path(__file__).with_name("alice-consumer.py")
)
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


class StoreReadinessTests(unittest.TestCase):
    def neighbors(self, filtered=False):
        peers = ["pb_as64496", "pb6_as64496", "pb_as64497", "pb6_as64497"]
        if filtered:
            peers.append("pb_as64498")
        return [{"id": peer, "state": "up"} for peer in peers]

    def check(self, neighbors, filtered=False, totals=None, ready_only=True):
        if totals is None:
            totals = {"imported": 7, "filtered": 2 if filtered else 0}
        documents = {
            "/status": {
                "version": "6.2.0",
                "routes": {"total_routes": totals},
            },
            "/routeservers/rs0/neighbors": {"neighbors": neighbors},
        }
        args = ["alice-consumer.py", "http://fixture", "6.2.0"]
        if ready_only:
            args.append("--stores-ready")
        if filtered:
            args.append("--filtered-peer")
        with patch.object(consumer.sys, "argv", args), patch.object(
            consumer, "get_json", side_effect=lambda base, path: documents[path]
        ):
            consumer.main()

    def test_route_totals_do_not_hide_stale_neighbors(self):
        stale = self.neighbors()
        stale[2]["state"] = stale[3]["state"] = "down"
        with self.assertRaisesRegex(SystemExit, "neighbors not up"):
            self.check(stale)
        self.check(self.neighbors())

    def test_neighbor_inventory_must_be_exact(self):
        wrong = self.neighbors()
        wrong[0]["id"] = "unexpected"
        for neighbors in [
            None, self.neighbors()[:-1], wrong,
            self.neighbors() + self.neighbors()[:1],
        ]:
            with self.subTest(neighbors=neighbors), self.assertRaises(SystemExit):
                self.check(neighbors)

    def test_fifth_peer_needs_its_own_complete_cache_and_totals(self):
        with self.assertRaisesRegex(SystemExit, "neighbor IDs drifted"):
            self.check(self.neighbors(), filtered=True)
        with self.assertRaisesRegex(SystemExit, "routes store totals drifted"):
            self.check(
                self.neighbors(True), filtered=True,
                totals={"imported": 7, "filtered": 0},
            )
        stale = self.neighbors(True)
        stale[-1]["state"] = "down"
        with self.assertRaisesRegex(SystemExit, "neighbors not up"):
            self.check(stale, filtered=True)
        self.check(self.neighbors(True), filtered=True)

    def test_full_consumer_continues_past_readiness(self):
        with self.assertRaisesRegex(KeyError, "/config"):
            self.check(self.neighbors(), ready_only=False)


if __name__ == "__main__":
    unittest.main()

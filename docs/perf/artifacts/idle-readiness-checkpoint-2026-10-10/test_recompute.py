#!/usr/bin/env python3
"""Plausible broken-input controls against this receipt's own retained data."""

import copy
from datetime import datetime, timedelta
import json
from pathlib import Path
import unittest

import recompute as r

ROOT = Path(__file__).resolve().parent


class ReceiptControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = json.loads((ROOT / "records.json").read_text())
        cls.provenance = json.loads((ROOT / "provenance.json").read_text())
        cls.audits = json.loads((ROOT / "feature-audit.json").read_text())
        # Establish the complete positive before relying on any negative case.
        r.compute(cls.records)
        r.validate_provenance(cls.provenance, cls.audits)

    def reject_records(self, edit):
        data = copy.deepcopy(self.records)
        edit(data[r.CELLS[0]])
        with self.assertRaises((AssertionError, KeyError, ValueError)):
            r.compute(data)

    def reject_audits(self, edit):
        data = copy.deepcopy(self.audits)
        edit(data)
        with self.assertRaises((AssertionError, KeyError, ValueError)):
            r.validate_provenance(self.provenance, data)

    def test_complete_receipt_and_stored_clocks(self):
        r.main()

    def test_long_gap_is_retained_without_cutoff(self):
        data = copy.deepcopy(self.records)
        events = [
            item["event"]
            for item in data[r.CELLS[0]]["selected_daemon_events"]
            if item["event"]["fields"]["message"] == "handling route refresh request"
        ]
        stamp = datetime.fromisoformat(events[1]["timestamp"].replace("Z", "+00:00"))
        events[1]["timestamp"] = (stamp + timedelta(seconds=1)).isoformat()
        _, pairs, _ = r.compute(data)
        self.assertEqual(len(pairs), 24)
        self.assertGreater(pairs[0]["inter_handler_gap_ms"], 1000)

    def test_missing_pair_fails(self):
        def edit(record):
            selected = record["selected_daemon_events"]
            index = next(
                i
                for i, item in enumerate(selected)
                if item["event"]["fields"]["message"] == "handling route refresh request"
            )
            del selected[index]

        self.reject_records(edit)

    def test_missing_checkpoint_fails(self):
        def edit(record):
            lines = record["harness_log"].splitlines()
            index = next(
                i for i, line in enumerate(lines) if line.startswith("converged_table_checkpoint,")
            )
            del lines[index]
            record["harness_log"] = "\n".join(lines)

        self.reject_records(edit)

    def test_readiness_failure_fails(self):
        self.reject_records(
            lambda record: record["full_daemon_scan"]["readiness_failures"].append(
                {"fields": {"message": "readiness probe failed: RIB manager probe timed out"}}
            )
        )

    def test_native_failures_and_forced_cleanup_fail(self):
        for field in ("cell", "harness", "daemon", "metrics"):
            with self.subTest(exit=field):
                self.reject_records(
                    lambda record, field=field: record["exits"].__setitem__(field, 1)
                )
        self.reject_records(lambda record: record.__setitem__("forced_kill", 1))

    def test_incomplete_table_and_missing_eor_fail(self):
        for source, replacement in (
            ("unique=399828,eor=present", "unique=399827,eor=present"),
            ("unique=399828,eor=present", "unique=399828,eor=absent"),
        ):
            with self.subTest(replacement=replacement):
                self.reject_records(
                    lambda record, source=source, replacement=replacement: record.__setitem__(
                        "harness_log", record["harness_log"].replace(source, replacement, 1)
                    )
                )

    def test_missing_unique_and_duplicate_build_units_fail(self):
        audit = self.audits["candidate"]
        build_only = audit["including_build_units"].keys() - audit["normal_units"].keys()
        duplicate = next(
            path
            for path in sorted(build_only)
            if Path(path).parent.name.startswith("libc-")
            and Path(path).name == "build-script-build-script-build.json"
        )
        for path in (sorted(build_only)[0], duplicate):
            with self.subTest(unit=path):
                self.reject_audits(
                    lambda data, path=path: data["candidate"]["including_build_units"].__delitem__(
                        path
                    )
                )

    def test_normal_and_build_features_fail(self):
        for scope in ("normal_units", "including_build_units"):
            with self.subTest(scope=scope):
                audit = self.audits["candidate"]
                paths = (
                    audit["normal_units"]
                    if scope == "normal_units"
                    else audit["including_build_units"].keys() - audit["normal_units"].keys()
                )
                path = sorted(paths)[0]

                def edit(data, path=path):
                    for selected in ("normal_units", "including_build_units"):
                        if path in data["candidate"][selected]:
                            data["candidate"][selected][path]["features"] = '["unmatched-feature"]'

                self.reject_audits(edit)

    def test_build_dependency_identity_fails(self):
        audit = self.audits["candidate"]
        build_only = audit["including_build_units"].keys() - audit["normal_units"].keys()
        path = next(
            path for path in sorted(build_only) if audit["including_build_units"][path]["deps"]
        )

        def edit(data):
            data["candidate"]["including_build_units"][path]["deps"][0][0] += 1

        self.reject_audits(edit)

    def test_both_equal_bench_enabled_arms_fail(self):
        for name in ("bin-rustbgpd.json", "lib-rustbgpd_rib.json"):
            with self.subTest(unit=name):

                def edit(data, name=name):
                    for arm in r.ARMS:
                        path = next(
                            path for path in data[arm]["normal_units"] if Path(path).name == name
                        )
                        for scope in ("normal_units", "including_build_units"):
                            data[arm][scope][path]["features"] = '["bench-internals"]'

                self.reject_audits(edit)

    def test_failed_final_integrity_and_missing_window_fail(self):
        for field, value in (
            ("end_instruments", "binary: FAILED\n"),
            ("outer_exit", 1),
            ("finish", ""),
        ):
            with self.subTest(field=field):
                data = copy.deepcopy(self.provenance)
                data["window"][field] = value
                with self.assertRaises((AssertionError, KeyError, ValueError)):
                    r.validate_provenance(data, self.audits)

    def test_wrong_family_and_reversed_pair_clock_fail(self):
        for kind in ("family", "clock"):
            with self.subTest(kind=kind):

                def edit(record, kind=kind):
                    event = next(
                        item["event"]
                        for item in record["selected_daemon_events"]
                        if item["event"]["fields"]["message"] == "handling route refresh request"
                    )
                    if kind == "family":
                        event["fields"]["afi"] = "Ipv6"
                    else:
                        event["timestamp"] = "2099-01-01T00:00:00Z"

                self.reject_records(edit)


if __name__ == "__main__":
    unittest.main()

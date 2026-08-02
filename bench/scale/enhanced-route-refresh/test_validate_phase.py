#!/usr/bin/env python3
"""Load-bearing tests for the durable phase validator."""

import pathlib
import tempfile
import unittest

import validate_phase


def line(name, value, **labels):
    encoded = ",".join(f'{key}="{labels[key]}"' for key in sorted(labels))
    suffix = f"{{{encoded}}}" if labels else ""
    return f"{name}{suffix} {value}\n"


def metrics(rib, active, stale, begin, eorr, timeout, *, current=1, established=1, flaps=0):
    text = ""
    text += line(
        "bgp_rib_prefixes",
        rib,
        peer=validate_phase.PEER,
        afi_safi="all",
    )
    for scope in ("aggregate", "ipv4_unicast"):
        text += line(
            "bgp_max_prefix_usage",
            rib,
            peer=validate_phase.PEER,
            scope=scope,
        )
    text += line(
        "bgp_route_refresh_in_progress",
        active,
        peer=validate_phase.PEER,
        afi_safi=validate_phase.FAMILY,
    )
    text += line(
        "bgp_route_refresh_stale_entries",
        stale,
        peer=validate_phase.PEER,
        afi_safi=validate_phase.FAMILY,
    )
    text += line(
        "bgp_session_established_total",
        established,
        peer=validate_phase.PEER,
    )
    text += line(
        "bgp_peer_session_established",
        current,
        peer=validate_phase.PEER,
        interface="",
    )
    if flaps is not None:
        text += line("bgp_session_flaps_total", flaps, peer=validate_phase.PEER)
    for operation, count in (
        ("begin", begin),
        ("eorr", eorr),
        ("timeout", timeout),
    ):
        text += line(
            "bgp_rib_route_refresh_actor_duration_seconds_count",
            count,
            operation=operation,
        )
        text += line(
            "bgp_rib_route_refresh_actor_duration_seconds_sum",
            count * 0.001,
            operation=operation,
        )
    return text


class PhaseValidatorTests(unittest.TestCase):
    def parse(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "metrics.prom"
            path.write_text(text, encoding="utf-8")
            return validate_phase.parse_metrics(path)

    def test_every_phase_accepts_only_its_exact_production_state(self):
        baseline = self.parse(metrics(100_000, 0, 0, 7, 11, 13))
        for phase, expected in validate_phase.EXPECTED.items():
            rib, active, stale, begin, eorr, timeout = expected
            candidate = self.parse(
                metrics(
                    rib,
                    active,
                    stale,
                    7 + begin,
                    11 + eorr,
                    13 + timeout,
                )
            )
            summary = validate_phase.validate(phase, candidate, baseline)
            self.assertEqual(summary["phase"], phase)

    def test_later_phase_requires_current_uninterrupted_session(self):
        baseline = self.parse(metrics(100_000, 0, 0, 7, 11, 13))
        candidate = dict(rib=100_000, active=0, stale=0, begin=9, eorr=12, timeout=13)
        summary = validate_phase.validate(
            "restored", self.parse(metrics(**candidate, flaps=None)), baseline
        )
        self.assertEqual(summary["session_established"], 1)
        for name, change, metric in (
            ("current-down", {"current": 0}, "bgp_peer_session_established"),
            ("reestablished", {"established": 2}, "bgp_session_established_total"),
            ("flapped", {"flaps": 1}, "bgp_session_flaps_total"),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(AssertionError, metric):
                    validate_phase.validate(
                        "restored", self.parse(metrics(**candidate, **change)), baseline
                    )

    def test_missing_eorr_sweep_is_red(self):
        baseline = self.parse(metrics(100_000, 0, 0, 0, 0, 0))
        unswept = self.parse(metrics(100_000, 0, 0, 2, 1, 0))
        with self.assertRaisesRegex(AssertionError, "bgp_rib_prefixes"):
            validate_phase.validate("eorr", unswept, baseline)

    def test_missing_actor_observation_is_red(self):
        baseline = self.parse(metrics(100_000, 0, 0, 0, 0, 0))
        unobserved = self.parse(metrics(100_000, 1, 100_000, 0, 0, 0))
        with self.assertRaisesRegex(
            AssertionError,
            "bgp_rib_route_refresh_actor_duration_seconds_count",
        ):
            validate_phase.validate("first-borr", unobserved, baseline)


if __name__ == "__main__":
    unittest.main()

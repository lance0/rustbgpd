#!/usr/bin/env python3
"""Load-bearing tests for the durable phase validator."""

import pathlib
import tempfile
import unittest

import validate_phase


VALID_SUM_DELTAS = {
    "baseline": {"begin": 0.0, "eorr": 0.0, "timeout": 0.0},
    "first-borr": {"begin": 0.010, "eorr": 0.0, "timeout": 0.0},
    "replay-one": {"begin": 0.010, "eorr": 0.0, "timeout": 0.0},
    "duplicate-borr": {"begin": 0.020, "eorr": 0.0, "timeout": 0.0},
    "eorr": {"begin": 0.020, "eorr": 0.100, "timeout": 0.0},
    "restored": {"begin": 0.020, "eorr": 0.100, "timeout": 0.0},
    "timeout-borr": {"begin": 0.030, "eorr": 0.100, "timeout": 0.0},
    "timeout-complete": {"begin": 0.030, "eorr": 0.100, "timeout": 0.100},
}


def line(name, value, **labels):
    encoded = ",".join(f'{key}="{labels[key]}"' for key in sorted(labels))
    suffix = f"{{{encoded}}}" if labels else ""
    return f"{name}{suffix} {value}\n"


def metrics(
    rib,
    active,
    stale,
    actor_counts,
    actor_sums,
    *,
    current=1,
    established=1,
    flaps=0,
):
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
    for operation in validate_phase.OPERATIONS:
        text += line(
            "bgp_rib_route_refresh_actor_duration_seconds_count",
            actor_counts[operation],
            operation=operation,
        )
        text += line(
            "bgp_rib_route_refresh_actor_duration_seconds_sum",
            actor_sums[operation],
            operation=operation,
        )
    return text


def metric_key(name, **labels):
    return name, tuple(sorted(labels.items()))


class PhaseValidatorTests(unittest.TestCase):
    BASE_COUNTS = {"begin": 7, "eorr": 11, "timeout": 13}
    BASE_SUMS = {"begin": 0.700, "eorr": 1.100, "timeout": 1.300}

    def parse(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "metrics.prom"
            path.write_text(text, encoding="utf-8")
            return validate_phase.parse_metrics(path)

    def make_chain(self, base_counts=None, base_sums=None):
        base_counts = dict(base_counts or self.BASE_COUNTS)
        base_sums = dict(base_sums or self.BASE_SUMS)
        chain = {}
        for phase, expected in validate_phase.EXPECTED.items():
            rib, active, stale, *count_deltas = expected
            counts = {
                operation: base_counts[operation] + delta
                for operation, delta in zip(validate_phase.OPERATIONS, count_deltas, strict=True)
            }
            sums = {
                operation: base_sums[operation] + VALID_SUM_DELTAS[phase][operation]
                for operation in validate_phase.OPERATIONS
            }
            chain[phase] = self.parse(metrics(rib, active, stale, counts, sums))
        return chain

    def validate_chain_phase(self, chain, phase, candidate=None, predecessor=None):
        previous_phase = validate_phase.PREDECESSOR.get(phase)
        if predecessor is None and previous_phase is not None:
            predecessor = chain[previous_phase]
        return validate_phase.validate(
            phase,
            chain[phase] if candidate is None else candidate,
            chain["baseline"],
            predecessor,
        )

    @staticmethod
    def changed(source, name, value, **labels):
        changed = dict(source)
        changed[metric_key(name, **labels)] = value
        return changed

    def test_every_phase_accepts_only_its_exact_adjacent_transition(self):
        chain = self.make_chain()
        for phase in validate_phase.EXPECTED:
            with self.subTest(phase=phase):
                summary = self.validate_chain_phase(chain, phase)
                self.assertEqual(summary["phase"], phase)

    def test_later_phase_requires_current_uninterrupted_session(self):
        chain = self.make_chain()
        for name, metric, labels, value in (
            (
                "current-down",
                "bgp_peer_session_established",
                {"interface": "", "peer": validate_phase.PEER},
                0,
            ),
            (
                "reestablished",
                "bgp_session_established_total",
                {"peer": validate_phase.PEER},
                2,
            ),
            (
                "flapped",
                "bgp_session_flaps_total",
                {"peer": validate_phase.PEER},
                1,
            ),
        ):
            with self.subTest(name=name):
                candidate = self.changed(chain["restored"], metric, value, **labels)
                with self.assertRaisesRegex(AssertionError, metric):
                    self.validate_chain_phase(chain, "restored", candidate=candidate)

    def test_missing_eorr_sweep_is_red(self):
        chain = self.make_chain()
        unswept = self.changed(
            chain["eorr"],
            "bgp_rib_prefixes",
            validate_phase.PREFIXES,
            afi_safi="all",
            peer=validate_phase.PEER,
        )
        with self.assertRaisesRegex(AssertionError, "bgp_rib_prefixes"):
            self.validate_chain_phase(chain, "eorr", candidate=unswept)

    def test_missing_actor_observation_is_red(self):
        chain = self.make_chain()
        unobserved = self.changed(
            chain["first-borr"],
            "bgp_rib_route_refresh_actor_duration_seconds_count",
            self.BASE_COUNTS["begin"],
            operation="begin",
        )
        with self.assertRaisesRegex(
            AssertionError,
            "bgp_rib_route_refresh_actor_duration_seconds_count",
        ):
            self.validate_chain_phase(chain, "first-borr", candidate=unobserved)

    def test_each_operation_accepts_ceiling_equality_and_rejects_over_cap(self):
        chain = self.make_chain()
        for phase, operation in (
            ("first-borr", "begin"),
            ("eorr", "eorr"),
            ("timeout-complete", "timeout"),
        ):
            previous = chain[validate_phase.PREDECESSOR[phase]]
            previous_sum = validate_phase.actor_sum(previous, operation)
            ceiling = validate_phase.TIMING_CEILINGS_SECONDS[operation]
            labels = {"operation": operation}
            at_ceiling = self.changed(
                chain[phase],
                "bgp_rib_route_refresh_actor_duration_seconds_sum",
                previous_sum + ceiling,
                **labels,
            )
            with self.subTest(phase=phase, operation=operation, boundary="equality"):
                summary = self.validate_chain_phase(chain, phase, candidate=at_ceiling)
                self.assertAlmostEqual(summary["actor_timed_delta_seconds"], ceiling)

            over_cap = self.changed(
                at_ceiling,
                "bgp_rib_route_refresh_actor_duration_seconds_sum",
                previous_sum + ceiling + 0.001,
                **labels,
            )
            message = rf"phase={phase} op={operation} observed=.* ceiling={ceiling:g}s"
            with self.subTest(phase=phase, operation=operation, boundary="over-cap"):
                with self.assertRaisesRegex(AssertionError, message):
                    self.validate_chain_phase(chain, phase, candidate=over_cap)

    def test_adjacent_delta_cannot_be_masked_by_a_low_cumulative_average(self):
        chain = self.make_chain(
            base_counts={"begin": 1_000, "eorr": 11, "timeout": 13},
            base_sums={"begin": 1.0, "eorr": 1.1, "timeout": 1.3},
        )
        previous = chain["replay-one"]
        operation = "begin"
        candidate = self.changed(
            chain["duplicate-borr"],
            "bgp_rib_route_refresh_actor_duration_seconds_sum",
            validate_phase.actor_sum(previous, operation) + 0.030,
            operation=operation,
        )
        cumulative_average = validate_phase.actor_sum(
            candidate, operation
        ) / validate_phase.actor_count(candidate, operation)
        self.assertLess(
            cumulative_average,
            validate_phase.TIMING_CEILINGS_SECONDS[operation],
        )
        with self.assertRaisesRegex(
            AssertionError,
            r"phase=duplicate-borr op=begin observed=.* ceiling=0.025s",
        ):
            self.validate_chain_phase(chain, "duplicate-borr", candidate=candidate)

    def test_untimed_operation_sum_movement_is_rejected(self):
        chain = self.make_chain()
        candidate = self.changed(
            chain["first-borr"],
            "bgp_rib_route_refresh_actor_duration_seconds_sum",
            validate_phase.actor_sum(chain["baseline"], "eorr") + 0.001,
            operation="eorr",
        )
        with self.assertRaisesRegex(
            AssertionError,
            r"phase=first-borr op=eorr observed=.* ceiling=0s",
        ):
            self.validate_chain_phase(chain, "first-borr", candidate=candidate)

    def test_count_delta_failure_reports_count_semantics(self):
        with self.assertRaisesRegex(
            AssertionError,
            r"phase=first-borr timed_op=begin op=begin "
            r"observed_count_delta=0 expected_count_delta=1",
        ):
            validate_phase.validate_transition(
                "first-borr",
                self.BASE_COUNTS,
                self.BASE_SUMS,
                self.BASE_COUNTS,
                self.BASE_SUMS,
            )

    def test_missing_and_wrong_predecessors_are_rejected(self):
        chain = self.make_chain()
        with self.assertRaisesRegex(
            AssertionError,
            "phase=replay-one: missing predecessor metrics for first-borr",
        ):
            validate_phase.validate(
                "replay-one",
                chain["replay-one"],
                chain["baseline"],
            )

        with self.assertRaisesRegex(AssertionError, "bgp_rib_prefixes"):
            validate_phase.validate(
                "restored",
                chain["restored"],
                chain["baseline"],
                chain["restored"],
            )

        with self.assertRaisesRegex(AssertionError, "must not have predecessor"):
            validate_phase.validate(
                "baseline",
                chain["baseline"],
                chain["baseline"],
                chain["baseline"],
            )

    def test_predecessor_absolute_counts_are_checked_before_its_state(self):
        chain = self.make_chain()
        wrong = self.changed(
            chain["restored"],
            "bgp_rib_route_refresh_actor_duration_seconds_count",
            self.BASE_COUNTS["eorr"],
            operation="eorr",
        )
        with self.assertRaisesRegex(
            AssertionError,
            "bgp_rib_route_refresh_actor_duration_seconds_count",
        ):
            validate_phase.validate(
                "restored",
                chain["restored"],
                chain["baseline"],
                wrong,
            )


if __name__ == "__main__":
    unittest.main()

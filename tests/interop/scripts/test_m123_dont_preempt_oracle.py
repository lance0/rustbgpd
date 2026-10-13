#!/usr/bin/env python3
"""Counterexamples for the M123 RFC 9785 Don't-Preempt oracle.

Each case copies one phase of the committed receipt, breaks one observation
the way a regression or a wrong decode would, and requires the phase's own
expectation to fail on exactly that fact.
"""

import json
from pathlib import Path
import shutil
import tempfile
import unittest

import m123_dont_preempt_oracle as oracle

RECEIPT = (
    Path(__file__).resolve().parents[3] / "docs/artifacts/interop/m123-evpn-dont-preempt-20261013"
)


SCRATCH = tempfile.TemporaryDirectory()


def tearDownModule():
    SCRATCH.cleanup()


class Phase:
    def __init__(self, name):
        self.dir = Path(tempfile.mkdtemp(dir=SCRATCH.name)) / name
        shutil.copytree(RECEIPT / name, self.dir)
        self.expected = json.loads((self.dir / "expect.json").read_text())

    def edit(self, name, change):
        """Mutate parsed JSON in place."""
        path = self.dir / name
        data = json.loads(path.read_text())
        change(data)
        path.write_text(json.dumps(data))

    def replace(self, name, old, new):
        path = self.dir / name
        text = path.read_text()
        assert old in text, f"{old!r} not in {name}"
        path.write_text(text.replace(old, new))

    def problems(self, **override):
        return oracle.check(self.dir, self.expected | override)


def own_route(routes, origin=oracle.RUST):
    return next(r for r in routes if r["ip"] == origin)


def rewrite_df(route, mutate):
    out = []
    for value in route["extended_communities"]:
        raw = bytearray(int(value).to_bytes(8, "big"))
        if raw[:2] == b"\x06\x06":
            mutate(raw)
        out.append(int.from_bytes(raw, "big"))
    route["extended_communities"] = out


def srl_es_bgp(es):
    return es["association"]["network-instance"][0]["bgp-instance"][0]


class ReceiptReplay(unittest.TestCase):
    def test_every_committed_phase_passes(self):
        phases = sorted(p.parent.name for p in RECEIPT.rglob("expect.json"))
        self.assertEqual(len(phases), 11)
        for name in phases:
            self.assertEqual(Phase(name).problems(), [], name)


class Counterexamples(unittest.TestCase):
    def assert_fails_on(self, problems, fact):
        self.assertTrue(problems, "a broken observation passed")
        self.assertTrue(all(p.startswith(fact) for p in problems), problems)

    def test_restart_without_inheritance_fails(self):
        phase = Phase("dp-boot")
        phase.edit(
            "rust-es.json",
            lambda d: d["segments"][0].update(
                advertised_df_preference=200, advertised_df_dont_preempt=True
            ),
        )
        self.assert_fails_on(phase.problems(), "rust_advertised")

    def test_own_type4_with_dp_set_fails(self):
        phase = Phase("dp-boot")
        phase.edit(
            "rust-type4.json",
            lambda d: rewrite_df(own_route(d), lambda raw: raw.__setitem__(3, raw[3] | 0x80)),
        )
        self.assert_fails_on(phase.problems(), "rust_own_type4")

    def test_non_preference_algorithm_fails(self):
        phase = Phase("dp-boot")
        phase.edit(
            "rust-type4.json", lambda d: rewrite_df(own_route(d), lambda raw: raw.__setitem__(2, 0))
        )
        self.assert_fails_on(phase.problems(), "rust_own_type4")

    def test_srl_decoding_dp_fails(self):
        phase = Phase("dp-boot")
        phase.replace("srl-rib.json", "DP:0/DF-Preference:100", "DP:1/DF-Preference:100")
        self.assert_fails_on(phase.problems(), "srl_decoded_rust")

    def test_missing_srl_df_community_fails(self):
        phase = Phase("srl-recovered")
        phase.replace(
            "srl-rib.json",
            '"df-election::DF-Type:Preference/DP:0/DF-Preference:200/AC:1"',
            '"target:1:1"',
        )
        self.assert_fails_on(phase.problems(), "srl_own_type4")

    def test_flipped_srl_candidates_fail(self):
        phase = Phase("dp-boot")

        def flip(es):
            for row in srl_es_bgp(es)["computed-designated-forwarder-candidates"][
                "designated-forwarder-candidate"
            ]:
                row["designated-forwarder"] = not row["designated-forwarder"]

        phase.edit("srl-es.json", flip)
        self.assert_fails_on(phase.problems(), "srl_df")

    def test_srl_role_change_between_phases_fails(self):
        phase = Phase("dp-boot")
        since = phase.expected["srl_role_unchanged_since"]
        moved = f"{since[:17]}{(int(since[17:19]) + 2) % 60:02d}{since[19:]}"
        self.assert_fails_on(phase.problems(srl_role_unchanged_since=moved), "srl_role_change")
        jitter = since[:-2] + ("1Z" if since[-2] != "1" else "2Z")
        self.assertEqual(phase.problems(srl_role_unchanged_since=jitter), [])

    def test_unsettled_role_stamp_fails(self):
        phase = Phase("srl-alone")
        self.assert_fails_on(phase.problems(srl_role_settled_for=10_000), "srl_role_change")

    def test_role_stamp_before_action_fails(self):
        phase = Phase("rust-drained")
        self.assert_fails_on(
            phase.problems(srl_role_changed_after="2099-01-01T00:00:00.000Z"), "srl_role_change"
        )

    def test_carrier_down_member_is_not_bundled(self):
        phase = Phase("dp-boot")
        phase.replace(
            "ce-bond.txt",
            "Slave Interface: eth2\nMII Status: up",
            "Slave Interface: eth2\nMII Status: down",
        )
        self.assert_fails_on(phase.problems(), "ce_bundled_ports")

    def test_unknown_expectation_key_is_refused(self):
        with self.assertRaises(KeyError):
            Phase("dp-boot").problems(srl_dp=True)


if __name__ == "__main__":
    unittest.main()

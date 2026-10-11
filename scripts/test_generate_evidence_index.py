"""Exercise the evidence-index generator against small synthetic trees."""

import json
import tempfile
import unittest
from pathlib import Path

from scripts import generate_evidence_index as gen

LEG = """#!/usr/bin/env bash
# leg: {m}  slug: {slug}
# proves: bounded proof
# claims: {claims}
# evidence: {evidence}
# pinned: FRR 10.3.1, 2026-03-06
#
# Free-form description.
TOPO="{topo}"
"""
LAB = """#!/usr/bin/env bash
# lab: {name}  slug: {slug}
# summary: An exercise.
#
set -euo pipefail
"""
INVENTORY = {
    "roles": [{"id": "route-reflector-unicast", "classification": "stable"}],
    "config": {
        "stable_fields": [{"definition": "Config", "fields": ["bmp"]}],
        "explicitly_unstable_roots": [{"path": "Config.flowspec", "classification": "outside_v1"}],
    },
    "grpc": {
        "stable_method_sets": [{"service": "RibService", "methods": ["ListFlowSpecRoutes"]}],
        "scoped_rr_only_method_sets": [],
        "explicitly_outside_v1": ["EvpnService"],
    },
    "capabilities": {
        "purpose": "Navigation only.",
        "rows": [{
            "id": "unicast-route-reflection",
            "scope": "IPv4 reflection",
            "excludes": ["scale"],
            "roles": ["route-reflector-unicast"],
            "surfaces": ["Config.bmp", "Config.flowspec"],
            "evidence": [{"leg": "m14-rr-frr", "claims": ["advertised"]}],
        }],
    },
}


class EvidenceIndexTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.put("justfile", 'lab:\n    case "$1" in\n'
                 '        rr) exec bash "labs/$1/lab.sh" "$2" ;;\n    esac\n')
        self.put("docs/reference/v1-stable-surface.json", json.dumps(INVENTORY))
        self.put("docs/interop.md", f"# Interop\n\n```\n# not a heading\n```\n"
                 f"{gen.BEGIN}\n{gen.END}\n\n## M14 Results (2026-03-06)\n")
        self.put("docs/cookbook/route-reflector.md", "# RR\n")
        self.put("tests/interop/m14-rr-frr.clab.yml", "")
        self.put("tests/interop/m22-flowspec-frr.clab.yml", "")
        self.leg("m14-rr-frr", "m14", "route-reflector")
        self.put("labs/rr/lab.sh", LAB.format(name="rr", slug="route-reflector"))

    def put(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def leg(self, key, m, slug, claims="stored advertised",
            evidence="docs/interop.md#m14-results-2026-03-06", topo="m14-rr-frr"):
        self.put(f"tests/interop/scripts/test-{key}.sh", LEG.format(
            m=m, slug=slug, claims=claims, evidence=evidence, topo=topo))

    def write(self):
        for path, text in gen.expected_outputs(self.root).items():
            (self.root / path).write_text(text)

    def assert_metadata_error(self, pattern):
        with self.assertRaisesRegex(gen.MetadataError, pattern):
            gen.expected_outputs(self.root)

    def test_written_outputs_are_fresh_and_derived(self):
        self.write()
        self.assertEqual(gen.stale_outputs(self.root), [])
        capabilities = (self.root / gen.CAPABILITIES_OUT).read_text()
        self.assertIn("`Config.flowspec`: outside_v1", capabilities)
        self.assertIn("`Config.bmp`: stable", capabilities)
        self.assertIn("role `route-reflector-unicast`: stable", capabilities)
        interop = (self.root / gen.INTEROP_DOC).read_text()
        self.assertTrue(interop.startswith("# Interop\n"))
        self.assertTrue(interop.endswith("## M14 Results (2026-03-06)\n"))
        self.assertIn("`m14-rr-frr` | `route-reflector`", interop)
        labs = (self.root / gen.LABS_OUT).read_text()
        self.assertIn("[`m14-rr-frr`](../tests/interop/scripts/test-m14-rr-frr.sh)", labs)
        self.assertIn("[route-reflector](../docs/cookbook/route-reflector.md)", labs)

    def test_hand_edit_of_each_output_is_stale(self):
        self.write()
        for path in (gen.CAPABILITIES_OUT, gen.LABS_OUT, gen.INTEROP_DOC):
            original = (self.root / path).read_text()
            (self.root / path).write_text(original.replace("stable", "Stable", 1)
                                          .replace("lab rr", "lab RR", 1)
                                          .replace("bounded proof", "unbounded proof", 1))
            self.assertEqual(gen.stale_outputs(self.root), [path])
            (self.root / path).write_text(original)

    def test_header_change_without_regeneration_is_stale(self):
        self.write()
        self.leg("m14-rr-frr", "m14", "route-reflector", claims="stored selected advertised")
        self.assertEqual(gen.stale_outputs(self.root), [gen.INTEROP_DOC])
        self.put("labs/rr/lab.sh", LAB.format(name="rr", slug="route-reflector")
                 .replace("An exercise.", "Another exercise."))
        self.assertEqual(gen.stale_outputs(self.root), [gen.LABS_OUT, gen.INTEROP_DOC])

    def test_missing_output_is_stale(self):
        self.write()
        (self.root / gen.LABS_OUT).unlink()
        self.assertEqual(gen.stale_outputs(self.root), [gen.LABS_OUT])

    def test_shared_m_number_and_topology_stay_separate_legs(self):
        self.leg("m22-flowspec-frr", "m22", "flowspec", topo="m22-flowspec-frr")
        self.leg("m22-flowspec-controller", "m22", "flowspec", topo="m22-flowspec-frr")
        legs = gen.load_legs(self.root)
        self.assertIn("m22-flowspec-frr", legs)
        self.assertIn("m22-flowspec-controller", legs)

    def test_driver_without_header_is_outside_the_index(self):
        self.put("tests/interop/scripts/test-m99-other.sh", "#!/usr/bin/env bash\n# M99\n")
        self.assertNotIn("m99-other", gen.load_legs(self.root))

    def test_malformed_leg_headers_fail(self):
        cases = [
            ("# leg: m14 slug: route-reflector", "malformed header line"),
            ("# leg: m14  slug: Route_Reflector", "malformed header line"),
        ]
        for head, pattern in cases:
            with self.subTest(head=head):
                text = LEG.format(m="m14", slug="x", claims="stored", evidence="docs/interop.md",
                                  topo="m14-rr-frr").splitlines()
                text[1] = head
                self.put("tests/interop/scripts/test-m14-rr-frr.sh", "\n".join(text))
                self.assert_metadata_error(pattern)

    def test_header_field_rules(self):
        path = "tests/interop/scripts/test-m14-rr-frr.sh"
        good = LEG.format(m="m14", slug="route-reflector", claims="stored",
                          evidence="docs/interop.md", topo="m14-rr-frr")
        cases = [
            (good.replace("# proves:", "# proof:"), "is not one of"),
            (good.replace("# pinned: FRR", "# claims: stored\n# pinned: FRR"), "duplicate header key"),
            (good.replace("# pinned: FRR 10.3.1, 2026-03-06\n", ""), r"missing \['pinned'\]"),
            (good.replace("#\n# Free-form", "# Free-form"), "is not one of"),
            (good.replace("#\n# Free-form description.\n", ""), "is not one of"),
        ]
        for text, pattern in cases:
            with self.subTest(pattern=pattern):
                self.put(path, text)
                self.assert_metadata_error(pattern)

    def test_leg_identity_and_claims_must_match(self):
        cases = [
            (dict(m="m15"), "header names m15"),
            (dict(claims="stored stable"), "must be distinct keys"),
            (dict(claims="stored stored"), "must be distinct keys"),
            (dict(topo="m99-missing"), "TOPO does not name"),
        ]
        for change, pattern in cases:
            with self.subTest(change=change):
                args = dict(key="m14-rr-frr", m="m14", slug="route-reflector") | change
                self.leg(**args)
                self.assert_metadata_error(pattern)

    def test_evidence_references_must_resolve_inside_the_repository(self):
        self.put("outside.md", "# Outside\n")
        cases = [
            ("docs/missing.md", "is not a file"),
            ("../outside.md", "is not a file"),
            ("/etc/hostname", "is not a file"),
            ("docs/interop.md#m14-results-2026-03-07", "is not a heading"),
            ("docs/interop.md#not-a-heading", "is not a heading"),
        ]
        for evidence, pattern in cases:
            with self.subTest(evidence=evidence):
                self.leg("m14-rr-frr", "m14", "route-reflector", evidence=evidence)
                self.assert_metadata_error(pattern)

    def test_lab_declarations(self):
        cases = [
            ("labs/rr/lab.sh", "#!/usr/bin/env bash\n# A lab.\n", "has no '# lab:' header"),
            ("labs/rr/lab.sh", LAB.format(name="ixp", slug="route-reflector"), "names lab 'ixp'"),
            ("labs/ixp/lab.sh", LAB.format(name="ixp", slug="route-reflector"), "both claim slug"),
            ("labs/ixp/lab.sh", LAB.format(name="ixp", slug="route-server"), "justfile lab names"),
        ]
        for path, text, pattern in cases:
            with self.subTest(pattern=pattern):
                self.setUp()
                self.put(path, text)
                self.assert_metadata_error(pattern)

    def test_lab_names_with_digits_and_hyphens_match_the_justfile(self):
        self.put("justfile", 'lab:\n    case "$1" in\n'
                 '        rr|m14-demo) exec bash "labs/$1/lab.sh" "$2" ;;\n    esac\n')
        self.put("labs/m14-demo/lab.sh", LAB.format(name="m14-demo", slug="m14-demo"))
        self.assertEqual(sorted(gen.load_labs(self.root)), ["m14-demo", "rr"])

    def test_capability_references_must_resolve(self):
        for change, pattern in (
            ({"evidence": [{"leg": "m99-missing", "claims": ["stored"]}]}, "unknown leg"),
            ({"surfaces": ["RibService.ListEvpnRoutes"]}, "is not inventoried"),
        ):
            with self.subTest(pattern=pattern):
                inventory = json.loads(json.dumps(INVENTORY))
                inventory["capabilities"]["rows"][0] |= change
                self.put("docs/reference/v1-stable-surface.json", json.dumps(inventory))
                self.assert_metadata_error(pattern)

    def test_interop_markers_are_required_once(self):
        self.put("docs/interop.md", "## M14 Results (2026-03-06)\n")
        self.assert_metadata_error("one generated leg-index block")

    def test_live_tree_is_fresh(self):
        self.assertEqual(gen.stale_outputs(gen.ROOT), [])


if __name__ == "__main__":
    unittest.main()

import copy, importlib.util, pathlib, unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "verify-mrt-attribute-scratch-campaign.py"
SPEC = importlib.util.spec_from_file_location("scratch_verify", SCRIPT)
VERIFY = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(VERIFY)

def fixture():
    rows = []
    for block in range(1, 5):
        for slot, scratch_variant in enumerate(VERIFY.ORDER, 1):
            for shape in VERIFY.SHAPE_ORDER:
                paths, prefixes, sources = VERIFY.SHAPES[shape]
                candidate = scratch_variant == "candidate"
                rows.append({"schema": 1, "block": block, "slot": slot,
                    "scratch_variant": scratch_variant, "growth_variant": "candidate",
                    "growth_path_assertion": "bounded-growth-observed", "shape": shape,
                    "source_commit": ("b" if candidate else "a") * 40,
                    "source_tree": ("d" if candidate else "c") * 40, "harness_sha256": "e" * 64,
                    "timing_binary_sha256": ("2" if candidate else "1") * 64,
                    "diagnostic_binary_sha256": ("4" if candidate else "3") * 64,
                    "timing_ns": [90 if candidate else 100] * 7,
                    "allocator_calls": 70 if candidate else 100, "eligible_opportunities": paths * 6,
                    "scratch_reuses": paths * 6 if candidate else 0,
                    "retained_scratch_capacity_bytes": 4096 if candidate else 0,
                    "output_len_bytes": paths * 80, "decoded_entry_count": paths,
                    "prefix_count": prefixes, "source_count": sources,
                    "raw_sha256": ("5" if shape == "ixp-700" else "7") * 64,
                    "semantic_sha256": ("6" if shape == "ixp-700" else "8") * 64})
    return rows

class CampaignContract(unittest.TestCase):
    def test_valid_fixture(self): self.assertEqual(VERIFY.verify(fixture())["classification"], "go")

    def assert_rejected(self, mutate):
        rows = copy.deepcopy(fixture()); mutate(rows)
        with self.assertRaises(VERIFY.Invalid): VERIFY.verify(rows)

    def test_existing_contract_destructive_proofs(self):
        mutations = (
            lambda r: r.pop(), lambda r: r[2].update(slot=1), lambda r: r[2].pop("shape"),
            lambda r: r[0].update(harness_sha256="9" * 64),
            lambda r: r[0].update(timing_binary_sha256="9" * 64),
            lambda r: [x.update(source_tree="c" * 40) for x in r if x["scratch_variant"] == "candidate"],
            lambda r: [r[i].update(raw_sha256="7" * 64) for i in (8, 10, 12, 14)],
            lambda r: [r[i].update(semantic_sha256="7" * 64) for i in (8, 10, 12, 14)],
            lambda r: [r[i].update(output_len_bytes=1) for i in (8, 10, 12, 14)],
            lambda r: r[0].update(decoded_entry_count=1), lambda r: r[0].update(eligible_opportunities=1),
            lambda r: r[0].update(prefix_count=1), lambda r: r[0].update(source_count=1),
            lambda r: r[2].update(scratch_reuses=0), lambda r: r[2].update(retained_scratch_capacity_bytes=131073),
            lambda r: r[2].update(retained_scratch_capacity_bytes=0),
            lambda r: [r[i].update(allocator_calls=81) for i in (2, 4)],
            lambda r: [r[i].update(timing_ns=[96] * 7) for i in (2, 4)],
            lambda r: (r[0].update(timing_ns=[96, 96, 96, 100, 106, 106, 106]),
                       r[6].update(timing_ns=[198, 198, 198, 200, 202, 202, 202]),
                       r[2].update(timing_ns=[144] * 7), r[4].update(timing_ns=[144] * 7)),
            lambda r: r[2].update(timing_ns=[1, 90, 90, 90, 90, 90, 90]),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.assert_rejected(mutate)

    def test_rejects_noncanonical_serialized_order(self):
        self.assert_rejected(lambda rows: rows.reverse())

    def test_rejects_zero_allocator_calls_in_any_row(self):
        self.assert_rejected(lambda rows: rows[2].update(allocator_calls=0))

    def test_rejects_source_commit_tree_alias(self):
        self.assert_rejected(lambda rows: [row.update(source_tree=row["source_commit"])
            for row in rows if row["scratch_variant"] == "control"])

    def test_rejects_cross_role_source_identity_alias(self):
        self.assert_rejected(lambda rows: [row.update(source_tree="a" * 40)
            for row in rows if row["scratch_variant"] == "candidate"])

    def test_rejects_timing_diagnostic_binary_alias(self):
        self.assert_rejected(lambda rows: [row.update(
            diagnostic_binary_sha256=row["timing_binary_sha256"])
            for row in rows if row["scratch_variant"] == "control"])

    def test_rejects_cross_role_binary_identity_alias(self):
        self.assert_rejected(lambda rows: [row.update(diagnostic_binary_sha256="1" * 64)
            for row in rows if row["scratch_variant"] == "candidate"])

    def test_rejects_cross_shape_raw_digest_alias(self):
        self.assert_rejected(lambda rows: [row.update(raw_sha256="5" * 64) for row in rows])

    def test_rejects_cross_shape_semantic_digest_alias(self):
        self.assert_rejected(lambda rows: [row.update(semantic_sha256="6" * 64) for row in rows])

    def test_rejects_ambiguous_normalized_variant(self):
        self.assert_rejected(lambda rows: [row.update(
            variant=row.pop("scratch_variant")) for row in rows])

    def test_requires_legacy_growth_variant(self):
        self.assert_rejected(lambda rows: rows[0].update(growth_variant="control"))

    def test_requires_legacy_growth_path_assertion(self):
        self.assert_rejected(lambda rows: rows[0].update(
            growth_path_assertion="ordinary-unbounded-observed"))

if __name__ == "__main__": unittest.main()

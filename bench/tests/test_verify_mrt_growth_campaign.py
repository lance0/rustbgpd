import copy, importlib.util, pathlib, unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "verify-mrt-growth-campaign.py"
SPEC = importlib.util.spec_from_file_location("mrt_growth_verify", SCRIPT)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)

def fixture():
    rows = []
    for block in range(1, 5):
        for slot, variant in enumerate(VERIFY.ORDER, 1):
            for shape, (paths, _, _) in VERIFY.SHAPES.items():
                candidate = variant == "candidate"
                rows.append({
                    "schema": 1, "block": block, "slot": slot, "variant": variant,
                    "source_commit": ("b" if candidate else "a") * 40,
                    "source_tree": ("d" if candidate else "c") * 40,
                    "harness_sha256": "e" * 64,
                    "timing_binary_sha256": ("2" if candidate else "1") * 64,
                    "diagnostic_binary_sha256": ("4" if candidate else "3") * 64,
                    "growth_path_assertion": ("bounded-growth-observed" if candidate
                                              else "ordinary-unbounded-observed"),
                    "shape": shape, "timing_ns": [90 if candidate else 100] * 7,
                    "allocator_calls": 70 if candidate else 100, "requested_bytes": 40 if candidate else 100,
                    "output_growth_misses": 1 if candidate else paths,
                    "output_len_bytes": paths * 80,
                    "output_capacity_bytes": paths * (81 if candidate else 80),
                    "peak_live_overhead_bytes": paths,
                    "decoded_entry_count": paths, "raw_sha256": "5" * 64,
                    "semantic_sha256": "6" * 64,
                })
    return rows

class CampaignContract(unittest.TestCase):
    def test_valid_fixture(self):
        self.assertEqual(VERIFY.verify(fixture())["classification"], "go")

    def test_destructive_red_proofs(self):
        source, pattern = (SCRIPT.parents[1] / "crates/mrt/benches/snapshot_allocation.rs").read_text(), r'(?s)let growth_path_assertion = encoded\.growth\.as_ref\(\)\.map\(\|growth\| \{\s*growth_path_assertion\(\s*args\.candidate,\s*growth\.top_level_unbounded_capacity_misses,\s*fixture\.routes\.len\(\) as u64,\s*\)\s*\.expect\("diagnostic growth path must match the declared variant"\)\s*\}\);'
        self.assertRegex(source, pattern)
        self.assertNotRegex(source.replace('.expect("diagnostic growth path must match the declared variant")', '.expect("diagnostic growth path must match the declared variant"); "ordinary-unbounded-observed"'), pattern)
        mutations = (
            lambda rows: rows[0].pop("timing_binary_sha256"), lambda rows: rows[2].update(variant="control"),
            lambda rows: rows[2].update(growth_path_assertion="ordinary-unbounded-observed"),
            lambda rows: rows.pop(),
            lambda rows: rows[0].update(output_growth_misses=1),
            lambda rows: rows[2].update(output_growth_misses=65),
            lambda rows: [rows[index].update(allocator_calls=0) for index in (0, 6)],
            lambda rows: [rows[index].update(requested_bytes=0) for index in (0, 6)],
            lambda rows: rows[2].update(allocator_calls=100),
            lambda rows: rows[2].update(requested_bytes=70),
            lambda rows: rows[2].update(timing_ns=[101] * 7),
            lambda rows: rows[2].update(timing_ns=[1, 100, 100, 100, 100, 100, 100]),
            lambda rows: [rows[index].update(raw_sha256="7" * 64) for index in (8, 10, 12, 14)],
            lambda rows: [rows[index].update(semantic_sha256="8" * 64) for index in (8, 10, 12, 14)],
            lambda rows: [rows[index].update(output_len_bytes=rows[index]["output_len_bytes"] - 1) for index in (8, 10, 12, 14)],
            lambda rows: [row.update(source_tree="c" * 40) for row in rows if row["variant"] == "candidate"],
            lambda rows: rows[0].update(harness_sha256="9" * 64),
            lambda rows: rows[0].update(timing_binary_sha256="9" * 64),
            lambda rows: rows[0].update(schema=True),
            lambda rows: rows[0].update(output_len_bytes=1.0),
            lambda rows: rows[2].update(output_capacity_bytes=rows[2]["output_len_bytes"] * 2),
            lambda rows: rows[2].update(peak_live_overhead_bytes=32 * 1024**2 + 1),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                rows = copy.deepcopy(fixture())
                mutate(rows)
                with self.assertRaises(VERIFY.Invalid):
                    VERIFY.verify(rows)

if __name__ == "__main__":
    unittest.main()

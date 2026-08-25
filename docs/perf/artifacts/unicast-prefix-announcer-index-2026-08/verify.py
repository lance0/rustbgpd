#!/usr/bin/env python3
import csv
import hashlib
import json
import math
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[3]
BASE = "812770e5297f6c455e457f158d057528f6bcf4fb"
HEAD = "5ed4d093d8985207108a463a6cc06e959a598457"
BASE_TREE = "e8d586c1623d1f1cda0374117e7c9755321a04b7"
HEAD_TREE = "9ccd399cf64bd97301d1609ffd881b4244eb3763"
T = 2.0150483733
CEILING = 5.0


def rows(name):
    with (ROOT / name).open(newline="") as handle:
        return list(csv.DictReader(handle))


def close(actual, expected, tolerance=0.000001):
    assert abs(actual - expected) <= tolerance, (actual, expected)


def verify_checksums():
    for line in (ROOT / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        actual = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        assert actual == expected, name


def git(*args, text=True):
    return subprocess.run(
        ["git", *args], cwd=REPO, check=True, capture_output=True, text=text
    ).stdout


def verify_git_identities_and_tools(manifest):
    assert git("rev-parse", f"{BASE}^{{commit}}").strip() == BASE
    assert git("rev-parse", f"{HEAD}^{{commit}}").strip() == HEAD
    assert git("rev-parse", f"{BASE}^{{tree}}").strip() == BASE_TREE
    assert git("rev-parse", f"{HEAD}^{{tree}}").strip() == HEAD_TREE
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", HEAD, "HEAD"],
        cwd=REPO, check=True, capture_output=True,
    )
    tested_blobs = {
        "driver_sha256": "bench/scale/compare-rrharness.sh",
        "parser_sha256": "bench/scale/rebaseline/parse_rrharness.py",
    }
    for field, path in tested_blobs.items():
        blob = git("show", f"{HEAD}:{path}", text=False)
        assert hashlib.sha256(blob).hexdigest() == manifest[field], path


manifest = json.loads((ROOT / "manifest.json").read_text())
assert (manifest["base_commit"], manifest["head_commit"]) == (BASE, HEAD)
assert (manifest["base_tree"], manifest["head_tree"]) == (BASE_TREE, HEAD_TREE)
close(float(manifest["student_t_one_sided_95_df5"]), T, 1e-12)
close(float(manifest["maximum_regression_ucl_percent"]), CEILING)
verify_git_identities_and_tools(manifest)

memory = rows("memory.csv")
assert len(memory) == 12
expected_memory = {(1, "base"): 7471120, (1, "head"): 3801336,
                   (2, "base"): 10871120, (2, "head"): 6947064}
for key, expected in expected_memory.items():
    values = [int(r["live_bytes"]) for r in memory
              if (int(r["announcers"]), r["variant"]) == key]
    assert len(values) == 3 and len(set(values)) == 1 and values[0] == expected
for announcers, expected_saving in ((1, 49.119597), (2, 36.096152)):
    base = expected_memory[(announcers, "base")]
    head = expected_memory[(announcers, "head")]
    close((base - head) / base * 100, expected_saving)

campaigns = rows("campaigns.csv")
assert {r["campaign"] for r in campaigns if r["status"] == "admitted"} == {"3", "4", "5"}
refused = [r for r in campaigns if r["campaign"] == "2"]
assert len(refused) == 1 and refused[0]["status"] == "refused"
refused_loads = [float(value) for value in refused[0]["pass_load_1m_values"].split("|")]
assert int(refused[0]["accepted_cells"]) == len(refused_loads) == 4
assert max(refused_loads) < 2.0
assert refused[0]["governor"] == "performance"
assert int(refused[0]["maximum_competing_count"]) == 2
assert all(word in refused[0]["note"] for word in
           ("zero competitors", "cargo", "rustc", "refusal", "excluded"))
for r in campaigns:
    if r["status"] == "admitted":
        loads = [float(value) for value in r["pass_load_1m_values"].split("|")]
        assert int(r["accepted_cells"]) == len(loads) == 16
        assert max(loads) < 2.0
        assert r["governor"] == "performance"
        assert int(r["maximum_competing_count"]) == 0

pairs = rows("paired-results.csv")
assert len(pairs) == 24 and {r["campaign"] for r in pairs} == {"3", "4", "5"}
keys = {(r["mode"], r["clients"], r["candidates"], r["prefixes"]) for r in pairs}
assert len(keys) == 4
summary = {(r["mode"], r["clients"], r["candidates"], r["prefixes"]): r
           for r in rows("combined-summary.csv")}
assert set(summary) == keys
for key in keys:
    selected = [r for r in pairs if
                (r["mode"], r["clients"], r["candidates"], r["prefixes"]) == key]
    assert len(selected) == 6
    assert {(r["campaign"], r["repetition"]) for r in selected} == {
        (str(c), str(rep)) for c in (3, 4, 5) for rep in (1, 2)}
    improvements = []
    for r in selected:
        computed = (float(r["head_rate"]) / float(r["base_rate"]) - 1) * 100
        close(computed, float(r["head_improvement_percent"]), 0.0000015)
        improvements.append(float(r["head_improvement_percent"]))
    mean = sum(improvements) / 6
    stdev = math.sqrt(sum((x - mean) ** 2 for x in improvements) / 5)
    regression_ucl = -mean + T * stdev / math.sqrt(6)
    stored = summary[key]
    assert int(stored["pairs"]) == 6
    close(mean, float(stored["mean_improvement_percent"]))
    close(regression_ucl, float(stored["regression_ucl_percent"]))
    close(float(stored["maximum_regression_ucl_percent"]), CEILING)
    assert regression_ucl <= CEILING and stored["verdict"] == "pass"

verify_checksums()
print("PASS: Git identities/blobs, integrity, memory repeats/savings, 48 admitted cells, 24 pairs, and four UCL gates")

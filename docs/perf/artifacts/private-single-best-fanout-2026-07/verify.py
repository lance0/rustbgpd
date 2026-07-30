#!/usr/bin/env python3
import hashlib
import json
import subprocess
import tarfile
from pathlib import Path
from statistics import fmean

ART = Path(__file__).resolve().parent
ROOT = ART.parents[3]
MANIFEST = json.loads((ART / "manifest.json").read_text())
FILES = [
    "crates/rib/src/manager/mod.rs",
    "crates/rib/src/manager/distribution/mod.rs",
    "crates/rib/src/manager/bench_support.rs",
    "crates/transport/benches/fanout.rs",
]

def must(condition, message):
    if not condition:
        raise SystemExit(f"FAIL: {message}")

def git(*args, input_data=None):
    return subprocess.run(
        ["git", *args], cwd=ROOT, input=input_data, check=True,
        stdout=subprocess.PIPE
    ).stdout


source = MANIFEST["source"]
expected_source = {
    "main": ["f5568242047ffbbd32d940dcbcdaec922564d6e2",
             "051c6a0df05eb6b00a4a65e418a288ddf47458e8"],
    "harness": ["775d47a662f2b7828528a2fe25e5a2a8e63daf56",
                "e7b741b160b0360ca6100d273dd5d24ba9e01a73",
                "10f9aeee7b6e4d88de5f5d90407b1e7d1ff268d4"],
    "candidate": ["232fb0fcd7231f21c8ac355878b56f47378b37b0",
                  "cf8cef93c480155bdd8016308b648955298e86f6",
                  "47eb3373160d73cd2dcacc9752dedb4dd9e8b2fa"],
    "measured": ["454a83b0f700a5d2488d9aefd684678d34fe54ad",
                 "b9f805a0abe6c0cac79b55af89ed866c7ffa10fb"],
    "diff_sha256": [
        "66c509ba38ca2306c6946fdf8baa9cb2d121acdcb2d809a07198987b551c5ac1",
        "fe7f2890f4203c4d0f54b299794fdbe5e90ecdadb940d9dd9e56bd97514bf907",
        "6f7dd217e4f2d93f606d2962e52ba38b04172ac397af4c669f73efa72d44bfe6",
    ],
    "cargo_lock_sha256":
        "38d32ad97957aaace25cc4f02b743e5a3e6647b9a48a9e8e213d0fc4e19bbc1b",
}
must(source == expected_source, "source manifest identity drift")
must(hashlib.sha256(git("show", f"{source['main'][0]}:Cargo.lock")).hexdigest() ==
     source["cargo_lock_sha256"], "Cargo.lock drift")
main, harness, candidate = (source[key][0] for key in
                            ("main", "harness", "candidate"))
must(git("show", "-s", "--format=%T", main).decode().strip() == source["main"][1],
     "main tree drift")
for name, commit, parent, tree in (
    ("harness", harness, main, source["harness"][1]),
    ("candidate", candidate, harness, source["candidate"][1]),
):
    actual = git("show", "-s", "--format=%T%n%P", commit).decode().splitlines()
    must(actual == [tree, parent], f"{name} tree or parent drift")
    patch = git("patch-id", "--stable",
                input_data=git("show", "--pretty=email", "--binary", commit))
    must(patch.decode().split()[0] == source[name][2], f"{name} patch-id drift")
for index, (base, head) in enumerate(
    ((main, harness), (harness, candidate), (main, candidate))
):
    digest = hashlib.sha256(git("diff", "--binary", base, head, "--", *FILES)).hexdigest()
    must(digest == source["diff_sha256"][index], f"source diff {index} drift")
expected_scans = {
    "harness": {"1": 64, "8": 512, "64": 4096, "256": 16384},
    "candidate": {"1": 0, "8": 0, "64": 0, "256": 0},
}
must(MANIFEST["scan_counts"] == expected_scans, "exact scan-count drift")
benchmark = MANIFEST["benchmark"]
must(benchmark["attempts"] == 6 and benchmark["peers"] == [1, 8, 64, 256],
     "benchmark matrix drift")
must(benchmark["claimed_peers"] == [8, 64, 256] and
     benchmark["unclaimed_peer"] == 1, "claim boundary drift")
must(MANIFEST["gate"] == {
    "all_attempt_deltas_negative": True, "last_ci_upper_negative": True,
    "beyond_control_band": True, "max_per_peer_savings_ratio": 1.10,
}, "gate manifest drift")
sums = {}
for line in (ART / "SHA256SUMS").read_text().splitlines():
    digest, name = line.split("  ", 1)
    sums[name] = digest
for name, digest in sums.items():
    must(hashlib.sha256((ART / name).read_bytes()).hexdigest() == digest,
         f"checksum mismatch: {name}")
expected_sum_files = {p.name for p in ART.iterdir()
                      if p.is_file() and p.name != "SHA256SUMS"}
must(set(sums) == expected_sum_files, "checksum file list drift")
archive = ART / MANIFEST["archive"]["file"]
must(archive.stat().st_size <= MANIFEST["archive"]["max_bytes"],
     "compressed estimate archive too large")
campaigns, peers, attempts, sides = ("control", "ab"), [1, 8, 64, 256], range(1, 7), ("base", "head")
expected_members = {
    f"{campaign}/private_single_best_fanout/policy_peer_context/{peer}/"
    f"attempt-{attempt}-{side}/estimates.json"
    for campaign in campaigns for peer in peers
    for attempt in attempts for side in sides
}
values = {}
with tarfile.open(archive, "r:gz") as bundle:
    members = bundle.getmembers()
    must({item.name for item in members} == expected_members, "archive member drift")
    must(len(members) == MANIFEST["archive"]["members"], "archive member count drift")
    for item in members:
        must(item.isfile() and item.mtime == item.uid == item.gid == 0 and
             item.uname == item.gname == "" and item.mode == 0o644,
             f"nondeterministic archive metadata: {item.name}")
        parts = item.name.split("/")
        campaign, peer, label = parts[0], int(parts[3]), parts[4]
        attempt, side = int(label.split("-")[1]), label.split("-")[2]
        estimate = json.load(bundle.extractfile(item))["median"]
        ci = estimate["confidence_interval"]
        values[campaign, peer, attempt, side] = (
            estimate["point_estimate"], ci["lower_bound"], ci["upper_bound"]
        )
def delta(head, base):
    return (head / base - 1.0) * 100.0

rows = {}
for campaign in campaigns:
    for peer in peers:
        pairs = [(values[campaign, peer, attempt, "base"],
                  values[campaign, peer, attempt, "head"]) for attempt in attempts]
        deltas = [delta(head[0], base[0]) for base, head in pairs]
        base, head = pairs[-1]
        ci = (delta(head[1], base[2]), delta(head[2], base[1]))
        rows[campaign, peer] = (pairs, deltas, ci)
for peer in benchmark["claimed_peers"]:
    control = rows["control", peer][1]
    pairs, deltas, ci = rows["ab", peer]
    must(all(value < 0 for value in deltas), f"{peer}: not all attempts improve")
    must(ci[1] < 0, f"{peer}: final propagated CI crosses zero")
    must(fmean(deltas) < min(control), f"{peer}: improvement within control band")
savings = []
for peer in benchmark["claimed_peers"]:
    pairs = rows["ab", peer][0]
    savings.append(fmean(base[0] - head[0] for base, head in pairs) / peer)
ratio = max(savings) / min(savings)
must(ratio <= MANIFEST["gate"]["max_per_peer_savings_ratio"],
     "absolute savings do not scale linearly")
text = "\n".join(path.read_text(errors="ignore") for path in ART.iterdir()
                 if path.is_file() and path.suffix != ".gz")
for token in ("/" + "home/", "/" + "Users/", "/" + "tmp/",
              "lance" + "box", "Cod" + "ex", "@" + "openai"):
    must(token not in text, f"artifact identity leak: {token}")
must("Observed private_extra_prefix_scans: 16384" in text and
     "Expected private_extra_prefix_scans: 0" in text, "counter red proof drift")
readme = (ART / "README.md").read_text()
must("The one-peer result is unclaimed." in readme and
     "No daemon, convergence, network, or\nfull-table result is claimed." in readme,
     "inference boundary drift")
print("PASS: exact identity, scans, 96 estimates, 8/64/256 gate, "
      f"per-peer savings ratio {ratio:.4f}")

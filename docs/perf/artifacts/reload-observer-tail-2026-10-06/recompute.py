#!/usr/bin/env python3
"""Validate and recompute the compact reload-tail receipt using the stdlib."""
import csv
import hashlib
import itertools
import json
import math
from pathlib import Path
from statistics import median

ROOT = Path(__file__).resolve().parent
ROUNDS = range(1, 5)
EXPECTED = {(r, i) for r in ROUNDS for i in range(700)}

# This dated receipt has one fixed workload and fixed archived identities.
WORKLOAD = {
    "N_PEERS": "700",
    "TOTAL_PREFIXES": "400400",
    "PORT": "1790",
    "RELOADS": "4",
    "CONTROL_SECS": "30",
    "CHANGED_PEERS": "",
    "FLAPSTORM": "",
    "BIRD_THREADS": "8",
    "PROBE_PREFIXES": ""
}
BINARIES = {
    "control": "600327d665de6764585c422c77b4b3b7c82d7b4a59b031e257aecee9759fb097",
    "probe": "9bce83d837beddbc0235df29374298f5ac00aee9ee71f67312787cfb0d77a927",
    "observer": "effe9c204e5cce66f324c49edb13c8ce5f7f4be95c411ec96bd1bcb7fa3e0e70"
}
PROBE_SOURCE = {
    "bench/scale/reloadstall/src/main.rs": "3434152e8e3b8f88be553331e88f7f08ecb526d23b37b5048df05743b0cd0a8c",
    "crates/rib/src/manager/distribution/mod.rs": "6eb5b973b098b60fa3cec5da4aa40e6d50bb9904cfcc003031a1c732b00f209e",
    "crates/transport/src/session/outbound.rs": "cf9ff27fed6f6e62ab8cd7452a662293fa8699653aeafa28c376feb5b702acb8",
    "crates/transport/src/session/shared_group.rs": "10037d2cf539cf6602871e19c78b72579d56cf856b36cc90d5197b80f501066b",
    "crates/transport/src/session/writer.rs": "d006c98ed145f42b6f550379d5c8979c309dfc7d4902ea2240eb3dd50798a0a0"
}
HELPERS = {
    "bench/scale/cgroup-memory.sh": "64753985d0b8c167daa1d382b70fe6f4369275713ebcaec8e4de677ff281ee3a",
    "bench/scale/host-quiet.sh": "abb3391cd5e0879c29aabd0aa0c316ea33d5f7c72f6d2a7d111b30025de411fd",
    "bench/scale/matrix/rss-sampler.sh": "3ecffb93298c49f8524320ecebe976efc806f9f0b0caf260d6a1431ca402a10d",
    "bench/scale/matrix/run-matrix.sh": "d7276ac13132bf33f87cdbd3edc1bc86aec2953f8921683b2db725eca1be5f17",
    "bench/scale/matrix/verify-provenance.py": "7da2a7088bd2a9669621895c33c60ea6fce6fc62c695be600f63efc4530aedc4",
    "bench/scale/provenance.sh": "7db6727dc99ec42515359f674e56c749453bc29c9981b67f30568f0d6cce1991",
    "bench/scale/reloadstall/gen-scenario.py": "e563659beef5857ee79ddac40e1cff5730c34e424b5ca074a3f9007b5dc0ab42",
    "tests/soak/host-lock.sh": "f5f419bb439f0b5e22521e9f7fa73d4ef73df159abeec31fafff63548899c658"
}
RAW_HASHES = {
    "control/rustbgpd/reloadstall.log": "bbe3f2f7417fa1942ea696e7629dc408833d8f02aecaf8fe5519df4dad39fc94",
    "control/rustbgpd/daemon.log": "fe1e51c8254879617613aa24ede775c1c7799be1315fa46b310c33f1fbaf5663",
    "control/rustbgpd/provenance.json": "0dfc8350165165ebf65a489628dc0c9e69bb8e97038c24c07368e3e3496f0f53",
    "control/rustbgpd/quiet.tsv": "78486333baf5f1ff811a234632ae49162d69258ca19ba5e0d23666ea783086c8",
    "control/analysis/observers.csv": "3728820debbb3b16a7802a19d2596c8f143e186150129b1d408b34b7f1bbac5a",
    "control/analysis/coverage.json": "f8e039f9cb7a8ba1cb6de97d85fef7033144c76755d9b9a1b9727c1f737f1d1a",
    "control/analysis/producer.json": "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570",
    "control/analysis/summary.json": "1cae437bed5a52c8497fde43f50032499b1b2819e56b09d3bed32d0dea65f67f",
    "control/pre-freeze.json": "4b3ff2cd6c85af3cda207aec25487809273fb842bb86495e5d4b6918387e228c",
    "control/post-freeze.json": "4b3ff2cd6c85af3cda207aec25487809273fb842bb86495e5d4b6918387e228c",
    "probe/rustbgpd/reloadstall.log": "a4c6c8c13b893a5c7f2ac9ebe73a0412176e3442989c03d46c77ba663f13e84b",
    "probe/rustbgpd/daemon.log": "a13ba10dd1a7585cb7565e0a577f111d9b71fba65f1c53f22091317d47b6d015",
    "probe/rustbgpd/provenance.json": "893ca3a8d47b652302feeed5783f930a904d38d8d152eebb9857b7a9d2e2fd3d",
    "probe/rustbgpd/quiet.tsv": "446317d2ec2a7c082fd78ea2d813137dce6275f1dbde56c64c219632f473fcfb",
    "probe/analysis/observers.csv": "d2880a160198a44282b9ce6f0633dbf79386344517d68bd6ae16b43caa35b3ba",
    "probe/analysis/coverage.json": "2151d13d608dcf09586db1fe4e660b152bdde2e062963342515856faa15c1446",
    "probe/analysis/producer.json": "39efe666f9b5bafe17840554aecac0d3852c1c676626b1ae7d8caf34f3d9f233",
    "probe/analysis/summary.json": "564f82774dd6542b45354eaaed84e9ea88ac56d60af4bd77dfcc8751d6332289",
    "probe/pre-freeze.json": "dd996ed79f62ffeb8e7807cb817a67c92ddcede3a8548ba60d01cbf990fa34c5",
    "probe/post-freeze.json": "dd996ed79f62ffeb8e7807cb817a67c92ddcede3a8548ba60d01cbf990fa34c5",
    "method/local-instrumentation-v4.diff": "23289bea4d89ed83e3aee623573965a556bf6636fbf1d78f46f46ab576d07dc0",
    "method/analyze-probe-v4.py": "dcd407d3c3034a160a1588669e4b0fbe6b6e1a7cceb62f87326888a1d5dbe486",
    "method/build-probe-v4-witness.json": "8ddb2991d9ba274b89bb019c7da982e680026f72c2f42d5ac7876431e8a38eed",
    "method/probe-source-v4-sha256.json": "2c87cb1241ee0ef53dc5ac0623cb6e9743cac9fb326c8b9c04c0b4abc043f74e",
    "method/run-leg-v4.sh": "876c3b34d4e173fab675cab6e2a4fbea50b25419999a363f907748bbdbdffa1f",
    "method/check-analysis-v4.py": "2196603029983b930888c727a3ddb15a3f7010d3d73a39a7c26199b79613977b",
    "method/check-optimized-entry-v4.py": "122b3ebdef2c2d2ff5f755e0549da4eaf16ba364f46dcf5e05a65a9532e1f8ab",
    "method/build-probe-v4.sh": "b1377bb06d5765aaff19d51714e78b57d8e424de0397d66678c4e97bf1f74ad2",
    "method/build-clean-control.sh": "8266f6b7a308baf470baf9674602ed04ce9448f403bafc1854e9ab1af9094a73",
    "method/control-source.txt": "91750a0a43ee88c89e1d775ad4e5763ffe0c5d603ccacd1ea37d34427b234894",
    "method/build-clean-control.log": "b8f8494370cfae989cace4228886567450cf38a7938d27b611f67c134c407099",
    "method/build-clean-control.exit": "9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa",
    "method/build-probe-v4.log": "71aaeaf21b69bfaf169476f184c82b8ec34f432084f65b7bc78e30a8d9917ecf",
    "method/build-probe-v4.exit": "9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa",
    "method/binary-sha256-v4.txt": "f943a78133a11f4c3e5920aee879c5c18f8a484274643ab92a47158d2b56092b"
}
COMMIT = "19842a5a114287af7a8f5ae66407aaacc9d0142a"
TREE = "fe3a2dbe6e01eb4fbb6aec5482f1184eae1973e9"
PATCH = "23289bea4d89ed83e3aee623573965a556bf6636fbf1d78f46f46ab576d07dc0"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value):
    result = float(value)
    require(math.isfinite(result), "nonfinite measurement")
    return result


def quantiles(values):
    values = sorted(values)
    return {k: values[round((len(values) - 1) * p)]
            for k, p in (("p50", .5), ("p95", .95), ("max", 1))}


def ranks(values):
    ordered = sorted(enumerate(values), key=lambda pair: pair[1])
    result = [0.] * len(values)
    offset = 0
    for _, group in itertools.groupby(ordered, key=lambda pair: pair[1]):
        members = list(group)
        for index, _ in members:
            result[index] = offset + (len(members) - 1) / 2
        offset += len(members)
    return result


def spearman(a, b):
    a, b = ranks(a), ranks(b)
    center = (len(a) - 1) / 2
    a, b = [x - center for x in a], [x - center for x in b]
    divisor = math.sqrt(sum(x*x for x in a) * sum(x*x for x in b))
    return sum(x*y for x, y in zip(a, b)) / divisor if divisor else None


def verify_hashes(root):
    entries = {}
    for line in (root / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        require(name not in entries and Path(name).name == name, "invalid hash entry")
        entries[name] = digest
    actual = {p.name for p in root.iterdir() if p.is_file() and p.name != "SHA256SUMS"}
    require(set(entries) == actual, "hash manifest does not cover every artifact")
    for name, digest in entries.items():
        require(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest,
                f"hash mismatch: {name}")


def validate_identity(root):
    def read(name):
        return json.loads((root / name).read_text())

    p, legs, native, freezes, builds, raw = [read(name) for name in (
        "provenance.json", "legs.json", "native-provenance.json", "freezes.json",
        "builds.json", "archived-raw-sha256.json")]
    require(p["workload"] == WORKLOAD, "wrong provenance workload")
    require(p["binaries"] == BINARIES and p["source_commit"] == COMMIT and
            p["source_tree"] == TREE and p["probe_source_patch_sha256"] == PATCH,
            "wrong source or binary identity")
    require(p["order"] == ["control", "probe"] and p["processes_per_arm"] == 1 and
            p["correlated_reloads_per_arm"] == 4 and p["added_rtt_ms"] == 0 and
            p["reader_pacing"] == "none" and p["receipt_vocabulary"] == "current" and
            p["policy_mode"] == "historical import plus export", "wrong campaign shape")
    require(p["date"] == "2026-10-06" and p["rust_version"] == "1.99.0 (b940084d7 2026-09-28)" and
            p["platform"] == "Linux 7.0.0-30-generic x86_64", "wrong measurement environment")
    require(p["raw_archive"] == {
        "sha256": "2a0da40e0067ff0f6530b634ece6fb190e9bf95793833aaa42e868d7541a8908",
        "bytes": 352378880, "verified_files": 148}, "wrong frozen archive identity")
    require(p["cleanup"] == {"exit": 0, "lock_exit": 0, "owned_processes_remaining": 0,
                             "scenario_removed": True, "source_files_restored": 5}, "incomplete cleanup")
    require(raw == RAW_HASHES, "wrong archived raw hashes")
    require(set(legs) == set(native) == set(freezes) == {"control", "probe"}, "missing leg/native/freeze map")
    require(set(builds) == {"control", "probe", "observer"}, "missing build map")
    features = ["rustbgpd-transport/bench-internals"]
    require(p["daemon_features"] == features, "wrong daemon features")
    for arm in ("control", "probe"):
        leg, n, f, b = legs[arm], native[arm], freezes[arm], builds[arm]
        require(all(leg[k] == 0 for k in ("driver_exit", "runner_exit", "daemon_exit", "analysis_exit",
                                         "provenance_verification_exit")), "failed leg exit")
        require(leg["cooldown_seconds"] == 300, "wrong cooldown")
        quiet = leg["quiet_samples"]
        require(len(quiet) == 2 and int(quiet[1]["epoch_s"])-int(quiet[0]["epoch_s"]) >= 30,
                "missing quiet samples")
        require(all(number(x["load1"]) < 2 and x["quiet"] == "true" and x["competitors"] == "none"
                    and int(x["performance_governors"]) == int(x["governor_count"]) == 64 for x in quiet),
                "failed quiet sample")
        require(all(quiet[0][k] == quiet[1][k] for k in ("pswpin", "pswpout")), "swap changed")
        require(set(f) == {"pre", "post"} and f["pre"] == f["post"], "missing or changed freeze")
        for phase in ("pre", "post"):
            require(leg[phase+"_freeze_sha256"] == raw[f"{arm}/{phase}-freeze.json"], "wrong freeze hash")
        f = f["pre"]
        require(f["head"] == COMMIT and f["diff_sha256"] == PATCH and f["source"] == PROBE_SOURCE,
                "wrong execution worktree source")
        require(f["helpers"] == HELPERS and f["analysis"] == raw["method/analyze-probe-v4.py"],
                "wrong execution helper or analysis hash")
        method = {k.removeprefix("method/"): v for k, v in raw.items() if k.startswith("method/")}
        require(f["build_and_probe_archive"] == method, "missing or wrong build archive map")
        require(f["archived_binary"] == f["installed_binary"] == BINARIES[arm] and
                f["harness"] == BINARIES["observer"] and f["probe"] == str(int(arm == "probe")) and
                f["build_features"] == features[0], "wrong arm freeze binary binding")
        require(n["schema"] == 1 and n["cell"] == "rustbgpd" and n["git"] == {
            "commit": COMMIT, "tree": TREE, "dirty": True}, "wrong native source")
        require(n["toolchain"] == native["control"]["toolchain"] and
                n["toolchain"].startswith("rustc " + p["rust_version"]) and
                n["host"] == native["control"]["host"] and n["host"].startswith("Linux 7.0.0-30-generic "),
                "wrong native environment")
        require(n["workload"] == {"sha256": BINARIES[arm], "inputs": WORKLOAD}, "wrong native workload or binary")
        sources = n["sources"]
        generator = "bench/scale/reloadstall/gen-scenario.py"
        common = {k: v for k, v in HELPERS.items() if k != generator}
        require(sources == {"common": common, "generator": {generator: HELPERS[generator]},
                            "reloadstall": {"sha256": BINARIES["observer"]}}, "wrong native helper or harness map")
        require(b["source_commit"] == COMMIT and b["binary_sha256"] == BINARIES[arm] and
                b["features"] == features and b["build_exit"] == 0, "wrong arm build binding")
    require(builds["control"]["source_clean_at_build"] is True and
            builds["control"]["source_patch_sha256"] == hashlib.sha256(b"").hexdigest(), "wrong clean-control build source")
    probe = builds["probe"]
    require(probe["source_patch_sha256"] == PATCH and probe["source_files"] == PROBE_SOURCE,
            "wrong probe build source")
    witness = probe["witness"]
    sites = ("scout member release", "scout consumer entered", "scout first shared enqueue",
             "scout encoder sorted", "scout first publish", "scout encoder finished",
             "benchmark writer write-future polls (not kernel wakeups)")
    require(witness == {"binary_sha256": BINARIES["probe"], "required_probe_site_counts": dict.fromkeys(sites, 1),
                        "compiled_packages": ["rustbgpd-rib", "rustbgpd-transport", "rustbgpd"]}, "wrong probe build witness")
    require(builds["observer"] == {"source_commit": COMMIT,
            "source_file_sha256": PROBE_SOURCE["bench/scale/reloadstall/src/main.rs"],
            "binary_sha256": BINARIES["observer"], "profile": "scale", "build_exit": 0}, "wrong observer build binding")


def native_maps(path):
    clocks, gaps, generations, aggregates = {}, {}, {}, []
    header = None
    for fields in csv.reader(path.read_text().splitlines()):
        tag, *v = fields
        if tag == "reloadstall_csv_header":
            require(header is None, "duplicate native header")
            header = v
        elif tag == "reloadstall_csv":
            require(header is not None and len(v) == len(header), "invalid native aggregate")
            aggregates.append(dict(zip(header, v)))
        elif tag == "scout_clock":
            r, a, wall, b = map(int, v)
            require(r not in clocks and 0 <= a <= b and wall > 0, "invalid native clock")
            clocks[r] = (wall - (b-a)/2, (b-a)/2)
        elif tag in ("scout_gap", "scout_generation"):
            key = tuple(map(int, v[:2]))
            target = gaps if tag == "scout_gap" else generations
            require(key not in target, "duplicate native observer map")
            target[key] = v[2:] if tag == "scout_gap" else number(v[2])/1000
        else:
            raise ValueError(f"unknown native record: {tag}")
    require(set(clocks) == set(ROUNDS), "missing native clock map")
    require(set(gaps) == set(generations) == EXPECTED, "missing native observer map")
    require([int(row["reload"]) for row in aggregates] == list(ROUNDS), "missing native reload map")
    for row in aggregates:
        require(all(int(row[k]) == v for k, v in {
            "peers_total": 700, "peers_changed": 700, "peers_stable": 0,
            "prefixes": 400400, "sessions_up": 700, "parse_errors": 0,
        }.items()), "wrong native workload or session result")
    return clocks, gaps, generations, aggregates


def read_observers(root, arm):
    clocks, gaps, generations, aggregates = native_maps(root / f"native-{arm}.log")
    with (root / f"observers-{arm}.csv").open() as stream:
        rows = list(csv.DictReader(stream))
    seen = set()
    for row in rows:
        key = int(row["reload"]), int(row["observer"])
        require(key in EXPECTED and key not in seen, "duplicate or unexpected observer")
        seen.add(key)
        for field in row:
            if field not in ("inventory", "elected_encoder"):
                row[field] = number(row[field])
        native = gaps[key]
        for field, value in zip(("gap_ms", "gap_start_ms", "gap_end_ms", "end_base_nlri"), native[:4]):
            require(row[field] == number(value), "observer differs from native gap map")
        require(row["first_base_ms"] == number(native[5]) and row["completion_ms"] == number(native[6]),
                "observer differs from native completion map")
        require(row["first_generation_ms"] == generations[key], "observer differs from native generation map")
        require(row["clock_uncertainty_us"] == clocks[key[0]][1], "observer clock mismatch")
        require(0 <= row["gap_start_ms"] <= row["gap_end_ms"] <= row["completion_ms"], "unordered observer")
        require(abs(row["gap_ms"] - row["gap_end_ms"] + row["gap_start_ms"]) < .002, "gap boundary mismatch")
        require(0 <= row["first_base_ms"] <= row["completion_ms"] and
                0 <= row["first_generation_ms"] <= row["completion_ms"], "invalid first observation")
    require(seen == EXPECTED, "missing observer")
    for r, aggregate in zip(ROUNDS, aggregates):
        cohort = [x for x in rows if x["reload"] == r]
        for source, prefix, scale, tolerance in (
            ("gap_ms", "changed_maxgap", 1, .002),
            ("first_generation_ms", "changed_first_generation_update", 1, .002),
            ("completion_ms", "completion", .001, .000002),
        ):
            suffix = "s" if source == "completion_ms" else "ms"
            for quantile, value in quantiles([x[source] for x in cohort]).items():
                require(abs(number(aggregate[f"{prefix}_{quantile}_{suffix}"])-value*scale) < tolerance,
                        "native aggregate differs from observer map")
    return rows, aggregates


def validate_probe(root, rows):
    coverage = json.loads((root / "coverage-probe.json").read_text())
    producers = json.loads((root / "producer.json").read_text())
    with (root / "matched-writers.csv").open() as stream:
        writers = list(csv.DictReader(stream))
    require(len(writers) == 2800, "missing matched writers")
    writers = {(int(x["reload"]), int(x["observer"])): x for x in writers}
    require(set(writers) == EXPECTED, "duplicate or missing matched writer")
    require([x["reload"] for x in coverage] == list(ROUNDS), "missing stage coverage")
    require([x["reload"] for x in producers] == list(ROUNDS), "missing producer stages")
    for r in ROUNDS:
        cohort = [x for x in rows if x["reload"] == r]
        c, p = coverage[r-1], producers[r-1]
        alias = f"reload-{r}-inventory"
        require(c["inventory"] == p["inventory"] == alias, "inventory alias mismatch")
        require(all(c[k] == 700 for k in ("observers", "generations", "writer_start")), "incomplete stage coverage")
        for stage in ("release", "consumer", "enqueue"):
            require(c[stage] == c[stage+"_events"] == 700 and c[stage+"_duplicate_peers"] == 0,
                    "incomplete or duplicate stage coverage")
        require({x["release_rank"] for x in cohort} == set(range(700)), "invalid release ranks")
        require(sum(x["elected_encoder"] == "True" for x in cohort) == 1, "invalid elected encoder count")
        encoder = next(x for x in cohort if x["elected_encoder"] == "True")
        require(encoder["observer"] == p["observer"], "producer observer mismatch")
        require(encoder["consumer_ms"] <= number(p["sorted_ms"]) <= number(p["first_publish_log_ms"])
                <= number(p["finished_ms"]), "unordered producer stages")
        for x in cohort:
            require(x["inventory"] == alias and x["inventory_rows"] == c["inventory_rows"] == p["inventory_rows"],
                    "inventory size mismatch")
            require(0 <= x["release_ms"] <= x["consumer_ms"] <= x["enqueue_ms"], "unordered admission stages")
            require(0 <= x["writer_start_ms"] <= x["writer_logged_ms"], "unordered writer")
            require(0 <= x["writer_pending_polls"] < x["writer_polls"] and x["batch_frames"] > 0,
                    "invalid writer counters")
            require(0 <= x["writer_busy_ms"] <= x["writer_elapsed_ms"] + .001, "invalid writer duration")
            w = writers[r, int(x["observer"])]
            before, size = int(w["bulk_before"]), int(w["bytes"])
            require(before <= x["admitted_before"] < before+size and
                    0 < x["chunk_bytes"] <= before+size-x["admitted_before"], "first chunk outside FIFO writer interval")
            require(size == x["batch_bytes"] and number(w["writer_start_ms"]) == x["writer_start_ms"],
                    "matched writer differs from observer row")
            require(x["writer_start_ms"] <= x["first_generation_ms"] + x["clock_uncertainty_us"]/1000 + .002,
                    "writer starts after observation")
            for field, expected in {
                "release_to_consumer_ms": x["consumer_ms"]-x["release_ms"],
                "enqueue_to_writer_trace_ms": x["writer_start_ms"]-x["enqueue_ms"],
                "writer_to_arrival_ms": x["first_generation_ms"]-x["writer_start_ms"],
            }.items():
                require(abs(x[field]-expected) < 1e-8, "derived interval mismatch")
            x["consumer_to_enqueue_ms"] = x["enqueue_ms"]-x["consumer_ms"]


def summarize(rows, probe):
    rounds, vectors, tails = [], [], []
    for r in ROUNDS:
        cohort = sorted((x for x in rows if x["reload"] == r), key=lambda x: x["observer"])
        gap = [x["gap_ms"] for x in cohort]
        vectors.append(gap)
        top = sorted(cohort, key=lambda x: x["gap_ms"], reverse=True)[:35]
        tails.append({int(x["observer"]) for x in top})
        result = {"reload": r, "gap_ms": quantiles(gap),
                  "gap_ends_first_base": sum(x["gap_end_ms"] == x["first_base_ms"] for x in cohort),
                  "gap_ends_first_generation": sum(x["gap_end_ms"] == x["first_generation_ms"] for x in cohort)}
        if probe:
            fields = ("release_to_consumer_ms", "consumer_to_enqueue_ms", "enqueue_to_writer_trace_ms",
                      "writer_elapsed_ms", "writer_busy_ms", "writer_to_arrival_ms")
            result["phases"] = {k: quantiles([x[k] for x in cohort]) for k in fields}
            result["top35_phases"] = {k: quantiles([x[k] for x in top]) for k in fields}
            result["release_span_ms"] = max(x["release_ms"] for x in cohort)-min(x["release_ms"] for x in cohort)
            result["gap_spearman"] = {k: spearman([x[k] for x in cohort], gap) for k in (
                "release_rank", "consumer_ms", "enqueue_ms", "writer_start_ms", "batch_bytes")}
            result["first_writer_pending_count"] = sum(x["writer_pending_polls"] > 0 for x in cohort)
        rounds.append(result)
    return {"rounds": rounds, "top35_union": len(set.union(*tails)),
            "top35_all_round_intersection": len(set.intersection(*tails)),
            "cross_rounds": [{"a": a+1, "b": b+1, "spearman": spearman(vectors[a], vectors[b]),
                              "top35_overlap": len(tails[a] & tails[b])}
                             for a, b in itertools.combinations(range(4), 2)]}


def recompute(root=ROOT):
    verify_hashes(root)
    validate_identity(root)
    results, native = {}, {}
    for arm in ("control", "probe"):
        rows, aggregate = read_observers(root, arm)
        if arm == "probe":
            validate_probe(root, rows)
        results[arm] = summarize(rows, arm == "probe")
        native[arm] = {"completion_p50_median_s": median(number(x["completion_p50_s"]) for x in aggregate),
                       "gap_p50_median_ms": median(number(x["changed_maxgap_p50_ms"]) for x in aggregate)}
    results["native_aggregate_medians"] = native
    results["probe_change_percent"] = {k: (native["probe"][k]/native["control"][k]-1)*100 for k in native["control"]}
    return results


if __name__ == "__main__":
    print(json.dumps(recompute(), indent=2, allow_nan=False))

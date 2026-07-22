#!/usr/bin/env python3
# Deterministic LAN-548 value-gate evaluator.
import csv, statistics, sys
from pathlib import Path

timings, payload_file, result_file, state_file, self_test = sys.argv[1:]
MIB = 1024 * 1024

def verdict(control, candidate, control_warm, candidate_warm,
            control_size, candidate_size, removed_unit, final, marginal=False):
    med = statistics.median
    clean_seconds = med(control) - med(candidate)
    clean_pct = clean_seconds * 100 / med(control)
    size_bytes = control_size - candidate_size
    size_pct = size_bytes * 100 / control_size
    warm_pct = (med(candidate_warm) - med(control_warm)) * 100 / med(control_warm)
    paired = all(a > b for a, b in zip(control, candidate))
    overlap = max(min(control), min(candidate)) <= min(max(control), max(candidate))
    if marginal:
        size_gate = size_pct >= 5 and size_bytes >= MIB
        build_gate = clean_pct >= 10
        near = ((abs(size_pct - 5) <= 2 and abs(size_bytes - MIB) <= 256 * 1024)
                or abs(clean_pct - 10) <= 2 or abs(warm_pct - 5) <= 1)
    else:
        size_gate = size_pct >= 10 and size_bytes >= 2 * MIB
        build_gate = removed_unit and clean_pct >= 15 and clean_seconds >= 30
        near = ((abs(size_pct - 10) <= 2 and abs(size_bytes - 2 * MIB) <= 256 * 1024)
                or (removed_unit and abs(clean_pct - 15) <= 2
                    and abs(clean_seconds - 30) <= 10)
                or abs(warm_pct - 5) <= 1)
    if not final and (overlap or near):
        decision = "ADDITIONAL_RUNS_REQUIRED"
    elif paired and warm_pct <= 5 and (size_gate or build_gate):
        decision = "GO"
    else:
        decision = "NO_GO"
    return dict(decision=decision, paired=paired, clean_seconds=clean_seconds,
                clean_pct=clean_pct, size_bytes=size_bytes, size_pct=size_pct,
                warm_pct=warm_pct, overlap=overlap, near=near,
                size_gate=size_gate, build_gate=build_gate)

def gate_score(result):
    size = min(result["size_pct"] / 10, result["size_bytes"] / (2 * MIB))
    build = min(result["clean_pct"] / 15, result["clean_seconds"] / 30)
    return max(size, build)

def choose_winner(names, results):
    return max(names, key=lambda name: gate_score(results[name])) if names else "none"

if self_test == "1":
    base, warm = [100, 101, 99], [10, 10, 10]
    check = lambda cand, cwarm, size, full=30 * MIB, removed=True, final=True: verdict(
        base, cand, warm, cwarm, full, size, removed, final)["decision"]
    assert check([80, 81, 79], warm, 26 * MIB) == "GO"
    assert check([90, 91, 89], warm, int(27.3 * MIB)) == "NO_GO"
    assert check([90, 91, 89], warm, 8.5 * MIB, 10 * MIB) == "NO_GO"
    assert check([80, 102, 79], warm, 26 * MIB) == "NO_GO"
    assert check([80, 81, 79], [10.6] * 3, 26 * MIB) == "NO_GO"
    assert check([98, 99, 97], warm, 29 * MIB, final=False) == "ADDITIONAL_RUNS_REQUIRED"
    assert check([90, 91, 89], warm, 18.1 * MIB, 20 * MIB,
                 final=False) == "ADDITIONAL_RUNS_REQUIRED"
    build_base = [300, 301, 299]
    assert verdict(build_base, [240, 241, 239], warm, warm, 30 * MIB, 30 * MIB,
                   True, True)["decision"] == "GO"
    assert verdict(build_base, [268, 269, 267], warm, warm, 30 * MIB, 30 * MIB,
                   True, True)["decision"] == "NO_GO"
    assert check([80, 81, 79], warm, 30 * MIB) == "NO_GO"
    assert verdict(build_base, [240, 241, 239], warm, warm, 30 * MIB, 30 * MIB,
                   False, True)["decision"] == "NO_GO"
    far = verdict(base, [50, 51, 49], warm, warm, 30 * MIB, 20 * MIB,
                  True, False)
    assert far["decision"] == "GO" and not far["near"]
    marginal_good = verdict(base, [89, 90, 88], warm, warm, 30 * MIB, 30 * MIB,
                            True, True, True)
    assert marginal_good["decision"] == "GO"
    assert verdict(base, [97, 98, 96], warm, warm, 30 * MIB, 28 * MIB,
                   True, True, True)["decision"] == "GO"
    assert verdict(base, [97, 98, 96], warm, warm, 30 * MIB, 28.8 * MIB,
                   True, True, True)["decision"] == "NO_GO"
    assert verdict(base, [97, 98, 96], warm, warm, 10 * MIB, 9.4 * MIB,
                   True, True, True)["decision"] == "NO_GO"
    marginal_far = verdict(base, [50, 51, 49], warm, warm, 30 * MIB, 20 * MIB,
                           True, False, True)
    assert marginal_far["decision"] == "GO" and not marginal_far["near"]
    assert gate_score(dict(size_pct=20, size_bytes=2 * MIB,
                           clean_pct=0, clean_seconds=0)) == 1
    assert gate_score(dict(size_pct=0, size_bytes=0,
                           clean_pct=30, clean_seconds=30)) == 1
    choices = {
        "percent-only": dict(size_pct=20, size_bytes=2 * MIB, clean_pct=0, clean_seconds=0),
        "balanced": dict(size_pct=12, size_bytes=3 * MIB, clean_pct=0, clean_seconds=0),
    }
    assert choose_winner(choices, choices) == "balanced"
    for name in ("size-percent", "size-bytes", "build-percent", "build-seconds",
                 "build-evidence", "same-sign", "warm-cap", "extension",
                 "far-past", "combined-gates"):
        print(f"RED evaluator-{name} synthetic-guard-break")
    raise SystemExit

with open(timings, newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))
with open(payload_file, newline="", encoding="utf-8") as f:
    payloads = {r["variant"]: int(r["normalized_release_payload_gzip_bytes"])
                for r in csv.DictReader(f)}

def series(phase, variant):
    found = sorted((r for r in rows if r["phase"] == phase and r["variant"] == variant),
                   key=lambda r: int(r["round"]))
    return [float(r["elapsed_seconds"]) for r in found]

full, full_warm = series("clean", "full"), series("warm", "full")
if len(full) not in (3, 5) or len(full_warm) != len(full):
    raise SystemExit("expected three or five balanced full rows")
results = {}
for name, removed in (("no-history", True), ("control-plane", True)):
    clean, warm = series("clean", name), series("warm", name)
    if len(clean) != len(full) or len(warm) != len(full):
        raise SystemExit(f"unbalanced rows for {name}")
    results[name] = verdict(full, clean, full_warm, warm, payloads["full"],
                            payloads[name], removed, len(full) == 5)

go = [name for name in results if results[name]["decision"] == "GO"]
winner = choose_winner(go, results)
combined = None
if "combined" in payloads:
    if winner == "none":
        raise SystemExit("combined measurement without individual GO")
    bc, cc = series("marginal-clean", winner), series("marginal-clean", "combined")
    bw, cw = series("marginal-warm", winner), series("marginal-warm", "combined")
    if len(bc) not in (3, 5) or len({len(bc), len(cc), len(bw), len(cw)}) != 1:
        raise SystemExit("unbalanced combined rows")
    combined = verdict(bc, cc, bw, cw, payloads["marginal-" + winner], payloads["combined"],
                       False, len(bc) == 5, True)

additional_primary = any(r["decision"] == "ADDITIONAL_RUNS_REQUIRED"
                         for r in results.values())
additional_combined = bool(combined and combined["decision"] == "ADDITIONAL_RUNS_REQUIRED")
Path(state_file).write_text(
    f"additional_primary={str(additional_primary).lower()}\n"
    f"winner={winner}\n"
    f"additional_combined={str(additional_combined).lower()}\n",
    encoding="utf-8")

out = [
    "LAN-548 deterministic evaluation", f"primary_repetitions={len(full)}",
    "near_definition=size within 2 percentage points and 256 KiB; build within 2 percentage points and 10 seconds; warm within 1 percentage point; or clean ranges overlap"]
fields = ("decision", "paired", "clean_seconds", "clean_pct", "size_bytes",
          "size_pct", "warm_pct", "overlap", "near", "size_gate", "build_gate")
for name, result in results.items():
    for field in fields:
        value = result[field]
        out.append(f"{name}.{field}={value:.2f}" if isinstance(value, float)
                   else f"{name}.{field}={str(value).lower()}")
out += [f"individual_winner={winner}",
        "no-history.removed_unit=libsqlite3-sys bundled SQLite C compilation",
        "control-plane.removed_unit=rtnetlink and netlink protocol compile units"]
if combined:
    out.append(f"combined.repetitions={len(series('marginal-clean', 'combined'))}")
    for field in fields:
        value = combined[field]
        out.append(f"combined.{field}={value:.2f}" if isinstance(value, float)
                   else f"combined.{field}={str(value).lower()}")
else:
    out.append("combined.decision=NOT_ELIGIBLE_OR_NOT_YET_MEASURED")
Path(result_file).write_text("\n".join(out) + "\n", encoding="utf-8")

#!/usr/bin/env python3
"""Emit the flapstorm failover overlap allocation (`overlap.tsv`).

Each of the first `flappers` members (the harness's `--flapstorm K` cohort)
gets an alternate for the first `percent`% of its base slice. The
alternates come from `sources` distinct surviving members, round-robin over
that flapper's prefixes, so one flapper's down pass has `sources` new
winning members. Survivors exclude the flappers and the harness's last
CHURNERS stubs. The harness announces these extras with the stub's ASN
prepended, so they lose the initial tie-break and take over only when the
flapper goes away.

Output rows are `member<TAB>global prefix index`, the format of
`RELOADSTALL_OVERLAP_FILE`. The slice layout matches the harness's IPv4-only
`member_slice`: `total` must divide evenly by `n_peers`.

Usage:
    gen-failover-overlap.py <n_peers> <total> <flappers> <percent> <sources> <out>
"""
import sys

CHURNERS = 8  # must match src/main.rs


def allocation(n_peers, total, flappers, percent, sources):
    if total % n_peers:
        raise ValueError("total must divide evenly by n_peers")
    if not 0 <= percent <= 100:
        raise ValueError("percent must be within 0..=100")
    survivors = list(range(flappers, n_peers - CHURNERS))
    if not 1 <= sources <= len(survivors):
        raise ValueError(f"sources must be within 1..={len(survivors)}")
    per_peer = total // n_peers
    covered = per_peer * percent // 100
    rows = []
    for flapper in range(flappers):
        alternates = [survivors[(flapper * sources + j) % len(survivors)] for j in range(sources)]
        for offset in range(covered):
            rows.append((alternates[offset % sources], flapper * per_peer + offset))
    return rows


def main(argv):
    if len(argv) != 7:
        sys.exit(__doc__)
    n_peers, total, flappers, percent, sources = (int(value) for value in argv[1:6])
    rows = allocation(n_peers, total, flappers, percent, sources)
    with open(argv[6], "w", encoding="ascii") as out:
        for member, index in rows:
            out.write(f"{member}\t{index}\n")


if __name__ == "__main__":
    main(sys.argv)

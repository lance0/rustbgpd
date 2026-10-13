#!/usr/bin/env python3
"""Re-run the as-run summarizer on the compact evidence and check its output.

The summarizer reads full daemon logs, metrics scrapes and neighbor JSON,
which are not published. This script rebuilds the minimal form of each from
the retained extracts in a temporary directory:

  daemon.log          <- cells/*/daemon-events.jsonl (post-injection events the
                         summarizer reads; pre_inject_log_lines becomes 0)
  metrics-*.prom      <- cells/*/refresh-counter-*.prom
  neighbors-*.json    <- cells/*/neighbors-*.tsv

then runs summarize.py with the job's arguments and requires its stdout to
equal summary.txt and its per-cell rows to equal cells.json (less the
per-process counts_digest). Exits non-zero on any difference.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        (out / "schedule.txt").write_text((HERE / "schedule.txt").read_text())
        for cell in sorted((HERE / "cells").iterdir()):
            dst = out / "raw" / cell.name
            dst.mkdir(parents=True)
            for f in cell.iterdir():
                if f.suffix not in (".jsonl",) and not f.name.startswith(("refresh-counter-", "neighbors-")):
                    (dst / f.name).write_bytes(f.read_bytes())
            env = (cell / "cell.env").read_text().splitlines()
            env = ["pre_inject_log_lines=0" if l.startswith("pre_inject_log_lines=") else l for l in env]
            (dst / "cell.env").write_text("\n".join(env) + "\n")
            (dst / "daemon.log").write_text((cell / "daemon-events.jsonl").read_text())
            for side in ("before", "after"):
                (dst / f"metrics-{side}.prom").write_text((cell / f"refresh-counter-{side}.prom").read_text())
                rows = (cell / f"neighbors-{side}.tsv").read_text().splitlines()
                head = rows[0].split("\t")
                nb = []
                for r in rows[1:]:
                    x = dict(zip(head, r.split("\t")))
                    for k in ("flap_count", "prefixes_received", "prefixes_sent"):
                        x[k] = int(x[k])
                    nb.append(x)
                (dst / f"neighbors-{side}.json").write_text(json.dumps(nb))
        run = subprocess.run([sys.executable, str(HERE / "summarize.py"), str(out), "10 100 1000", "10", "50", ""],
                             capture_output=True, text=True)
        ok = True
        if run.returncode != 0:
            print(f"summarize.py exited {run.returncode} (expected 0, PASS)\n{run.stderr}")
            ok = False
        if run.stdout != (HERE / "summary.txt").read_text():
            print("summary differs from summary.txt:\n" + run.stdout)
            ok = False
        rows = json.loads((out / "cells.json").read_text())
        for r in rows:
            r.pop("counts_digest", None)
        if json.loads(json.dumps(rows, default=str)) != json.loads((HERE / "cells.json").read_text()):
            print("per-cell rows differ from cells.json")
            ok = False
    print("recompute OK: summary.txt and cells.json reproduced" if ok else "recompute FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

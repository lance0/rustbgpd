#!/usr/bin/env python3
"""Require live unsent-data threshold readback for every established session.

Usage: check-unsent-readback.py DAEMON_LOG unset|BYTES

The benchmark writer logs one readback per connection before it writes the
OPEN, so each "session established" event, reconnects included, must follow
an unconsumed readback for that peer. A positive arm needs the requested value
in effect; the unset arm needs proof that nothing was applied (socket value 0).
A daemon built without the benchmark hook logs no readback and fails.
"""
from collections import Counter
import json
import sys

READBACK = "benchmark unsent-data threshold read back from live socket"
ESTABLISHED = "session established"


def check(lines, threshold):
    """Return a list of errors; empty means every established session is covered."""
    want = (
        ("None", 0) if threshold == "unset" else (f"Some({int(threshold)})", int(threshold))
    )
    pending, established, errors = Counter(), 0, []
    for number, line in enumerate(lines, 1):
        try:
            fields = json.loads(line)["fields"]
            message = fields["message"]
        except (ValueError, KeyError, TypeError):
            continue
        if message == READBACK:
            got = (fields.get("requested"), fields.get("actual"))
            if "peer" not in fields or got != want:
                errors.append(f"line {number}: readback {got} for {fields.get('peer')}, want {want}")
                continue
            pending[fields["peer"]] += 1
        elif message == ESTABLISHED:
            established += 1
            peer = fields.get("peer")
            if pending[peer] == 0:
                errors.append(f"line {number}: session {peer} established without readback")
            else:
                pending[peer] -= 1
    if established == 0:
        errors.append("no established sessions")
    return errors


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1], encoding="utf-8", errors="replace") as log:
        errors = check(log, sys.argv[2])
    for error in errors:
        print(error, file=sys.stderr)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()

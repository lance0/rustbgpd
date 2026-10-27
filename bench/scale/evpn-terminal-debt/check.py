"""Raw-evidence checks; structural faults are INVALID, breached bars are FAIL."""

from decimal import Decimal
import json
import re


def require(ok, message):
    if not ok:
        raise ValueError(message)


def lines(path, prefix):
    return [json.loads(line[len(prefix):]) for line in path.read_text().splitlines() if line.startswith(prefix)]


def positive(row):
    return (row["complete"] and row["current"] and row["channel_match"] and not row["dirty"]
            and row["session"] == row["record_session"] > 0 and row["channel"] > 0 and row["revision"] > 0 and row["owed"] > 0
            and type(row["target_group"]) is int and row["target_group"] >= 0 and row["table_stamp"] > 0)


def validate_feed(rows, peers):
    for row in rows:
        require(row["peer"] in peers and row["event"] in {
            "sample", "root_before", "data_admitted", "terminal_admitted", "marker_refused", "complete_noop"},
            "unknown feed identity/event")
        require(all(type(row[name]) is bool for name in ("complete", "current", "channel_match", "dirty"))
                and all(type(row[name]) is int and row[name] >= 0 for name in
                        ("wall_us", "root", "rows", "session", "record_session", "channel", "revision", "table_stamp", "owed", "capacity", "max_capacity"))
                and (row["target_group"] is None or type(row["target_group"]) is int and row["target_group"] >= 0)
                and row["owed"] <= 3 and row["capacity"] <= row["max_capacity"] == 4096,
                "malformed actual feed observation")


def settled(row):
    fields = ("dirty", "marker_debt", "pending_resets", "retained_recovery", "completion_receipts",
              "refresh_pending", "eor_pending", "protocol_obligations")
    require(all(type(row[name]) is int and row[name] >= 0 for name in fields), "malformed settlement observation")
    return not any(row[name] for name in fields)


def reset_free(resets):
    causes = {"peer_limit", "daemon_limit", "allocation_failure", "capture_unavailable", "admission_invariant"}
    require(set(resets) == causes and all(type(value) is int and value >= 0 for value in resets.values()),
            "malformed reset-cause roster")
    return not any(resets.values())


def ss_rows(text, started, ended):
    """ss sk is the Linux SO_COOKIE in hex; absent limited counters mean zero.

    No inference is made from an omitted snd_wnd field. Keep the original ss
    output too; these are cumulative kernel duration counters, not Tokio polls.
    """
    rows = []
    for block in re.split(r"\n(?=ESTAB\s)", text):
        cookie = re.search(r"\bsk:([0-9a-fA-F]+)\b", block)
        if not cookie:
            continue
        row = {"cookie": int(cookie[1], 16), "started_us": started, "ended_us": ended}
        for name in ("rwnd_limited", "sndbuf_limited"):
            value = re.search(rf"\b{name}:([0-9.]+)(ms|us|s)\b", block)
            row[name + "_us"] = int(Decimal(value[1]) * {"us": 1, "ms": 1000, "s": 1000000}[value[2]]) if value else 0
        notsent = re.search(r"\bnotsent:(\d+)\b", block)
        row["notsent"] = int(notsent[1]) if notsent else 0
        rows.append(row)
    return rows


def kernel_pressure(sockets, writes, samples, peer, start, end, root_at, applied_at):
    matches = [row for row in sockets if row["peer"] == peer]
    require(len(matches) == 1 and matches[0]["cookie"] > 0 and matches[0]["send_buffer"] == 8192
            and matches[0]["notsent_lowat"] == 4096,
            "missing unique live socket identity/readback")
    cookie = matches[0]["cookie"]
    candidates = [row for row in writes if row["event"] == "pending" and row["cookie"] == cookie]
    for pending in candidates:
        if any(row["event"] == "failed" and row["cookie"] == cookie and row["id"] == pending["id"] for row in writes):
            continue
        completions = [row["wall_us"] for row in writes if row["event"] == "complete"
                       and row["cookie"] == cookie and row["id"] == pending["id"]]
        require(pending["id"] > 0 and pending["started_us"] <= pending["wall_us"], "malformed first-Pending write identity")
        require(len(completions) <= 1, "duplicate write completion")
        if pending["wall_us"] > root_at or min(completions, default=end) < applied_at:
            continue
        lower, upper = max(start, pending["wall_us"]), min(end, min(completions, default=end))
        actual = [row for row in samples if row["cookie"] == cookie
                  and lower <= row["started_us"] <= row["ended_us"] <= upper]
        for left, right in zip(actual, actual[1:]):
            for name in ("rwnd_limited_us", "sndbuf_limited_us"):
                require(right[name] >= left[name], "nonmonotone kernel limited counter")
        before = [row for row in actual if row["ended_us"] <= root_at]
        after = [row for row in actual if row["started_us"] >= applied_at]
        if before and after:
            left, right = before[-1], after[0]
            if any(right[name] > left[name] for name in ("rwnd_limited_us", "sndbuf_limited_us")):
                return {"pending": pending, "samples": [left, right], "socket": matches[0]}
    return None


def pending_write(writes, cookie, after):
    for row in writes:
        if row["event"] == "pending" and row["cookie"] == cookie and row["started_us"] >= after:
            if not any(end["id"] == row["id"] and end["cookie"] == cookie and end["event"] in ("complete", "failed") for end in writes):
                return row
    return None


def socket_roster(daemon, receivers, peers):
    require(len(daemon) == len(receivers) == len(peers)
            and {row["peer"] for row in daemon} == {row["peer"] for row in receivers} == peers,
            "missing/duplicate live socket roster")
    require(len({row["cookie"] for row in daemon + receivers}) == 2 * len(peers), "socket cookie reused across distinct endpoints")
    for receiver in receivers:
        peer = next(row for row in daemon if row["peer"] == receiver["peer"])
        require(type(peer["cookie"]) is int and type(receiver["cookie"]) is int and min(peer["cookie"], receiver["cookie"]) > 0
                and peer["send_buffer"] == receiver["receive_buffer"] == 8192 and peer["notsent_lowat"] == 4096,
                "live socket buffer/threshold readback differs")
        require(peer["local"] == receiver["remote"] and peer["remote"] == receiver["local"],
                "live socket endpoints do not match their actual peer")
    return {"daemon": daemon, "receivers": receivers}


COUNTERS = ("stage_rows", "delta_rows", "prepare_attempts", "projection_walks", "projection_rows",
            "current_walks", "current_rows", "old_walks", "old_rows", "old_delta_rows",
            "success_walks", "success_rows", "data_admissions", "data_rows", "terminal_admissions")


def work_receipt(rows, root_ids):
    selected = [row for row in rows if row["id"] in root_ids]
    require(selected and {row["id"] for row in selected} == set(root_ids), "missing actual root producer work")
    require(len(selected) == len(root_ids), "duplicate root work receipt")
    for row in selected:
        require(all(type(row[name]) is int and row[name] >= 0 for name in COUNTERS), "malformed work counter")
        attempts = row["prepare_attempts"]
        require(row["debtors_before"] > 0 and row["keys"] > 0 and row["stage_rows"] >= row["keys"]
                and row["delta_rows"] >= row["keys"] and attempts > 0,
                "root work omitted staging, delta or complete producer")
        require(row["projection_walks"] == 2 * attempts and row["current_walks"] == attempts
                and row["old_walks"] == attempts and row["success_walks"] == attempts,
                "root work omitted a producer/proof inventory pass")
        require(all(row[name] > 0 for name in ("projection_rows", "current_rows", "old_rows", "old_delta_rows", "success_rows")),
                "root work omitted visited inventory/delta rows")
    total = sum(row[name] for row in selected for name in ("projection_rows", "current_rows", "old_rows", "success_rows"))
    return {"calls": len(selected), "inventory_visits": total,
            "delta_visits": sum(row["delta_rows"] + row["old_delta_rows"] for row in selected),
            "producer_elapsed_us": sum(row["elapsed_us"] for row in selected)}


def debt_receipt(feed, work, sockets, writes, samples, applied_us, source_peer):
    admitted = [row for row in feed if row["event"] == "data_admitted" and row["root"] == 0
                and row["rows"] > 0 and row["peer"] != source_peer and positive(row)]
    for before in admitted:
        peer = before["peer"]
        roots = [row for row in feed if row["event"] == "root_before" and row["root"] > 0
                 and row["peer"] == peer and row["wall_us"] > before["wall_us"] and positive(row)
                 and row["session"] == before["session"]]
        for during in roots:
            updates = [row for row in feed if row["event"] == "data_admitted" and row["root"] == during["root"]
                       and row["peer"] == peer and row["wall_us"] > during["wall_us"] and row["rows"] > 0
                       and positive(row) and row["session"] == before["session"]
                       and row["target_group"] == before["target_group"]
                       and row["table_stamp"] > before["table_stamp"]]
            afters = [row for row in feed if row["event"] == "sample" and row["peer"] == peer and positive(row)
                      and row["wall_us"] > applied_us and row["session"] == before["session"]]
            for update in updates:
                for after in afters:
                    if after["wall_us"] <= update["wall_us"]:
                        continue
                    interval = [row for row in feed if row["peer"] == peer
                                and before["wall_us"] <= row["wall_us"] <= after["wall_us"]]
                    # A later good receipt cannot conceal a settled, stale or
                    # replaced completion in the claimed continuous interval.
                    if not all(positive(row) and row["session"] == before["session"]
                               and row["channel"] == before["channel"] for row in interval):
                        continue
                    identity = before["revision"], before["target_group"], before["table_stamp"]
                    lineage = True
                    for row in interval:
                        target = row["revision"], row["target_group"], row["table_stamp"]
                        if target != identity:
                            is_data_admission = row["event"] == "data_admitted" and row["rows"] > 0
                            proved_noop = row["event"] == "complete_noop" and row["root"] > 0
                            if not (is_data_admission or proved_noop):
                                lineage = False
                                break
                            identity = target
                    if not lineage:
                        continue
                    pressure = kernel_pressure(sockets, writes, samples, peer, before["wall_us"], after["wall_us"],
                                               during["wall_us"], applied_us)
                    if pressure:
                        return {"before": before, "during": during, "admitted_churn": update, "after": after,
                                "kernel": pressure, "work": work_receipt(work, [during["root"]]),
                                "marker_refusals": sum(row["event"] == "marker_refused" for row in interval)}
    return None


def readiness(samples):
    require(samples, "missing readiness samples")
    ordered = sorted(samples, key=lambda row: row["scheduled"])
    require(all(abs(right["scheduled"] - left["scheduled"] - .05) < .000001
                for left, right in zip(ordered, ordered[1:])), "missing 20 Hz readiness probe")
    require(all(0 <= row["at"] - row["scheduled"] < .05 for row in samples), "20 Hz readiness scheduling miss")
    return all(row["status"] == 200 and 0 <= row["seconds"] < .2 for row in samples)


def raw_updates(data):
    """Retain actual socket UPDATE bytes; reject unnegotiated type-5 markers."""
    cursor, result = 0, bytearray()
    while cursor < len(data):
        require(cursor + 19 <= len(data) and data[cursor:cursor + 16] == b"\xff" * 16, "truncated raw BGP header")
        size, kind = int.from_bytes(data[cursor + 16:cursor + 18], "big"), data[cursor + 18]
        require(19 <= size <= 4096 and cursor + size <= len(data), "truncated raw BGP frame")
        require(kind in (2, 4), "unexpected raw message: ERR is not negotiated in this leg")
        require(kind != 4 or size == 19, "malformed KEEPALIVE")
        if kind == 2:
            result.extend(data[cursor:cursor + size])
        cursor += size
    return bytes(result)

#!/usr/bin/env python3
"""Second run: RPKI-Invalid share from a pinned real VRP snapshot, and the
scenario VRP fixtures that carry that share.

usage: real-fixture.py WT OUT_DIR

Inputs (sha256-pinned below, checked before use):
  VRPs  RIPE NCC RPKI archive, 2026-08-08, the five RIR TAs' validated roas.csv.xz
        (https://ftp.ripe.net/rpki/<ta>.tal/2026/08/08/roas.csv.xz); hashes equal the
        publisher's .sha256 files.
  RIBs  RouteViews route-views2 (IPv4) and route-views6 (IPv6) rib.20260808.0000, the
        same date. The IPv4 file is a frozen input from an earlier real-table receipt.

Share: every distinct (prefix, origin AS) announced by any RouteViews peer, validated per
RFC 6811 against the deduplicated VRP set (covering VRP => Valid on an origin+maxLength
match, else Invalid; no covering VRP => NotFound; an AS_SET origin matches nothing).
Per-peer shares are reported too.

Why not validate the scenario's own routes: reloadstall announces synthetic
20.0.0.0-23.13.x /24s and 3001:x:y::/48s from private ASNs 64512+i. Against a real snapshot
every covered synthetic route is Invalid only because its origin is private, and IPv6
3001::/16 is unallocated, so that share (reported as `literal_scenario`) measures address
choice, not route-server reality. Instead the measured Valid/Invalid/NotFound shares are
assigned to the scenario's routes per family: a deterministic sha256 order of the base
indexes picks round(share*T) Invalid routes (an exact VRP for the route under a non-member
ASN 4200001000+idx%1000) and round(share*T) NotFound routes (no VRP); the rest keep the
canonical exact Valid VRP. Padding /24s fill the table to VRPS, as rpki_cell.py does.
Deltas change N covering entries' maxLength (+1), spread over both families as
rpki_cell.py maxlen-delta does: validity-neutral, so the job's changed_routes=0 rule holds.

Writes OUT_DIR/{base.json, delta-N.json, delta-N.counts, import-rejected.txt, share.json}.
"""
import bz2, csv, hashlib, ipaddress, json, lzma, struct, sys
from collections import Counter, defaultdict
from pathlib import Path

PEERS, TOTAL, V4, VRPS, DELTAS = 700, 400400, 200200, 500000, (10, 100, 1000)
Q = Path("<prep-dir>/fixtures")
VRP_SRC = {
    "afrinic": "639fab2e6572162ccce106b9e76d1a4ee2489aeafb9a64286b9449446329c561",
    "apnic": "dce7bd7ef7fe7f4fb0d76ba317f9688b3fd42e04cdcd7b87587b5fe6e4e4daf9",
    "arin": "6f6511ebde145d414b2869dadb815a6b4b1e06844920130cef1018b614ddaa1b",
    "lacnic": "8ed140a2319a365933b09fe68a558683b086d5ab897206fdc0a97d22ab56f231",
    "ripencc": "e5d2f1b936ab322de020b8cc21b13112eab568773edc9227ca6684c4d8dd09bd",
}
RIBS = {
    4: (Path("<route-views2-rib>"),
        "03bf1ea39809789576786c61c7ff77d8e1977d04706af1457aaafaf7cb0e95fb",
        "https://archive.routeviews.org/route-views2/bgpdata/2026.08/RIBS/rib.20260808.0000.bz2"),
    6: (Q / "src-rib6-2026-08-08/rib.20260808.0000.bz2",
        "9aa035ad09ff6b7c64bb84c1aacc38df6d5ce30857ed465e0ad3450c82c59a4e",
        "https://archive.routeviews.org/route-views6/bgpdata/2026.08/RIBS/rib.20260808.0000.bz2"),
}
SEED = "<seed>"  # as-run order label withheld; the chosen indexes are in fixtures/import-rejected.txt
INVALID_ASN = 4200001000  # private 4-octet, disjoint from stubs 64512+i, pads 65000+, RS 4200000000


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_vrps():
    vrps = set()
    for ta, want in VRP_SRC.items():
        path = Q / "src-vrp-2026-08-08" / f"{ta}-roas.csv.xz"
        assert sha256(path) == want, f"{path} hash"
        with lzma.open(path, "rt") as f:
            for row in csv.DictReader(f):
                net = ipaddress.ip_network(row["IP Prefix"])
                vrps.add((net.version, int(net.network_address), net.prefixlen,
                          int(row["ASN"].removeprefix("AS")), int(row["Max Length"])))
    index = defaultdict(lambda: defaultdict(list))  # (fam) -> len -> net -> [(asn, maxlen)]
    for fam, net, plen, asn, maxlen in vrps:
        index[fam][plen].append((net, asn, maxlen))
    out = {}
    for fam, by_len in index.items():
        out[fam] = {}
        for plen, rows in by_len.items():
            d = defaultdict(list)
            for net, asn, maxlen in rows:
                d[net].append((asn, maxlen))
            out[fam][plen] = dict(d)
    return len(vrps), out


def validate(index, fam, net, plen, origin):
    bits = 32 if fam == 4 else 128
    covered = False
    for vlen, table in index[fam].items():
        if vlen > plen:
            continue
        hit = table.get(net >> (bits - vlen) << (bits - vlen) if vlen else 0)
        if hit is None:
            continue
        covered = True
        if origin is not None and any(asn == origin and asn != 0 and plen <= ml for asn, ml in hit):
            return "valid"
    return "invalid" if covered else "notfound"


def rib_pairs(path, fam):
    """Distinct (net, len, origin) per peer index from a TABLE_DUMP_V2 RIB."""
    peers, per_peer = [], defaultdict(set)
    with bz2.open(path, "rb") as stream:
        while header := stream.read(12):
            _, kind, subtype, length = struct.unpack(">IHHI", header)
            body = stream.read(length)
            assert len(body) == length, "truncated MRT record"
            if kind != 13:
                continue
            if subtype == 1:
                p = 6 + int.from_bytes(body[4:6], "big")
                count = int.from_bytes(body[p:p + 2], "big"); p += 2
                peers = []
                for _ in range(count):
                    t = body[p]; p += 5 + (16 if t & 1 else 4)
                    n = 4 if t & 2 else 2
                    peers.append(int.from_bytes(body[p:p + n], "big")); p += n
                continue
            if subtype not in ((2, 8) if fam == 4 else (4, 10)):
                continue
            plen = body[4]
            nb = (plen + 7) // 8
            raw = body[5:5 + nb] + bytes((4 if fam == 4 else 16) - nb)
            net = int.from_bytes(raw, "big")
            net = net >> ((32 if fam == 4 else 128) - plen) << ((32 if fam == 4 else 128) - plen) if plen else 0
            p = 5 + nb
            entries = int.from_bytes(body[p:p + 2], "big"); p += 2
            for _ in range(entries):
                pi = int.from_bytes(body[p:p + 2], "big")
                p += 6 + (4 if subtype in (8, 10) else 0)
                size = int.from_bytes(body[p:p + 2], "big"); p += 2
                attrs, p = body[p:p + size], p + size
                origin, q, seen_path = peers[pi], 0, False
                while q < len(attrs):
                    flags, code = attrs[q], attrs[q + 1]; q += 2
                    alen = int.from_bytes(attrs[q:q + (2 if flags & 0x10 else 1)], "big")
                    q += 2 if flags & 0x10 else 1
                    if code == 2:
                        seen_path, s = True, q
                        while s < q + alen:
                            stype, scount = attrs[s], attrs[s + 1]; s += 2
                            if scount:
                                origin = int.from_bytes(attrs[s + 4 * (scount - 1):s + 4 * scount], "big") if stype != 1 else None
                            s += 4 * scount
                    q += alen
                per_peer[pi].add((net, plen, origin))
    return peers, per_peer


def main(wt, out):
    sys.path.insert(0, str(Path(wt) / "bench/scale/rpki-cell"))
    import rpki_cell
    out = Path(out); out.mkdir(parents=True, exist_ok=True)
    nvrps, index = load_vrps()
    share = {"vrp_snapshot": {"source": "https://ftp.ripe.net/rpki/<ta>.tal/2026/08/08/roas.csv.xz",
                              "date": "2026-08-08", "sha256": VRP_SRC, "unique_vrps": nvrps}}
    for fam, (path, want, url) in RIBS.items():
        assert sha256(path) == want, f"{path} hash"
        peers, per_peer = rib_pairs(path, fam)
        union = set().union(*per_peer.values())
        states = Counter(validate(index, fam, *r) for r in union)
        pp = []
        for pi, routes in per_peer.items():
            c = Counter(validate(index, fam, *r) for r in routes)
            if len(routes) >= 100000:  # full-feed peers only
                pp.append(round(c["invalid"] / len(routes), 5))
        share[f"ipv{fam}"] = {"rib": url, "rib_sha256": want, "rib_peers": len(peers),
                              "distinct_prefix_origin": len(union), **states,
                              "invalid_share": states["invalid"] / len(union),
                              "notfound_share": states["notfound"] / len(union),
                              "full_feed_peer_invalid_shares": sorted(pp)}
        print(fam, share[f"ipv{fam}"]["invalid_share"], dict(states), file=sys.stderr)
    # Literal check: the synthetic scenario routes against the real snapshot.
    v6 = TOTAL - V4
    lit = Counter()
    for fam, total in ((4, V4), (6, v6)):
        for m in range(PEERS):
            start, n = rpki_cell.member_slice(total, PEERS, m)
            for idx in range(start, start + n):
                if fam == 4:
                    net, plen = int(ipaddress.IPv4Address(f"{20 + (idx >> 16)}.{(idx >> 8) & 0xFF}.{idx & 0xFF}.0")), 24
                else:
                    net, plen = int(ipaddress.IPv6Address(f"3001:{idx >> 16:x}:{idx & 0xffff:x}::")), 48
                lit[(fam, validate(index, fam, net, plen, 64512 + m))] += 1
    share["literal_scenario"] = {f"ipv{f}_{s}": c for (f, s), c in sorted(lit.items())}
    # Scenario assignment.
    canon = rpki_cell.fixture_doc(PEERS, TOTAL, VRPS, V4)["roas"]
    covering, rejected, assigned = [], [], {}
    pos = 0
    for fam, total in ((4, V4), (6, v6)):
        s = share[f"ipv{fam}"]
        n_inv, n_nf = round(s["invalid_share"] * total), round(s["notfound_share"] * total)
        order = sorted(range(total), key=lambda i: hashlib.sha256(f"{SEED}:{fam}:{i}".encode()).digest())
        inv, nf = set(order[:n_inv]), set(order[n_inv:n_inv + n_nf])
        assigned[f"ipv{fam}"] = {"routes": total, "invalid": n_inv, "notfound": n_nf, "valid": total - n_inv - n_nf}
        for idx in range(total):  # canonical entries are in global base-index order per family
            e = dict(canon[pos + idx])
            if idx in nf:
                continue
            if idx in inv:
                e["asn"] = f"AS{INVALID_ASN + idx % 1000}"
                rejected.append(f"{fam} {idx}")
            covering.append((fam, idx in inv, e))
        pos += total
    roas = [e for _, _, e in covering]
    for j in range(VRPS - len(roas)):
        roas.append({"asn": f"AS{rpki_cell.PAD_ASN + j % 500}",
                     "prefix": f"{100 + (j >> 16)}.{(j >> 8) & 0xFF}.{j & 0xFF}.0/24", "maxLength": 24, "ta": "bench"})
    assert len(roas) == VRPS and 100 + ((VRPS - len(covering) - 1) >> 16) <= 223
    doc = {"metadata": {"generated": 1710000000, "valid": 4102444800}, "roas": roas}
    (out / "base.json").write_text(json.dumps(doc, separators=(",", ":")))
    (out / "import-rejected.txt").write_text("\n".join(rejected) + "\n")
    c4 = sum(1 for f, _, _ in covering if f == 4)
    deltas = {}
    for n in DELTAS:
        d = json.loads(json.dumps(doc))
        sel = rpki_cell.replacement_indices(c4, len(covering) - c4, n)
        for i in sel:
            d["roas"][i]["maxLength"] += 1
        (out / f"delta-{n}.json").write_text(json.dumps(d, separators=(",", ":")))
        n4 = sum(i < c4 for i in sel)
        touched = sum(covering[i][1] for i in sel)
        (out / f"delta-{n}.counts").write_text(
            f"real-fixture: withdrawals={n} announcements={n} ipv4={n4} ipv6={n - n4} invalid_entries={touched}\n")
        deltas[n] = {"ipv4": n4, "ipv6": n - n4, "invalid_vrps_touched": touched}
    share["scenario"] = {"peers": PEERS, "prefixes": TOTAL, "ipv4": V4, "vrps": VRPS, "covering_vrps": len(covering),
                         "assigned": assigned, "rejected_total": len(rejected), "deltas": deltas,
                         "invalid_asn_base": INVALID_ASN}
    (out / "share.json").write_text(json.dumps(share, indent=1) + "\n")
    print(json.dumps({k: v for k, v in share.items() if k != "vrp_snapshot"}, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:3])

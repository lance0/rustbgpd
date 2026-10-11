#!/usr/bin/env python3
"""Compare captured actual normal AND build-script artifact units."""

import json
from pathlib import Path
import sys

FIELDS = (
    "rustc",
    "features",
    "declared_features",
    "target",
    "profile",
    "path",
    "rustflags",
    "config",
    "compile_kind",
)
SCOPES = ("normal_units", "including_build_units")


def unit_identity(path, data):
    # Cargo run-build-script units have zero target/profile/path fields. Their
    # package and unit filename distinguish them without comparing the varying
    # fingerprint directory suffix or dependency output signature.
    path = Path(path)
    package = path.parent.name.rsplit("-", 1)[0]
    # Two versions of a package can each have an all-zero run unit. Their
    # stable build-script package ID separates them; output signature dep[3]
    # is intentionally absent from identity.
    build_package = (
        tuple(tuple(dep[:3]) for dep in data["deps"]) if path.name.startswith("run-") else ()
    )
    return (
        package,
        path.name,
        data["target"],
        data["profile"],
        data["path"],
        data["compile_kind"],
        build_package,
    )


def index_units(units):
    indexed = {}
    for path, data in units.items():
        indexed.setdefault(unit_identity(path, data), []).append((path, data))
    # The same package can also have two build-script feature variants, and
    # two corresponding all-zero run units. Preserve their multiplicity;
    # compare every configuration and dependency record without using the
    # varying output signature to pair them.
    return {
        key: sorted(
            values,
            key=lambda pair: json.dumps(
                {
                    "configuration": {field: pair[1][field] for field in FIELDS},
                    "build_environment": build_environment(pair[1]),
                    "dependency_identities": sorted(dep[:3] for dep in pair[1]["deps"]),
                },
                sort_keys=True,
            ),
        )
        for key, values in indexed.items()
    }


def build_environment(data):
    # Output paths, source timestamps and dependency output signatures may
    # differ. Captured build-script environment inputs remain configuration.
    return sorted(
        (item["RerunIfEnvChanged"]["var"], item["RerunIfEnvChanged"]["val"])
        for item in data.get("local", [])
        if "RerunIfEnvChanged" in item
    )


def compare_scope(a, b, include_build):
    aa, bb = index_units(a), index_units(b)
    config, edges = [], []
    only_a = [path for key in aa.keys() - bb.keys() for path, _ in aa[key]]
    only_b = [path for key in bb.keys() - aa.keys() for path, _ in bb[key]]
    for key in aa.keys() & bb.keys():
        count = min(len(aa[key]), len(bb[key]))
        only_a.extend(path for path, _ in aa[key][count:])
        only_b.extend(path for path, _ in bb[key][count:])
        for (ap, ad), (bp, bd) in zip(aa[key], bb[key]):
            diff = {
                field: {"baseline": ad[field], "candidate": bd[field]}
                for field in FIELDS
                if ad[field] != bd[field]
            }
            if build_environment(ad) != build_environment(bd):
                diff["build_environment"] = {
                    "baseline": build_environment(ad),
                    "candidate": build_environment(bd),
                }
            if diff:
                config.append({"baseline": ap, "candidate": bp, "fields": diff})
            ae = sorted(
                dep[:3] for dep in ad["deps"] if include_build or dep[1] != "build_script_build"
            )
            be = sorted(
                dep[:3] for dep in bd["deps"] if include_build or dep[1] != "build_script_build"
            )
            if ae != be:
                edges.append(
                    {"baseline": ap, "candidate": bp, "baseline_edges": ae, "candidate_edges": be}
                )
    return {
        "baseline_artifact_units": len(a),
        "candidate_artifact_units": len(b),
        "only_baseline_units": sorted(only_a),
        "only_candidate_units": sorted(only_b),
        "configuration_differences": sorted(config, key=lambda d: d["baseline"]),
        "dependency_identity_differences": sorted(edges, key=lambda d: d["baseline"]),
    }


def validate_capture(data):
    normal, full = data["normal_units"], data["including_build_units"]
    assert data["entry"] in normal, "actual daemon entry absent from normal closure"
    assert all(full.get(path) == unit for path, unit in normal.items()), (
        "normal unit missing or inconsistent in including-build closure"
    )
    packages = {unit_identity(path, unit)[0] for path, unit in normal.items()}
    assert "rustbgpd" in packages and "rustbgpd-rib" in packages, "daemon/RIB normal units absent"
    forbidden = []
    for path, unit in normal.items():
        if unit_identity(path, unit)[0] in {"rustbgpd", "rustbgpd-rib"}:
            active = json.loads(unit["features"]) if unit["features"] else []
            if "bench-internals" in active:
                forbidden.append(path)
    return sorted(forbidden)


def main(root):
    captures = {
        arm: json.loads((root / f"binaries/{arm}/actual/closure.json").read_text())
        for arm in ("baseline", "candidate")
    }
    a, b = captures["baseline"], captures["candidate"]
    report = {
        "scopes": {
            scope: compare_scope(a[scope], b[scope], scope == "including_build_units")
            for scope in SCOPES
        },
        "missing": {
            arm: {kind: data[kind] for kind in ("normal_missing", "including_build_missing")}
            for arm, data in captures.items()
        },
        "forbidden_bench_internals": {
            arm: validate_capture(data) for arm, data in captures.items()
        },
    }
    graphs = {
        arm: (root / f"binaries/{arm}/normal-build-tree.normalized.txt").read_text()
        for arm in captures
    }
    report["normal_build_resolution_equal"] = graphs["baseline"] == graphs["candidate"]
    (root / "actual-feature-comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    assert all(
        not scope[field]
        for scope in report["scopes"].values()
        for field in (
            "only_baseline_units",
            "only_candidate_units",
            "configuration_differences",
            "dependency_identity_differences",
        )
    )
    assert all(not missing for data in report["missing"].values() for missing in data.values())
    assert all(not units for units in report["forbidden_bench_internals"].values()), (
        "bench-internals changes measured readiness behavior"
    )
    assert report["normal_build_resolution_equal"]
    print(
        "matching actual normal/build artifact configuration/features/dependency identities; "
        "daemon/RIB bench-internals absent; matching normal/build resolution"
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]))

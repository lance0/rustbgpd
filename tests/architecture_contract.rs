use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

type DependencyGraph = BTreeMap<String, BTreeSet<String>>;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_toml(path: &Path) -> toml::Value {
    let source = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    toml::from_str(&source)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn internal_name(package: &str) -> Option<String> {
    package
        .strip_prefix("rustbgpd-")
        .map(str::to_owned)
        .or_else(|| (package == "rustbgpctl").then(|| "cli".to_owned()))
}

fn dependency_package(name: &str, value: &toml::Value) -> String {
    value
        .as_table()
        .and_then(|table| table.get("package"))
        .and_then(toml::Value::as_str)
        .unwrap_or(name)
        .to_owned()
}

fn internal_dependencies(table: Option<&toml::value::Table>) -> BTreeSet<String> {
    table
        .into_iter()
        .flat_map(|dependencies| dependencies.iter())
        .filter_map(|(name, value)| internal_name(&dependency_package(name, value)))
        .collect()
}

fn regular_internal_dependencies(manifest: &toml::Value) -> BTreeSet<String> {
    let mut dependencies =
        internal_dependencies(manifest.get("dependencies").and_then(toml::Value::as_table));

    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            dependencies.extend(internal_dependencies(
                target.get("dependencies").and_then(toml::Value::as_table),
            ));
        }
    }

    dependencies
}

fn crate_manifests() -> BTreeMap<String, toml::Value> {
    let crates_dir = repository_root().join("crates");
    let mut manifests = BTreeMap::new();
    for entry in fs::read_dir(&crates_dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", crates_dir.display()))
    {
        let path = entry
            .expect("crate directory entry must be readable")
            .path();
        let manifest_path = path.join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let manifest = read_toml(&manifest_path);
        let package = manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("{} has no package.name", manifest_path.display()));
        let name = internal_name(package).unwrap_or_else(|| {
            panic!(
                "{} has unexpected internal package name {package}",
                manifest_path.display()
            )
        });
        assert!(
            manifests.insert(name.clone(), manifest).is_none(),
            "duplicate architecture crate name {name}"
        );
    }
    manifests
}

fn architecture_graph() -> (DependencyGraph, BTreeSet<String>) {
    let architecture =
        fs::read_to_string(repository_root().join("docs/explanation/architecture.md"))
            .expect("docs/explanation/architecture.md must be readable");
    let section = architecture
        .split_once("## Crate Dependency Graph\n")
        .expect("crate dependency graph heading must exist")
        .1;
    let graph = section
        .split_once("```\n")
        .expect("crate dependency graph fence must open")
        .1
        .split_once("\n```")
        .expect("crate dependency graph fence must close")
        .0;

    let mut rows = BTreeMap::new();
    let mut cli_dev_dependencies = None;
    for line in graph.lines().filter(|line| !line.trim().is_empty()) {
        let line = line.trim();
        let (name, dependencies) = if let Some((name, rest)) = line.split_once("──►") {
            let name = name.trim();
            let (regular, dev) = rest.trim().split_once("    (dev tests also use ").map_or(
                (rest.trim(), None),
                |(regular, dev)| {
                    (
                        regular,
                        Some(
                            dev.strip_suffix(')')
                                .expect("CLI dev-dependency annotation must close"),
                        ),
                    )
                },
            );
            if let Some(dev) = dev {
                assert_eq!(name, "cli", "only cli may annotate dev dependencies");
                cli_dev_dependencies = Some(
                    dev.split(',')
                        .map(|dependency| dependency.trim().to_owned())
                        .collect(),
                );
            }
            (
                name,
                regular
                    .split(',')
                    .map(|dependency| dependency.trim().to_owned())
                    .collect(),
            )
        } else {
            let name = line
                .strip_suffix("(no internal deps)")
                .unwrap_or_else(|| panic!("unrecognized dependency graph row: {line}"))
                .trim();
            (name, BTreeSet::new())
        };
        assert!(
            rows.insert(name.to_owned(), dependencies).is_none(),
            "duplicate dependency graph row for {name}"
        );
    }

    (
        rows,
        cli_dev_dependencies.expect("cli graph row must list its test-only dependencies"),
    )
}

#[test]
fn architecture_graph_matches_every_crate_manifest_exactly() {
    let (graph, documented_cli_dev_dependencies) = architecture_graph();
    let manifests = crate_manifests();

    assert_eq!(
        graph.keys().collect::<BTreeSet<_>>(),
        manifests.keys().collect::<BTreeSet<_>>(),
        "docs/explanation/architecture.md must have exactly one row for every crates/*/Cargo.toml"
    );
    for (name, manifest) in &manifests {
        assert_eq!(
            graph.get(name).expect("manifest row checked above"),
            &regular_internal_dependencies(manifest),
            "regular internal dependency edges drifted for {name}"
        );
    }

    let cli = manifests.get("cli").expect("CLI manifest must exist");
    assert_eq!(
        documented_cli_dev_dependencies,
        internal_dependencies(cli.get("dev-dependencies").and_then(toml::Value::as_table),),
        "CLI test-only internal dependencies drifted"
    );
}

#[test]
fn root_daemon_depends_on_every_graphed_library_crate() {
    let (graph, _) = architecture_graph();
    let root_manifest = read_toml(&repository_root().join("Cargo.toml"));
    let daemon_dependencies = regular_internal_dependencies(&root_manifest);
    let expected = graph
        .keys()
        .filter(|name| name.as_str() != "cli")
        .cloned()
        .collect::<BTreeSet<_>>();
    let graphed_crates = graph.keys().cloned().collect::<BTreeSet<_>>();
    let root_dev_dependencies = internal_dependencies(
        root_manifest
            .get("dev-dependencies")
            .and_then(toml::Value::as_table),
    );

    assert_eq!(daemon_dependencies, expected);
    assert_eq!(
        root_dev_dependencies
            .intersection(&graphed_crates)
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["cli".to_owned()]),
        "the client crate belongs only to the root integration-test surface"
    );
}

#[test]
fn documented_startup_phases_match_unique_main_anchors_in_order() {
    let source = fs::read_to_string(repository_root().join("src/main.rs"))
        .expect("src/main.rs must be readable");
    let production = source
        .split_once("\n#[cfg(test)]\nmod tests")
        .expect("main test module boundary must remain explicit")
        .0;
    let anchors = [
        "let listener_result = if let Some(endpoints)",
        "let metrics_listener = if let Some(prometheus_addr)",
        "EventHistoryManager::start(ehm_config).await",
        "// Spawn BMP subsystem (manager + per-collector clients).",
        "let mut rib_handle = tokio::spawn(rib_manager.run());",
        "// Spawn RPKI subsystem (VRP manager + per-cache RTR clients)",
        "// Spawn MRT manager (periodic TABLE_DUMP_V2 snapshots)",
        "let mut peer_mgr_handle = tokio::spawn(async move {",
        "let bfd_runtime_handle = bfd_runtime::spawn_prepared(",
        "let mut grpc_handle = tokio::spawn(async move {",
        "for neighbor in peer_configs {",
        "let mut bgp_listener_handle = tokio::spawn(async move {",
        "metrics_server::serve_metrics(metrics_listener, metrics_clone, readiness_probe).await;",
        "rustbgpd_api::gnmi_dialout::DialoutManager::new(",
        "Ok(targets) if !initial_peer_boot_failed => {",
        "gnmi_dialout_manager.lock().await.apply(&targets);",
    ];

    let positions = anchors.map(|anchor| {
        assert_eq!(
            production.matches(anchor).count(),
            1,
            "startup anchor must be unique: {anchor}"
        );
        production
            .find(anchor)
            .unwrap_or_else(|| panic!("startup anchor is missing: {anchor}"))
    });
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "documented startup phases drifted from src/main.rs"
    );

    let guarded_dialout_apply = production
        .split_once("Ok(targets) if !initial_peer_boot_failed => {")
        .expect("gNMI dial-out startup apply must retain the initial-peer guard")
        .1
        .split_once("Ok(_) => {}")
        .expect("gNMI dial-out startup match must retain its suppressed branch")
        .0;
    assert!(
        guarded_dialout_apply.contains("gnmi_dialout_manager.lock().await.apply(&targets);"),
        "configured gNMI dial-out must only activate after successful initial peer registration"
    );
}

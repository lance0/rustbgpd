//! Accepted-config ownership and same-read source identity (ADR-0121).

#![allow(
    dead_code,
    reason = "accepted ownership is active while digest and v2 exposure remain private"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustbgpd_policy::datasets::{DatasetFileFingerprint, DatasetKind};
use rustbgpd_policy::rpol::RpolFile;
use sha2::{Digest, Sha256};

use super::{Config, DatasetBindMode, persisted_config_document};

const SOURCE_DIGEST_DOMAIN: &[u8] = b"rustbgpd.config-source.v2\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceManifest {
    pub(crate) toml_sha256: [u8; 32],
    pub(crate) rpol_units: Vec<RpolUnitSource>,
    pub(crate) datasets: Vec<DatasetSource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RpolUnitSource {
    pub(crate) modules: Vec<RpolModuleSource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RpolModuleSource {
    pub(crate) path: PathBuf,
    pub(crate) length: u64,
    pub(crate) sha256: [u8; 32],
    pub(crate) imports: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DatasetSource {
    pub(crate) name: String,
    pub(crate) kind: DatasetKind,
    pub(crate) path: PathBuf,
    pub(crate) length: u64,
    pub(crate) sha256: [u8; 32],
}

#[derive(Default)]
pub(super) struct SourceCapture {
    rpol_units: Vec<RpolUnitSource>,
    datasets: Vec<DatasetSource>,
}

impl SourceCapture {
    pub(super) fn push_rpol_unit(&mut self, file: &RpolFile) {
        let fingerprints = file.source_fingerprints();
        assert_eq!(file.modules().len(), fingerprints.len());
        let modules = file
            .modules()
            .iter()
            .zip(fingerprints)
            .map(|(module, (path, length, sha256))| RpolModuleSource {
                path: path.to_path_buf(),
                length,
                sha256,
                imports: module.imports.clone(),
            })
            .collect();
        self.rpol_units.push(RpolUnitSource { modules });
    }

    pub(super) fn push_dataset(
        &mut self,
        name: &str,
        kind: DatasetKind,
        source: &DatasetFileFingerprint,
    ) {
        self.datasets.push(DatasetSource {
            name: name.to_string(),
            kind,
            path: source.canonical_path.clone(),
            length: source.raw_len,
            sha256: source.raw_sha256,
        });
    }

    pub(super) fn retain_dataset(
        &mut self,
        name: &str,
        prior: Option<&SourceManifest>,
    ) -> Result<(), &'static str> {
        let source = prior
            .and_then(|manifest| manifest.datasets.iter().find(|source| source.name == name))
            .ok_or("failed staged dataset refresh has no prior accepted provenance")?;
        self.datasets.push(source.clone());
        Ok(())
    }

    fn finish(mut self, toml_sha256: [u8; 32]) -> SourceManifest {
        self.datasets
            .sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
        SourceManifest {
            toml_sha256,
            rpol_units: self.rpol_units,
            datasets: self.datasets,
        }
    }
}

impl SourceManifest {
    fn source_sha256(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(SOURCE_DIGEST_DOMAIN);
        frame(&mut digest, &self.toml_sha256);
        frame_u64(&mut digest, self.rpol_units.len());
        for unit in &self.rpol_units {
            frame_u64(&mut digest, unit.modules.len());
            for module in &unit.modules {
                frame_path(&mut digest, &module.path);
                frame_u64_value(&mut digest, module.length);
                frame(&mut digest, &module.sha256);
                frame_u64(&mut digest, module.imports.len());
                for &import in &module.imports {
                    frame(&mut digest, &import.to_be_bytes());
                }
            }
        }
        frame_u64(&mut digest, self.datasets.len());
        for dataset in &self.datasets {
            frame(&mut digest, dataset.name.as_bytes());
            frame(&mut digest, dataset.kind.as_str().as_bytes());
            frame_path(&mut digest, &dataset.path);
            frame_u64_value(&mut digest, dataset.length);
            frame(&mut digest, &dataset.sha256);
        }
        digest.finalize().into()
    }
}

fn frame(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(
        u64::try_from(bytes.len())
            .expect("field length fits u64")
            .to_be_bytes(),
    );
    digest.update(bytes);
}

fn frame_u64(digest: &mut Sha256, value: usize) {
    frame_u64_value(digest, u64::try_from(value).expect("roster count fits u64"));
}

fn frame_u64_value(digest: &mut Sha256, value: u64) {
    frame(digest, &value.to_be_bytes());
}

fn frame_path(digest: &mut Sha256, path: &Path) {
    let (encoding, bytes) = lossless_path_bytes(path);
    frame(digest, encoding);
    frame(digest, &bytes);
}

#[cfg(unix)]
pub(crate) fn lossless_path_bytes(path: &Path) -> (&'static [u8], Vec<u8>) {
    use std::os::unix::ffi::OsStrExt;
    (b"unix-os-bytes", path.as_os_str().as_bytes().to_vec())
}

#[cfg(windows)]
pub(crate) fn lossless_path_bytes(path: &Path) -> (&'static [u8], Vec<u8>) {
    use std::os::windows::ffi::OsStrExt;
    let bytes = path
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_be_bytes)
        .collect();
    (b"windows-wide-be", bytes)
}

pub(crate) struct AcceptedConfigSnapshot {
    config: Arc<Config>,
    normalized_toml: Arc<str>,
    manifest: SourceManifest,
    sha256: [u8; 32],
    source_sha256: [u8; 32],
}

impl AcceptedConfigSnapshot {
    pub(crate) fn load(path: &Path, prior: Option<&Self>) -> Result<Self, String> {
        Self::load_with_hook(path, prior, || {})
    }

    /// Load a retained normalized document while resolving its declared
    /// external inputs relative to the daemon's real config path. The retained
    /// TOML bytes are already pinned by the history reader; this performs the
    /// one detached external-source capture used by provenance-aware restore.
    pub(crate) fn load_retained(content: &str, config_path: &Path) -> Result<Arc<Self>, String> {
        Self::load_retained_with_hook(content, config_path, || {})
    }

    fn load_retained_with_hook(
        content: &str,
        config_path: &Path,
        after_capture: impl FnOnce(),
    ) -> Result<Arc<Self>, String> {
        let base_dir = config_path.parent().map(PathBuf::from);
        let mut capture = SourceCapture::default();
        let mut config = Config::load_from_toml_source_with_capture(
            content,
            "retained config history snapshot",
            base_dir.as_deref(),
            None,
            DatasetBindMode::Stage,
            Some(&mut capture),
            None,
        )?;
        config.file_path = Some(config_path.to_path_buf());
        after_capture();
        config.policy.dataset_bindings = config.policy.dataset_bindings.detached_clone();
        let normalized_toml: Arc<str> = persisted_config_document(&config)
            .map_err(|error| format!("failed to normalize retained config: {error}"))?
            .into();
        let sha256 = Sha256::digest(normalized_toml.as_bytes()).into();
        let manifest = capture.finish(sha256);
        let source_sha256 = manifest.source_sha256();
        Ok(Arc::new(Self {
            config: Arc::new(config),
            normalized_toml,
            manifest,
            sha256,
            source_sha256,
        }))
    }

    pub(crate) fn declares_external_sources(&self) -> bool {
        Self::config_declares_external_sources(&self.config)
    }

    pub(crate) fn toml_declares_external_sources(content: &str) -> Result<bool, String> {
        let config: Config = toml::from_str(content)
            .map_err(|error| format!("invalid config transaction document: {error}"))?;
        Ok(Self::config_declares_external_sources(&config))
    }

    fn config_declares_external_sources(config: &Config) -> bool {
        !config.policy.rpol_files.is_empty() || !config.policy.datasets.is_empty()
    }

    pub(crate) fn load_for_reload(
        path: &Path,
        prior: &Self,
        live_bindings: &rustbgpd_policy::datasets::DatasetBindings,
    ) -> Result<Self, String> {
        Self::load_captured(path, Some(prior), Some(live_bindings), || {})
    }

    fn load_with_hook(
        path: &Path,
        prior: Option<&Self>,
        after_capture: impl FnOnce(),
    ) -> Result<Self, String> {
        Self::load_captured(
            path,
            prior,
            prior.map(|snapshot| &snapshot.config.policy.dataset_bindings),
            after_capture,
        )
    }

    fn load_captured(
        path: &Path,
        prior: Option<&Self>,
        live_bindings: Option<&rustbgpd_policy::datasets::DatasetBindings>,
        after_capture: impl FnOnce(),
    ) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|error| format!("error: failed to read {}: {error}", path.display()))?;
        let content = String::from_utf8(bytes)
            .map_err(|error| format!("error: failed to read {}: {error}", path.display()))?;
        let base_dir = path.parent().map(PathBuf::from);
        let mut capture = SourceCapture::default();
        let mut config = Config::load_from_toml_source_with_capture(
            &content,
            &path.display().to_string(),
            base_dir.as_deref(),
            live_bindings,
            DatasetBindMode::Stage,
            Some(&mut capture),
            prior.map(|snapshot| &snapshot.manifest),
        )?;
        config.file_path = Some(path.to_path_buf());
        after_capture();
        config.policy.dataset_bindings = config.policy.dataset_bindings.detached_clone();

        let normalized_toml: Arc<str> = persisted_config_document(&config)
            .map_err(|error| format!("failed to normalize accepted config: {error}"))?
            .into();
        let sha256 = Sha256::digest(normalized_toml.as_bytes()).into();
        let manifest = capture.finish(sha256);
        let source_sha256 = manifest.source_sha256();
        Ok(Self {
            config: Arc::new(config),
            normalized_toml,
            manifest,
            sha256,
            source_sha256,
        })
    }

    pub(crate) fn derive_config(&self, mut config: Config) -> Result<Arc<Self>, String> {
        self.require_same_external_roster(&config)?;
        config.policy.dataset_bindings = config.policy.dataset_bindings.detached_clone();
        let normalized_toml: Arc<str> = persisted_config_document(&config)
            .map_err(|error| format!("failed to normalize accepted config: {error}"))?
            .into();
        let sha256 = Sha256::digest(normalized_toml.as_bytes()).into();
        let mut manifest = self.manifest.clone();
        manifest.toml_sha256 = sha256;
        let source_sha256 = manifest.source_sha256();
        Ok(Arc::new(Self {
            config: Arc::new(config),
            normalized_toml,
            manifest,
            sha256,
            source_sha256,
        }))
    }

    pub(crate) fn derive_toml_without_sources(
        &self,
        content: &str,
        source_name: &str,
    ) -> Result<Arc<Self>, String> {
        let mut config: Config =
            toml::from_str(content).map_err(|error| format!("invalid {source_name}: {error}"))?;
        self.require_same_external_roster(&config)?;
        config.file_path.clone_from(&self.config.file_path);
        config.policy.rpol.clone_from(&self.config.policy.rpol);
        config.policy.dataset_bindings = self.config.policy.dataset_bindings.detached_clone();
        config.policy.dataset_events = self.config.policy.dataset_events.clone();
        config
            .validate()
            .map_err(|error| format!("invalid {source_name}: {error}"))?;
        self.derive_config(config)
    }

    pub(crate) fn runtime_config_without_sources(
        &self,
        content: &str,
        rpol_files: &[String],
        rpol: rustbgpd_policy::rpol::RpolPolicySet,
        live_bindings: &rustbgpd_policy::datasets::DatasetBindings,
    ) -> Result<Config, String> {
        let mut config: Config = toml::from_str(content)
            .map_err(|error| format!("invalid runtime config snapshot: {error}"))?;
        if config.policy.rpol_files != rpol_files {
            return Err(
                "runtime config snapshot rpol roster disagrees with live registry".to_string(),
            );
        }
        config.file_path.clone_from(&self.config.file_path);
        config.policy.rpol = rpol;
        config.policy.dataset_bindings = live_bindings.clone();
        config
            .validate()
            .map_err(|error| format!("invalid runtime config snapshot: {error}"))?;
        Ok(config)
    }

    /// Reconstruct a config document for transaction editing or rollback
    /// serialization without attaching any accepted or live external data.
    ///
    /// A partial SIGHUP may leave runtime generation A beside accepted desired
    /// generation B. Transaction construction needs A's document shape, but
    /// must not validate it against B's detached datasets or expose those
    /// bindings to policy planning. The eventual transaction executor reloads
    /// and validates the candidate at its existing accepted-input boundary.
    pub(crate) fn transaction_config_without_sources(
        &self,
        content: &str,
        rpol_files: &[String],
    ) -> Result<Config, String> {
        let mut config: Config = toml::from_str(content)
            .map_err(|error| format!("invalid runtime config document: {error}"))?;
        if config.policy.rpol_files != rpol_files {
            return Err(
                "runtime config document rpol roster disagrees with live registry".to_string(),
            );
        }
        config.file_path.clone_from(&self.config.file_path);
        Ok(config)
    }

    fn require_same_external_roster(&self, config: &Config) -> Result<(), String> {
        if config.policy.rpol_files != self.config.policy.rpol_files
            || config.policy.rpol_roots != self.config.policy.rpol_roots
            || config.policy.rpol_max_graph_bytes != self.config.policy.rpol_max_graph_bytes
            || config.policy.datasets != self.config.policy.datasets
        {
            return Err(
                "runtime config mutation cannot change external policy-source inventory; edit the config file and use SIGHUP"
                    .to_string(),
            );
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn from_config_for_test(config: Config) -> Arc<Self> {
        let normalized_toml: Arc<str> = persisted_config_document(&config).unwrap().into();
        let sha256 = Sha256::digest(normalized_toml.as_bytes()).into();
        let manifest = SourceCapture::default().finish(sha256);
        Arc::new(Self {
            config: Arc::new(config),
            normalized_toml,
            source_sha256: manifest.source_sha256(),
            manifest,
            sha256,
        })
    }

    pub(crate) fn config(&self) -> Config {
        let mut config = (*self.config).clone();
        config.policy.dataset_bindings = config.policy.dataset_bindings.detached_clone();
        config
    }

    pub(crate) fn config_ref(&self) -> &Config {
        &self.config
    }

    pub(crate) fn normalized_toml(&self) -> &str {
        &self.normalized_toml
    }

    pub(crate) fn source_manifest(&self) -> &SourceManifest {
        &self.manifest
    }

    pub(crate) fn source_sha256(&self) -> [u8; 32] {
        self.source_sha256
    }
}

impl std::ops::Deref for AcceptedConfigSnapshot {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        self.config_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use rustbgpd_policy::datasets::DatasetData;
    use rustbgpd_policy::sets::AsnSet;

    use super::*;
    use crate::test_support::tier_authorized_uds_test_config;

    const MAIN_RPOL: &str =
        "import \"lib.rpol\"\nimport \"a-child.rpol\"\npolicy outbound { term rest { accept } }\n";
    const LIB_RPOL: &str = "dataset asn-set customers\npolicy inbound {\n  term customer { if route.origin-as in customers { accept } }\n  term rest { reject }\n}\n";

    fn fixture(dir: &Path) -> PathBuf {
        fs::write(dir.join("policy.rpol"), MAIN_RPOL).expect("main rpol");
        fs::write(dir.join("lib.rpol"), LIB_RPOL).expect("import rpol");
        fs::write(
            dir.join("a-child.rpol"),
            "policy child { term rest { accept } }\n",
        )
        .expect("second import");
        fs::write(
            dir.join("a-unit.rpol"),
            "policy second-unit { term rest { accept } }\n",
        )
        .expect("second unit");
        fs::write(dir.join("customers.txt"), "64500\n").expect("dataset");
        let config = tier_authorized_uds_test_config(
            r#"
[global]
asn = 65000
router_id = "192.0.2.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[policy]
rpol_files = ["policy.rpol", "a-unit.rpol"]
[policy.datasets.customers]
path = "customers.txt"
"#,
        );
        let path = dir.join("config.toml");
        fs::write(&path, config).expect("config");
        path
    }

    fn fingerprint(path: &Path, bytes: &[u8]) -> DatasetFileFingerprint {
        DatasetFileFingerprint {
            canonical_path: path.to_path_buf(),
            raw_len: u64::try_from(bytes.len()).unwrap(),
            raw_sha256: Sha256::digest(bytes).into(),
        }
    }

    fn dataset(snapshot: &AcceptedConfigSnapshot) -> Arc<rustbgpd_policy::datasets::DatasetHandle> {
        Arc::clone(
            snapshot
                .config
                .policy
                .dataset_bindings
                .get("customers")
                .unwrap(),
        )
    }

    fn module_names(unit: &RpolUnitSource) -> Vec<&str> {
        unit.modules
            .iter()
            .map(|module| module.path.file_name().unwrap().to_str().unwrap())
            .collect()
    }

    #[test]
    fn source_free_derivation_retains_roster_and_rejects_inventory_change() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = AcceptedConfigSnapshot::load(&fixture(dir.path()), None).unwrap();
        fs::remove_file(dir.path().join("policy.rpol")).unwrap();
        fs::remove_file(dir.path().join("lib.rpol")).unwrap();
        fs::remove_file(dir.path().join("a-child.rpol")).unwrap();
        fs::remove_file(dir.path().join("a-unit.rpol")).unwrap();
        fs::remove_file(dir.path().join("customers.txt")).unwrap();

        let mut fib_only = snapshot.config();
        fib_only.fib_tables.push(super::super::FibTableConfig {
            name: "edge".to_string(),
            table_id: 100,
            metric: 100,
            families: super::super::default_fib_families(),
            allowed_peer_groups: Vec::new(),
            allowed_neighbors: Vec::new(),
            max_routes: None,
            maximum_paths: None,
            maximum_paths_ebgp: None,
            maximum_paths_ibgp: None,
        });
        let derived = snapshot
            .derive_config(fib_only)
            .expect("post-capture derivation must not reread deleted sources");
        assert_eq!(derived.manifest.rpol_units, snapshot.manifest.rpol_units);
        assert_eq!(derived.manifest.datasets, snapshot.manifest.datasets);

        let live_bindings = snapshot.policy.dataset_bindings.detached_clone();
        let live_dataset = Arc::clone(live_bindings.get("customers").unwrap());
        let supplied_rpol = snapshot.policy.rpol.clone();
        let supplied_file = Arc::clone(&supplied_rpol.policies["outbound"].file);
        let runtime = snapshot
            .runtime_config_without_sources(
                snapshot.normalized_toml(),
                &snapshot.policy.rpol_files,
                supplied_rpol,
                &live_bindings,
            )
            .expect("runtime reconstruction must not reread deleted external sources");
        assert!(Arc::ptr_eq(
            runtime.policy.dataset_bindings.get("customers").unwrap(),
            &live_dataset
        ));
        assert!(Arc::ptr_eq(
            &runtime.policy.rpol.policies["outbound"].file,
            &supplied_file
        ));

        let mut changed_roster = snapshot.config();
        changed_roster
            .policy
            .rpol_files
            .push("/new/source.rpol".to_string());
        assert!(
            snapshot.derive_config(changed_roster).is_err(),
            "a source-free mutation must not relabel changed external inventory"
        );
    }

    #[test]
    fn partial_reload_runtime_roster_stays_distinct_from_accepted_desired() {
        let dir = tempfile::tempdir().unwrap();
        let desired = AcceptedConfigSnapshot::load(&fixture(dir.path()), None).unwrap();
        fs::remove_file(dir.path().join("policy.rpol")).unwrap();
        fs::remove_file(dir.path().join("lib.rpol")).unwrap();
        fs::remove_file(dir.path().join("a-child.rpol")).unwrap();
        fs::remove_file(dir.path().join("a-unit.rpol")).unwrap();
        fs::remove_file(dir.path().join("customers.txt")).unwrap();

        let runtime_toml = tier_authorized_uds_test_config(
            r#"
[global]
asn = 65000
router_id = "192.0.2.1"
listen_port = 179
[global.telemetry]
log_format = "json"
"#,
        );
        let runtime = desired
            .runtime_config_without_sources(
                &runtime_toml,
                &[],
                rustbgpd_policy::rpol::RpolPolicySet::default(),
                &rustbgpd_policy::datasets::DatasetBindings::default(),
            )
            .expect("runtime A must reconstruct independently of desired roster B");

        assert!(runtime.policy.rpol_files.is_empty());
        assert!(runtime.policy.datasets.is_empty());
        assert_eq!(desired.policy.rpol_files.len(), 2);
        assert_eq!(desired.policy.datasets.len(), 1);
    }

    #[test]
    fn digest_canonical_framing_is_stable() {
        let manifest = SourceManifest {
            toml_sha256: [0x11; 32],
            rpol_units: vec![RpolUnitSource {
                modules: vec![RpolModuleSource {
                    path: PathBuf::from("/policy"),
                    length: 3,
                    sha256: [0x22; 32],
                    imports: vec![0, 1],
                }],
            }],
            datasets: vec![DatasetSource {
                name: "customers".to_string(),
                kind: DatasetKind::Asn,
                path: PathBuf::from("/dataset"),
                length: 4,
                sha256: [0x33; 32],
            }],
        };
        // Golden over the ADR-0121 domain, every roster count, and every
        // field length. Removing any one of those production frames changes
        // this digest and makes the test red.
        assert_eq!(
            manifest.source_sha256(),
            [
                0xea, 0x0d, 0x43, 0x50, 0x1b, 0x20, 0x1f, 0xce, 0xc9, 0x72, 0x4d, 0x17, 0xad, 0xa9,
                0x60, 0x3e, 0x72, 0xa6, 0x35, 0xcc, 0x9c, 0x04, 0x85, 0x23, 0xb6, 0x44, 0x9f, 0x0e,
                0x4c, 0x7e, 0x60, 0x09,
            ]
        );
    }

    #[test]
    fn datasets_finish_in_name_byte_order_not_insertion_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut left = SourceCapture::default();
        left.push_dataset(
            "zeta",
            DatasetKind::Asn,
            &fingerprint(&dir.path().join("z"), b"1"),
        );
        left.push_dataset(
            "alpha",
            DatasetKind::Prefix,
            &fingerprint(&dir.path().join("a"), b"2"),
        );
        let mut right = SourceCapture::default();
        right.push_dataset(
            "alpha",
            DatasetKind::Prefix,
            &fingerprint(&dir.path().join("a"), b"2"),
        );
        right.push_dataset(
            "zeta",
            DatasetKind::Asn,
            &fingerprint(&dir.path().join("z"), b"1"),
        );
        let left = left.finish([7; 32]);
        let right = right.finish([7; 32]);
        assert_eq!(left.datasets[0].name, "alpha");
        assert_eq!(left, right);
        assert_eq!(left.source_sha256(), right.source_sha256());
    }

    #[test]
    fn capture_keeps_configured_rpol_unit_order() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = AcceptedConfigSnapshot::load(&fixture(dir.path()), None).unwrap();
        let units = &snapshot.manifest.rpol_units;
        assert_eq!(module_names(&units[0])[0], "policy.rpol");
        assert_eq!(module_names(&units[1])[0], "a-unit.rpol");
    }

    #[test]
    fn capture_keeps_resolver_file_index_order() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = AcceptedConfigSnapshot::load(&fixture(dir.path()), None).unwrap();
        assert_eq!(
            module_names(&snapshot.manifest.rpol_units[0]),
            ["policy.rpol", "lib.rpol", "a-child.rpol"]
        );
    }

    #[test]
    fn capture_keeps_import_edge_declaration_order() {
        let dir = tempfile::tempdir().unwrap();
        let snapshot = AcceptedConfigSnapshot::load(&fixture(dir.path()), None).unwrap();
        let unit = &snapshot.manifest.rpol_units[0];
        let names = module_names(unit);
        let targets: Vec<_> = unit.modules[0]
            .imports
            .iter()
            .map(|&index| names[index as usize])
            .collect();
        assert_eq!(targets, ["lib.rpol", "a-child.rpol"]);
    }

    #[test]
    fn semantically_equal_dataset_rewrite_changes_source_identity() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = fixture(dir.path());
        let before = AcceptedConfigSnapshot::load(&config_path, None).unwrap();
        fs::write(dir.path().join("customers.txt"), "# same set\n64500\n").unwrap();
        let after = AcceptedConfigSnapshot::load(&config_path, Some(&before)).unwrap();

        assert_eq!(dataset(&before).pin().data, dataset(&after).pin().data);
        assert_ne!(
            before.manifest.datasets[0].sha256,
            after.manifest.datasets[0].sha256
        );
        assert_ne!(before.source_sha256, after.source_sha256);
    }

    #[test]
    fn capture_never_rereads_external_sources() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = fixture(dir.path());
        let snapshot = AcceptedConfigSnapshot::load_with_hook(&config_path, None, || {
            fs::remove_file(dir.path().join("policy.rpol")).unwrap();
            fs::remove_file(dir.path().join("lib.rpol")).unwrap();
            fs::remove_file(dir.path().join("a-child.rpol")).unwrap();
            fs::remove_file(dir.path().join("a-unit.rpol")).unwrap();
            fs::remove_file(dir.path().join("customers.txt")).unwrap();
        })
        .unwrap();

        assert_eq!(snapshot.manifest.rpol_units[0].modules.len(), 3);
        assert_eq!(snapshot.manifest.datasets[0].length, 6);
        assert_eq!(
            snapshot.manifest.datasets[0].sha256,
            <[u8; 32]>::from(Sha256::digest(b"64500\n"))
        );
    }

    /// Red proof: moving the hook before external capture, omitting detached
    /// bindings, or rereading a source after the hook changes the captured
    /// digest and makes the first/second generation assertions collapse.
    #[test]
    fn retained_load_captures_one_detached_external_generation() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = fixture(dir.path());
        let retained = fs::read_to_string(&config_path).unwrap();
        let first =
            AcceptedConfigSnapshot::load_retained_with_hook(&retained, &config_path, || {
                fs::write(dir.path().join("customers.txt"), "64501\n").unwrap();
            })
            .unwrap();
        let second = AcceptedConfigSnapshot::load_retained(&retained, &config_path).unwrap();
        assert_ne!(first.source_sha256(), second.source_sha256());
        let first_handle = first
            .config_ref()
            .policy
            .dataset_bindings
            .handles()
            .next()
            .unwrap();
        let second_handle = second
            .config_ref()
            .policy
            .dataset_bindings
            .handles()
            .next()
            .unwrap();
        assert!(!Arc::ptr_eq(first_handle, second_handle));
        let DatasetData::Asn(first_data) = &first_handle.pin().data else {
            panic!("fixture dataset must be an ASN set");
        };
        assert!(first_data.contains(64500));
        assert!(!first_data.contains(64501));
        let DatasetData::Asn(second_data) = &second_handle.pin().data else {
            panic!("fixture dataset must be an ASN set");
        };
        assert!(!second_data.contains(64500));
        assert!(second_data.contains(64501));
    }

    #[test]
    fn failed_staged_refresh_retains_prior_accepted_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = fixture(dir.path());
        let before = AcceptedConfigSnapshot::load(&config_path, None).unwrap();
        fs::write(dir.path().join("customers.txt"), "not-an-asn\n").unwrap();
        let after = AcceptedConfigSnapshot::load(&config_path, Some(&before)).unwrap();

        assert_eq!(after.config.policy.dataset_events.failed.len(), 1);
        assert_eq!(after.manifest.datasets, before.manifest.datasets);
        assert_eq!(after.source_sha256, before.source_sha256);
        let after_handle = dataset(&after);
        let generation = after_handle.pin().generation;
        dataset(&before).refresh(DatasetData::Asn(AsnSet::new([64501])));
        assert_eq!(after_handle.pin().generation, generation);
        assert_eq!(
            after_handle.pin().data,
            DatasetData::Asn(AsnSet::new([64500]))
        );

        after
            .config()
            .policy
            .dataset_bindings
            .get("customers")
            .unwrap()
            .refresh(DatasetData::Asn(AsnSet::new([64502])));
        assert_eq!(after_handle.pin().generation, generation);
        assert_eq!(
            after_handle.pin().data,
            DatasetData::Asn(AsnSet::new([64500]))
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonical_rpol_path_preserves_invalid_utf8_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let config_path = fixture(dir.path());
        fs::remove_file(dir.path().join("policy.rpol")).unwrap();
        let first_target = dir
            .path()
            .join(OsString::from_vec(b"policy-\xff.rpol".to_vec()));
        let second_target = dir
            .path()
            .join(OsString::from_vec(b"policy-\xfe.rpol".to_vec()));
        fs::write(&first_target, MAIN_RPOL).unwrap();
        fs::write(&second_target, MAIN_RPOL).unwrap();
        let entry = dir.path().join("policy.rpol");
        symlink(&first_target, &entry).unwrap();

        let first = AcceptedConfigSnapshot::load(&config_path, None).unwrap();
        fs::remove_file(&entry).unwrap();
        symlink(&second_target, &entry).unwrap();
        let second = AcceptedConfigSnapshot::load(&config_path, None).unwrap();
        let first_raw_path = first.manifest.rpol_units[0].modules[0]
            .path
            .as_os_str()
            .as_bytes();
        assert!(first_raw_path.contains(&0xff));
        assert!(
            second.manifest.rpol_units[0].modules[0]
                .path
                .as_os_str()
                .as_bytes()
                .contains(&0xfe)
        );
        // Lossy display renders both bytes as U+FFFD; if digest identity uses it,
        // snapshots collapse and this assertion goes red.
        assert_ne!(first.source_sha256, second.source_sha256);
    }
}

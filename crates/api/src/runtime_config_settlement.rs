//! Process-independent settlement watchdog for owned runtime-config mutations.
//!
//! This module supplies the fail-stop ownership kernel. Call sites arm it only
//! after acquiring [`RuntimeConfigCoordinatorPermit`].

use arc_swap::ArcSwapOption;
use prometheus::core::{Collector, Desc};
use prometheus::proto::MetricFamily;
use prometheus::{CounterVec, GaugeVec, Opts};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::health_probe::DaemonGate;
use crate::server::{RuntimeConfigCoordinator, RuntimeConfigCoordinatorPermit};

/// Debug-only, filesystem-mediated control for deterministic settlement tests.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub mod settlement_test_control {
    use nix::unistd::Uid;
    use std::collections::BTreeMap;
    use std::fs::{self, OpenOptions};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    const CONTROL_ENV: &str = "RUSTBGPD_TEST_SETTLEMENT_CONTROL_DIR";
    const CONTROL_VERSION: &str = "settlement-control-v1";
    const SETTINGS: &str = "settings.v1";
    const ARM: &str = "arm.v1";
    const CLAIMED: &str = "claimed.v1";
    const RECEIPT: &str = "receipt.v1";
    const RELEASE: &str = "release.v1";
    const MIN_BUDGET_MS: u64 = 250;
    const MAX_BUDGET_MS: u64 = 10_000;
    const MIN_GRACE_MS: u64 = 100;
    const MAX_GRACE_MS: u64 = 5_000;
    const MAX_CONTROL_FILE_BYTES: usize = 1_024;
    const MAX_CONTROL_FILE_BYTES_U64: u64 = 1_024;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Checkpoint {
        TransactionAfterBeginMutation,
        CatalogActorCommandAccepted,
        ReplaceBeforePublish,
        StagedCommitBeforePublish,
    }

    impl Checkpoint {
        const fn as_str(self) -> &'static str {
            match self {
                Self::TransactionAfterBeginMutation => "transaction_after_begin_mutation",
                Self::CatalogActorCommandAccepted => "catalog_actor_command_accepted",
                Self::ReplaceBeforePublish => "replace_before_publish",
                Self::StagedCommitBeforePublish => "staged_commit_before_publish",
            }
        }

        fn parse(value: &str) -> Result<Self, String> {
            match value {
                "transaction_after_begin_mutation" => Ok(Self::TransactionAfterBeginMutation),
                "catalog_actor_command_accepted" => Ok(Self::CatalogActorCommandAccepted),
                "replace_before_publish" => Ok(Self::ReplaceBeforePublish),
                "staged_commit_before_publish" => Ok(Self::StagedCommitBeforePublish),
                _ => Err(format!("unknown checkpoint {value:?}")),
            }
        }

        const fn allows_drop_ack(self) -> bool {
            matches!(
                self,
                Self::ReplaceBeforePublish | Self::StagedCommitBeforePublish
            )
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Action {
        Hold,
        DropAck,
    }

    impl Action {
        const fn as_str(self) -> &'static str {
            match self {
                Self::Hold => "hold",
                Self::DropAck => "drop_ack",
            }
        }

        fn parse(value: &str) -> Result<Self, String> {
            match value {
                "hold" => Ok(Self::Hold),
                "drop_ack" => Ok(Self::DropAck),
                _ => Err(format!("unknown action {value:?}")),
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Settings {
        budget: Duration,
        grace: Duration,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Command {
        nonce: String,
        checkpoint: Checkpoint,
        action: Action,
    }

    struct ControlDirectory {
        path: PathBuf,
        settings: Settings,
    }

    impl ControlDirectory {
        fn from_environment(setup: bool) -> Result<Option<Self>, String> {
            let Some(value) = std::env::var_os(CONTROL_ENV) else {
                return Ok(None);
            };
            let path = PathBuf::from(value);
            let control = Self::open(path)?;
            if setup {
                for name in [ARM, CLAIMED, RECEIPT, RELEASE] {
                    if read_optional(&control.path, name)?.is_some() {
                        return Err(format!(
                            "settlement control {name} must be absent during setup"
                        ));
                    }
                }
            }
            Ok(Some(control))
        }

        fn open(path: PathBuf) -> Result<Self, String> {
            if !path.is_absolute() {
                return Err("settlement control directory must be absolute".to_string());
            }
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect settlement control directory: {error}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("settlement control directory must be a non-symlink directory".into());
            }
            let canonical = fs::canonicalize(&path).map_err(|error| {
                format!("cannot canonicalize settlement control directory: {error}")
            })?;
            if canonical != path {
                return Err("settlement control directory must be canonical".into());
            }
            if metadata.permissions().mode() & 0o777 != 0o700 {
                return Err("settlement control directory mode must be 0700".into());
            }
            if metadata.uid() != Uid::effective().as_raw() {
                return Err("settlement control directory must belong to the current uid".into());
            }
            let settings = parse_settings(&read_required(&path, SETTINGS)?)?;
            Ok(Self { path, settings })
        }

        fn read_arm(&self) -> Result<Option<Command>, String> {
            read_optional(&self.path, ARM)?
                .map(|contents| parse_command(&contents))
                .transpose()
        }

        fn claim(&self, expected: Checkpoint) -> Result<Option<Command>, String> {
            let Some(command) = self.read_arm()? else {
                return Ok(None);
            };
            if read_optional(&self.path, CLAIMED)?.is_some()
                || read_optional(&self.path, RECEIPT)?.is_some()
            {
                return Err("duplicate settlement control claim".into());
            }
            if command.checkpoint != expected {
                return Ok(None);
            }
            if command.action == Action::DropAck && !expected.allows_drop_ack() {
                return Err(format!(
                    "drop_ack is not valid at checkpoint {}",
                    expected.as_str()
                ));
            }
            match fs::rename(self.path.join(ARM), self.path.join(CLAIMED)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(format!("cannot claim settlement control arm: {error}")),
            }
            let receipt = format!(
                "version={CONTROL_VERSION}\nnonce={}\ncheckpoint={}\naction={}\npid={}\n",
                command.nonce,
                command.checkpoint.as_str(),
                command.action.as_str(),
                std::process::id()
            );
            atomic_write(&self.path, RECEIPT, receipt.as_bytes())?;
            Ok(Some(command))
        }

        async fn wait_for_release(&self, command: &Command) -> Result<(), String> {
            let deadline = tokio::time::Instant::now()
                + self.settings.budget
                + self.settings.grace
                + Duration::from_secs(5);
            loop {
                if let Some(contents) = read_optional(&self.path, RELEASE)?
                    && parse_command(&contents)? == *command
                {
                    return Ok(());
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err("settlement control hold timed out".into());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    #[must_use]
    pub fn duration_override() -> Option<(Duration, Duration)> {
        ControlDirectory::from_environment(true)
            .unwrap_or_else(|error| panic!("settlement_test_control setup error: {error}"))
            .map(|control| (control.settings.budget, control.settings.grace))
    }

    pub async fn hold(checkpoint: Checkpoint) {
        let Some(control) = ControlDirectory::from_environment(false)
            .unwrap_or_else(|error| panic!("settlement_test_control error: {error}"))
        else {
            return;
        };
        let Some(command) = control
            .claim(checkpoint)
            .unwrap_or_else(|error| panic!("settlement_test_control claim error: {error}"))
        else {
            return;
        };
        control
            .wait_for_release(&command)
            .await
            .unwrap_or_else(|error| panic!("settlement_test_control release error: {error}"));
    }

    pub async fn persister_checkpoint(checkpoint: Checkpoint) -> bool {
        let Some(control) = ControlDirectory::from_environment(false)
            .unwrap_or_else(|error| panic!("settlement_test_control error: {error}"))
        else {
            return false;
        };
        let Some(command) = control
            .claim(checkpoint)
            .unwrap_or_else(|error| panic!("settlement_test_control claim error: {error}"))
        else {
            return false;
        };
        match command.action {
            Action::Hold => {
                control
                    .wait_for_release(&command)
                    .await
                    .unwrap_or_else(|error| {
                        panic!("settlement_test_control release error: {error}")
                    });
                false
            }
            Action::DropAck => true,
        }
    }

    fn read_required(directory: &Path, name: &str) -> Result<String, String> {
        read_optional(directory, name)?
            .ok_or_else(|| format!("settlement control {name} is missing"))
    }

    fn read_optional(directory: &Path, name: &str) -> Result<Option<String>, String> {
        let path = directory.join(name);
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("cannot open settlement control {name}: {error}")),
        };
        let metadata = file
            .metadata()
            .map_err(|error| format!("cannot inspect settlement control {name}: {error}"))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(format!(
                "settlement control {name} must be a regular mode-0600 file"
            ));
        }
        if metadata.uid() != Uid::effective().as_raw() {
            return Err(format!("settlement control {name} has the wrong owner"));
        }
        if metadata.len() > MAX_CONTROL_FILE_BYTES_U64 {
            return Err(format!("settlement control {name} exceeds the size limit"));
        }
        let mut bytes = Vec::with_capacity(MAX_CONTROL_FILE_BYTES + 1);
        std::io::Read::by_ref(&mut file)
            .take(MAX_CONTROL_FILE_BYTES_U64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read settlement control {name}: {error}"))?;
        if bytes.len() > MAX_CONTROL_FILE_BYTES {
            return Err(format!(
                "settlement control {name} changed beyond the size limit"
            ));
        }
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| format!("settlement control {name} must be UTF-8"))
    }

    fn parse_fields(contents: &str, expected: &[&str]) -> Result<BTreeMap<String, String>, String> {
        let mut fields = BTreeMap::new();
        for line in contents.lines() {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("malformed settlement control line {line:?}"))?;
            if key.is_empty()
                || value.is_empty()
                || fields.insert(key.into(), value.into()).is_some()
            {
                return Err(format!(
                    "malformed or duplicate settlement control field {key:?}"
                ));
            }
        }
        if fields.len() != expected.len() || expected.iter().any(|key| !fields.contains_key(*key)) {
            return Err("settlement control fields do not match the closed schema".into());
        }
        Ok(fields)
    }

    fn parse_settings(contents: &str) -> Result<Settings, String> {
        let fields = parse_fields(contents, &["version", "budget_ms", "grace_ms"])?;
        require_version(&fields)?;
        let budget_ms = parse_bounded(&fields, "budget_ms", MIN_BUDGET_MS, MAX_BUDGET_MS)?;
        let grace_ms = parse_bounded(&fields, "grace_ms", MIN_GRACE_MS, MAX_GRACE_MS)?;
        Ok(Settings {
            budget: Duration::from_millis(budget_ms),
            grace: Duration::from_millis(grace_ms),
        })
    }

    fn parse_command(contents: &str) -> Result<Command, String> {
        let fields = parse_fields(contents, &["version", "nonce", "checkpoint", "action"])?;
        require_version(&fields)?;
        let nonce = fields["nonce"].clone();
        if nonce.len() != 32
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("settlement control nonce must be 32 lowercase hex characters".into());
        }
        Ok(Command {
            nonce,
            checkpoint: Checkpoint::parse(&fields["checkpoint"])?,
            action: Action::parse(&fields["action"])?,
        })
    }

    fn require_version(fields: &BTreeMap<String, String>) -> Result<(), String> {
        if fields["version"] == CONTROL_VERSION {
            Ok(())
        } else {
            Err("unsupported settlement control version".into())
        }
    }

    fn parse_bounded(
        fields: &BTreeMap<String, String>,
        name: &str,
        minimum: u64,
        maximum: u64,
    ) -> Result<u64, String> {
        let value = fields[name]
            .parse::<u64>()
            .map_err(|_| format!("settlement control {name} must be an integer"))?;
        if (minimum..=maximum).contains(&value) {
            Ok(value)
        } else {
            Err(format!(
                "settlement control {name} is outside {minimum}..={maximum}"
            ))
        }
    }

    fn atomic_write(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
        let temporary = directory.join(format!(".{name}.{}.tmp", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| format!("cannot create settlement control {name}: {error}"))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot write settlement control {name}: {error}"))?;
        fs::rename(&temporary, directory.join(name))
            .map_err(|error| format!("cannot publish settlement control {name}: {error}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const NONCE: &str = "0123456789abcdef0123456789abcdef";

        fn control_directory() -> (tempfile::TempDir, ControlDirectory) {
            let directory = tempfile::tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(
                directory.path().join(SETTINGS),
                format!("version={CONTROL_VERSION}\nbudget_ms=250\ngrace_ms=100\n"),
            )
            .unwrap();
            fs::set_permissions(
                directory.path().join(SETTINGS),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let control = ControlDirectory::open(directory.path().to_path_buf()).unwrap();
            (directory, control)
        }

        fn command(checkpoint: Checkpoint, action: Action, nonce: &str) -> String {
            format!(
                "version={CONTROL_VERSION}\nnonce={nonce}\ncheckpoint={}\naction={}\n",
                checkpoint.as_str(),
                action.as_str()
            )
        }

        #[test]
        fn parsers_enforce_closed_version_bounds_nonce_checkpoints_and_actions() {
            assert!(!Checkpoint::TransactionAfterBeginMutation.allows_drop_ack());
            assert!(!Checkpoint::CatalogActorCommandAccepted.allows_drop_ack());
            assert!(Checkpoint::ReplaceBeforePublish.allows_drop_ack());
            assert!(Checkpoint::StagedCommitBeforePublish.allows_drop_ack());
            let settings = parse_settings(&format!(
                "version={CONTROL_VERSION}\nbudget_ms=10000\ngrace_ms=5000\n"
            ))
            .unwrap();
            assert_eq!(settings.budget, Duration::from_secs(10));
            assert_eq!(settings.grace, Duration::from_secs(5));
            for invalid in [
                "version=wrong\nbudget_ms=250\ngrace_ms=100\n",
                &format!("version={CONTROL_VERSION}\nbudget_ms=249\ngrace_ms=100\n"),
                &format!("version={CONTROL_VERSION}\nbudget_ms=250\ngrace_ms=5001\n"),
                &format!("version={CONTROL_VERSION}\nbudget_ms=250\nbudget_ms=251\ngrace_ms=100\n"),
            ] {
                assert!(parse_settings(invalid).is_err(), "accepted {invalid:?}");
            }
            for checkpoint in [
                Checkpoint::TransactionAfterBeginMutation,
                Checkpoint::CatalogActorCommandAccepted,
                Checkpoint::ReplaceBeforePublish,
                Checkpoint::StagedCommitBeforePublish,
            ] {
                for action in [Action::Hold, Action::DropAck] {
                    assert_eq!(
                        parse_command(&command(checkpoint, action, NONCE)).unwrap(),
                        Command {
                            nonce: NONCE.into(),
                            checkpoint,
                            action
                        }
                    );
                }
            }
            for invalid in [
                command(Checkpoint::ReplaceBeforePublish, Action::Hold, "ABC"),
                format!(
                    "version={CONTROL_VERSION}\nnonce={NONCE}\ncheckpoint=other\naction=hold\n"
                ),
                format!(
                    "version={CONTROL_VERSION}\nnonce={NONCE}\ncheckpoint=replace_before_publish\naction=other\n"
                ),
            ] {
                assert!(parse_command(&invalid).is_err(), "accepted {invalid:?}");
            }
        }

        #[test]
        fn directory_must_be_absolute_canonical_private_owned_and_not_symlinked() {
            assert!(ControlDirectory::open(PathBuf::from("relative")).is_err());
            let (directory, _) = control_directory();
            let settings = directory.path().join(SETTINGS);
            fs::set_permissions(&settings, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(ControlDirectory::open(directory.path().to_path_buf()).is_err());
            fs::set_permissions(settings, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
            assert!(ControlDirectory::open(directory.path().to_path_buf()).is_err());
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let link = directory.path().with_extension("settlement-control-link");
            std::os::unix::fs::symlink(directory.path(), &link).unwrap();
            assert!(ControlDirectory::open(link.clone()).is_err());
            fs::remove_file(link).unwrap();
            fs::write(directory.path().join(SETTINGS), vec![b'x'; 1_025]).unwrap();
            assert!(ControlDirectory::open(directory.path().to_path_buf()).is_err());
        }

        #[tokio::test]
        async fn mismatch_is_not_consumed_and_claim_receipt_release_are_exact_and_one_shot() {
            let (directory, control) = control_directory();
            let armed = command(Checkpoint::ReplaceBeforePublish, Action::Hold, NONCE);
            atomic_write(directory.path(), ARM, armed.as_bytes()).unwrap();
            assert_eq!(
                control
                    .claim(Checkpoint::CatalogActorCommandAccepted)
                    .unwrap(),
                None
            );
            assert_eq!(
                fs::read_to_string(directory.path().join(ARM)).unwrap(),
                armed
            );
            let claimed = control
                .claim(Checkpoint::ReplaceBeforePublish)
                .unwrap()
                .unwrap();
            assert!(!directory.path().join(ARM).exists());
            assert_eq!(
                fs::read_to_string(directory.path().join(CLAIMED)).unwrap(),
                armed
            );
            let receipt = fs::read_to_string(directory.path().join(RECEIPT)).unwrap();
            assert!(receipt.contains(&format!("version={CONTROL_VERSION}\n")));
            assert!(receipt.contains(&format!("nonce={NONCE}\n")));
            assert!(receipt.contains("checkpoint=replace_before_publish\naction=hold\n"));
            assert!(receipt.contains(&format!("pid={}\n", std::process::id())));

            let mismatch = command(
                Checkpoint::ReplaceBeforePublish,
                Action::Hold,
                "ffffffffffffffffffffffffffffffff",
            );
            atomic_write(directory.path(), RELEASE, mismatch.as_bytes()).unwrap();
            let path = directory.path().to_path_buf();
            let release = armed.clone();
            let writer = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(30));
                atomic_write(&path, RELEASE, release.as_bytes()).unwrap();
            });
            control.wait_for_release(&claimed).await.unwrap();
            writer.join().unwrap();

            atomic_write(directory.path(), ARM, armed.as_bytes()).unwrap();
            assert!(control.claim(Checkpoint::ReplaceBeforePublish).is_err());

            let (drop_directory, drop_control) = control_directory();
            let drop_ack = command(
                Checkpoint::StagedCommitBeforePublish,
                Action::DropAck,
                NONCE,
            );
            atomic_write(drop_directory.path(), ARM, drop_ack.as_bytes()).unwrap();
            assert_eq!(
                drop_control
                    .claim(Checkpoint::StagedCommitBeforePublish)
                    .unwrap()
                    .unwrap()
                    .action,
                Action::DropAck
            );

            let (forbidden_directory, forbidden_control) = control_directory();
            let forbidden = command(
                Checkpoint::CatalogActorCommandAccepted,
                Action::DropAck,
                NONCE,
            );
            atomic_write(forbidden_directory.path(), ARM, forbidden.as_bytes()).unwrap();
            assert!(
                forbidden_control
                    .claim(Checkpoint::CatalogActorCommandAccepted)
                    .is_err()
            );
            assert!(forbidden_directory.path().join(ARM).exists());
        }
    }
}

pub const OWNED_SETTLEMENT_BUDGET: Duration = Duration::from_mins(30);
pub const AMBIGUITY_FENCE_GRACE: Duration = Duration::from_secs(5);
pub const AMBIGUOUS_CONFIG_EXIT_STATUS: i32 = 70;

/// Closed roster of runtime-config operations wired into settlement ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeConfigOperationKind {
    Sighup,
    Apply,
    GnmiSet,
    Confirm,
    Abort,
    Rollback,
    AutoRevert,
    NeighborAdd,
    NeighborDelete,
    DynamicNeighborAdd,
    DynamicNeighborDelete,
    FibSet,
    FibDelete,
    PeerGroupSet,
    PeerGroupDelete,
    NeighborPeerGroupSet,
    NeighborPeerGroupClear,
    PolicySet,
    PolicyDelete,
    NeighborSetSet,
    NeighborSetDelete,
    GlobalImportChainSet,
    GlobalExportChainSet,
    GlobalImportChainClear,
    GlobalExportChainClear,
    NeighborImportChainSet,
    NeighborExportChainSet,
    NeighborImportChainClear,
    NeighborExportChainClear,
}

impl RuntimeConfigOperationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Sighup => "sighup",
            Self::Apply => "apply",
            Self::GnmiSet => "gnmi_set",
            Self::Confirm => "confirm",
            Self::Abort => "abort",
            Self::Rollback => "rollback",
            Self::AutoRevert => "auto_revert",
            Self::NeighborAdd => "neighbor_add",
            Self::NeighborDelete => "neighbor_delete",
            Self::DynamicNeighborAdd => "dynamic_neighbor_add",
            Self::DynamicNeighborDelete => "dynamic_neighbor_delete",
            Self::FibSet => "fib_set",
            Self::FibDelete => "fib_delete",
            Self::PeerGroupSet => "peer_group_set",
            Self::PeerGroupDelete => "peer_group_delete",
            Self::NeighborPeerGroupSet => "neighbor_peer_group_set",
            Self::NeighborPeerGroupClear => "neighbor_peer_group_clear",
            Self::PolicySet => "policy_set",
            Self::PolicyDelete => "policy_delete",
            Self::NeighborSetSet => "neighbor_set_set",
            Self::NeighborSetDelete => "neighbor_set_delete",
            Self::GlobalImportChainSet => "global_import_chain_set",
            Self::GlobalExportChainSet => "global_export_chain_set",
            Self::GlobalImportChainClear => "global_import_chain_clear",
            Self::GlobalExportChainClear => "global_export_chain_clear",
            Self::NeighborImportChainSet => "neighbor_import_chain_set",
            Self::NeighborExportChainSet => "neighbor_export_chain_set",
            Self::NeighborImportChainClear => "neighbor_import_chain_clear",
            Self::NeighborExportChainClear => "neighbor_export_chain_clear",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RuntimeConfigSettlementPhase {
    OwnedPreflight,
    Mutating,
    SettlingRollback,
}

impl RuntimeConfigSettlementPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::OwnedPreflight => "owned_preflight",
            Self::Mutating => "mutating",
            Self::SettlingRollback => "settling_rollback",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeConfigSettlementTerminal {
    Owned,
    Settled,
    RecoveryFenced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeConfigFenceReason {
    BudgetExpired,
    ExecutorLost,
    KnownDivergence,
    PublicationAmbiguous,
    AcknowledgementLost,
}

impl RuntimeConfigFenceReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BudgetExpired => "budget_expired",
            Self::ExecutorLost => "executor_lost",
            Self::KnownDivergence => "known_divergence",
            Self::PublicationAmbiguous => "publication_ambiguous",
            Self::AcknowledgementLost => "acknowledgement_lost",
        }
    }
}

const PHASE_PREFLIGHT: u8 = 0;
const PHASE_MUTATING: u8 = 1;
const PHASE_SETTLING: u8 = 2;
const PHASE_MASK: u8 = 0b11;
const TERMINAL_OWNED: u8 = 0;
const TERMINAL_SETTLED: u8 = 1 << 2;
const TERMINAL_AMBIGUOUS: u8 = 2 << 2;
const TERMINAL_MASK: u8 = 0b11 << 2;
const REASON_SHIFT: u8 = 4;
const REASON_MASK: u8 = 0b111 << REASON_SHIFT;
const AMBIGUITY_REASON_BUDGET: u8 = 1;
const AMBIGUITY_REASON_EXECUTOR: u8 = 2;
const FENCE_REASON_DIVERGENCE: u8 = 3;
const FENCE_REASON_PUBLICATION: u8 = 4;
const FENCE_REASON_ACKNOWLEDGEMENT: u8 = 5;
const RECOVERY_NOT_READY: &str = "runtime config settlement requires supervised recovery";
const WARNING_HALF_BUDGET: Duration = Duration::from_mins(15);
const WARNING_FIVE_MINUTES_REMAINING: Duration = Duration::from_mins(25);
const WARNING_ONE_MINUTE_REMAINING: Duration = Duration::from_mins(29);
const WARNING_HALF_BIT: u8 = 1;
const WARNING_FIVE_MINUTES_BIT: u8 = 1 << 1;
const WARNING_ONE_MINUTE_BIT: u8 = 1 << 2;
const METRIC_LABELS: [&str; 4] = ["kind", "phase", "response_attached", "fence_reason"];

fn phase_from_state(state: u8) -> RuntimeConfigSettlementPhase {
    match state & PHASE_MASK {
        PHASE_PREFLIGHT => RuntimeConfigSettlementPhase::OwnedPreflight,
        PHASE_MUTATING => RuntimeConfigSettlementPhase::Mutating,
        _ => RuntimeConfigSettlementPhase::SettlingRollback,
    }
}

fn terminal_from_state(state: u8) -> RuntimeConfigSettlementTerminal {
    match state & TERMINAL_MASK {
        TERMINAL_OWNED => RuntimeConfigSettlementTerminal::Owned,
        TERMINAL_SETTLED => RuntimeConfigSettlementTerminal::Settled,
        _ => RuntimeConfigSettlementTerminal::RecoveryFenced,
    }
}

fn fence_reason_from_state(state: u8) -> Option<RuntimeConfigFenceReason> {
    match (state & REASON_MASK) >> REASON_SHIFT {
        AMBIGUITY_REASON_BUDGET => Some(RuntimeConfigFenceReason::BudgetExpired),
        AMBIGUITY_REASON_EXECUTOR => Some(RuntimeConfigFenceReason::ExecutorLost),
        FENCE_REASON_DIVERGENCE => Some(RuntimeConfigFenceReason::KnownDivergence),
        FENCE_REASON_PUBLICATION => Some(RuntimeConfigFenceReason::PublicationAmbiguous),
        FENCE_REASON_ACKNOWLEDGEMENT => Some(RuntimeConfigFenceReason::AcknowledgementLost),
        _ => None,
    }
}

#[derive(Debug)]
struct OwnedResources {
    _coordinator_permit: RuntimeConfigCoordinatorPermit,
    _stream_permit: Option<OwnedSemaphorePermit>,
    stream_admission: Option<Arc<Semaphore>>,
}

struct OperationInner {
    id: u64,
    kind: RuntimeConfigOperationKind,
    registered_at: Instant,
    deadline: Instant,
    state: AtomicU8,
    response_attached: Arc<AtomicBool>,
    fatal_at_nanos: AtomicU64,
    warning_bits: AtomicU8,
    propagation_claimed: AtomicBool,
    #[cfg(test)]
    propagation_completed: AtomicBool,
    coordinator: RuntimeConfigCoordinator,
    daemon_gate: DaemonGate,
    resources: Mutex<Option<OwnedResources>>,
    registry: Arc<Registry>,
}

impl std::fmt::Debug for OperationInner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OperationInner")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("registered_at", &self.registered_at)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl OperationInner {
    fn phase(&self) -> RuntimeConfigSettlementPhase {
        phase_from_state(self.state.load(Ordering::Acquire))
    }

    fn terminal(&self) -> RuntimeConfigSettlementTerminal {
        terminal_from_state(self.state.load(Ordering::Acquire))
    }

    fn fence_reason(&self) -> Option<RuntimeConfigFenceReason> {
        fence_reason_from_state(self.state.load(Ordering::Acquire))
    }

    /// Elapsed ownership time, derived on every call from the stored
    /// `registered_at` instant. Nothing stores an elapsed value at phase
    /// transitions, so a wedged owner still reads a growing elapsed on a
    /// frozen phase at scrape time.
    fn elapsed(&self) -> Duration {
        let now = Instant::now();
        #[cfg(test)]
        let now = now
            + Duration::from_nanos(
                self.registry
                    .scrape_clock_advance_nanos
                    .load(Ordering::Acquire),
            );
        now.saturating_duration_since(self.registered_at)
    }
}

struct Registry {
    current: ArcSwapOption<OperationInner>,
    idle_lock: Mutex<()>,
    wake: Condvar,
    next_id: AtomicU64,
    budget: Duration,
    grace: Duration,
    epoch: Instant,
    stopping: AtomicBool,
    fatal_thread: OnceLock<thread::Thread>,
    observer_thread: OnceLock<thread::Thread>,
    #[cfg(test)]
    terminal: std::sync::mpsc::Sender<i32>,
    #[cfg(test)]
    terminal_fired: AtomicBool,
    /// Test-only clock advance applied to elapsed derivation, proving the
    /// scrape reads elapsed from `registered_at` instead of a value written
    /// at the last phase transition.
    #[cfg(test)]
    scrape_clock_advance_nanos: AtomicU64,
}

impl Registry {
    #[cfg(not(test))]
    fn new(budget: Duration, grace: Duration) -> Self {
        Self {
            current: ArcSwapOption::empty(),
            idle_lock: Mutex::new(()),
            wake: Condvar::new(),
            next_id: AtomicU64::new(1),
            budget,
            grace,
            epoch: Instant::now(),
            stopping: AtomicBool::new(false),
            fatal_thread: OnceLock::new(),
            observer_thread: OnceLock::new(),
        }
    }

    #[cfg(test)]
    fn new(budget: Duration, grace: Duration, terminal: std::sync::mpsc::Sender<i32>) -> Self {
        Self {
            current: ArcSwapOption::empty(),
            idle_lock: Mutex::new(()),
            wake: Condvar::new(),
            next_id: AtomicU64::new(1),
            budget,
            grace,
            epoch: Instant::now(),
            stopping: AtomicBool::new(false),
            fatal_thread: OnceLock::new(),
            observer_thread: OnceLock::new(),
            terminal,
            terminal_fired: AtomicBool::new(false),
            scrape_clock_advance_nanos: AtomicU64::new(0),
        }
    }

    fn instant_nanos(&self, instant: Instant) -> u64 {
        u64::try_from(instant.saturating_duration_since(self.epoch).as_nanos())
            .unwrap_or(u64::MAX)
            .max(1)
    }

    fn nanos_instant(&self, nanos: u64) -> Instant {
        self.epoch + Duration::from_nanos(nanos)
    }

    fn wake_threads(&self) {
        self.wake.notify_all();
        if let Some(observer) = self.observer_thread.get() {
            observer.unpark();
        }
        if let Some(fatal) = self.fatal_thread.get() {
            fatal.unpark();
        }
    }
}

struct RuntimeConfigSettlementCollector {
    registry: Arc<Registry>,
    scrape_lock: Mutex<()>,
    active: GaugeVec,
    elapsed: GaugeVec,
    budget: GaugeVec,
    fail_stops: CounterVec,
    descs: Vec<Desc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SettlementMetricSnapshot {
    phase: RuntimeConfigSettlementPhase,
    terminal: RuntimeConfigSettlementTerminal,
    fence_reason: Option<RuntimeConfigFenceReason>,
    response_attached: bool,
}

impl SettlementMetricSnapshot {
    fn capture(operation: &OperationInner) -> Self {
        let state = operation.state.load(Ordering::Acquire);
        let response_attached = operation.response_attached.load(Ordering::Acquire);
        Self::decode(state, response_attached)
    }

    fn decode(state: u8, response_attached: bool) -> Self {
        Self {
            phase: phase_from_state(state),
            terminal: terminal_from_state(state),
            fence_reason: fence_reason_from_state(state),
            response_attached,
        }
    }

    fn labels(self, kind: RuntimeConfigOperationKind) -> [&'static str; 4] {
        [
            kind.as_str(),
            self.phase.as_str(),
            if self.response_attached {
                "attached"
            } else {
                "detached"
            },
            self.fence_reason
                .map_or("none", RuntimeConfigFenceReason::as_str),
        ]
    }
}

impl RuntimeConfigSettlementCollector {
    fn new(registry: Arc<Registry>) -> Self {
        let active = GaugeVec::new(
            Opts::new(
                "bgp_runtime_config_settlement_active",
                "Whether one runtime-config settlement owner is active or recovery-fenced.",
            ),
            &METRIC_LABELS,
        )
        .expect("valid runtime-config settlement active metric");
        let elapsed = GaugeVec::new(
            Opts::new(
                "bgp_runtime_config_settlement_elapsed_seconds",
                "Elapsed wall-clock seconds for the current runtime-config settlement owner.",
            ),
            &METRIC_LABELS,
        )
        .expect("valid runtime-config settlement elapsed metric");
        let budget = GaugeVec::new(
            Opts::new(
                "bgp_runtime_config_settlement_budget_seconds",
                "Fixed wall-clock budget for the current runtime-config settlement owner.",
            ),
            &METRIC_LABELS,
        )
        .expect("valid runtime-config settlement budget metric");
        let fail_stops = CounterVec::new(
            Opts::new(
                "bgp_runtime_config_settlement_fail_stops_total",
                "Runtime-config settlement owners that won recovery fencing and armed exit 70.",
            ),
            &METRIC_LABELS,
        )
        .expect("valid runtime-config settlement fail-stop metric");
        let descs = active
            .desc()
            .into_iter()
            .chain(elapsed.desc())
            .chain(budget.desc())
            .chain(fail_stops.desc())
            .cloned()
            .collect();
        Self {
            registry,
            scrape_lock: Mutex::new(()),
            active,
            elapsed,
            budget,
            fail_stops,
            descs,
        }
    }
}

impl Collector for RuntimeConfigSettlementCollector {
    fn desc(&self) -> Vec<&Desc> {
        self.descs.iter().collect()
    }

    fn collect(&self) -> Vec<MetricFamily> {
        let _scrape = self
            .scrape_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.active.reset();
        self.elapsed.reset();
        self.budget.reset();
        self.fail_stops.reset();
        let Some(operation) = self.registry.current.load_full() else {
            return Vec::new();
        };
        let snapshot = SettlementMetricSnapshot::capture(&operation);
        let labels = snapshot.labels(operation.kind);
        self.active.with_label_values(&labels).set(1.0);
        self.elapsed
            .with_label_values(&labels)
            .set(operation.elapsed().as_secs_f64());
        self.budget
            .with_label_values(&labels)
            .set(self.registry.budget.as_secs_f64());
        // The sole recovery-fenced owner cannot settle, and its fatal clock
        // exits this process. The process-lifetime counter therefore moves
        // only from 0 to 1; a fence-reason label change is a distinct series.
        let fail_stops_total =
            u32::from(snapshot.terminal == RuntimeConfigSettlementTerminal::RecoveryFenced);
        self.fail_stops
            .with_label_values(&labels)
            .inc_by(f64::from(fail_stops_total));
        let mut families = self.active.collect();
        families.extend(self.elapsed.collect());
        families.extend(self.budget.collect());
        families.extend(self.fail_stops.collect());
        families
    }
}

#[derive(Clone)]
pub struct RuntimeConfigSettlementWatchdog {
    registry: Arc<Registry>,
    #[cfg(test)]
    threads: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
}

impl std::fmt::Debug for RuntimeConfigSettlementWatchdog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeConfigSettlementWatchdog")
            .finish_non_exhaustive()
    }
}

impl RuntimeConfigSettlementWatchdog {
    /// Start the process watchdog with fixed production durations. Debug
    /// builds may accept a validated settlement-test duration override.
    #[must_use]
    #[cfg(not(test))]
    #[allow(
        clippy::new_without_default,
        reason = "construction starts the process watchdog thread, so Default would hide lifecycle side effects"
    )]
    pub fn new() -> Self {
        #[cfg(debug_assertions)]
        let (budget, grace) = settlement_test_control::duration_override()
            .unwrap_or((OWNED_SETTLEMENT_BUDGET, AMBIGUITY_FENCE_GRACE));
        #[cfg(not(debug_assertions))]
        let (budget, grace) = (OWNED_SETTLEMENT_BUDGET, AMBIGUITY_FENCE_GRACE);
        Self::start(budget, grace)
    }

    #[cfg(not(test))]
    fn start(budget: Duration, grace: Duration) -> Self {
        let registry = Arc::new(Registry::new(budget, grace));
        start_threads(&registry);
        Self { registry }
    }

    #[cfg(test)]
    fn start(budget: Duration, grace: Duration, terminal: std::sync::mpsc::Sender<i32>) -> Self {
        let registry = Arc::new(Registry::new(budget, grace, terminal));
        let threads = start_threads(&registry);
        Self {
            registry,
            threads: Arc::new(Mutex::new(threads)),
        }
    }

    /// Register scrape-time settlement metrics in the daemon's private registry.
    ///
    /// # Panics
    ///
    /// Panics if the registry already contains one of the closed metric names.
    pub fn register_metrics(&self, registry: &prometheus::Registry) {
        registry
            .register(Box::new(RuntimeConfigSettlementCollector::new(Arc::clone(
                &self.registry,
            ))))
            .expect("runtime-config settlement metric definitions must be unique");
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the closed ownership registration lists every retained fail-stop resource explicitly"
    )]
    /// Register the sole retained runtime-config owner.
    ///
    /// # Panics
    ///
    /// Panics if a second owner bypasses the coordinator invariant.
    pub fn register_owned(
        &self,
        kind: RuntimeConfigOperationKind,
        coordinator: RuntimeConfigCoordinator,
        coordinator_permit: RuntimeConfigCoordinatorPermit,
        daemon_gate: DaemonGate,
        stream_permit: Option<OwnedSemaphorePermit>,
        stream_admission: Option<Arc<Semaphore>>,
        response_attached: Arc<AtomicBool>,
    ) -> (OwnedRuntimeConfigOperation, RuntimeConfigExecutorGuard) {
        let registered_at = Instant::now();
        let deadline = registered_at + self.registry.budget;
        let id = self.registry.next_id.fetch_add(1, Ordering::Relaxed);
        let operation = Arc::new(OperationInner {
            id,
            kind,
            registered_at,
            deadline,
            state: AtomicU8::new(TERMINAL_OWNED | PHASE_PREFLIGHT),
            response_attached,
            fatal_at_nanos: AtomicU64::new(
                self.registry.instant_nanos(deadline + self.registry.grace),
            ),
            warning_bits: AtomicU8::new(0),
            propagation_claimed: AtomicBool::new(false),
            #[cfg(test)]
            propagation_completed: AtomicBool::new(false),
            coordinator,
            daemon_gate,
            resources: Mutex::new(Some(OwnedResources {
                _coordinator_permit: coordinator_permit,
                _stream_permit: stream_permit,
                stream_admission,
            })),
            registry: Arc::clone(&self.registry),
        });
        let previous = self
            .registry
            .current
            .compare_and_swap(&None::<Arc<OperationInner>>, Some(Arc::clone(&operation)));
        assert!(
            previous.is_none(),
            "runtime-config settlement permits only one current operation"
        );
        tracing::info!(
            operation_id = operation.id,
            kind = operation.kind.as_str(),
            phase = operation.phase().as_str(),
            elapsed_seconds = operation.elapsed().as_secs(),
            budget_seconds = self.registry.budget.as_secs(),
            "runtime config settlement ownership registered"
        );
        self.registry.wake.notify_one();
        if let Some(observer) = self.registry.observer_thread.get() {
            observer.unpark();
        }
        if let Some(fatal) = self.registry.fatal_thread.get() {
            fatal.unpark();
        }
        (
            OwnedRuntimeConfigOperation {
                inner: Arc::clone(&operation),
            },
            RuntimeConfigExecutorGuard {
                inner: Some(operation),
            },
        )
    }

    /// Run one detached, owned mutation from coordinator acquisition through
    /// typed settlement. Registration is the first post-acquire operation.
    /// Caller cancellation detaches only the response; typed ambiguity,
    /// deadline, or executor loss fences and parks the retained owner.
    ///
    /// # Errors
    ///
    /// Returns only the error carried by a typed clean outcome or coordinator
    /// acquisition before ownership. Ambiguous owned outcomes never return.
    pub async fn execute_owned<T, E, F, Fut>(
        &self,
        kind: RuntimeConfigOperationKind,
        coordinator: RuntimeConfigCoordinator,
        daemon_gate: DaemonGate,
        response_attached: Arc<AtomicBool>,
        body: F,
    ) -> Result<T, E>
    where
        T: Send + 'static,
        E: From<crate::server::RuntimeConfigCoordinatorClosed> + Send + 'static,
        F: FnOnce(OwnedRuntimeConfigOperation) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = OwnedRuntimeConfigOutcome<T, E>> + Send + 'static,
    {
        let watchdog = self.clone();
        let join = tokio::spawn(async move {
            let coordinator_permit = coordinator.acquire().await?;
            let (operation, executor_guard) = watchdog.register_owned(
                kind,
                coordinator,
                coordinator_permit,
                daemon_gate,
                None,
                None,
                response_attached,
            );
            let outcome = body(operation.clone()).await;
            match outcome {
                OwnedRuntimeConfigOutcome::CleanNoEffect(result) => {
                    if !operation.try_settle() {
                        std::future::pending::<()>().await;
                    }
                    drop(executor_guard);
                    result
                }
                OwnedRuntimeConfigOutcome::PublishedDurable(value)
                | OwnedRuntimeConfigOutcome::AcknowledgedAuthority(value) => {
                    if !operation.try_settle() {
                        std::future::pending::<()>().await;
                    }
                    drop(executor_guard);
                    Ok(value)
                }
                OwnedRuntimeConfigOutcome::Fenced { error, reason } => {
                    let _ = error;
                    let _ = operation.fence_recovery(reason);
                    std::future::pending().await
                }
            }
        });
        match join.await {
            Ok(result) => result,
            Err(_) => std::future::pending().await,
        }
    }

    /// Block the calling OS thread until every clean registration settles.
    /// Ambiguous ownership deliberately never unregisters; its fail-stop wins.
    pub fn wait_until_idle(&self) {
        let mut idle = self
            .registry
            .idle_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while self.registry.current.load().is_some() {
            idle = self
                .registry
                .wake
                .wait(idle)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

/// Typed result from an owned body; never inferred from transport status.
pub enum OwnedRuntimeConfigOutcome<T, E> {
    /// Success or a proven no-effect or fully-compensated failure.
    CleanNoEffect(Result<T, E>),
    /// The requested candidate is fully applied and durable.
    PublishedDurable(T),
    /// A non-publication operation whose authority was acknowledged by every
    /// runtime consumer.
    AcknowledgedAuthority(T),
    /// An accepted effect whose final state cannot be proved.
    /// Ownership must be retained until supervised recovery.
    Fenced {
        error: E,
        reason: RuntimeConfigFenceReason,
    },
}

/// Response attachment shared with a detached owned executor.
pub struct OwnedRuntimeConfigRequestContext {
    response_attached: Arc<AtomicBool>,
}

impl OwnedRuntimeConfigRequestContext {
    /// Create a unary response attachment owned by the outer RPC future.
    #[must_use]
    pub fn unary() -> (Self, OwnedRuntimeConfigResponseAttachment) {
        let attached = Arc::new(AtomicBool::new(true));
        (
            Self {
                response_attached: Arc::clone(&attached),
            },
            OwnedRuntimeConfigResponseAttachment(attached),
        )
    }

    /// Create a daemon-owned request with no response transport attached.
    #[must_use]
    pub fn detached() -> Self {
        Self {
            response_attached: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Transfer the shared attachment sentinel to the detached executor.
    #[must_use]
    pub fn response_attached(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.response_attached)
    }
}

/// Outer-RPC sentinel; dropping it records cancellation without releasing ownership.
pub struct OwnedRuntimeConfigResponseAttachment(Arc<AtomicBool>);

impl Drop for OwnedRuntimeConfigResponseAttachment {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Handle used by the daemon-owned operation to report progress and settlement.
#[derive(Clone, Debug)]
pub struct OwnedRuntimeConfigOperation {
    inner: Arc<OperationInner>,
}

impl OwnedRuntimeConfigOperation {
    #[must_use]
    pub fn kind(&self) -> RuntimeConfigOperationKind {
        self.inner.kind
    }

    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.inner.deadline
    }

    #[must_use]
    pub fn phase(&self) -> RuntimeConfigSettlementPhase {
        self.inner.phase()
    }

    /// Advance the phase monotonically while ownership is live.
    /// Settlement and recovery fencing atomically freeze the last phase.
    pub fn advance_phase(&self, phase: RuntimeConfigSettlementPhase) {
        let desired = match phase {
            RuntimeConfigSettlementPhase::OwnedPreflight => PHASE_PREFLIGHT,
            RuntimeConfigSettlementPhase::Mutating => PHASE_MUTATING,
            RuntimeConfigSettlementPhase::SettlingRollback => PHASE_SETTLING,
        };
        let mut observed = self.inner.state.load(Ordering::Acquire);
        loop {
            if observed & TERMINAL_MASK != TERMINAL_OWNED || observed & PHASE_MASK >= desired {
                return;
            }
            let next = (observed & !PHASE_MASK) | desired;
            match self.inner.state.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    tracing::info!(
                        operation_id = self.inner.id,
                        kind = self.inner.kind.as_str(),
                        phase = phase.as_str(),
                        elapsed_seconds = self.inner.elapsed().as_secs(),
                        budget_seconds = self.inner.registry.budget.as_secs(),
                        "runtime config settlement phase advanced"
                    );
                    return;
                }
                Err(actual) => observed = actual,
            }
        }
    }

    #[must_use]
    pub fn terminal(&self) -> RuntimeConfigSettlementTerminal {
        self.inner.terminal()
    }

    #[must_use]
    pub fn fence_reason(&self) -> Option<RuntimeConfigFenceReason> {
        self.inner.fence_reason()
    }

    /// Fence a typed recovery result before any response can be published.
    #[must_use]
    pub fn fence_recovery(&self, reason: RuntimeConfigFenceReason) -> bool {
        fence(self.inner.as_ref(), reason)
    }

    #[must_use]
    pub fn response_attached(&self) -> bool {
        self.inner.response_attached.load(Ordering::Acquire)
    }

    /// Prove settlement and release physical ownership. Returns false after fencing.
    pub fn try_settle(&self) -> bool {
        let mut observed = self.inner.state.load(Ordering::Acquire);
        loop {
            if observed & TERMINAL_MASK != TERMINAL_OWNED {
                return false;
            }
            let settled = (observed & PHASE_MASK) | TERMINAL_SETTLED;
            match self.inner.state.compare_exchange_weak(
                observed,
                settled,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => observed = actual,
            }
        }
        tracing::info!(
            operation_id = self.inner.id,
            kind = self.inner.kind.as_str(),
            phase = self.inner.phase().as_str(),
            elapsed_seconds = self.inner.elapsed().as_secs(),
            budget_seconds = self.inner.registry.budget.as_secs(),
            "runtime config settlement settled"
        );
        self.inner.registry.current.store(None);
        self.inner.registry.wake_threads();
        let resources = self
            .inner
            .resources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drop(resources);
        true
    }
}

/// Drop sentinel for loss of the daemon-owned executor after ownership.
#[must_use = "keep the executor guard alive until settlement is proved"]
#[derive(Debug)]
pub struct RuntimeConfigExecutorGuard {
    inner: Option<Arc<OperationInner>>,
}

impl Drop for RuntimeConfigExecutorGuard {
    fn drop(&mut self) {
        let Some(operation) = self.inner.take() else {
            return;
        };
        fence(&operation, RuntimeConfigFenceReason::ExecutorLost);
    }
}

fn fence(operation: &OperationInner, reason: RuntimeConfigFenceReason) -> bool {
    transition_to_fenced(operation, reason)
}

fn transition_to_fenced(operation: &OperationInner, reason: RuntimeConfigFenceReason) -> bool {
    let reason_value = match reason {
        RuntimeConfigFenceReason::BudgetExpired => AMBIGUITY_REASON_BUDGET,
        RuntimeConfigFenceReason::ExecutorLost => AMBIGUITY_REASON_EXECUTOR,
        RuntimeConfigFenceReason::KnownDivergence => FENCE_REASON_DIVERGENCE,
        RuntimeConfigFenceReason::PublicationAmbiguous => FENCE_REASON_PUBLICATION,
        RuntimeConfigFenceReason::AcknowledgementLost => FENCE_REASON_ACKNOWLEDGEMENT,
    };
    let mut observed = operation.state.load(Ordering::Acquire);
    loop {
        if observed & TERMINAL_MASK != TERMINAL_OWNED {
            return false;
        }
        let fenced = (observed & PHASE_MASK) | TERMINAL_AMBIGUOUS | (reason_value << REASON_SHIFT);
        match operation.state.compare_exchange_weak(
            observed,
            fenced,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(actual) => observed = actual,
        }
    }
    shorten_fatal_deadline(operation, Instant::now() + operation.registry.grace);
    operation.registry.wake_threads();
    true
}

fn shorten_fatal_deadline(operation: &OperationInner, deadline: Instant) {
    let candidate = operation.registry.instant_nanos(deadline);
    let mut observed = operation.fatal_at_nanos.load(Ordering::Acquire);
    while candidate < observed {
        match operation.fatal_at_nanos.compare_exchange_weak(
            observed,
            candidate,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(actual) => observed = actual,
        }
    }
}

fn propagate_fence(operation: &OperationInner) {
    if operation.propagation_claimed.swap(true, Ordering::AcqRel) {
        return;
    }
    operation.daemon_gate.mark_not_ready(RECOVERY_NOT_READY);
    operation.daemon_gate.begin_shutdown();
    operation.coordinator.close();
    if let Some(admission) = operation
        .resources
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(|resources| resources.stream_admission.as_ref())
    {
        admission.close();
    }
    tracing::error!(
        operation_id = operation.id,
        kind = operation.kind.as_str(),
        phase = operation.phase().as_str(),
        elapsed_seconds = operation.elapsed().as_secs(),
        budget_seconds = operation.registry.budget.as_secs(),
        response_attached = if operation.response_attached.load(Ordering::Acquire) {
            "attached"
        } else {
            "detached"
        },
        terminal = "recovery_fenced",
        fence_reason = operation
            .fence_reason()
            .map_or("none", RuntimeConfigFenceReason::as_str),
        exit_status = AMBIGUOUS_CONFIG_EXIT_STATUS,
        "runtime config settlement fail-stop armed"
    );
    #[cfg(test)]
    operation
        .propagation_completed
        .store(true, Ordering::Release);
}

fn start_threads(registry: &Arc<Registry>) -> Vec<thread::JoinHandle<()>> {
    let observer_registry = Arc::clone(registry);
    let observer = thread::Builder::new()
        .name("config-settlement-observer".into())
        .spawn(move || observer_loop(&observer_registry))
        .expect("config settlement observer OS thread must start");
    let fatal_registry = Arc::clone(registry);
    let fatal = thread::Builder::new()
        .name("config-settlement-fatal-clock".into())
        .spawn(move || fatal_clock_loop(&fatal_registry))
        .expect("config settlement fatal-clock OS thread must start");
    vec![observer, fatal]
}

fn observer_loop(registry: &Arc<Registry>) {
    let _ = registry.observer_thread.set(thread::current());
    while !registry.stopping.load(Ordering::Acquire) {
        if let Some(operation) = registry.current.load_full() {
            if operation.terminal() == RuntimeConfigSettlementTerminal::RecoveryFenced {
                propagate_fence(&operation);
            } else if operation.terminal() == RuntimeConfigSettlementTerminal::Owned {
                emit_due_warnings(&operation, Instant::now());
            }
        }
        thread::park_timeout(Duration::from_secs(1));
    }
}

fn emit_due_warnings(operation: &OperationInner, now: Instant) {
    let elapsed = now.saturating_duration_since(operation.registered_at);
    for (threshold, bit, remaining) in [
        (WARNING_HALF_BUDGET, WARNING_HALF_BIT, "15_minutes"),
        (
            WARNING_FIVE_MINUTES_REMAINING,
            WARNING_FIVE_MINUTES_BIT,
            "5_minutes",
        ),
        (
            WARNING_ONE_MINUTE_REMAINING,
            WARNING_ONE_MINUTE_BIT,
            "1_minute",
        ),
    ] {
        if elapsed >= threshold && operation.warning_bits.fetch_or(bit, Ordering::AcqRel) & bit == 0
        {
            tracing::warn!(
                operation_id = operation.id,
                kind = operation.kind.as_str(),
                phase = operation.phase().as_str(),
                elapsed_seconds = elapsed.as_secs(),
                budget_seconds = operation.registry.budget.as_secs(),
                response_attached = if operation.response_attached.load(Ordering::Acquire) {
                    "attached"
                } else {
                    "detached"
                },
                terminal = "owned",
                fence_reason = "none",
                remaining,
                "runtime config settlement budget warning"
            );
        }
    }
}

fn fatal_clock_loop(registry: &Arc<Registry>) {
    let _ = registry.fatal_thread.set(thread::current());
    while !registry.stopping.load(Ordering::Acquire) {
        let Some(operation) = registry.current.load_full() else {
            thread::park();
            continue;
        };
        let now = Instant::now();
        match operation.terminal() {
            RuntimeConfigSettlementTerminal::Owned => {
                if now >= operation.deadline {
                    let _ =
                        transition_to_fenced(&operation, RuntimeConfigFenceReason::BudgetExpired);
                    continue;
                }
                thread::park_timeout(operation.deadline.saturating_duration_since(now));
            }
            RuntimeConfigSettlementTerminal::RecoveryFenced => {
                let fatal_at =
                    registry.nanos_instant(operation.fatal_at_nanos.load(Ordering::Acquire));
                if now >= fatal_at {
                    run_terminal_action(registry);
                }
                thread::park_timeout(fatal_at.saturating_duration_since(now));
            }
            RuntimeConfigSettlementTerminal::Settled => thread::yield_now(),
        }
    }
}

#[cfg(not(test))]
#[allow(unsafe_code)]
fn terminate_process() -> ! {
    unsafe { libc::_exit(AMBIGUOUS_CONFIG_EXIT_STATUS) }
}

#[cfg(not(test))]
fn run_terminal_action(_registry: &Registry) -> ! {
    terminate_process()
}

#[cfg(test)]
fn run_terminal_action(registry: &Registry) {
    if !registry.terminal_fired.swap(true, Ordering::AcqRel) {
        let _ = registry.terminal.send(AMBIGUOUS_CONFIG_EXIT_STATUS);
    }
    thread::park();
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Encoder as _;

    struct TestWatchdog(RuntimeConfigSettlementWatchdog);

    impl std::ops::Deref for TestWatchdog {
        type Target = RuntimeConfigSettlementWatchdog;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Drop for TestWatchdog {
        fn drop(&mut self) {
            self.registry.stopping.store(true, Ordering::Release);
            self.registry.current.store(None);
            self.registry.wake_threads();
            for thread in self.0.threads.lock().unwrap().drain(..) {
                thread
                    .join()
                    .expect("watchdog test thread must stop cleanly");
            }
        }
    }

    fn test_watchdog(
        budget: Duration,
        grace: Duration,
    ) -> (TestWatchdog, std::sync::mpsc::Receiver<i32>) {
        let (sender, receiver) = std::sync::mpsc::channel();
        (
            TestWatchdog(RuntimeConfigSettlementWatchdog::start(
                budget, grace, sender,
            )),
            receiver,
        )
    }

    async fn operation(
        watchdog: &RuntimeConfigSettlementWatchdog,
        stream: bool,
    ) -> (
        OwnedRuntimeConfigOperation,
        RuntimeConfigExecutorGuard,
        RuntimeConfigCoordinator,
        Option<Arc<Semaphore>>,
    ) {
        let coordinator = RuntimeConfigCoordinator::new();
        let permit = coordinator.acquire().await.unwrap();
        let admission = stream.then(|| Arc::new(Semaphore::new(1)));
        let stream_permit = match &admission {
            Some(value) => Some(value.clone().acquire_owned().await.unwrap()),
            None => None,
        };
        let (operation, guard) = watchdog.register_owned(
            RuntimeConfigOperationKind::Apply,
            coordinator.clone(),
            permit,
            DaemonGate::new(),
            stream_permit,
            admission.clone(),
            Arc::new(AtomicBool::new(true)),
        );
        (operation, guard, coordinator, admission)
    }

    fn metrics(watchdog: &RuntimeConfigSettlementWatchdog) -> String {
        let registry = prometheus::Registry::new();
        watchdog.register_metrics(&registry);
        encode_metric_families(&registry.gather())
    }

    fn encode_metric_families(families: &[MetricFamily]) -> String {
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(families, &mut output)
            .unwrap();
        String::from_utf8(output).unwrap()
    }

    fn wait_for_propagation(operation: &OwnedRuntimeConfigOperation) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while !operation
            .inner
            .propagation_completed
            .load(Ordering::Acquire)
        {
            assert!(
                Instant::now() < deadline,
                "fence propagation did not complete"
            );
            thread::yield_now();
        }
    }

    #[test]
    fn constants_and_closed_states_are_exact() {
        assert_eq!(OWNED_SETTLEMENT_BUDGET, Duration::from_mins(30));
        assert_eq!(AMBIGUITY_FENCE_GRACE, Duration::from_secs(5));
        assert_eq!(AMBIGUOUS_CONFIG_EXIT_STATUS, 70);
        assert_eq!(RuntimeConfigSettlementTerminal::Owned as u8, 0);
        assert_eq!(RuntimeConfigFenceReason::BudgetExpired as u8, 0);
        assert_eq!(WARNING_HALF_BUDGET, Duration::from_mins(15));
        assert_eq!(WARNING_FIVE_MINUTES_REMAINING, Duration::from_mins(25));
        assert_eq!(WARNING_ONE_MINUTE_REMAINING, Duration::from_mins(29));
        assert_eq!(
            [
                RuntimeConfigSettlementPhase::OwnedPreflight.as_str(),
                RuntimeConfigSettlementPhase::Mutating.as_str(),
                RuntimeConfigSettlementPhase::SettlingRollback.as_str(),
            ],
            ["owned_preflight", "mutating", "settling_rollback"]
        );
        assert_eq!(
            [
                RuntimeConfigFenceReason::BudgetExpired.as_str(),
                RuntimeConfigFenceReason::ExecutorLost.as_str(),
                RuntimeConfigFenceReason::KnownDivergence.as_str(),
                RuntimeConfigFenceReason::PublicationAmbiguous.as_str(),
                RuntimeConfigFenceReason::AcknowledgementLost.as_str(),
            ],
            [
                "budget_expired",
                "executor_lost",
                "known_divergence",
                "publication_ambiguous",
                "acknowledgement_lost",
            ]
        );
        assert_eq!(
            [
                RuntimeConfigOperationKind::Sighup,
                RuntimeConfigOperationKind::Apply,
                RuntimeConfigOperationKind::GnmiSet,
                RuntimeConfigOperationKind::Confirm,
                RuntimeConfigOperationKind::Abort,
                RuntimeConfigOperationKind::Rollback,
                RuntimeConfigOperationKind::AutoRevert,
                RuntimeConfigOperationKind::NeighborAdd,
                RuntimeConfigOperationKind::NeighborDelete,
                RuntimeConfigOperationKind::DynamicNeighborAdd,
                RuntimeConfigOperationKind::DynamicNeighborDelete,
                RuntimeConfigOperationKind::FibSet,
                RuntimeConfigOperationKind::FibDelete,
                RuntimeConfigOperationKind::PeerGroupSet,
                RuntimeConfigOperationKind::PeerGroupDelete,
                RuntimeConfigOperationKind::NeighborPeerGroupSet,
                RuntimeConfigOperationKind::NeighborPeerGroupClear,
                RuntimeConfigOperationKind::PolicySet,
                RuntimeConfigOperationKind::PolicyDelete,
                RuntimeConfigOperationKind::NeighborSetSet,
                RuntimeConfigOperationKind::NeighborSetDelete,
                RuntimeConfigOperationKind::GlobalImportChainSet,
                RuntimeConfigOperationKind::GlobalExportChainSet,
                RuntimeConfigOperationKind::GlobalImportChainClear,
                RuntimeConfigOperationKind::GlobalExportChainClear,
                RuntimeConfigOperationKind::NeighborImportChainSet,
                RuntimeConfigOperationKind::NeighborExportChainSet,
                RuntimeConfigOperationKind::NeighborImportChainClear,
                RuntimeConfigOperationKind::NeighborExportChainClear,
            ]
            .map(RuntimeConfigOperationKind::as_str),
            [
                "sighup",
                "apply",
                "gnmi_set",
                "confirm",
                "abort",
                "rollback",
                "auto_revert",
                "neighbor_add",
                "neighbor_delete",
                "dynamic_neighbor_add",
                "dynamic_neighbor_delete",
                "fib_set",
                "fib_delete",
                "peer_group_set",
                "peer_group_delete",
                "neighbor_peer_group_set",
                "neighbor_peer_group_clear",
                "policy_set",
                "policy_delete",
                "neighbor_set_set",
                "neighbor_set_delete",
                "global_import_chain_set",
                "global_export_chain_set",
                "global_import_chain_clear",
                "global_export_chain_clear",
                "neighbor_import_chain_set",
                "neighbor_export_chain_set",
                "neighbor_import_chain_clear",
                "neighbor_export_chain_clear",
            ]
        );
    }

    #[test]
    fn metric_snapshot_decodes_one_packed_state_coherently() {
        for (phase_bits, expected_phase) in [
            (
                PHASE_PREFLIGHT,
                RuntimeConfigSettlementPhase::OwnedPreflight,
            ),
            (PHASE_MUTATING, RuntimeConfigSettlementPhase::Mutating),
            (
                PHASE_SETTLING,
                RuntimeConfigSettlementPhase::SettlingRollback,
            ),
        ] {
            let owned = SettlementMetricSnapshot::decode(TERMINAL_OWNED | phase_bits, true);
            assert_eq!(owned.phase, expected_phase);
            assert_eq!(owned.terminal, RuntimeConfigSettlementTerminal::Owned);
            assert_eq!(owned.fence_reason, None);
            assert!(owned.response_attached);

            let settled = SettlementMetricSnapshot::decode(TERMINAL_SETTLED | phase_bits, false);
            assert_eq!(settled.phase, expected_phase);
            assert_eq!(settled.terminal, RuntimeConfigSettlementTerminal::Settled);
            assert_eq!(settled.fence_reason, None);
            assert!(!settled.response_attached);

            for (reason_bits, expected_reason) in [
                (
                    AMBIGUITY_REASON_BUDGET,
                    RuntimeConfigFenceReason::BudgetExpired,
                ),
                (
                    AMBIGUITY_REASON_EXECUTOR,
                    RuntimeConfigFenceReason::ExecutorLost,
                ),
                (
                    FENCE_REASON_DIVERGENCE,
                    RuntimeConfigFenceReason::KnownDivergence,
                ),
                (
                    FENCE_REASON_PUBLICATION,
                    RuntimeConfigFenceReason::PublicationAmbiguous,
                ),
                (
                    FENCE_REASON_ACKNOWLEDGEMENT,
                    RuntimeConfigFenceReason::AcknowledgementLost,
                ),
            ] {
                let fenced = SettlementMetricSnapshot::decode(
                    TERMINAL_AMBIGUOUS | phase_bits | (reason_bits << REASON_SHIFT),
                    false,
                );
                assert_eq!(fenced.phase, expected_phase);
                assert_eq!(
                    fenced.terminal,
                    RuntimeConfigSettlementTerminal::RecoveryFenced
                );
                assert_eq!(fenced.fence_reason, Some(expected_reason));
                assert!(!fenced.response_attached);
            }
        }
    }

    #[test]
    fn collector_source_captures_state_and_attachment_exactly_once() {
        let source = include_str!("runtime_config_settlement.rs");
        let capture = source
            .split_once("fn capture(operation: &OperationInner) -> Self {")
            .unwrap()
            .1
            .split_once("fn decode(state: u8, response_attached: bool) -> Self {")
            .unwrap()
            .0;
        assert_eq!(capture.matches("operation.state.load(").count(), 1);
        assert_eq!(
            capture.matches("operation.response_attached.load(").count(),
            1
        );

        let collect = source
            .split_once("impl Collector for RuntimeConfigSettlementCollector {")
            .unwrap()
            .1
            .split_once("#[derive(Clone)]\npub struct RuntimeConfigSettlementWatchdog")
            .unwrap()
            .0;
        assert_eq!(
            collect
                .matches("SettlementMetricSnapshot::capture(&operation)")
                .count(),
            1
        );
        for forbidden in [
            "operation.state.load(",
            "operation.response_attached.load(",
            "operation.phase()",
            "operation.terminal()",
            "operation.fence_reason()",
            "GaugeVec::new(",
            "CounterVec::new(",
        ] {
            assert!(!collect.contains(forbidden), "collector used {forbidden}");
        }
    }

    #[tokio::test]
    async fn metrics_are_dynamic_single_tuple_and_idle_is_empty() {
        let (watchdog, receiver) = test_watchdog(Duration::from_secs(5), Duration::from_millis(20));
        let registry = prometheus::Registry::new();
        watchdog.register_metrics(&registry);
        assert!(encode_metric_families(&registry.gather()).is_empty());
        let (first_operation, guard, _, _) = operation(&watchdog, false).await;
        let attached = encode_metric_families(&registry.gather());
        assert!(attached.contains("kind=\"apply\""));
        assert!(attached.contains("phase=\"owned_preflight\""));
        assert!(attached.contains("response_attached=\"attached\""));
        assert!(attached.contains("fence_reason=\"none\""));
        first_operation
            .inner
            .response_attached
            .store(false, Ordering::Release);
        first_operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
        let detached = encode_metric_families(&registry.gather());
        assert!(detached.contains("phase=\"mutating\""));
        assert!(detached.contains("response_attached=\"detached\""));
        assert!(!detached.contains("phase=\"owned_preflight\""));
        assert!(!detached.contains("response_attached=\"attached\""));
        assert!(first_operation.try_settle());
        assert!(encode_metric_families(&registry.gather()).is_empty());
        drop(guard);

        let (operation, guard, _, _) = operation(&watchdog, false).await;
        assert!(operation.fence_recovery(RuntimeConfigFenceReason::KnownDivergence));
        wait_for_propagation(&operation);
        let fenced = metrics(&watchdog);
        assert!(fenced.contains("fence_reason=\"known_divergence\""));
        assert!(fenced.contains("bgp_runtime_config_settlement_fail_stops_total"));
        assert_eq!(
            fenced
                .lines()
                .filter(|line| line.starts_with("bgp_runtime_config_settlement_active{"))
                .count(),
            1
        );
        assert_eq!(receiver.recv_timeout(Duration::from_secs(1)).unwrap(), 70);
        drop(guard);
    }

    #[tokio::test]
    async fn scrape_derives_elapsed_from_start_instant_while_wedged_phase_is_frozen() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_mins(30), Duration::from_secs(5));
        let registry = prometheus::Registry::new();
        watchdog.register_metrics(&registry);
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
        // The operation is now wedged: nothing below writes any phase or
        // metric. Only the scrape clock advances, and each scrape must derive
        // elapsed from the stored start instant at that moment.
        let scrape_elapsed_at = |advance: Duration| {
            watchdog.registry.scrape_clock_advance_nanos.store(
                u64::try_from(advance.as_nanos()).unwrap(),
                Ordering::Release,
            );
            let text = encode_metric_families(&registry.gather());
            assert!(
                text.contains(
                    "bgp_runtime_config_settlement_active{fence_reason=\"none\",\
                     kind=\"apply\",phase=\"mutating\",response_attached=\"attached\"} 1"
                ),
                "wedged owner must stay active in its frozen phase: {text}"
            );
            assert!(!text.contains("phase=\"owned_preflight\""));
            assert!(text.contains("bgp_runtime_config_settlement_fail_stops_total{"));
            assert!(!text.contains("fail_stops_total{fence_reason=\"budget_expired\""));
            text.lines()
                .find(|line| line.starts_with("bgp_runtime_config_settlement_elapsed_seconds{"))
                .unwrap()
                .rsplit_once(' ')
                .unwrap()
                .1
                .parse::<f64>()
                .unwrap()
        };
        let fifteen = scrape_elapsed_at(Duration::from_mins(15));
        assert!(
            (900.0..905.0).contains(&fifteen),
            "scrape 15 minutes into the wedge must read 15 minutes, got {fifteen}"
        );
        let sixteen = scrape_elapsed_at(Duration::from_mins(16));
        assert!(
            sixteen - fifteen >= 59.0,
            "elapsed must keep growing on a frozen phase: {fifteen} -> {sixteen}"
        );
        assert_eq!(operation.phase(), RuntimeConfigSettlementPhase::Mutating);
        assert!(operation.try_settle());
        drop(guard);
    }

    #[tokio::test]
    async fn concurrent_scrapes_each_return_one_coherent_tuple() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(5), Duration::from_secs(1));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
        operation
            .inner
            .response_attached
            .store(false, Ordering::Release);
        let collector = Arc::new(RuntimeConfigSettlementCollector::new(Arc::clone(
            &watchdog.registry,
        )));
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let scrapes = (0..8)
            .map(|_| {
                let collector = Arc::clone(&collector);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    encode_metric_families(&collector.collect())
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for scrape in scrapes {
            let text = scrape.join().unwrap();
            for name in [
                "bgp_runtime_config_settlement_active{",
                "bgp_runtime_config_settlement_elapsed_seconds{",
                "bgp_runtime_config_settlement_budget_seconds{",
                "bgp_runtime_config_settlement_fail_stops_total{",
            ] {
                assert_eq!(
                    text.lines().filter(|line| line.starts_with(name)).count(),
                    1
                );
            }
            assert_eq!(text.matches("kind=\"apply\"").count(), 4);
            assert_eq!(text.matches("phase=\"mutating\"").count(), 4);
            assert_eq!(text.matches("response_attached=\"detached\"").count(), 4);
            assert_eq!(text.matches("fence_reason=\"none\"").count(), 4);
        }
        assert!(operation.try_settle());
        drop(guard);
    }

    #[tokio::test]
    #[should_panic(expected = "permits only one current operation")]
    async fn second_current_registration_is_an_invariant_failure() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(5), Duration::from_secs(1));
        let (_operation, _guard, _, _) = operation(&watchdog, false).await;
        let coordinator = RuntimeConfigCoordinator::new();
        let permit = coordinator.acquire().await.unwrap();
        let _ = watchdog.register_owned(
            RuntimeConfigOperationKind::Confirm,
            coordinator.clone(),
            permit,
            DaemonGate::new(),
            None,
            None,
            Arc::new(AtomicBool::new(false)),
        );
    }

    #[tokio::test]
    async fn warning_boundaries_fire_once_without_changing_deadline() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_mins(30), Duration::from_secs(5));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        let deadline = operation.deadline();
        let start = operation.inner.registered_at;
        emit_due_warnings(
            &operation.inner,
            (start + WARNING_HALF_BUDGET)
                .checked_sub(Duration::from_nanos(1))
                .unwrap(),
        );
        assert_eq!(operation.inner.warning_bits.load(Ordering::Acquire), 0);
        emit_due_warnings(&operation.inner, start + WARNING_HALF_BUDGET);
        emit_due_warnings(
            &operation.inner,
            start + WARNING_HALF_BUDGET + Duration::from_nanos(1),
        );
        assert_eq!(
            operation.inner.warning_bits.load(Ordering::Acquire),
            WARNING_HALF_BIT
        );
        emit_due_warnings(&operation.inner, start + WARNING_FIVE_MINUTES_REMAINING);
        emit_due_warnings(&operation.inner, start + WARNING_ONE_MINUTE_REMAINING);
        emit_due_warnings(&operation.inner, start + WARNING_ONE_MINUTE_REMAINING);
        assert_eq!(operation.inner.warning_bits.load(Ordering::Acquire), 0b111);
        assert_eq!(operation.deadline(), deadline);
        assert!(operation.try_settle());
        drop(guard);
    }

    #[tokio::test]
    async fn phase_is_monotonic_and_deadline_is_fixed() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(1), Duration::from_secs(1));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        let deadline = operation.deadline();
        operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
        operation.advance_phase(RuntimeConfigSettlementPhase::OwnedPreflight);
        assert_eq!(
            operation.phase(),
            RuntimeConfigSettlementPhase::SettlingRollback
        );
        assert_eq!(operation.deadline(), deadline);
        assert!(operation.try_settle());
        operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
        assert_eq!(
            operation.phase(),
            RuntimeConfigSettlementPhase::SettlingRollback
        );
        drop(guard);
    }

    #[tokio::test]
    async fn terminal_transition_freezes_phase_against_concurrent_advance() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(1), Duration::from_secs(1));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let advance = {
            let operation = operation.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
            })
        };
        let settle = {
            let operation = operation.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                operation.try_settle()
            })
        };
        barrier.wait();
        advance.join().unwrap();
        assert!(settle.join().unwrap());
        let frozen = operation.phase();
        operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
        assert_eq!(operation.phase(), frozen);
        drop(guard);
    }

    #[tokio::test]
    async fn recovery_fence_freezes_last_owned_phase() {
        let (watchdog, receiver) = test_watchdog(Duration::from_secs(5), Duration::from_millis(20));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        operation.advance_phase(RuntimeConfigSettlementPhase::Mutating);
        assert!(operation.fence_recovery(RuntimeConfigFenceReason::KnownDivergence));
        operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
        assert_eq!(operation.phase(), RuntimeConfigSettlementPhase::Mutating);
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
        drop(guard);
    }

    #[tokio::test]
    async fn settlement_releases_both_permits() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(1), Duration::from_secs(1));
        let (operation, guard, coordinator, admission) = operation(&watchdog, true).await;
        let coordinator_waiter = tokio::spawn({
            let coordinator = coordinator.clone();
            async move { coordinator.acquire().await }
        });
        let admission_waiter = tokio::spawn(admission.unwrap().acquire_owned());
        assert!(operation.try_settle());
        drop(guard);
        assert!(coordinator_waiter.await.unwrap().is_ok());
        assert!(admission_waiter.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn clean_settlement_freezes_preflight_phase() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(1), Duration::from_secs(1));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        assert!(operation.try_settle());
        operation.advance_phase(RuntimeConfigSettlementPhase::SettlingRollback);
        assert_eq!(
            operation.phase(),
            RuntimeConfigSettlementPhase::OwnedPreflight
        );
        drop(guard);
    }

    #[tokio::test]
    async fn executor_loss_fences_before_resources_release() {
        let (watchdog, receiver) = test_watchdog(Duration::from_secs(5), Duration::from_millis(20));
        let (operation, guard, coordinator, admission) = operation(&watchdog, true).await;
        drop(guard);
        wait_for_propagation(&operation);
        assert_eq!(
            operation.terminal(),
            RuntimeConfigSettlementTerminal::RecoveryFenced
        );
        assert_eq!(
            operation.fence_reason(),
            Some(RuntimeConfigFenceReason::ExecutorLost)
        );
        assert!(coordinator.is_closed());
        assert!(admission.unwrap().is_closed());
        assert!(!operation.try_settle());
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
    }

    #[tokio::test]
    async fn detected_ambiguity_closes_both_admission_resources() {
        let (watchdog, receiver) = test_watchdog(Duration::from_secs(5), Duration::from_millis(20));
        let (operation, guard, coordinator, admission) = operation(&watchdog, true).await;
        assert!(operation.fence_recovery(RuntimeConfigFenceReason::PublicationAmbiguous));
        wait_for_propagation(&operation);
        assert_eq!(
            operation.fence_reason(),
            Some(RuntimeConfigFenceReason::PublicationAmbiguous)
        );
        assert!(coordinator.is_closed());
        assert!(admission.unwrap().is_closed());
        assert!(!operation.try_settle());
        let fatal_at = operation.inner.fatal_at_nanos.load(Ordering::Acquire);
        assert!(!operation.fence_recovery(RuntimeConfigFenceReason::ExecutorLost));
        assert_eq!(
            operation.inner.fatal_at_nanos.load(Ordering::Acquire),
            fatal_at,
            "a repeated fence must neither reset nor extend grace"
        );
        assert!(metrics(&watchdog).contains(
            "bgp_runtime_config_settlement_fail_stops_total{fence_reason=\"publication_ambiguous\",kind=\"apply\",phase=\"owned_preflight\",response_attached=\"attached\"} 1"
        ));
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
        drop(guard);
    }

    #[tokio::test]
    async fn blocked_propagation_and_locks_cannot_delay_fatal_clock() {
        let (watchdog, receiver) = test_watchdog(Duration::from_secs(5), Duration::from_millis(20));
        let (operation, guard, _, _) = operation(&watchdog, true).await;
        let idle_lock = watchdog.registry.idle_lock.lock().unwrap();
        let resource_lock = operation.inner.resources.lock().unwrap();
        assert!(operation.fence_recovery(RuntimeConfigFenceReason::KnownDivergence));
        let deadline = Instant::now() + Duration::from_secs(1);
        while !operation.inner.propagation_claimed.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "observer did not claim propagation"
            );
            thread::yield_now();
        }
        assert!(metrics(&watchdog).contains(
            "bgp_runtime_config_settlement_fail_stops_total{fence_reason=\"known_divergence\",kind=\"apply\",phase=\"owned_preflight\",response_attached=\"attached\"} 1"
        ));
        assert!(
            !operation
                .inner
                .propagation_completed
                .load(Ordering::Acquire)
        );
        assert_eq!(receiver.recv_timeout(Duration::from_secs(1)).unwrap(), 70);
        drop(resource_lock);
        drop(idle_lock);
        wait_for_propagation(&operation);
        drop(guard);
    }

    #[test]
    fn production_terminal_wrapper_is_an_exact_exit_only_boundary() {
        let source = include_str!("runtime_config_settlement.rs");
        let body = source
            .split_once("fn terminate_process() -> ! {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        assert_eq!(
            body.trim(),
            "unsafe { libc::_exit(AMBIGUOUS_CONFIG_EXIT_STATUS) }"
        );
        for forbidden in [
            "lock", "alloc", "clone", "drop", "tracing", "metric", "write", "wait", "park",
            "sleep", "spawn", "dispatch", "panic", "unwrap",
        ] {
            assert!(
                !body.contains(forbidden),
                "terminal wrapper contains {forbidden}"
            );
        }
        assert!(source.contains("current: ArcSwapOption<OperationInner>"));
        let final_decision = source
            .split_once("if now >= fatal_at {")
            .unwrap()
            .1
            .split_once("\n                }")
            .unwrap()
            .0;
        assert_eq!(final_decision.trim(), "run_terminal_action(registry);");
    }

    #[tokio::test]
    async fn wait_until_idle_returns_only_after_clean_settlement() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(5), Duration::from_secs(1));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        let waiter = {
            let watchdog = watchdog.clone();
            thread::spawn(move || watchdog.wait_until_idle())
        };
        thread::sleep(Duration::from_millis(10));
        assert!(!waiter.is_finished());
        assert!(operation.try_settle());
        drop(guard);
        waiter.join().unwrap();
    }

    #[tokio::test]
    async fn shared_executor_outlives_rpc_cancellation_and_settles_cleanly() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(5), Duration::from_secs(1));
        let coordinator = RuntimeConfigCoordinator::new();
        let gate = DaemonGate::new();
        let (context, attachment) = OwnedRuntimeConfigRequestContext::unary();
        let (operation_tx, operation_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let executor = tokio::spawn({
            let watchdog = watchdog.clone();
            let coordinator = coordinator.clone();
            async move {
                watchdog
                    .execute_owned(
                        RuntimeConfigOperationKind::Sighup,
                        coordinator,
                        gate,
                        context.response_attached(),
                        move |operation| async move {
                            let _ = operation_tx.send(operation);
                            let _ = release_rx.await;
                            OwnedRuntimeConfigOutcome::<(), tonic::Status>::AcknowledgedAuthority(())
                        },
                    )
                    .await
            }
        });
        let operation = operation_rx.await.unwrap();
        executor.abort();
        let _ = executor.await;
        drop(attachment);
        assert!(!operation.response_attached());
        assert_eq!(operation.terminal(), RuntimeConfigSettlementTerminal::Owned);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), coordinator.acquire())
                .await
                .is_err(),
            "caller cancellation must not release coordinator ownership"
        );
        release_tx.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), coordinator.acquire())
                .await
                .unwrap()
                .is_ok()
        );
        assert_eq!(
            operation.terminal(),
            RuntimeConfigSettlementTerminal::Settled
        );
    }

    #[tokio::test]
    async fn shared_executor_ambiguity_fences_queued_and_future_owners() {
        let (watchdog, receiver) = test_watchdog(Duration::from_secs(5), Duration::from_millis(20));
        let coordinator = RuntimeConfigCoordinator::new();
        let gate = DaemonGate::new();
        let (context, _attachment) = OwnedRuntimeConfigRequestContext::unary();
        let (operation_tx, operation_rx) = tokio::sync::oneshot::channel();
        let (ambiguous_tx, ambiguous_rx) = tokio::sync::oneshot::channel();
        let executor = tokio::spawn({
            let watchdog = watchdog.clone();
            let coordinator = coordinator.clone();
            let gate = gate.clone();
            async move {
                watchdog
                    .execute_owned(
                        RuntimeConfigOperationKind::FibDelete,
                        coordinator,
                        gate,
                        context.response_attached(),
                        move |operation| async move {
                            let _ = operation_tx.send(operation);
                            let _ = ambiguous_rx.await;
                            OwnedRuntimeConfigOutcome::<(), tonic::Status>::Fenced {
                                error: tonic::Status::internal("typed recovery test outcome"),
                                reason: RuntimeConfigFenceReason::PublicationAmbiguous,
                            }
                        },
                    )
                    .await
            }
        });
        let operation = operation_rx.await.unwrap();
        let queued = tokio::spawn({
            let coordinator = coordinator.clone();
            async move { coordinator.acquire().await }
        });
        ambiguous_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while operation.terminal() == RuntimeConfigSettlementTerminal::Owned {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            operation.terminal(),
            RuntimeConfigSettlementTerminal::RecoveryFenced
        );
        assert_eq!(
            operation.fence_reason(),
            Some(RuntimeConfigFenceReason::PublicationAmbiguous)
        );
        wait_for_propagation(&operation);
        assert!(gate.is_shutting_down());
        assert!(queued.await.unwrap().is_err());
        assert!(coordinator.acquire().await.is_err());
        assert!(
            !executor.is_finished(),
            "ambiguous outcome must never return"
        );
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
        executor.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn std_thread_deadline_ignores_paused_tokio_clock_and_detach() {
        let (watchdog, receiver) =
            test_watchdog(Duration::from_millis(40), Duration::from_millis(20));
        let coordinator = RuntimeConfigCoordinator::new();
        let permit = coordinator.acquire().await.unwrap();
        let context = OwnedRuntimeConfigRequestContext::detached();
        let (operation, guard) = watchdog.register_owned(
            RuntimeConfigOperationKind::Sighup,
            coordinator.clone(),
            permit,
            DaemonGate::new(),
            None,
            None,
            context.response_attached(),
        );
        assert!(!operation.response_attached());
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
        assert!(coordinator.is_closed());
        assert_eq!(
            operation.fence_reason(),
            Some(RuntimeConfigFenceReason::BudgetExpired)
        );
        drop(guard);
    }

    #[tokio::test]
    async fn many_settlements_leave_no_registrations_and_share_thread() {
        let (watchdog, _receiver) = test_watchdog(Duration::from_secs(5), Duration::from_secs(1));
        let start_deadline = Instant::now() + Duration::from_secs(5);
        let thread_id = loop {
            if let Some(thread) = watchdog.registry.fatal_thread.get() {
                break thread.id();
            }
            assert!(
                Instant::now() < start_deadline,
                "watchdog thread failed to start"
            );
            thread::yield_now();
        };
        for _ in 0..32 {
            let (operation, guard, _, _) = operation(&watchdog, false).await;
            assert!(operation.try_settle());
            drop(guard);
        }
        assert!(watchdog.registry.current.load().is_none());
        assert_eq!(
            watchdog.registry.fatal_thread.get().map(thread::Thread::id),
            Some(thread_id),
        );
    }

    #[tokio::test]
    async fn settlement_and_executor_loss_have_exactly_one_winner() {
        let (watchdog, receiver) = test_watchdog(Duration::from_secs(5), Duration::from_millis(20));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let settle = {
            let operation = operation.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                operation.try_settle()
            })
        };
        let lose = {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                drop(guard);
            })
        };
        barrier.wait();
        let settled = settle.join().unwrap();
        lose.join().unwrap();
        assert_eq!(
            settled,
            operation.terminal() == RuntimeConfigSettlementTerminal::Settled
        );
        if settled {
            assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        } else {
            assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
        }
    }

    #[tokio::test]
    async fn settlement_and_deadline_have_exactly_one_winner() {
        let (watchdog, receiver) =
            test_watchdog(Duration::from_millis(2), Duration::from_millis(20));
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        thread::sleep(Duration::from_millis(2));
        let settled = operation.try_settle();
        assert_eq!(
            settled,
            operation.terminal() == RuntimeConfigSettlementTerminal::Settled
        );
        if settled {
            assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        } else {
            assert_eq!(
                operation.fence_reason(),
                Some(RuntimeConfigFenceReason::BudgetExpired)
            );
            assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), 70);
        }
        drop(guard);
    }

    #[tokio::test]
    async fn executor_loss_shortens_prearmed_fatal_deadline() {
        let old_deadline = Duration::from_secs(4);
        let grace = Duration::from_millis(20);
        let (watchdog, receiver) = test_watchdog(old_deadline, grace);
        let (operation, guard, _, _) = operation(&watchdog, false).await;
        let prearmed = operation.inner.fatal_at_nanos.load(Ordering::Acquire);
        let started = Instant::now();
        drop(guard);
        let shortened = operation.inner.fatal_at_nanos.load(Ordering::Acquire);
        assert!(shortened < prearmed);
        assert_eq!(receiver.recv_timeout(Duration::from_secs(1)).unwrap(), 70);
        assert!(started.elapsed() < old_deadline);
        assert_eq!(
            operation.fence_reason(),
            Some(RuntimeConfigFenceReason::ExecutorLost)
        );
    }

    #[test]
    fn debug_settlement_control_source_inventory_is_closed_and_ordered() {
        let runtime = include_str!("runtime_config_settlement.rs");
        let server = include_str!("server.rs");
        let controller = include_str!("../../../src/config_transaction_control.rs");
        let persister = include_str!("../../../src/config_persister.rs");
        let environment = ["RUSTBGPD_TEST_SETTLEMENT_", "CONTROL_DIR"].concat();
        assert_eq!(
            [runtime, server, controller, persister]
                .iter()
                .map(|source| source.matches(&environment).count())
                .sum::<usize>(),
            1
        );
        assert!(runtime.contains("settlement_test_control::duration_override()"));
        let ordered = |source: &str, needles: &[&str]| {
            let mut remainder = source;
            for needle in needles {
                remainder = remainder.split_once(needle).unwrap().1;
            }
        };
        ordered(
            controller
                .split_once("commit_candidate_snapshot_locked")
                .unwrap()
                .1,
            &[
                "progress.begin_mutation();",
                "Checkpoint::TransactionAfterBeginMutation",
                "stage_config_snapshot(",
            ],
        );
        ordered(
            server
                .split_once("dispatch_owned_catalog_mutation")
                .unwrap()
                .1,
            &[
                "peer_mgr_tx.send(command)",
                "Checkpoint::CatalogActorCommandAccepted",
                "timeout(timeout, reply_rx)",
            ],
        );
        ordered(
            persister
                .split_once("ReplaceConfigAck(new_config, ack)")
                .unwrap()
                .1,
            &[
                "Checkpoint::ReplaceBeforePublish",
                "self.discard_staged()",
                "let result = self.persist();",
                "if !drop_ack",
            ],
        );
        ordered(
            persister.split_once("CommitStagedConfig(ack)").unwrap().1,
            &[
                "Checkpoint::StagedCommitBeforePublish",
                "self.commit_staged()",
                "if !drop_ack",
            ],
        );
    }
}

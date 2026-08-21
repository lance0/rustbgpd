use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use nix::errno::Errno;
use nix::fcntl::{OFlag, openat, renameat};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};
use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix, Prefix};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::PinnedRuntimeStateDirectory;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;

const FILE_NAME: &str = "blackhole-owned.json";
const TEMP_PREFIX: &str = ".blackhole-owned.json.tmp";
const SCHEMA: &str = "rustbgpd.blackhole-owned/v1";
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PREFIXES: usize = 1_000_000;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    prefixes: Vec<String>,
}

/// Descriptor-relative authority for exact daemon-owned BLACKHOLE prefixes.
pub(super) struct OwnedStateStore {
    directory: Arc<PinnedRuntimeStateDirectory>,
    pub(super) fault: FaultPoint,
}

#[derive(Default)]
pub(super) struct OwnershipState {
    pub(super) store: Option<OwnedStateStore>,
    pub(super) prefixes: BTreeSet<Prefix>,
    pub(super) available: bool,
}

impl OwnershipState {
    pub(super) fn load(directory: Option<Arc<PinnedRuntimeStateDirectory>>) -> Self {
        let Some(directory) = directory else {
            warn!("BLACKHOLE ownership receipt unavailable: runtime-state authority unavailable");
            return Self::default();
        };
        match OwnedStateStore::load(directory) {
            Ok((store, prefixes)) => Self {
                store: Some(store),
                prefixes,
                available: true,
            },
            Err(error) => {
                warn!(%error, "BLACKHOLE ownership receipt unavailable; kernel mutations disabled");
                Self::default()
            }
        }
    }

    #[cfg(test)]
    pub(super) fn ephemeral(prefixes: impl IntoIterator<Item = Prefix>) -> Self {
        Self {
            store: None,
            prefixes: prefixes.into_iter().collect(),
            available: true,
        }
    }

    pub(super) fn replace(&mut self, next: BTreeSet<Prefix>) -> bool {
        if !self.available {
            return false;
        }
        if let Some(store) = &self.store
            && let Err(error) = store.replace(&self.prefixes, &next)
        {
            warn!(%error, "BLACKHOLE ownership persistence failed; kernel mutations disabled");
            self.available = false;
            return false;
        }
        self.prefixes = next;
        true
    }

    pub(super) fn add(&mut self, prefix: Prefix) -> bool {
        let mut next = self.prefixes.clone();
        next.insert(prefix);
        self.replace(next)
    }

    pub(super) fn remove(&mut self, prefix: Prefix) -> bool {
        if !self.prefixes.contains(&prefix) {
            self.available = false;
            return false;
        }
        let mut next = self.prefixes.clone();
        next.remove(&prefix);
        self.replace(next)
    }
}

impl OwnedStateStore {
    pub(super) fn load(
        directory: Arc<PinnedRuntimeStateDirectory>,
    ) -> Result<(Self, BTreeSet<Prefix>), String> {
        let store = Self {
            directory,
            fault: FaultPoint::None,
        };
        let prefixes = store.read()?.unwrap_or_default();
        Ok((store, prefixes))
    }

    pub(super) fn replace(
        &self,
        current: &BTreeSet<Prefix>,
        next: &BTreeSet<Prefix>,
    ) -> Result<(), String> {
        self.replace_inner(current, next, self.fault)
    }

    pub(super) fn replace_inner(
        &self,
        current: &BTreeSet<Prefix>,
        next: &BTreeSet<Prefix>,
        fault: FaultPoint,
    ) -> Result<(), String> {
        let temp_name = format!(
            "{TEMP_PREFIX}.{}.{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        self.replace_at(current, next, fault, &temp_name)
    }

    fn replace_at(
        &self,
        current: &BTreeSet<Prefix>,
        next: &BTreeSet<Prefix>,
        fault: FaultPoint,
        temp_name: &str,
    ) -> Result<(), String> {
        let on_disk = self.read()?;
        if on_disk.as_ref().is_none_or(BTreeSet::is_empty) && current.is_empty() {
            // Missing is empty authority only before anything has been owned.
        } else if on_disk.as_ref() != Some(current) {
            return Err("BLACKHOLE ownership receipt changed outside the actor".to_string());
        }
        if next.is_empty() {
            fault.fail(FaultPoint::Unlink)?;
            match unlinkat(&self.directory.file, FILE_NAME, UnlinkatFlags::NoRemoveDir) {
                Ok(()) => {}
                Err(Errno::ENOENT) if current.is_empty() => {}
                Err(error) => return Err(io_error(error)),
            }
            fault.fail(FaultPoint::DirectorySync)?;
            return self
                .directory
                .file
                .sync_all()
                .map_err(|error| error.to_string());
        }

        let encoded = encode(next)?;
        let mut temp_created = false;
        let mut renamed = false;
        let result = (|| -> Result<(), String> {
            fault.fail(FaultPoint::Write)?;
            let fd = openat(
                &self.directory.file,
                temp_name,
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(io_error)?;
            let mut temp = File::from(fd);
            temp_created = true;
            fchmod(&temp, Mode::from_bits_truncate(0o600)).map_err(io_error)?;
            validate_metadata(&temp, "temporary BLACKHOLE ownership receipt")?;
            temp.write_all(&encoded)
                .map_err(|error| error.to_string())?;
            fault.fail(FaultPoint::FileSync)?;
            temp.sync_all().map_err(|error| error.to_string())?;
            drop(temp);
            if self.read()? != on_disk {
                return Err("BLACKHOLE ownership receipt changed during publication".to_string());
            }
            fault.fail(FaultPoint::Rename)?;
            renameat(
                &self.directory.file,
                temp_name,
                &self.directory.file,
                FILE_NAME,
            )
            .map_err(io_error)?;
            renamed = true;
            fault.fail(FaultPoint::DirectorySync)?;
            self.directory
                .file
                .sync_all()
                .map_err(|error| error.to_string())
        })();
        if result.is_err() && temp_created && !renamed {
            let _ = unlinkat(&self.directory.file, temp_name, UnlinkatFlags::NoRemoveDir);
        }
        result.map_err(|error| {
            if renamed {
                format!("BLACKHOLE ownership publication visibility is ambiguous: {error}")
            } else {
                error
            }
        })
    }

    pub(super) fn read(&self) -> Result<Option<BTreeSet<Prefix>>, String> {
        let fd = match openat(
            &self.directory.file,
            FILE_NAME,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        let file = File::from(fd);
        validate_metadata(&file, "BLACKHOLE ownership receipt")?;
        if file.metadata().map_err(|error| error.to_string())?.len() > MAX_BYTES {
            return Err(format!("ownership receipt exceeds {MAX_BYTES} bytes"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(format!("ownership receipt exceeds {MAX_BYTES} bytes"));
        }
        decode(&bytes).map(Some)
    }
}

fn validate_metadata(file: &File, label: &str) -> Result<(), String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(format!("{label} has unsafe identity"));
    }
    Ok(())
}

fn encode(prefixes: &BTreeSet<Prefix>) -> Result<Vec<u8>, String> {
    if prefixes.len() > MAX_PREFIXES {
        return Err(format!("ownership receipt exceeds {MAX_PREFIXES} prefixes"));
    }
    serde_json::to_vec(&Receipt {
        schema: SCHEMA.to_string(),
        prefixes: prefixes.iter().map(ToString::to_string).collect(),
    })
    .map_err(|error| error.to_string())
}

fn decode(bytes: &[u8]) -> Result<BTreeSet<Prefix>, String> {
    let receipt: Receipt = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if receipt.schema != SCHEMA {
        return Err("unsupported BLACKHOLE ownership receipt schema".to_string());
    }
    if receipt.prefixes.len() > MAX_PREFIXES {
        return Err(format!("ownership receipt exceeds {MAX_PREFIXES} prefixes"));
    }
    let mut prefixes = BTreeSet::new();
    let mut previous = None;
    for raw in receipt.prefixes {
        let prefix = parse_prefix(&raw)?;
        if previous.is_some_and(|value| value >= prefix) || !prefixes.insert(prefix) {
            return Err("BLACKHOLE ownership prefixes are not sorted and unique".to_string());
        }
        previous = Some(prefix);
    }
    Ok(prefixes)
}

fn parse_prefix(raw: &str) -> Result<Prefix, String> {
    let (address, length) = raw
        .rsplit_once('/')
        .filter(|(address, length)| !address.contains('/') && !length.is_empty())
        .ok_or_else(|| "invalid BLACKHOLE ownership prefix".to_string())?;
    let length = length
        .parse::<u8>()
        .map_err(|_| "invalid BLACKHOLE ownership prefix length".to_string())?;
    let prefix = match address
        .parse::<IpAddr>()
        .map_err(|_| "invalid BLACKHOLE ownership address".to_string())?
    {
        IpAddr::V4(address) if length <= 32 => Prefix::V4(Ipv4Prefix::new(address, length)),
        IpAddr::V6(address) if length <= 128 => Prefix::V6(Ipv6Prefix::new(address, length)),
        _ => return Err("invalid BLACKHOLE ownership family length".to_string()),
    };
    if prefix.to_string() != raw {
        return Err("noncanonical BLACKHOLE ownership prefix".to_string());
    }
    Ok(prefix)
}

fn io_error(error: Errno) -> String {
    std::io::Error::from_raw_os_error(error as i32).to_string()
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FaultPoint {
    None,
    Write,
    FileSync,
    Rename,
    Unlink,
    DirectorySync,
}

impl FaultPoint {
    fn fail(self, at: Self) -> Result<(), String> {
        (self != at)
            .then_some(())
            .ok_or_else(|| "injected ownership persistence failure".to_string())
    }
}

#[cfg(test)]
pub(super) fn test_store() -> (tempfile::TempDir, OwnedStateStore, BTreeSet<Prefix>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let pinned = Arc::new(PinnedRuntimeStateDirectory::prepare(dir.path()).unwrap());
    let (store, empty) = OwnedStateStore::load(pinned).unwrap();
    assert!(empty.is_empty());
    let prefixes = [
        parse_prefix("192.0.2.0/24").unwrap(),
        parse_prefix("2001:db8::/32").unwrap(),
    ]
    .into();
    (dir, store, prefixes)
}
#[cfg(test)]
#[test]
fn receipt_identity_and_durability_are_strict() {
    use FaultPoint::{DirectorySync, FileSync, Rename, Unlink, Write};

    let (dir, store, expected) = test_store();
    let final_path = dir.path().join(FILE_NAME);
    store.replace(&BTreeSet::new(), &expected).unwrap();
    assert_eq!(store.read().unwrap(), Some(expected.clone()));
    store.replace(&expected, &BTreeSet::new()).unwrap();
    assert_eq!(store.read().unwrap(), None);
    std::os::unix::fs::symlink("target", &final_path).unwrap();
    assert!(store.replace(&expected, &BTreeSet::new()).is_err());
    std::fs::remove_file(&final_path).unwrap();
    let stale = dir.path().join(TEMP_PREFIX);
    std::os::unix::fs::symlink("stale", &stale).unwrap();
    store.replace(&BTreeSet::new(), &expected).unwrap();
    assert_eq!(std::fs::read_link(&stale).unwrap().to_str(), Some("stale"));
    store.replace(&expected, &BTreeSet::new()).unwrap();
    let planted_name = format!("{TEMP_PREFIX}.planted");
    let planted = dir.path().join(&planted_name);
    std::os::unix::fs::symlink("sentinel", &planted).unwrap();
    let refused = store.replace_at(&BTreeSet::new(), &expected, FaultPoint::None, &planted_name);
    assert!(refused.is_err());
    let target = std::fs::read_link(&planted).unwrap();
    assert_eq!(target.to_str(), Some("sentinel"));
    let oversized = std::fs::File::create(&final_path).unwrap();
    oversized
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    oversized.set_len(MAX_BYTES + 1).unwrap();
    assert!(store.read().is_err());
    std::fs::remove_file(&final_path).unwrap();
    store.replace(&BTreeSet::new(), &expected).unwrap();
    let link = dir.path().join("hardlink");
    std::fs::hard_link(&final_path, &link).unwrap();
    assert!(store.read().is_err());
    std::fs::remove_file(link).unwrap();
    std::fs::set_permissions(&final_path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(store.read().is_err());
    std::fs::remove_file(&final_path).unwrap();
    std::fs::create_dir(&final_path).unwrap();
    assert!(store.read().is_err());
    let fails = |fault, removing| {
        let (_dir, store, prefixes) = test_store();
        if removing {
            store.replace(&BTreeSet::new(), &prefixes).unwrap();
        }
        let empty = BTreeSet::new();
        let (current, next) = if removing {
            (&prefixes, &empty)
        } else {
            (&empty, &prefixes)
        };
        assert!(store.replace_inner(current, next, fault).is_err());
    };
    for fault in [Write, FileSync, Rename, DirectorySync] {
        fails(fault, false);
    }
    for fault in [Unlink, DirectorySync] {
        fails(fault, true);
    }
}
#[cfg(test)]
#[test]
fn strict_receipt_data_is_refused() {
    for bytes in [br#"{"schema":"new","prefixes":[]}"#.as_slice(), b"{"] {
        let (dir, store, expected) = test_store();
        let path = dir.path().join(FILE_NAME);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut state = OwnershipState::load(Some(store.directory));
        assert!(!state.available && !state.add(*expected.first().unwrap()));
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    for bytes in [
        br#"{"schema":"rustbgpd.blackhole-owned/v1","prefixes":[],"extra":1}"#.as_slice(),
        br#"{"schema":"rustbgpd.blackhole-owned/v1","prefixes":["192.0.2.0/24","192.0.2.0/24"]}"#,
        br#"{"schema":"rustbgpd.blackhole-owned/v1","prefixes":["2001:db8::/32","192.0.2.0/24"]}"#,
    ] {
        assert!(decode(bytes).is_err());
    }
    for raw in [
        "192.0.2.1/24",
        "192.0.2.0/024",
        "192.0.2.0/33",
        "2001:DB8::/32",
    ] {
        assert!(parse_prefix(raw).is_err());
    }
    let too_many = Receipt {
        schema: SCHEMA.to_string(),
        prefixes: vec!["0.0.0.0/0".to_string(); MAX_PREFIXES + 1],
    };
    assert!(decode(&serde_json::to_vec(&too_many).unwrap()).is_err());
}
#[test]
fn umask_is_overridden() {
    if std::env::var_os("RUSTBGPD_BLACKHOLE_UMASK_CHILD").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "blackhole::owned_state::umask_is_overridden"])
            .env("RUSTBGPD_BLACKHOLE_UMASK_CHILD", "1")
            .status()
            .unwrap();
        let source = include_str!("owned_state.rs");
        assert!(status.success() && source.contains("temp_created = true;\n            fchmod"));
        return;
    }
    let (dir, store, expected) = test_store();
    let previous = nix::sys::stat::umask(Mode::from_bits_truncate(0o777));
    let published = store.replace(&BTreeSet::new(), &expected);
    nix::sys::stat::umask(previous);
    published.unwrap();
    let mode = std::fs::metadata(dir.path().join(FILE_NAME))
        .unwrap()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

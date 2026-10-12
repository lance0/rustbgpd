//! ADR-0140 decision 6: the write-ahead ownership receipt for links the
//! core-isolation hold took administratively down.
//!
//! Admin state has no kernel owner marker, so ownership is an
//! exact-value receipt in `runtime_state_dir` (the ADR-0079 pattern used
//! by the BLACKHOLE and FIB receipts):
//!
//! - every update is published atomically: temporary file, fsync,
//!   rename over the receipt, fsync of the directory; an empty receipt
//!   is unlinked;
//! - mutual exclusion uses a separate lock file that is created once and
//!   never renamed or removed, because a rename replaces the receipt's
//!   inode. The daemon holds an exclusive `flock` on it for its lifetime;
//!   the release helper takes it without blocking.
//!
//! Each entry records the incarnation identity the safe rule compares:
//! boot ID, network namespace, binding, ifindex, name, permanent and
//! assigned MACs, and the master bond.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg, OFlag, open, openat, renameat};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{UnlinkatFlags, geteuid, unlinkat};
use rustbgpd_evpn_linux::AdminLinkState;
use serde::{Deserialize, Serialize};

/// Receipt file name inside `runtime_state_dir`.
pub(crate) const RECEIPT_FILE: &str = "evpn-core-isolation-owned.json";
/// Stable lock file beside the receipt.
pub(crate) const LOCK_FILE: &str = "evpn-core-isolation-owned.json.lock";
const TEMP_PREFIX: &str = ".evpn-core-isolation-owned.json.tmp";
const SCHEMA: &str = "rustbgpd.evpn-core-isolation-owned/v1";
const MAX_BYTES: u64 = 4 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Network namespace identity: the device and inode of
/// `/proc/self/ns/net`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetnsId {
    pub dev: u64,
    pub ino: u64,
}

/// The incarnation context a receipt entry is valid in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostIdentity {
    pub boot_id: String,
    pub netns: NetnsId,
}

impl HostIdentity {
    /// Read the kernel boot ID and this process's network namespace.
    pub(crate) fn current() -> Result<Self, String> {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|error| format!("cannot read the kernel boot ID: {error}"))?
            .trim()
            .to_string();
        let netns = std::fs::metadata("/proc/self/ns/net")
            .map_err(|error| format!("cannot identify the network namespace: {error}"))?;
        Ok(Self {
            boot_id,
            netns: NetnsId {
                dev: netns.dev(),
                ino: netns.ino(),
            },
        })
    }
}

/// The master bond of an owned member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MasterIdentity {
    pub ifindex: u32,
    pub name: String,
}

/// Everything netlink exposes that tells one link incarnation from
/// another. Absent attributes are recorded as absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinkIdentity {
    pub ifindex: u32,
    pub name: String,
    /// `IFLA_PERM_ADDRESS`.
    pub perm_address: Option<String>,
    /// `IFLA_BOND_SLAVE_PERM_HWADDR`.
    pub bond_perm_hwaddr: Option<String>,
    /// `IFLA_ADDRESS`.
    pub address: Option<String>,
    pub master: Option<MasterIdentity>,
}

impl LinkIdentity {
    /// Identity of `link`, whose `IFLA_MASTER` resolves to `master`. A
    /// master index that does not resolve keeps the index with an empty
    /// name, so it can never match a recorded master.
    pub(crate) fn of(link: &AdminLinkState, master: Option<&AdminLinkState>) -> Self {
        Self {
            ifindex: link.ifindex,
            name: link.name.clone(),
            perm_address: link.perm_address.as_deref().map(mac_text),
            bond_perm_hwaddr: link.bond_perm_hwaddr.as_deref().map(mac_text),
            address: link.address.as_deref().map(mac_text),
            master: link.master.map(|ifindex| MasterIdentity {
                ifindex,
                name: master
                    .filter(|m| m.ifindex == ifindex)
                    .map(|m| m.name.clone())
                    .unwrap_or_default(),
            }),
        }
    }

    /// Identity of `link` with its master resolved from `links`.
    pub(crate) fn in_dump(link: &AdminLinkState, links: &[AdminLinkState]) -> Self {
        let master = link
            .master
            .and_then(|index| links.iter().find(|l| l.ifindex == index));
        Self::of(link, master)
    }
}

/// One owned link: intent to hold it down, recorded before the write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnedLink {
    pub boot_id: String,
    pub netns: NetnsId,
    /// The binding's configured `esi` text.
    pub esi: String,
    /// The bound interface name.
    pub binding: String,
    pub link: LinkIdentity,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    links: Vec<OwnedLink>,
}

/// How a receipt entry relates to current kernel state (the safe rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Guard {
    /// Another boot: the entry is stale and discarded untouched.
    ForeignBoot,
    /// Exactly one link matches every recorded field.
    Matched { ifindex: u32, admin_up: bool },
    /// Anything else: the link is never raised and the entry is kept.
    Ambiguous(String),
}

/// Apply the safe rule to `entry` against a full link dump.
pub(crate) fn classify(entry: &OwnedLink, host: &HostIdentity, links: &[AdminLinkState]) -> Guard {
    if entry.boot_id != host.boot_id {
        return Guard::ForeignBoot;
    }
    if entry.netns != host.netns {
        return Guard::Ambiguous("recorded in another network namespace".to_string());
    }
    let candidates: Vec<&AdminLinkState> = links
        .iter()
        .filter(|l| l.ifindex == entry.link.ifindex || l.name == entry.link.name)
        .collect();
    match candidates.as_slice() {
        [] => Guard::Ambiguous("link is missing".to_string()),
        [link] => {
            let current = LinkIdentity::in_dump(link, links);
            if current == entry.link {
                Guard::Matched {
                    ifindex: link.ifindex,
                    admin_up: link.admin_up,
                }
            } else {
                Guard::Ambiguous(describe_mismatch(&entry.link, &current))
            }
        }
        _ => Guard::Ambiguous("more than one link matches its name or ifindex".to_string()),
    }
}

/// Whether an ambiguous entry no longer owns anything: no link carries
/// its recorded ifindex or name, or every such link is admin-up (the
/// operator raised it). Dropping such an entry raises nothing. An entry
/// whose link still exists and is admin-down is kept.
pub(crate) fn ambiguous_entry_is_stale(entry: &OwnedLink, links: &[AdminLinkState]) -> bool {
    links
        .iter()
        .filter(|l| l.ifindex == entry.link.ifindex || l.name == entry.link.name)
        .all(|l| l.admin_up)
}

fn describe_mismatch(recorded: &LinkIdentity, current: &LinkIdentity) -> String {
    let mut fields = Vec::new();
    if recorded.ifindex != current.ifindex {
        fields.push("ifindex");
    }
    if recorded.name != current.name {
        fields.push("name");
    }
    if recorded.perm_address != current.perm_address
        || recorded.bond_perm_hwaddr != current.bond_perm_hwaddr
    {
        fields.push("permanent MAC");
    }
    if recorded.address != current.address {
        fields.push("assigned MAC");
    }
    if recorded.master != current.master {
        fields.push("master");
    }
    format!("identity changed: {}", fields.join(", "))
}

fn mac_text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Why the store could not be opened.
#[derive(Debug)]
pub(crate) enum OpenError {
    /// Another process (a live daemon or a running helper) holds the lock.
    Locked,
    Other(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => f.write_str("another rustbgpd process holds the core-isolation lock"),
            Self::Other(message) => f.write_str(message),
        }
    }
}

/// The receipt directory with the lock held. Dropping it releases the
/// lock.
pub(crate) struct ReceiptStore {
    directory: File,
    _lock: Flock<File>,
}

impl ReceiptStore {
    /// Open an existing runtime-state directory by path, without creating
    /// it, and take the lock without blocking.
    pub(crate) fn open_path(path: &Path) -> Result<Self, OpenError> {
        let fd = open(
            path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| {
            OpenError::Other(format!(
                "cannot open runtime-state directory {}: {}",
                path.display(),
                io_error(error)
            ))
        })?;
        let directory = File::from(fd);
        let metadata = directory
            .metadata()
            .map_err(|error| OpenError::Other(error.to_string()))?;
        if !metadata.is_dir()
            || metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return Err(OpenError::Other(format!(
                "runtime-state directory {} has an unsafe owner or mode",
                path.display()
            )));
        }
        Self::lock(directory)
    }

    /// Take the lock on an already pinned directory.
    pub(crate) fn lock(directory: File) -> Result<Self, OpenError> {
        let fd = openat(
            &directory,
            LOCK_FILE,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| {
            OpenError::Other(format!("cannot open {LOCK_FILE}: {}", io_error(error)))
        })?;
        let lock = Flock::lock(File::from(fd), FlockArg::LockExclusiveNonblock).map_err(
            |(_, error)| match error {
                Errno::EWOULDBLOCK => OpenError::Locked,
                other => OpenError::Other(format!("cannot lock {LOCK_FILE}: {}", io_error(other))),
            },
        )?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }

    /// Whether a receipt file exists in `directory`, without the lock.
    pub(crate) fn receipt_exists(directory: &File) -> bool {
        nix::sys::stat::fstatat(
            directory,
            RECEIPT_FILE,
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .is_ok()
    }

    /// Read the receipt; `Ok(None)` when it does not exist.
    pub(crate) fn read(&self) -> Result<Option<Vec<OwnedLink>>, String> {
        let fd = match openat(
            &self.directory,
            RECEIPT_FILE,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(format!("cannot open {RECEIPT_FILE}: {}", io_error(error))),
        };
        let file = File::from(fd);
        validate_metadata(&file)?;
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read {RECEIPT_FILE}: {error}"))?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(format!("{RECEIPT_FILE} exceeds {MAX_BYTES} bytes"));
        }
        let receipt: Receipt = serde_json::from_slice(&bytes)
            .map_err(|error| format!("cannot parse {RECEIPT_FILE}: {error}"))?;
        if receipt.schema != SCHEMA {
            return Err(format!(
                "{RECEIPT_FILE} has unsupported schema {:?}",
                receipt.schema
            ));
        }
        Ok(Some(receipt.links))
    }

    /// Atomically publish `links` as the whole receipt; an empty set
    /// removes it. Durable when this returns `Ok`.
    pub(crate) fn publish(&self, links: &[OwnedLink]) -> Result<(), String> {
        if links.is_empty() {
            match unlinkat(&self.directory, RECEIPT_FILE, UnlinkatFlags::NoRemoveDir) {
                Ok(()) | Err(Errno::ENOENT) => {}
                Err(error) => {
                    return Err(format!("cannot remove {RECEIPT_FILE}: {}", io_error(error)));
                }
            }
            return self
                .directory
                .sync_all()
                .map_err(|error| format!("cannot sync the runtime-state directory: {error}"));
        }
        let encoded = serde_json::to_vec_pretty(&Receipt {
            schema: SCHEMA.to_string(),
            links: links.to_vec(),
        })
        .map_err(|error| error.to_string())?;
        let temp_name = format!(
            "{TEMP_PREFIX}.{}.{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let mut renamed = false;
        let result = (|| -> Result<(), String> {
            let fd = openat(
                &self.directory,
                temp_name.as_str(),
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(|error| format!("cannot create the temporary receipt: {}", io_error(error)))?;
            let mut temp = File::from(fd);
            fchmod(&temp, Mode::from_bits_truncate(0o600)).map_err(io_error)?;
            temp.write_all(&encoded)
                .map_err(|error| error.to_string())?;
            temp.sync_all().map_err(|error| error.to_string())?;
            drop(temp);
            renameat(
                &self.directory,
                temp_name.as_str(),
                &self.directory,
                RECEIPT_FILE,
            )
            .map_err(|error| format!("cannot publish {RECEIPT_FILE}: {}", io_error(error)))?;
            renamed = true;
            self.directory
                .sync_all()
                .map_err(|error| format!("cannot sync the runtime-state directory: {error}"))
        })();
        if result.is_err() && !renamed {
            let _ = unlinkat(
                &self.directory,
                temp_name.as_str(),
                UnlinkatFlags::NoRemoveDir,
            );
        }
        result
    }
}

fn validate_metadata(file: &File) -> Result<(), String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(format!(
            "{RECEIPT_FILE} has an unsafe type, owner, mode or link count"
        ));
    }
    Ok(())
}

fn io_error(error: Errno) -> String {
    std::io::Error::from_raw_os_error(error as i32).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> HostIdentity {
        HostIdentity {
            boot_id: "boot-a".into(),
            netns: NetnsId {
                dev: 4,
                ino: 4_026_531_840,
            },
        }
    }

    fn link(ifindex: u32, name: &str, master: Option<u32>) -> AdminLinkState {
        AdminLinkState {
            ifindex,
            name: name.into(),
            admin_up: false,
            carrier: false,
            is_bond: master.is_none() && name.starts_with("bond"),
            master,
            address: Some(vec![2, 0, 0, 0, 0, 1]),
            perm_address: None,
            bond_perm_hwaddr: master.map(|_| vec![2, 0, 0, 0, 0, u8::try_from(ifindex).unwrap()]),
        }
    }

    fn entry(member: &AdminLinkState, links: &[AdminLinkState]) -> OwnedLink {
        OwnedLink {
            boot_id: "boot-a".into(),
            netns: host().netns,
            esi: "auto-lacp".into(),
            binding: "bond0".into(),
            link: LinkIdentity::in_dump(member, links),
        }
    }

    #[test]
    fn safe_rule_raises_only_an_exact_unique_match() {
        let links = vec![link(3, "bond0", None), link(7, "m0", Some(3))];
        let owned = entry(&links[1], &links);
        assert_eq!(
            classify(&owned, &host(), &links),
            Guard::Matched {
                ifindex: 7,
                admin_up: false
            }
        );

        let mut foreign = owned.clone();
        foreign.boot_id = "boot-b".into();
        assert_eq!(classify(&foreign, &host(), &links), Guard::ForeignBoot);

        let mut other_ns = owned.clone();
        other_ns.netns.ino += 1;
        assert!(matches!(
            classify(&other_ns, &host(), &links),
            Guard::Ambiguous(_)
        ));

        // Renamed: same ifindex, new name.
        let renamed = vec![links[0].clone(), link(7, "m0-new", Some(3))];
        assert!(matches!(
            classify(&owned, &host(), &renamed),
            Guard::Ambiguous(_)
        ));
        // Recreated: same name, new ifindex.
        let recreated = vec![links[0].clone(), link(9, "m0", Some(3))];
        assert!(matches!(
            classify(&owned, &host(), &recreated),
            Guard::Ambiguous(_)
        ));
        // Left the bond.
        let released = vec![links[0].clone(), link(7, "m0", None)];
        assert!(matches!(
            classify(&owned, &host(), &released),
            Guard::Ambiguous(_)
        ));
        // Missing, and two candidates.
        assert!(matches!(
            classify(&owned, &host(), &links[..1]),
            Guard::Ambiguous(_)
        ));
        let two = vec![
            links[0].clone(),
            link(7, "x", Some(3)),
            link(8, "m0", Some(3)),
        ];
        assert!(matches!(
            classify(&owned, &host(), &two),
            Guard::Ambiguous(_)
        ));
    }

    #[test]
    fn publication_is_atomic_and_lock_is_exclusive_across_receipt_updates() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let store = ReceiptStore::open_path(dir.path()).unwrap();
        assert_eq!(store.read().unwrap(), None);
        let links = vec![link(3, "bond0", None), link(7, "m0", Some(3))];
        store.publish(&[entry(&links[1], &links)]).unwrap();
        assert_eq!(store.read().unwrap().unwrap().len(), 1);
        // The receipt's inode changed; the lock file did not, so a second
        // opener is still refused.
        store
            .publish(&[entry(&links[1], &links), entry(&links[0], &links)])
            .unwrap();
        assert!(matches!(
            ReceiptStore::open_path(dir.path()),
            Err(OpenError::Locked)
        ));
        store.publish(&[]).unwrap();
        assert!(!dir.path().join(RECEIPT_FILE).exists());
        assert!(dir.path().join(LOCK_FILE).exists(), "the lock file stays");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().starts_with(TEMP_PREFIX))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        drop(store);
        assert!(ReceiptStore::open_path(dir.path()).is_ok());
    }
}

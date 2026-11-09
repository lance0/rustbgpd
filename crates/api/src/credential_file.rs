//! Admission rules for management-plane credential files.
//!
//! One judgement shared by config load, credential staging and reload,
//! `rustbgpd --check`, and `rbgp doctor`, so they cannot disagree. The CLI
//! compiles this file directly instead of depending on the API crate, so it
//! uses only `std` and `nix`.
//!
//! Every credential file must be a regular file once symlinks are followed:
//! a directory or FIFO is refused, and opening never blocks on one. A credential
//! file that any local user can write is refused. A token or
//! key readable beyond the daemon is accepted with a warning: owned by
//! someone other than the daemon user or root, readable by every user, or
//! accessible to a group other than the daemon's. Mode `0600` owned by the
//! daemon user and `0640 root:<daemon group>` (the packaged config pattern)
//! pass silently. Certificates, CA bundles and CRLs are public.

use std::fs::{File, Metadata, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

/// What a credential file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialKind {
    /// A bearer token or private key: only the daemon may read it.
    Secret,
    /// A certificate, CA bundle, or CRL.
    Public,
}

/// The user and group the daemon runs as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaemonIdentity {
    pub uid: u32,
    pub gid: u32,
}

impl DaemonIdentity {
    /// The calling process's effective user and group.
    #[must_use]
    pub fn current() -> Self {
        Self {
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
        }
    }
}

/// The judgement on one credential file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    /// Accepted; the message names the file, its mode and owner, and the fix.
    Warn(String),
    /// Refused; the message names the file and the reason.
    Refuse(String),
}

/// Judge a credential file from the metadata of its final target. With no
/// `daemon` identity (an offline doctor run) only the mode is judged.
#[must_use]
pub fn assess(
    path: &Path,
    label: &str,
    kind: CredentialKind,
    metadata: &Metadata,
    daemon: Option<DaemonIdentity>,
) -> Verdict {
    let path = path.display();
    if !metadata.is_file() {
        return Verdict::Refuse(format!(
            "{label} file {path} is not a regular file (after following symlinks)"
        ));
    }
    if metadata.len() > MAX_CREDENTIAL_FILE_BYTES {
        return Verdict::Refuse(format!(
            "{label} file {path} is larger than {MAX_CREDENTIAL_FILE_BYTES} bytes"
        ));
    }
    let mode = metadata.mode() & 0o7777;
    let (uid, gid) = (metadata.uid(), metadata.gid());
    if mode & 0o002 != 0 {
        return Verdict::Refuse(format!(
            "{label} file {path} is world-writable (mode {mode:04o}); any local user could replace it"
        ));
    }
    if kind == CredentialKind::Public {
        return Verdict::Accept;
    }
    let mut problems = Vec::new();
    if mode & 0o004 != 0 {
        problems.push("readable by every local user".to_string());
    }
    if let Some(daemon) = daemon {
        if uid != daemon.uid && uid != 0 {
            problems.push(format!(
                "owned by uid {uid}, not the daemon user (uid {}) or root",
                daemon.uid
            ));
        }
        if mode & 0o060 != 0 && gid != daemon.gid {
            problems.push(format!(
                "accessible to group gid {gid}, not the daemon's group (gid {})",
                daemon.gid
            ));
        }
    }
    if problems.is_empty() {
        return Verdict::Accept;
    }
    let group = daemon.map_or_else(
        || "<daemon group>".to_string(),
        |daemon| {
            nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(daemon.gid))
                .ok()
                .flatten()
                .map_or_else(|| daemon.gid.to_string(), |group| group.name)
        },
    );
    Verdict::Warn(format!(
        "{label} file {path} (mode {mode:04o}, owner {uid}:{gid}) is {}; restrict it with \
         `chmod 600` owned by the daemon user, or mode 0640 owned by root:{group}",
        problems.join(" and ")
    ))
}

/// Open a credential file for reading after judging what the opened handle
/// refers to, so the judged file is the file read. Returns the handle and any
/// warning.
///
/// # Errors
/// Returns the open failure or the refusal reason.
pub fn open_credential(
    path: &Path,
    label: &str,
    kind: CredentialKind,
    daemon: DaemonIdentity,
) -> Result<(File, Option<String>), String> {
    // Non-blocking, so a FIFO planted at the path cannot stall the open;
    // regular-file reads ignore the flag.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open(path)
        .map_err(|e| format!("failed to read {label} file {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("failed to inspect {label} file {}: {e}", path.display()))?;
    match assess(path, label, kind, &metadata, Some(daemon)) {
        Verdict::Accept => Ok((file, None)),
        Verdict::Warn(warning) => Ok((file, Some(warning))),
        Verdict::Refuse(reason) => Err(reason),
    }
}

/// Maximum size of any management credential file.
pub const MAX_CREDENTIAL_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Read into the caller-owned buffer from the judged descriptor, including
/// a one-byte oversize probe. Secret callers keep the buffer zeroizing even
/// when admission or reading fails.
///
/// # Errors
/// Returns the admission or bounded read failure.
pub fn read_credential(
    path: &Path,
    label: &str,
    kind: CredentialKind,
    daemon: DaemonIdentity,
    bytes: &mut Vec<u8>,
) -> Result<Option<String>, String> {
    let (file, warning) = open_credential(path, label, kind, daemon)?;
    // Size the buffer once from the judged descriptor: growing it while
    // reading would free unscrubbed partial copies of a secret.
    let len = file
        .metadata()
        .map_err(|e| format!("failed to inspect {label} file {}: {e}", path.display()))?
        .len()
        .min(MAX_CREDENTIAL_FILE_BYTES);
    bytes.reserve_exact(usize::try_from(len + 1).unwrap_or(usize::MAX));
    read_bounded(file, MAX_CREDENTIAL_FILE_BYTES, bytes)
        .map_err(|error| format!("failed to read {label} file {}: {error}", path.display()))?;
    Ok(warning)
}

/// Read at most `max_bytes + 1` bytes from an already admitted file.
///
/// # Errors
/// Returns a read failure or an oversize error.
pub fn read_bounded(
    reader: impl std::io::Read,
    max_bytes: u64,
    bytes: &mut Vec<u8>,
) -> std::io::Result<()> {
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!("larger than {max_bytes} bytes"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn bounded_reader_limits_each_read_and_total_bytes() {
        struct Growing {
            calls: usize,
            bytes: usize,
            largest_request: usize,
        }
        impl std::io::Read for Growing {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                self.calls += 1;
                if self.bytes == 128 {
                    return Ok(0);
                }
                self.largest_request = self.largest_request.max(out.len());
                let count = out.len().min(1);
                out[..count].fill(b'x');
                self.bytes += count;
                Ok(count)
            }
        }
        let mut reader = Growing {
            calls: 0,
            bytes: 0,
            largest_request: 0,
        };
        let mut bytes = Vec::new();
        assert_eq!(
            read_bounded(&mut reader, 32, &mut bytes)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::FileTooLarge
        );
        assert_eq!(reader.bytes, 33);
        assert_eq!(reader.calls, 33);
        assert!(reader.largest_request <= 33);
        bytes.clear();
        read_bounded(&b"abc"[..], 3, &mut bytes).unwrap();
        assert_eq!(bytes, b"abc");
    }

    /// A credential is read into one allocation sized from the file, so no
    /// reallocation leaves a partial copy behind.
    #[test]
    fn credential_read_does_not_grow_its_buffer() {
        let file = file_with_mode(0o600);
        std::fs::write(file.path(), vec![b'k'; 5000]).unwrap();
        let mut bytes = Vec::new();
        read_credential(file.path(), "key", CredentialKind::Secret, me(), &mut bytes).unwrap();
        assert_eq!(bytes.len(), 5000);
        assert_eq!(bytes.capacity(), 5001);
    }

    fn me() -> DaemonIdentity {
        DaemonIdentity::current()
    }

    fn file_with_mode(mode: u32) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"secret\n").unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        file
    }

    fn verdict(path: &Path, kind: CredentialKind, daemon: DaemonIdentity) -> Verdict {
        match open_credential(path, "token", kind, daemon) {
            Ok((_, None)) => Verdict::Accept,
            Ok((_, Some(warning))) => Verdict::Warn(warning),
            Err(reason) => Verdict::Refuse(reason),
        }
    }

    /// Load-bearing mode boundaries: owner-only passes, the daemon group may
    /// read, any other group or every user draws a warning, and a
    /// world-writable secret is refused.
    #[test]
    fn secret_mode_boundaries() {
        let daemon = me();
        let other_group = DaemonIdentity {
            gid: daemon.gid.wrapping_add(1),
            ..daemon
        };
        for (mode, expected_self_group, expected_other_group) in [
            (0o600, "accept", "accept"),
            (0o400, "accept", "accept"),
            (0o640, "accept", "warn"),
            (0o660, "accept", "warn"),
            (0o644, "warn", "warn"),
            (0o604, "warn", "warn"),
            (0o602, "refuse", "refuse"),
            (0o666, "refuse", "refuse"),
        ] {
            let file = file_with_mode(mode);
            for (identity, expected) in [
                (daemon, expected_self_group),
                (other_group, expected_other_group),
            ] {
                let got = verdict(file.path(), CredentialKind::Secret, identity);
                let class = match &got {
                    Verdict::Accept => "accept",
                    Verdict::Warn(_) => "warn",
                    Verdict::Refuse(_) => "refuse",
                };
                assert_eq!(class, expected, "mode {mode:04o}: {got:?}");
                if let Verdict::Warn(message) = got {
                    assert!(message.contains(&format!("mode {mode:04o}")), "{message}");
                    assert!(message.contains(&file.path().display().to_string()));
                    assert!(message.contains("chmod 600"), "{message}");
                }
            }
        }
    }

    /// Public material may be shared for reading, but not for writing.
    #[test]
    fn public_material_ignores_mode() {
        let file = file_with_mode(0o644);
        assert_eq!(
            verdict(file.path(), CredentialKind::Public, me()),
            Verdict::Accept
        );
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            matches!(verdict(file.path(), CredentialKind::Public, me()), Verdict::Refuse(message) if message.contains("world-writable"))
        );
    }

    /// A foreign owner draws a warning; root ownership does not.
    #[test]
    fn foreign_owner_warns() {
        let file = file_with_mode(0o600);
        let elsewhere = DaemonIdentity {
            uid: me().uid.wrapping_add(1),
            gid: me().gid,
        };
        let got = verdict(file.path(), CredentialKind::Secret, elsewhere);
        if me().uid == 0 {
            assert_eq!(got, Verdict::Accept, "root ownership is trusted");
        } else {
            assert!(
                matches!(&got, Verdict::Warn(m) if m.contains("not the daemon user")),
                "{got:?}"
            );
        }
    }

    /// Load-bearing: following the symlink judges its target, and a
    /// directory or FIFO is refused without blocking.
    #[test]
    fn symlinks_are_judged_by_target_and_non_regular_files_refused() {
        let dir = tempfile::tempdir().unwrap();
        let private = file_with_mode(0o600);
        let shared = file_with_mode(0o644);
        let link = dir.path().join("private-link");
        std::os::unix::fs::symlink(private.path(), &link).unwrap();
        assert_eq!(
            verdict(&link, CredentialKind::Secret, me()),
            Verdict::Accept
        );
        let link = dir.path().join("shared-link");
        std::os::unix::fs::symlink(shared.path(), &link).unwrap();
        assert!(matches!(
            verdict(&link, CredentialKind::Secret, me()),
            Verdict::Warn(_)
        ));

        for kind in [CredentialKind::Secret, CredentialKind::Public] {
            assert!(matches!(
                verdict(dir.path(), kind, me()),
                Verdict::Refuse(m) if m.contains("not a regular file")
            ));
        }
        let fifo = dir.path().join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        assert!(matches!(
            verdict(&fifo, CredentialKind::Public, me()),
            Verdict::Refuse(m) if m.contains("not a regular file")
        ));
        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("absent"), &dangling).unwrap();
        assert!(matches!(
            verdict(&dangling, CredentialKind::Secret, me()),
            Verdict::Refuse(m) if m.contains("failed to read")
        ));
    }
}

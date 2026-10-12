//! ADR-0140 core-isolation hold for bound Ethernet Segments: the
//! ownership [`receipt`] and the out-of-process `--release-core-isolation`
//! helper ([`release_core_isolation`]). The helper reads no config: it
//! takes the receipt lock, applies the safe rule, and reports through its
//! exit status.

use std::path::Path;

use rustbgpd_evpn_linux::AdminLinks;

pub(crate) mod receipt;

use receipt::{Guard, HostIdentity, LinkIdentity, OpenError, ReceiptStore};

// ─── out-of-process release ──────────────────────────────────────────

/// `rustbgpd --release-core-isolation --runtime-state-dir DIR`. Returns
/// the process exit status: 0 only when nothing owned is left down.
pub(crate) fn release_core_isolation(directory: &Path) -> u8 {
    let store = match ReceiptStore::open_path(directory) {
        Ok(store) => store,
        Err(OpenError::Locked) => {
            eprintln!(
                "error: a running rustbgpd holds {}/{}; it releases its own holds on shutdown",
                directory.display(),
                receipt::LOCK_FILE
            );
            return 1;
        }
        Err(OpenError::Other(message)) => {
            eprintln!("error: {message}");
            return 1;
        }
    };
    let mut entries = match store.read() {
        Ok(None) => {
            println!(
                "no core-isolation receipt in {}; nothing to release",
                directory.display()
            );
            return 0;
        }
        Ok(Some(entries)) => entries,
        Err(message) => {
            eprintln!("error: {message}");
            return 1;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: cannot start the release runtime: {error}");
            return 1;
        }
    };
    let result: Result<(), String> = runtime.block_on(async {
        let host = HostIdentity::current()?;
        let links = AdminLinks::open().map_err(|e| e.to_string())?;
        let dump = links.dump().await.map_err(|e| e.to_string())?;
        let mut kept = Vec::new();
        for entry in entries.drain(..) {
            match receipt::classify(&entry, &host, &dump) {
                Guard::ForeignBoot | Guard::Matched { admin_up: true, .. } => {}
                Guard::Matched { admin_up: false, ifindex } => {
                    let fresh = links.get(ifindex).await.map_err(|e| e.to_string())?;
                    let master = match fresh.as_ref().and_then(|s| s.master) {
                        Some(index) => links.get(index).await.map_err(|e| e.to_string())?,
                        None => None,
                    };
                    let unchanged = fresh.as_ref().is_some_and(|state| {
                        LinkIdentity::of(state, master.as_ref()) == entry.link
                    });
                    if !unchanged {
                        eprintln!(
                            "ownership_ambiguous: {} (ifindex {}) changed before the write; left down",
                            entry.link.name, entry.link.ifindex
                        );
                        kept.push(entry);
                        continue;
                    }
                    if fresh.is_some_and(|s| !s.admin_up)
                        && let Err(error) = links.set_admin_up(ifindex, true).await
                    {
                        eprintln!("error: cannot raise {}: {error}", entry.link.name);
                        kept.push(entry);
                        continue;
                    }
                    println!("raised {} (binding {})", entry.link.name, entry.binding);
                }
                Guard::Ambiguous(reason) => {
                    eprintln!(
                        "ownership_ambiguous: {} (ifindex {}, binding {}): {reason}; left down. \
                         Raise it by hand, then remove the entry",
                        entry.link.name, entry.link.ifindex, entry.binding
                    );
                    kept.push(entry);
                }
            }
        }
        store.publish(&kept)?;
        if kept.is_empty() {
            Ok(())
        } else {
            Err(format!("{} owned link(s) remain down", kept.len()))
        }
    });
    match result {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("error: {message}");
            1
        }
    }
}

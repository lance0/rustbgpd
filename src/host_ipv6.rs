//! Read-only Linux IPv6 prerequisites shared by the daemon and local doctor.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::net::Ipv6Addr;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Finding {
    pub condition: &'static str,
    pub detail: String,
    pub unusable: bool,
}

impl Finding {
    fn new(condition: &'static str, detail: impl Into<String>, unusable: bool) -> Self {
        Self {
            condition,
            detail: detail.into(),
            unusable,
        }
    }
}

/// Reuse one address inventory for every configured interface in a sweep.
pub(crate) struct Inspector {
    addresses: io::Result<BTreeMap<String, Vec<u32>>>,
}

impl Inspector {
    pub(crate) fn new() -> Self {
        Self {
            addresses: read_addresses(Path::new("/proc")),
        }
    }

    /// None means absent, preserving discovery's wait-for-link policy without
    /// claiming recovery. Read failures remain explicit findings.
    pub(crate) fn inspect(&self, interface: &str, interface_only: bool) -> Option<Vec<Finding>> {
        match read(
            interface,
            interface_only,
            Path::new("/proc"),
            &self.addresses,
        ) {
            Ok(findings) => findings,
            Err(error) => Some(vec![Finding::new(
                "ipv6_state_unavailable",
                format!("cannot inspect IPv6 prerequisites: {error}"),
                false,
            )]),
        }
    }
}

fn read_addresses(proc_root: &Path) -> io::Result<BTreeMap<String, Vec<u32>>> {
    link_local_flags(&fs::read_to_string(proc_root.join("net/if_inet6"))?)
}

fn read(
    interface: &str,
    interface_only: bool,
    proc_root: &Path,
    addresses: &io::Result<BTreeMap<String, Vec<u32>>>,
) -> io::Result<Option<Vec<Finding>>> {
    if interface.is_empty() || interface.contains('/') || matches!(interface, "." | "..") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    let dir = proc_root.join("sys/net/ipv6/conf").join(interface);
    if !dir.try_exists()? {
        // A missing IPv6 stack must not look like a missing interface.
        if !proc_root.join("sys/net/ipv6/conf").try_exists()? {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "IPv6 sysctls unavailable",
            ));
        }
        return Ok(None);
    }
    let sysctl = |name: &str| -> io::Result<u32> {
        fs::read_to_string(dir.join(name))?
            .trim()
            .parse()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    };
    let disabled = sysctl("disable_ipv6")? != 0;
    let flags = if disabled {
        &[][..]
    } else {
        addresses
            .as_ref()
            .map_err(|error| io::Error::new(error.kind(), error.to_string()))?
            .get(interface)
            .map_or(&[][..], Vec::as_slice)
    };
    let mut findings = classify_addresses(disabled, flags);
    if !disabled
        && interface_only
        && accepts_ra_default(
            sysctl("forwarding")?,
            sysctl("accept_ra")?,
            sysctl("accept_ra_defrtr")?,
        )
    {
        findings.push(Finding::new("ra_default_route", format!("peer Router Advertisements can install a default route outside BGP; set net.ipv6.conf.{interface}.accept_ra=0 or net.ipv6.conf.{interface}.accept_ra_defrtr=0"), false));
    }
    Ok(Some(findings))
}

fn link_local_flags(text: &str) -> io::Result<BTreeMap<String, Vec<u32>>> {
    let mut flags = BTreeMap::<String, Vec<u32>>::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 6 || fields[0].len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed /proc/net/if_inet6 row",
            ));
        }
        let address = u128::from_str_radix(fields[0], 16)
            .map(Ipv6Addr::from)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if address.is_unicast_link_local() {
            flags.entry(fields[5].to_owned()).or_default().push(
                u32::from_str_radix(fields[4], 16)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            );
        }
    }
    Ok(flags)
}

fn classify_addresses(disabled: bool, flags: &[u32]) -> Vec<Finding> {
    const TENTATIVE: u32 = 0x40;
    const DADFAILED: u32 = 0x08;
    if disabled {
        return vec![Finding::new(
            "ipv6_disabled",
            "IPv6 is disabled; set the interface's disable_ipv6=0",
            true,
        )];
    }
    if flags.is_empty() {
        return vec![Finding::new(
            "link_local_missing",
            "no IPv6 link-local address; configure one or enable address generation (addr_gen_mode)",
            true,
        )];
    }
    if flags
        .iter()
        .any(|flags| flags & (TENTATIVE | DADFAILED) == 0)
    {
        return Vec::new();
    }
    let mut findings = Vec::new();
    if flags.iter().any(|flags| flags & DADFAILED != 0) {
        findings.push(Finding::new(
            "link_local_dad_failed",
            "no usable IPv6 link-local address: DAD failed; resolve the duplicate address",
            true,
        ));
    }
    if flags
        .iter()
        .any(|flags| flags & TENTATIVE != 0 && flags & DADFAILED == 0)
    {
        findings.push(Finding::new(
            "link_local_tentative",
            "no usable IPv6 link-local address: DAD is still tentative",
            true,
        ));
    }
    findings
}

fn accepts_ra_default(forwarding: u32, accept_ra: u32, accept_ra_defrtr: u32) -> bool {
    accept_ra_defrtr != 0 && (accept_ra == 2 || (accept_ra == 1 && forwarding == 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ipv6_classifies_address_flags() {
        for (disabled, flags, condition) in [
            (true, vec![0x80], Some("ipv6_disabled")),
            (false, vec![], Some("link_local_missing")),
            (false, vec![0x40], Some("link_local_tentative")),
            (false, vec![0x48], Some("link_local_dad_failed")),
            (false, vec![0x08], Some("link_local_dad_failed")),
            (false, vec![0x40, 0x80], None),
            (false, vec![0x20], None),
        ] {
            assert_eq!(
                classify_addresses(disabled, &flags)
                    .first()
                    .map(|f| f.condition),
                condition
            );
        }
        assert_eq!(classify_addresses(false, &[0x40, 0x08]).len(), 2);
    }

    #[test]
    fn host_ipv6_ra_defaults_follow_effective_kernel_acceptance() {
        for (forwarding, accept_ra, defrtr, expected) in [
            (0, 0, 1, false),
            (0, 1, 1, true),
            (1, 1, 1, false),
            (0, 2, 1, true),
            (1, 2, 1, true),
            (0, 1, 0, false),
            (0, 2, 0, false),
            (1, 2, 0, false),
        ] {
            assert_eq!(
                accepts_ra_default(forwarding, accept_ra, defrtr),
                expected,
                "forwarding={forwarding}, accept_ra={accept_ra}, defrtr={defrtr}"
            );
        }
    }

    #[test]
    fn host_ipv6_read_reports_disabled_missing_unusable_and_unreadable_state() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("sys/net/ipv6/conf/swp1");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir(root.path().join("net")).unwrap();
        for (name, value) in [
            ("disable_ipv6", "1"),
            ("forwarding", "0"),
            ("accept_ra", "1"),
            ("accept_ra_defrtr", "1"),
        ] {
            fs::write(dir.join(name), value).unwrap();
        }
        let inspect = || {
            read("swp1", true, root.path(), &read_addresses(root.path()))
                .unwrap()
                .unwrap()
        };
        assert_eq!(inspect()[0].condition, "ipv6_disabled");
        assert_eq!(inspect().len(), 1, "disabled IPv6 cannot learn RA defaults");
        fs::write(dir.join("disable_ipv6"), "0").unwrap();
        assert!(
            read("swp1", true, root.path(), &read_addresses(root.path())).is_err(),
            "missing address inventory is unknown"
        );
        fs::write(root.path().join("net/if_inet6"), "").unwrap();
        assert_eq!(inspect()[0].condition, "link_local_missing");
        fs::write(
            root.path().join("net/if_inet6"),
            "fe800000000000000000000000000001 02 40 20 08 swp1\n",
        )
        .unwrap();
        assert_eq!(inspect()[0].condition, "link_local_dad_failed");
        assert_eq!(inspect()[1].condition, "ra_default_route");
        assert_eq!(
            read("swp1", false, root.path(), &read_addresses(root.path()))
                .unwrap()
                .unwrap()
                .len(),
            1,
            "static peers do not enable discovery's RA-default advisory"
        );
        assert!(
            read("missing", true, root.path(), &read_addresses(root.path()))
                .unwrap()
                .is_none()
        );
        fs::write(dir.join("disable_ipv6"), "bad").unwrap();
        assert!(read("swp1", true, root.path(), &read_addresses(root.path())).is_err());
        assert!(read("../all", true, root.path(), &read_addresses(root.path())).is_err());
    }

    #[test]
    fn host_ipv6_reads_only_link_local_flags_for_named_interface() {
        let rows = "fe800000000000000000000000000001 02 40 20 48 swp1\n20010db8000000000000000000000001 02 40 00 80 swp1\nfe800000000000000000000000000001 03 40 20 80 swp2\n";
        assert_eq!(
            link_local_flags(rows).unwrap(),
            BTreeMap::from([
                ("swp1".to_owned(), vec![0x48]),
                ("swp2".to_owned(), vec![0x80])
            ])
        );
        assert!(link_local_flags("broken").is_err());
        assert!(link_local_flags("bad 02 40 20 zz swp1").is_err());
    }
}

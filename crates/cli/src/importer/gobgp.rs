//! GoBGP TOML configuration structural frontend.
//!
//! Walks the parsed TOML value against an explicit whitelist of
//! consumed keys; everything else is reported. Line numbers are
//! recovered by scanning the source text for the first occurrence of
//! the offending key/table header (GoBGP configs use explicit table
//! headers, so this is reliable in practice; a miss reports without a
//! line rather than guessing).

use super::{GENERIC_GUIDANCE, Group, ImportError, Model, Neighbor, RPOL_GUIDANCE, Skip};

pub fn parse(input: &str) -> Result<Model, ImportError> {
    let value: toml::Value =
        toml::from_str(input).map_err(|e| ImportError::Parse(e.to_string()))?;
    let Some(root) = value.as_table() else {
        return Err(ImportError::Parse(
            "top level is not a TOML table".to_owned(),
        ));
    };

    let mut model = Model::default();
    for (key, val) in root {
        match key.as_str() {
            "global" => global(&mut model, input, val),
            "neighbors" => {
                for (idx, item) in as_array(val).iter().enumerate() {
                    neighbor(&mut model, input, idx, item);
                }
            }
            "peer-groups" => {
                for item in as_array(val) {
                    peer_group(&mut model, input, item);
                }
            }
            // GoBGP's zebra integration: rustbgpd exports to the kernel
            // directly via [[fib_tables]].
            "zebra" => skip_key(
                &mut model,
                input,
                key,
                key,
                "kernel/FIB export: configure rustbgpd [[fib_tables]] by hand",
            ),
            "policy-definitions" | "defined-sets" => {
                skip_key(&mut model, input, key, key, RPOL_GUIDANCE);
            }
            "dynamic-neighbors" => skip_key(
                &mut model,
                input,
                key,
                key,
                "declare via rustbgpd [[dynamic_neighbors]] by hand",
            ),
            _ => skip_key(&mut model, input, key, key, GENERIC_GUIDANCE),
        }
    }
    Ok(model)
}

fn as_array(value: &toml::Value) -> &[toml::Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

fn as_u32(value: &toml::Value) -> Option<u32> {
    match value {
        toml::Value::Integer(n) => u32::try_from(*n).ok(),
        // gobgp's config dumper writes some integers as floats.
        toml::Value::Float(f) if f.fract() == 0.0 && *f >= 0.0 => Some(*f as u32),
        _ => None,
    }
}

/// First 1-based source line containing `needle`.
fn line_of(source: &str, needle: &str) -> Option<usize> {
    source
        .lines()
        .position(|l| l.contains(needle))
        .map(|i| i + 1)
}

fn skip_key(model: &mut Model, source: &str, needle: &str, stanza: &str, guidance: &str) {
    model.skips.push(Skip {
        line: line_of(source, needle),
        stanza: stanza.to_owned(),
        guidance: guidance.to_owned(),
    });
}

fn global(model: &mut Model, source: &str, value: &toml::Value) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, val) in table {
        match key.as_str() {
            "config" => {
                let Some(config) = val.as_table() else {
                    continue;
                };
                for (ckey, cval) in config {
                    match ckey.as_str() {
                        "as" => model.local_asn = as_u32(cval),
                        "router-id" => {
                            model.router_id = cval.as_str().map(str::to_owned);
                        }
                        other => skip_key(
                            model,
                            source,
                            other,
                            &format!("global.config.{other}"),
                            GENERIC_GUIDANCE,
                        ),
                    }
                }
            }
            "apply-policy" => skip_key(
                model,
                source,
                "apply-policy",
                "global.apply-policy",
                RPOL_GUIDANCE,
            ),
            other => skip_key(
                model,
                source,
                other,
                &format!("global.{other}"),
                GENERIC_GUIDANCE,
            ),
        }
    }
}

/// Shared shape of `[[neighbors]]` and `[[peer-groups]]` entries.
/// `header` is the TOML array name, used to line-locate nested skipped
/// tables (`[neighbors.apply-policy]` vs the global one).
#[derive(Default)]
struct Session {
    address: Option<String>,
    group_name: Option<String>,
    remote_asn: Option<u32>,
    description: Option<String>,
    peer_group: Option<String>,
    hold_time: Option<u16>,
    families: Vec<String>,
    max_prefixes_ipv4: Option<u32>,
    max_prefixes_ipv6: Option<u32>,
    auth_present: bool,
}

fn session(
    model: &mut Model,
    source: &str,
    header: &str,
    label: &str,
    value: &toml::Value,
) -> Session {
    let mut s = Session::default();
    let Some(table) = value.as_table() else {
        return s;
    };
    for (key, val) in table {
        match key.as_str() {
            "config" => {
                let Some(config) = val.as_table() else {
                    continue;
                };
                for (ckey, cval) in config {
                    match ckey.as_str() {
                        "neighbor-address" => s.address = cval.as_str().map(str::to_owned),
                        "peer-group-name" => s.group_name = cval.as_str().map(str::to_owned),
                        "peer-as" => s.remote_asn = as_u32(cval),
                        "description" => s.description = cval.as_str().map(str::to_owned),
                        "peer-group" => s.peer_group = cval.as_str().map(str::to_owned),
                        "auth-password" => {
                            s.auth_present = cval.as_str().is_some_and(|p| !p.is_empty());
                        }
                        other => skip_key(
                            model,
                            source,
                            other,
                            &format!("{label}: config.{other}"),
                            GENERIC_GUIDANCE,
                        ),
                    }
                }
            }
            "timers" => {
                let config = val.get("config").and_then(toml::Value::as_table);
                let Some(config) = config else { continue };
                let keepalive = config.get("keepalive-interval").and_then(as_u32);
                for (tkey, tval) in config {
                    match tkey.as_str() {
                        "hold-time" => {
                            s.hold_time = as_u32(tval).and_then(|h| u16::try_from(h).ok());
                        }
                        "keepalive-interval" => {}
                        other => skip_key(
                            model,
                            source,
                            other,
                            &format!("{label}: timers.config.{other}"),
                            GENERIC_GUIDANCE,
                        ),
                    }
                }
                if let (Some(keepalive), Some(hold)) = (keepalive, s.hold_time)
                    && keepalive * 3 != u32::from(hold)
                {
                    model.warnings.push(format!(
                        "{label}: keepalive {keepalive}s is not hold/3 ({hold}/3); rustbgpd \
                         always derives keepalive as hold_time/3"
                    ));
                }
            }
            "afi-safis" => {
                for afi in as_array(val) {
                    afi_safi(model, source, label, afi, &mut s);
                }
            }
            "apply-policy" => skip_key(
                model,
                source,
                &format!("[{header}.apply-policy"),
                &format!("{label}: apply-policy"),
                RPOL_GUIDANCE,
            ),
            other => skip_key(
                model,
                source,
                other,
                &format!("{label}: {other}"),
                GENERIC_GUIDANCE,
            ),
        }
    }
    s
}

fn afi_safi(model: &mut Model, source: &str, label: &str, value: &toml::Value, s: &mut Session) {
    let name = value
        .get("config")
        .and_then(|c| c.get("afi-safi-name"))
        .and_then(toml::Value::as_str)
        .unwrap_or("");
    let (family, ipv6) = match name {
        "ipv4-unicast" => ("ipv4_unicast", false),
        "ipv6-unicast" => ("ipv6_unicast", true),
        other => {
            skip_key(
                model,
                source,
                other,
                &format!("{label}: afi-safi {other}"),
                "address family outside the structural subset (ipv4/ipv6 unicast only)",
            );
            return;
        }
    };
    s.families.push(family.to_owned());
    if let Some(limit) = value
        .get("prefix-limit")
        .and_then(|p| p.get("config"))
        .and_then(|c| c.get("max-prefixes"))
        .and_then(as_u32)
        .filter(|limit| *limit > 0)
    {
        if ipv6 {
            s.max_prefixes_ipv6 = Some(limit);
        } else {
            s.max_prefixes_ipv4 = Some(limit);
        }
    }
}

fn neighbor(model: &mut Model, source: &str, idx: usize, value: &toml::Value) {
    let address_label = value
        .get("config")
        .and_then(|c| c.get("neighbor-address"))
        .and_then(toml::Value::as_str)
        .unwrap_or("?");
    let label = format!("neighbors[{idx}] ({address_label})");
    let s = session(model, source, "neighbors", &label, value);
    let Some(address) = s.address else {
        model.skips.push(Skip {
            line: None,
            stanza: label,
            guidance: "entry has no neighbor-address; not translated".to_owned(),
        });
        return;
    };
    model.neighbors.push(Neighbor {
        source_line: line_of(source, &address).unwrap_or(0),
        address,
        remote_asn: s.remote_asn,
        description: s.description,
        peer_group: s.peer_group,
        hold_time: s.hold_time,
        families: s.families,
        max_prefixes_ipv4: s.max_prefixes_ipv4,
        max_prefixes_ipv6: s.max_prefixes_ipv6,
        auth_present: s.auth_present,
    });
}

fn peer_group(model: &mut Model, source: &str, value: &toml::Value) {
    let name_label = value
        .get("config")
        .and_then(|c| c.get("peer-group-name"))
        .and_then(toml::Value::as_str)
        .unwrap_or("?");
    let label = format!("peer-groups ({name_label})");
    let s = session(model, source, "peer-groups", &label, value);
    let Some(name) = s.group_name else {
        model.skips.push(Skip {
            line: None,
            stanza: label,
            guidance: "entry has no peer-group-name; not translated".to_owned(),
        });
        return;
    };
    model.groups.push(Group {
        name,
        remote_asn: s.remote_asn,
        hold_time: s.hold_time,
        families: s.families,
        max_prefixes_ipv4: s.max_prefixes_ipv4,
        max_prefixes_ipv6: s.max_prefixes_ipv6,
        auth_present: s.auth_present,
    });
}

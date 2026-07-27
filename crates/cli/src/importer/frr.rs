//! FRR (vtysh running-config style) structural frontend.
//!
//! Line-oriented: `router bgp` opens the BGP block, `address-family`
//! opens a sub-block, `!` separates top-level stanzas. Policy carriers
//! (route-maps, prefix-lists, community-lists, per-neighbor policy
//! attachments) are reported for `.rpol` hand-translation, never
//! guessed at.

use super::{GENERIC_GUIDANCE, Group, Model, Neighbor, RPOL_GUIDANCE, Skip};

/// Top-level daemon boilerplate with no BGP-structural content.
const BENIGN_TOP: &[&str] = &[
    "frr version",
    "frr defaults",
    "hostname",
    "domainname",
    "log ",
    "log\t",
    "service ",
    "line vty",
    "password ",
    "enable password",
    "agentx",
    "end",
    "exit",
];

/// Single-line policy-carrier entries: one report per line.
const POLICY_LINE_TOP: &[&str] = &[
    "ip prefix-list",
    "ipv6 prefix-list",
    "access-list",
    "ipv6 access-list",
    "bgp community-list",
    "ip community-list",
    "bgp large-community-list",
    "ip large-community-list",
    "bgp extcommunity-list",
    "ip extcommunity-list",
    "bgp as-path access-list",
    "ip as-path access-list",
];

#[derive(PartialEq)]
enum Af {
    V4,
    V6,
    Unsupported,
}

pub fn parse(input: &str) -> Model {
    let mut model = Model::default();
    let mut in_bgp = false;
    let mut af: Option<Af> = None;
    // True while swallowing the indented body of an already-reported
    // top-level stanza (route-map entries, another routing protocol).
    let mut swallow_top = false;
    // FRR activates IPv4 unicast on every neighbor unless the config
    // says `no bgp default ipv4-unicast`.
    let mut default_ipv4 = true;
    let mut default_hold: Option<u16> = None;

    for (idx, raw) in input.lines().enumerate() {
        let line = idx + 1;
        let text = raw.trim();
        if text.is_empty() || text == "!" {
            // vtysh running-config has no explicit `exit` for `router
            // bgp`: the section ends at the next column-0 `!` (inner
            // separators are indented, " !").
            if raw.starts_with('!') {
                in_bgp = false;
                af = None;
                swallow_top = false;
            }
            continue;
        }

        if in_bgp {
            match text {
                "exit-address-family" => {
                    af = None;
                    continue;
                }
                "exit" | "end" => {
                    if af.take().is_none() {
                        in_bgp = false;
                    }
                    continue;
                }
                _ => {}
            }
            if let Some(rest) = text.strip_prefix("address-family ") {
                af = Some(match rest.trim() {
                    "ipv4 unicast" | "ipv4" => Af::V4,
                    "ipv6 unicast" | "ipv6" => Af::V6,
                    other => {
                        skip(
                            &mut model,
                            line,
                            format!("address-family {other}"),
                            "address family outside the structural subset (ipv4/ipv6 \
                             unicast only)",
                        );
                        Af::Unsupported
                    }
                });
                continue;
            }
            if af == Some(Af::Unsupported) {
                continue; // body of an already-reported address family
            }
            bgp_line(
                &mut model,
                line,
                text,
                &af,
                &mut default_ipv4,
                &mut default_hold,
            );
            continue;
        }

        if let Some(rest) = text.strip_prefix("router bgp ") {
            let mut instance = rest.split_whitespace();
            let asn = instance.next().and_then(|word| word.parse().ok());
            if instance.next().is_some() {
                skip(
                    &mut model,
                    line,
                    text.to_owned(),
                    "BGP VRF/view instance: rustbgpd runs one global instance per daemon",
                );
                swallow_top = true;
                continue;
            }
            if model.local_asn.is_some() {
                skip(
                    &mut model,
                    line,
                    text.to_owned(),
                    "additional BGP instance/view: rustbgpd runs one instance per daemon",
                );
                swallow_top = true;
                continue;
            }
            match asn {
                Some(asn) => {
                    model.local_asn = Some(asn);
                    in_bgp = true;
                }
                None => skip(&mut model, line, text.to_owned(), GENERIC_GUIDANCE),
            }
            continue;
        }

        if swallow_top {
            continue; // body of an already-reported top-level stanza
        }
        if BENIGN_TOP.iter().any(|p| text.starts_with(p)) {
            continue;
        }
        if POLICY_LINE_TOP.iter().any(|p| text.starts_with(p)) {
            skip(&mut model, line, text.to_owned(), RPOL_GUIDANCE);
            continue;
        }
        if text.starts_with("route-map ") {
            skip(&mut model, line, text.to_owned(), RPOL_GUIDANCE);
            swallow_top = true; // match/set body lines belong to this entry
            continue;
        }
        if text.starts_with("ip route") || text.starts_with("ipv6 route") {
            skip(
                &mut model,
                line,
                text.to_owned(),
                "static route: not BGP configuration; not translated",
            );
            continue;
        }
        if text.starts_with("router ") || text.starts_with("vrf ") || text.starts_with("interface ")
        {
            skip(&mut model, line, text.to_owned(), GENERIC_GUIDANCE);
            swallow_top = true;
            continue;
        }
        skip(&mut model, line, text.to_owned(), GENERIC_GUIDANCE);
    }

    // Post-pass: FRR's default IPv4-unicast activation is additive to
    // explicit AF activation and applies to peer groups as well as peers.
    // Also apply the `timers bgp` instance-default hold time to neighbors
    // without their own timers (group timers inherit at daemon level).
    if default_ipv4 {
        for group in &mut model.groups {
            if !group.families.iter().any(|family| family == "ipv4_unicast") {
                group.families.push("ipv4_unicast".to_owned());
            }
        }
    }
    let groups = &model.groups;
    for neighbor in &mut model.neighbors {
        let group = neighbor
            .peer_group
            .as_ref()
            .and_then(|name| groups.iter().find(|group| &group.name == name));
        let inherits_families = group.is_some_and(|g| !g.families.is_empty());
        if default_ipv4
            && !neighbor
                .families
                .iter()
                .any(|family| family == "ipv4_unicast")
            && (!neighbor.families.is_empty() || !inherits_families)
        {
            neighbor.families.push("ipv4_unicast".to_owned());
        }
        if neighbor.hold_time.is_none() && group.and_then(|g| g.hold_time).is_none() {
            neighbor.hold_time = default_hold;
        }
    }
    model
}

fn skip(model: &mut Model, line: usize, stanza: String, guidance: impl Into<String>) {
    model.skips.push(Skip {
        line: Some(line),
        stanza,
        guidance: guidance.into(),
    });
}

/// One line inside `router bgp` (global part or a supported
/// address-family block).
fn bgp_line(
    model: &mut Model,
    line: usize,
    text: &str,
    af: &Option<Af>,
    default_ipv4: &mut bool,
    default_hold: &mut Option<u16>,
) {
    let words: Vec<&str> = text.split_whitespace().collect();

    if let Some(rest) = text.strip_prefix("neighbor ") {
        neighbor_line(model, line, text, rest, af);
        return;
    }
    match words.as_slice() {
        ["bgp", "router-id", id] => {
            model.router_id = Some((*id).to_owned());
            return;
        }
        ["no", "bgp", "default", "ipv4-unicast"] => {
            *default_ipv4 = false;
            return;
        }
        ["bgp", "default", "ipv4-unicast"] => {
            *default_ipv4 = true;
            return;
        }
        // Behavior-neutral for rustbgpd: it has no eBGP policy gate.
        ["no", "bgp", "ebgp-requires-policy"] => return,
        ["timers", "bgp", keepalive, hold] => {
            if let Ok(hold) = hold.parse::<u16>() {
                warn_keepalive(model, "instance default", keepalive, hold);
                *default_hold = Some(hold);
                return;
            }
        }
        _ => {}
    }
    if af.is_some() && (words.first() == Some(&"network") || words.first() == Some(&"redistribute"))
    {
        skip(
            model,
            line,
            text.to_owned(),
            "route origination/redistribution: declare the routes on the rustbgpd side \
             by hand (policy or FIB import)",
        );
        return;
    }
    skip(model, line, text.to_owned(), GENERIC_GUIDANCE);
}

/// `neighbor <peer> ...` — `<peer>` is an address or a peer-group name.
fn neighbor_line(model: &mut Model, line: usize, text: &str, rest: &str, af: &Option<Af>) {
    let mut words = rest.split_whitespace();
    let Some(peer) = words.next() else {
        skip(model, line, text.to_owned(), GENERIC_GUIDANCE);
        return;
    };
    let peer = peer.to_owned();
    let attr: Vec<&str> = words.collect();

    // Group declaration comes first in FRR configs, so a bare
    // `neighbor NAME peer-group` line decides which map `NAME` lives in.
    if attr == ["peer-group"] {
        if !model.groups.iter().any(|g| g.name == peer) {
            model.groups.push(Group {
                name: peer,
                ..Group::default()
            });
        }
        return;
    }
    if let ["peer-group", group] = attr.as_slice() {
        entry(model, &peer, line).peer_group(Some((*group).to_owned()));
        return;
    }

    match attr.as_slice() {
        ["remote-as", value] => match value.parse::<u32>() {
            Ok(asn) => entry(model, &peer, line).remote_asn(asn),
            Err(_) if *value == "internal" => {
                if let Some(local) = model.local_asn {
                    entry(model, &peer, line).remote_asn(local);
                } else {
                    skip(model, line, text.to_owned(), GENERIC_GUIDANCE);
                }
            }
            Err(_) => skip(
                model,
                line,
                text.to_owned(),
                "`remote-as external` carries no ASN; rustbgpd requires an explicit \
                 remote_asn — fill it in by hand",
            ),
        },
        ["description", ..] => {
            let description = attr[1..].join(" ");
            entry(model, &peer, line).description(description);
        }
        ["timers", keepalive, hold] => {
            if let Ok(hold_secs) = hold.parse::<u16>() {
                warn_keepalive(model, &format!("neighbor {peer}"), keepalive, hold_secs);
                entry(model, &peer, line).hold_time(hold_secs);
            } else {
                skip(model, line, text.to_owned(), GENERIC_GUIDANCE);
            }
        }
        ["password", ..] => entry(model, &peer, line).auth(),
        ["activate"] => match af {
            Some(Af::V4) => entry(model, &peer, line).family("ipv4_unicast"),
            Some(Af::V6) => entry(model, &peer, line).family("ipv6_unicast"),
            _ => skip(model, line, text.to_owned(), GENERIC_GUIDANCE),
        },
        ["maximum-prefix", limit, ..] => match (af, limit.parse::<u32>()) {
            (Some(Af::V4), Ok(limit)) => entry(model, &peer, line).max_prefixes(limit, false),
            (Some(Af::V6), Ok(limit)) => entry(model, &peer, line).max_prefixes(limit, true),
            _ => skip(model, line, text.to_owned(), GENERIC_GUIDANCE),
        },
        ["route-map", ..]
        | ["prefix-list", ..]
        | ["filter-list", ..]
        | ["distribute-list", ..]
        | ["unsuppress-map", ..] => {
            skip(model, line, text.to_owned(), RPOL_GUIDANCE);
        }
        _ => skip(model, line, text.to_owned(), GENERIC_GUIDANCE),
    }
}

/// Where a `neighbor <peer>` attribute lands: the group of that name if
/// one was declared, else the (created-on-first-use) neighbor entry.
enum Entry<'a> {
    Group(&'a mut Group),
    Neighbor(&'a mut Neighbor),
}

fn entry<'a>(model: &'a mut Model, peer: &str, line: usize) -> Entry<'a> {
    if let Some(pos) = model.groups.iter().position(|g| g.name == peer) {
        return Entry::Group(&mut model.groups[pos]);
    }
    if let Some(pos) = model.neighbors.iter().position(|n| n.address == peer) {
        return Entry::Neighbor(&mut model.neighbors[pos]);
    }
    model.neighbors.push(Neighbor {
        address: peer.to_owned(),
        source_line: line,
        ..Neighbor::default()
    });
    Entry::Neighbor(model.neighbors.last_mut().expect("just pushed"))
}

impl Entry<'_> {
    fn remote_asn(self, asn: u32) {
        match self {
            Entry::Group(g) => g.remote_asn = Some(asn),
            Entry::Neighbor(n) => n.remote_asn = Some(asn),
        }
    }
    fn description(self, description: String) {
        if let Entry::Neighbor(n) = self {
            n.description = Some(description);
        }
        // Group descriptions have no rustbgpd equivalent; harmless.
    }
    fn peer_group(self, group: Option<String>) {
        if let Entry::Neighbor(n) = self {
            n.peer_group = group;
        }
    }
    fn hold_time(self, hold: u16) {
        match self {
            Entry::Group(g) => g.hold_time = Some(hold),
            Entry::Neighbor(n) => n.hold_time = Some(hold),
        }
    }
    fn auth(self) {
        match self {
            Entry::Group(g) => g.auth_present = true,
            Entry::Neighbor(n) => n.auth_present = true,
        }
    }
    fn family(self, family: &str) {
        match self {
            Entry::Group(g) => g.families.push(family.to_owned()),
            Entry::Neighbor(n) => n.families.push(family.to_owned()),
        }
    }
    fn max_prefixes(self, limit: u32, ipv6: bool) {
        let (v4, v6) = match self {
            Entry::Group(g) => (&mut g.max_prefixes_ipv4, &mut g.max_prefixes_ipv6),
            Entry::Neighbor(n) => (&mut n.max_prefixes_ipv4, &mut n.max_prefixes_ipv6),
        };
        if ipv6 {
            *v6 = Some(limit);
        } else {
            *v4 = Some(limit);
        }
    }
}

/// rustbgpd derives keepalive as hold/3; note when the source chose a
/// different ratio.
fn warn_keepalive(model: &mut Model, scope: &str, keepalive: &str, hold: u16) {
    match keepalive.parse::<u16>() {
        Ok(keepalive) if u32::from(keepalive) * 3 != u32::from(hold) => {
            model.warnings.push(format!(
                "{scope}: keepalive {keepalive}s is not hold/3 ({hold}/3); rustbgpd always \
                 derives keepalive as hold_time/3"
            ));
        }
        Ok(_) => {}
        Err(_) => model.warnings.push(format!(
            "{scope}: keepalive {keepalive:?} is not a valid number (0..=65535); dropped — \
             rustbgpd derives keepalive as hold_time/3 from the kept hold time {hold}"
        )),
    }
}

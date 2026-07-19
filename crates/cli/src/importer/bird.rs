//! BIRD 2 configuration structural frontend.
//!
//! A small scanner splits the file into brace/statement events (string-
//! and comment-aware, line-tracked); a frame stack then walks
//! `protocol bgp` / `template bgp` bodies and their `ipv4`/`ipv6`
//! channels. The filter language (`filter`/`function` blocks, inline
//! `import filter { ... }`, `export where ...`) is reported for `.rpol`
//! hand-translation, never guessed at.

use super::{GENERIC_GUIDANCE, Group, Model, Neighbor, RPOL_GUIDANCE, Skip};

#[derive(Debug)]
enum Event {
    /// `...;` statement (semicolon stripped).
    Stmt {
        line: usize,
        text: String,
    },
    /// `... {` block header (brace stripped).
    Open {
        line: usize,
        header: String,
    },
    Close,
}

/// Split the input into statement/brace events. Tracks `"` strings,
/// `#` / `//` line comments, and `/* */` block comments.
fn scan(input: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let mut buf = String::new();
    let mut buf_line = 1;
    let mut line = 1;
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if c == '\n' {
            line += 1;
            if !buf.is_empty() {
                buf.push(' ');
            }
            continue;
        }
        if in_string {
            buf.push(c);
            if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                if buf.trim().is_empty() {
                    buf_line = line;
                }
                in_string = true;
                buf.push(c);
            }
            '#' => {
                while chars.peek().is_some_and(|&n| n != '\n') {
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'/') => {
                while chars.peek().is_some_and(|&n| n != '\n') {
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = ' ';
                for n in chars.by_ref() {
                    if n == '\n' {
                        line += 1;
                    }
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
            }
            '{' => {
                events.push(Event::Open {
                    line: buf_line,
                    header: buf.trim().to_owned(),
                });
                buf.clear();
            }
            '}' => {
                // BIRD requires `};` after blocks; there is no pending
                // statement text at a close brace in valid input.
                buf.clear();
                events.push(Event::Close);
            }
            ';' => {
                let text = buf.trim();
                if !text.is_empty() {
                    events.push(Event::Stmt {
                        line: buf_line,
                        text: text.to_owned(),
                    });
                }
                buf.clear();
            }
            other => {
                if buf.trim().is_empty() && !other.is_whitespace() {
                    buf_line = line;
                }
                buf.push(other);
            }
        }
    }
    events
}

/// Accumulator for one `protocol bgp` / `template bgp` body.
#[derive(Default)]
struct BgpAcc {
    name: String,
    line: usize,
    template: bool,
    from: Option<String>,
    address: Option<String>,
    remote_asn: Option<u32>,
    description: Option<String>,
    hold_time: Option<u16>,
    keepalive: Option<u16>,
    families: Vec<String>,
    max_prefixes_ipv4: Option<u32>,
    max_prefixes_ipv6: Option<u32>,
    auth_present: bool,
}

enum Frame {
    Bgp(BgpAcc),
    /// `ipv4`/`ipv6` channel inside a bgp body; true = IPv6.
    Channel(bool),
    /// Body of an already-reported (or benign) block.
    Ignore,
}

/// Copy-out discriminant of the innermost frame, so event handlers can
/// borrow the stack fresh without fighting a live `last_mut` borrow.
#[derive(Clone, Copy)]
enum Ctx {
    Top,
    Bgp,
    Channel(bool),
    Ignore,
}

fn ctx(stack: &[Frame]) -> Ctx {
    match stack.last() {
        None => Ctx::Top,
        Some(Frame::Bgp(_)) => Ctx::Bgp,
        Some(Frame::Channel(ipv6)) => Ctx::Channel(*ipv6),
        Some(Frame::Ignore) => Ctx::Ignore,
    }
}

pub fn parse(input: &str) -> Model {
    let mut model = Model::default();
    let mut stack: Vec<Frame> = Vec::new();

    for event in scan(input) {
        match event {
            Event::Open { line, header } => {
                let frame = match ctx(&stack) {
                    Ctx::Top => top_open(&mut model, line, &header),
                    Ctx::Bgp => {
                        let Some(Frame::Bgp(acc)) = stack.last_mut() else {
                            unreachable!("ctx said Bgp");
                        };
                        bgp_open(&mut model, acc, line, &header)
                    }
                    // Inline `import filter { ... }` blocks and the like.
                    Ctx::Channel(_) => {
                        let guidance =
                            if header.starts_with("import") || header.starts_with("export") {
                                RPOL_GUIDANCE
                            } else {
                                GENERIC_GUIDANCE
                            };
                        skip(&mut model, line, format!("{header} {{ ... }}"), guidance);
                        Frame::Ignore
                    }
                    Ctx::Ignore => Frame::Ignore,
                };
                stack.push(frame);
            }
            Event::Stmt { line, text } => match ctx(&stack) {
                Ctx::Top => top_stmt(&mut model, line, &text),
                Ctx::Bgp => {
                    let Some(Frame::Bgp(acc)) = stack.last_mut() else {
                        unreachable!("ctx said Bgp");
                    };
                    bgp_stmt(&mut model, acc, line, &text);
                }
                Ctx::Channel(ipv6) => channel_stmt(&mut model, &mut stack, ipv6, line, &text),
                Ctx::Ignore => {}
            },
            Event::Close => {
                if let Some(Frame::Bgp(acc)) = stack.pop() {
                    finalize_bgp(&mut model, acc);
                }
            }
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

fn top_open(model: &mut Model, line: usize, header: &str) -> Frame {
    let words: Vec<&str> = header.split_whitespace().collect();
    match words.as_slice() {
        ["protocol", "bgp", rest @ ..] | ["template", "bgp", rest @ ..] => {
            let template = words[0] == "template";
            let name = rest.first().copied().unwrap_or("").to_owned();
            let from = rest
                .iter()
                .position(|w| *w == "from")
                .and_then(|i| rest.get(i + 1))
                .map(|s| (*s).to_owned());
            Frame::Bgp(BgpAcc {
                name,
                line,
                template,
                from,
                ..BgpAcc::default()
            })
        }
        // Pure interface-scanner boilerplate; nothing to translate.
        ["protocol", "device", ..] => Frame::Ignore,
        ["protocol", kind, ..] => {
            skip(
                model,
                line,
                format!("protocol {kind} {}", words.get(2).unwrap_or(&"")),
                format!(
                    "BIRD `{kind}` protocol is outside the BGP structural subset; \
                     kernel/static route handling differs per deployment — carry over by hand"
                ),
            );
            Frame::Ignore
        }
        ["filter", ..] | ["function", ..] => {
            skip(model, line, header.to_owned(), RPOL_GUIDANCE);
            Frame::Ignore
        }
        _ => {
            skip(model, line, header.to_owned(), GENERIC_GUIDANCE);
            Frame::Ignore
        }
    }
}

fn top_stmt(model: &mut Model, line: usize, text: &str) {
    if let Some(rest) = text.strip_prefix("router id ") {
        model.router_id = Some(rest.trim().to_owned());
        return;
    }
    let first = text.split_whitespace().next().unwrap_or("");
    match first {
        "log" | "debug" | "watchdog" | "timeformat" => {}
        "define" => skip(
            model,
            line,
            text.to_owned(),
            "constant used by filters; hand-translate alongside its filter to .rpol",
        ),
        _ => skip(model, line, text.to_owned(), GENERIC_GUIDANCE),
    }
}

fn bgp_open(model: &mut Model, acc: &mut BgpAcc, line: usize, header: &str) -> Frame {
    match header.split_whitespace().next() {
        Some("ipv4") => {
            acc.families.push("ipv4_unicast".to_owned());
            Frame::Channel(false)
        }
        Some("ipv6") => {
            acc.families.push("ipv6_unicast".to_owned());
            Frame::Channel(true)
        }
        _ => {
            let guidance = if header.contains("filter") {
                RPOL_GUIDANCE
            } else {
                GENERIC_GUIDANCE
            };
            skip(
                model,
                line,
                format!("{}: {header} {{ ... }}", scope(acc)),
                guidance,
            );
            Frame::Ignore
        }
    }
}

fn scope(acc: &BgpAcc) -> String {
    format!(
        "{} {}",
        if acc.template { "template" } else { "protocol" },
        acc.name
    )
}

fn bgp_stmt(model: &mut Model, acc: &mut BgpAcc, line: usize, text: &str) {
    let words: Vec<&str> = text.split_whitespace().collect();
    match words.as_slice() {
        // `local as N;` and `local <ip> as N;`
        ["local", rest @ ..] if rest.len() >= 2 && rest[rest.len() - 2] == "as" => {
            if let Ok(asn) = rest[rest.len() - 1].parse::<u32>() {
                match model.local_asn {
                    Some(existing) if existing != asn => model.warnings.push(format!(
                        "{}: local AS {asn} differs from previously seen {existing}; \
                         keeping {existing} (rustbgpd is a single-ASN daemon)",
                        scope(acc)
                    )),
                    _ => model.local_asn = Some(asn),
                }
                return;
            }
            skip(model, line, text.to_owned(), GENERIC_GUIDANCE);
        }
        ["neighbor", "range", ..] => skip(
            model,
            line,
            format!("{}: {text}", scope(acc)),
            "dynamic neighbor range: declare via rustbgpd [[dynamic_neighbors]] by hand",
        ),
        ["neighbor", rest @ ..] if rest.len() >= 3 && rest[rest.len() - 2] == "as" => {
            if let Ok(asn) = rest[rest.len() - 1].parse::<u32>() {
                acc.address = Some(rest[0].to_owned());
                acc.remote_asn = Some(asn);
                acc.line = line;
                return;
            }
            skip(model, line, text.to_owned(), GENERIC_GUIDANCE);
        }
        ["description", ..] => {
            acc.description = Some(unquote(&text["description".len()..]));
        }
        ["hold", "time", value] => match value.parse() {
            Ok(hold) => acc.hold_time = Some(hold),
            Err(_) => skip(model, line, text.to_owned(), GENERIC_GUIDANCE),
        },
        ["keepalive", "time", value] => match value.parse() {
            Ok(keepalive) => acc.keepalive = Some(keepalive),
            Err(_) => skip(model, line, text.to_owned(), GENERIC_GUIDANCE),
        },
        ["password", ..] => acc.auth_present = true,
        ["rr", "client"] => skip(
            model,
            line,
            format!("{}: rr client", scope(acc)),
            "set route_reflector_client = true on the neighbor by hand (iBGP only)",
        ),
        ["rs", "client"] => skip(
            model,
            line,
            format!("{}: rs client", scope(acc)),
            "set route_server_client = true on the neighbor by hand",
        ),
        _ => skip(
            model,
            line,
            format!("{}: {text}", scope(acc)),
            GENERIC_GUIDANCE,
        ),
    }
}

fn channel_stmt(model: &mut Model, stack: &mut [Frame], ipv6: bool, line: usize, text: &str) {
    let words: Vec<&str> = text.split_whitespace().collect();
    let acc_scope = stack
        .iter()
        .rev()
        .find_map(|f| match f {
            Frame::Bgp(acc) => Some(scope(acc)),
            _ => None,
        })
        .unwrap_or_default();
    match words.as_slice() {
        // Accept-everything matches rustbgpd's default (no policy = accept).
        ["import", "all"] | ["export", "all"] => {}
        ["import", "limit", value, ..] => {
            if let Ok(limit) = value.parse::<u32>() {
                if let Some(Frame::Bgp(acc)) =
                    stack.iter_mut().rev().find(|f| matches!(f, Frame::Bgp(_)))
                {
                    if ipv6 {
                        acc.max_prefixes_ipv6 = Some(limit);
                    } else {
                        acc.max_prefixes_ipv4 = Some(limit);
                    }
                }
                return;
            }
            skip(model, line, text.to_owned(), GENERIC_GUIDANCE);
        }
        ["import", ..] | ["export", ..] => {
            skip(model, line, format!("{acc_scope}: {text}"), RPOL_GUIDANCE)
        }
        _ => skip(
            model,
            line,
            format!("{acc_scope}: {text}"),
            GENERIC_GUIDANCE,
        ),
    }
}

fn finalize_bgp(model: &mut Model, acc: BgpAcc) {
    if let (Some(keepalive), Some(hold)) = (acc.keepalive, acc.hold_time)
        && u32::from(keepalive) * 3 != u32::from(hold)
    {
        model.warnings.push(format!(
            "{}: keepalive {keepalive}s is not hold/3 ({hold}/3); rustbgpd always derives \
             keepalive as hold_time/3",
            scope(&acc)
        ));
    }
    if acc.template {
        model.groups.push(Group {
            name: acc.name,
            remote_asn: acc.remote_asn,
            hold_time: acc.hold_time,
            families: acc.families,
            max_prefixes_ipv4: acc.max_prefixes_ipv4,
            max_prefixes_ipv6: acc.max_prefixes_ipv6,
            auth_present: acc.auth_present,
        });
        return;
    }
    let Some(address) = acc.address else {
        skip(
            model,
            acc.line,
            format!("{}: no `neighbor <ip> as <asn>` statement", scope(&acc)),
            "protocol declares no static neighbor; not translated",
        );
        return;
    };
    model.neighbors.push(Neighbor {
        address,
        source_line: acc.line,
        remote_asn: acc.remote_asn,
        description: acc.description,
        peer_group: acc.from,
        hold_time: acc.hold_time,
        families: acc.families,
        max_prefixes_ipv4: acc.max_prefixes_ipv4,
        max_prefixes_ipv6: acc.max_prefixes_ipv6,
        auth_present: acc.auth_present,
    });
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_owned()
}

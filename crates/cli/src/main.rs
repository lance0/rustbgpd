mod commands;
mod connection;
mod error;
mod output;
#[cfg(test)]
mod test_support;
mod tui;

pub mod proto {
    tonic::include_proto!("rustbgpd.v1");
}

use crate::connection::connect;
use crate::error::CliError;
use crate::output::parse_family;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

#[derive(Parser)]
#[command(name = "rustbgpctl", about = "CLI for rustbgpd", version)]
struct Cli {
    /// gRPC server address or unix:///path/to/socket
    #[arg(
        long,
        short = 's',
        default_value = "unix:///var/lib/rustbgpd/grpc.sock",
        env = "RUSTBGPD_ADDR",
        global = true
    )]
    addr: String,

    /// Bearer token file for authenticated gRPC endpoints
    #[arg(long, env = "RUSTBGPD_TOKEN_FILE", global = true)]
    token_file: Option<String>,

    /// Output in JSON format
    #[arg(long, short = 'j', global = true)]
    json: bool,

    /// Disable colored output
    ///
    /// The `NO_COLOR` environment variable is handled at runtime so its
    /// presence disables color without requiring a boolean value.
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show daemon global configuration
    Global,

    /// Manage BGP neighbors
    Neighbor {
        /// Neighbor address (omit to list all)
        address: Option<String>,

        #[command(subcommand)]
        action: Option<NeighborAction>,
    },

    /// Query and manage the RIB
    Rib {
        #[command(subcommand)]
        action: Option<RibAction>,

        /// Address family filter (ipv4_unicast, ipv6_unicast)
        #[arg(short = 'a', long)]
        family: Option<String>,

        /// Prefix filter (e.g., 10.0.0.0/24)
        #[arg(short = 'p', long)]
        prefix: Option<String>,

        /// Show longer (more specific) prefixes matching --prefix
        #[arg(short = 'l', long, requires = "prefix")]
        longer: bool,

        /// Show why the best route was selected (requires --prefix)
        #[arg(long, requires = "prefix")]
        explain: bool,

        /// Filter by origin ASN (last ASN in AS_PATH)
        #[arg(long)]
        origin_asn: Option<u32>,

        /// Filter by community (e.g., 65001:100); may be repeated
        #[arg(short = 'c', long, value_delimiter = ',')]
        community: Vec<String>,

        /// Filter by large community (e.g., 65001:100:200); may be repeated
        #[arg(long, value_delimiter = ',')]
        large_community: Vec<String>,
    },

    /// Manage FlowSpec routes
    Flowspec {
        #[command(subcommand)]
        action: Option<FlowspecAction>,

        /// Address family (ipv4_flowspec, ipv6_flowspec)
        #[arg(short = 'a', long)]
        family: Option<String>,
    },

    /// Watch route updates (streaming)
    Watch {
        /// Neighbor address filter
        address: Option<String>,

        /// Address family filter
        #[arg(short = 'a', long)]
        family: Option<String>,
    },

    /// Check daemon health
    Health,

    /// Show Prometheus metrics
    Metrics,

    /// Request daemon shutdown
    Shutdown {
        /// Shutdown reason
        #[arg(long)]
        reason: Option<String>,
    },

    /// Trigger an on-demand MRT dump
    MrtDump,

    /// Live TUI dashboard
    Top {
        /// Poll interval in seconds (1-60)
        #[arg(short = 'i', long, default_value = "2")]
        interval: u64,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum NeighborAction {
    /// Add a new neighbor
    Add {
        /// Remote AS number
        #[arg(long)]
        asn: u32,
        /// Description
        #[arg(long)]
        description: Option<String>,
        /// Hold time in seconds
        #[arg(long)]
        hold_time: Option<u32>,
        /// Max prefix limit
        #[arg(long)]
        max_prefixes: Option<u32>,
        /// Address families (comma-separated)
        #[arg(long, value_delimiter = ',')]
        families: Vec<String>,
        /// Enable transparent route-server client mode (eBGP only)
        #[arg(long)]
        route_server_client: bool,
        /// Enable Add-Path receive
        #[arg(long)]
        add_path_receive: bool,
        /// Enable Add-Path send
        #[arg(long)]
        add_path_send: bool,
        /// Max paths per prefix for Add-Path send
        #[arg(long, default_value = "0")]
        add_path_send_max: u32,
    },
    /// Delete this neighbor
    Delete,
    /// Enable this neighbor
    Enable,
    /// Disable this neighbor
    Disable {
        /// Disable reason
        #[arg(long)]
        reason: Option<String>,
    },
    /// Trigger soft reset (inbound)
    Softreset {
        /// Address family to refresh
        #[arg(short = 'a', long)]
        family: Option<String>,
    },
}

#[derive(Subcommand)]
enum RibAction {
    /// Show received routes from a neighbor
    Received {
        /// Neighbor address
        address: String,
        /// Address family filter
        #[arg(short = 'a', long)]
        family: Option<String>,
    },
    /// Show advertised routes to a neighbor
    Advertised {
        /// Neighbor address
        address: String,
        /// Address family filter
        #[arg(short = 'a', long)]
        family: Option<String>,
        /// Explain whether this exact prefix would be advertised to the peer
        #[arg(long)]
        explain: bool,
    },
    /// Inject a route
    Add {
        /// Prefix (e.g., 10.0.0.0/24)
        prefix: String,
        /// Next hop address
        #[arg(long)]
        nexthop: String,
        /// Origin (0=igp, 1=egp, 2=incomplete)
        #[arg(long)]
        origin: Option<u32>,
        /// Local preference
        #[arg(long)]
        local_pref: Option<u32>,
        /// MED
        #[arg(long)]
        med: Option<u32>,
        /// AS path (space-separated)
        #[arg(long, value_delimiter = ' ')]
        as_path: Vec<u32>,
        /// Communities (e.g., 65001:100)
        #[arg(long, value_delimiter = ',')]
        communities: Vec<String>,
        /// Large communities (e.g., 65001:100:200)
        #[arg(long, value_delimiter = ',')]
        large_communities: Vec<String>,
        /// Path ID for Add-Path
        #[arg(long)]
        path_id: Option<u32>,
    },
    /// Withdraw a route
    Delete {
        /// Prefix (e.g., 10.0.0.0/24)
        prefix: String,
        /// Path ID for Add-Path
        #[arg(long)]
        path_id: Option<u32>,
    },
}

#[derive(Subcommand)]
enum FlowspecAction {
    /// Add a FlowSpec rule
    Add {
        /// Address family (required: ipv4_flowspec or ipv6_flowspec)
        #[arg(short = 'a', long)]
        family: String,
        /// Match components (e.g., dest=10.0.0.0/24 port==80)
        #[arg(long = "match", value_delimiter = ' ')]
        components: Vec<String>,
        /// Actions (e.g., drop, rate=1000, redirect=65001:100)
        #[arg(long, value_delimiter = ' ')]
        action: Vec<String>,
    },
    /// Delete a FlowSpec rule
    Delete {
        /// Address family (required: ipv4_flowspec or ipv6_flowspec)
        #[arg(short = 'a', long)]
        family: String,
        /// Match components identifying the rule
        #[arg(long = "match", value_delimiter = ' ')]
        components: Vec<String>,
    },
}

fn resolve_family(family: &Option<String>) -> Result<Option<i32>, CliError> {
    match family {
        Some(f) => parse_family(f)
            .map(Some)
            .ok_or_else(|| CliError::Argument(format!("unknown address family: {f}"))),
        None => Ok(None),
    }
}

/// Parse community string "ASN:value" into u32.
fn parse_community_str(s: &str) -> Result<u32, String> {
    let (high, low) = s
        .split_once(':')
        .ok_or_else(|| format!("invalid community: {s} (expected ASN:value)"))?;
    let h: u32 = high
        .parse()
        .map_err(|_| format!("invalid community ASN: {high}"))?;
    let l: u32 = low
        .parse()
        .map_err(|_| format!("invalid community value: {low}"))?;
    if h > 65535 || l > 65535 {
        return Err(format!("community values must be <= 65535: {s}"));
    }
    Ok((h << 16) | l)
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let no_color = cli.no_color || std::env::var_os("NO_COLOR").is_some();
    if no_color || cli.json {
        owo_colors::set_override(false);
    }

    if let Err(e) = run(cli).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    // Shell completions don't need a gRPC connection.
    if let Command::Completions { shell } = cli.command {
        clap_complete::generate(
            shell,
            &mut Cli::command(),
            "rustbgpctl",
            &mut std::io::stdout(),
        );
        return Ok(());
    }

    let connection = connect(&cli.addr, cli.token_file.as_deref()).await?;
    let json = cli.json;

    match cli.command {
        Command::Global => commands::global::run(connection, json).await,

        Command::Neighbor { address, action } => match (address, action) {
            (None, None) => commands::neighbor::list(connection, json).await,
            (Some(addr), None) => commands::neighbor::show(connection, &addr, json).await,
            (
                Some(addr),
                Some(NeighborAction::Add {
                    asn,
                    description,
                    hold_time,
                    max_prefixes,
                    families,
                    route_server_client,
                    add_path_receive,
                    add_path_send,
                    add_path_send_max,
                }),
            ) => {
                commands::neighbor::add(
                    connection,
                    &addr,
                    commands::neighbor::AddNeighborOpts {
                        asn,
                        description,
                        hold_time,
                        max_prefixes,
                        families,
                        route_server_client,
                        add_path_receive,
                        add_path_send,
                        add_path_send_max,
                    },
                    json,
                )
                .await
            }
            (Some(addr), Some(NeighborAction::Delete)) => {
                commands::neighbor::delete(connection, &addr, json).await
            }
            (Some(addr), Some(NeighborAction::Enable)) => {
                commands::neighbor::enable(connection, &addr, json).await
            }
            (Some(addr), Some(NeighborAction::Disable { reason })) => {
                commands::neighbor::disable(connection, &addr, reason, json).await
            }
            (Some(addr), Some(NeighborAction::Softreset { family })) => {
                commands::neighbor::softreset(connection, &addr, family, json).await
            }
            (None, Some(_)) => Err(CliError::Argument(
                "neighbor address required for this action".into(),
            )),
        },

        Command::Rib {
            action,
            family,
            prefix,
            longer,
            explain,
            origin_asn,
            community,
            large_community,
        } => {
            let family_val = resolve_family(&family)?;
            let parsed_filter_communities: Vec<u32> = community
                .iter()
                .map(|s| parse_community_str(s))
                .collect::<Result<_, _>>()
                .map_err(CliError::Argument)?;
            let filters = commands::rib::RouteFilterOpts {
                prefix,
                longer,
                origin_asn,
                community: parsed_filter_communities,
                large_community,
            };
            match action {
                None => {
                    if explain {
                        if filters.longer {
                            return Err(CliError::Argument(
                                "--explain does not support --longer".into(),
                            ));
                        }
                        if filters.origin_asn.is_some()
                            || !filters.community.is_empty()
                            || !filters.large_community.is_empty()
                        {
                            return Err(CliError::Argument(
                                "--explain does not support route filters other than --prefix"
                                    .into(),
                            ));
                        }
                        let Some(prefix) = filters.prefix.as_deref() else {
                            return Err(CliError::Argument(
                                "--explain requires --prefix with an exact CIDR".into(),
                            ));
                        };
                        commands::rib::explain_best_path(connection, prefix, json).await
                    } else {
                        commands::rib::best(connection, family_val, &filters, json).await
                    }
                }
                Some(RibAction::Received {
                    address,
                    family: fam,
                }) => {
                    if explain {
                        return Err(CliError::Argument(
                            "--explain is only valid for the default best-routes view (rib --prefix X --explain)".into(),
                        ));
                    }
                    let f = resolve_family(&fam.or(family))?;
                    commands::rib::received(connection, &address, f, &filters, json).await
                }
                Some(RibAction::Advertised {
                    address,
                    family: fam,
                    explain: explain_advertised,
                }) => {
                    if explain {
                        return Err(CliError::Argument(
                            "--explain is only valid for the default best-routes view (rib --prefix X --explain)".into(),
                        ));
                    }
                    let f = resolve_family(&fam.or(family))?;
                    if explain_advertised {
                        if filters.longer {
                            return Err(CliError::Argument(
                                "--explain does not support --longer".into(),
                            ));
                        }
                        if filters.origin_asn.is_some()
                            || !filters.community.is_empty()
                            || !filters.large_community.is_empty()
                        {
                            return Err(CliError::Argument(
                                "--explain does not support route filters other than --prefix"
                                    .into(),
                            ));
                        }
                        let Some(prefix) = filters.prefix.as_deref() else {
                            return Err(CliError::Argument(
                                "--explain requires --prefix with an exact CIDR".into(),
                            ));
                        };
                        commands::rib::explain_advertised(connection, &address, prefix, json).await
                    } else {
                        commands::rib::advertised(connection, &address, f, &filters, json).await
                    }
                }
                Some(RibAction::Add {
                    prefix,
                    nexthop,
                    origin,
                    local_pref,
                    med,
                    as_path,
                    communities,
                    large_communities,
                    path_id,
                }) => {
                    if explain {
                        return Err(CliError::Argument(
                            "--explain is only valid for the default best-routes view (rib --prefix X --explain)".into(),
                        ));
                    }
                    let parsed_communities: Vec<u32> = communities
                        .iter()
                        .map(|s| parse_community_str(s))
                        .collect::<Result<_, _>>()
                        .map_err(CliError::Argument)?;
                    commands::rib::add_route(
                        connection,
                        &prefix,
                        commands::rib::AddRouteOpts {
                            next_hop: nexthop,
                            origin,
                            local_pref,
                            med,
                            as_path,
                            communities: parsed_communities,
                            large_communities,
                            path_id,
                        },
                        json,
                    )
                    .await
                }
                Some(RibAction::Delete { prefix, path_id }) => {
                    if explain {
                        return Err(CliError::Argument(
                            "--explain is only valid for the default best-routes view (rib --prefix X --explain)".into(),
                        ));
                    }
                    commands::rib::delete_route(connection, &prefix, path_id, json).await
                }
            }
        }

        Command::Watch { address, family } => {
            let family_val = resolve_family(&family)?;
            commands::watch::run(connection, address, family_val, json).await
        }

        Command::Flowspec { action, family } => {
            let family_val = resolve_family(&family)?;
            match action {
                None => commands::flowspec::list(connection, family_val, json).await,
                Some(FlowspecAction::Add {
                    family: fam,
                    components,
                    action: actions,
                }) => {
                    let f = parse_family(&fam).ok_or_else(|| {
                        CliError::Argument(format!("unknown address family: {fam}"))
                    })?;
                    commands::flowspec::add(connection, f, &components, &actions, json).await
                }
                Some(FlowspecAction::Delete {
                    family: fam,
                    components,
                }) => {
                    let f = parse_family(&fam).ok_or_else(|| {
                        CliError::Argument(format!("unknown address family: {fam}"))
                    })?;
                    commands::flowspec::delete(connection, f, &components, json).await
                }
            }
        }

        Command::Health => commands::control::health(connection, json).await,
        Command::Metrics => commands::control::metrics(connection).await,
        Command::Shutdown { reason } => commands::control::shutdown(connection, reason, json).await,
        Command::MrtDump => commands::control::mrt_dump(connection, json).await,
        Command::Top { interval } => {
            if !(1..=60).contains(&interval) {
                return Err(CliError::Argument(
                    "interval must be between 1 and 60 seconds".into(),
                ));
            }
            tui::run(connection, interval).await
        }
        Command::Completions { .. } => unreachable!("handled before connect"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_parse_global() {
        let cli = Cli::try_parse_from(["rustbgpctl", "global"]).unwrap();
        assert!(matches!(cli.command, Command::Global));
    }

    #[test]
    fn test_parse_health() {
        let cli = Cli::try_parse_from(["rustbgpctl", "health"]).unwrap();
        assert!(matches!(cli.command, Command::Health));
    }

    #[test]
    fn test_parse_neighbor_list() {
        let cli = Cli::try_parse_from(["rustbgpctl", "neighbor"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Neighbor {
                address: None,
                action: None
            }
        ));
    }

    #[test]
    fn test_parse_neighbor_show() {
        let cli = Cli::try_parse_from(["rustbgpctl", "neighbor", "10.0.0.1"]).unwrap();
        if let Command::Neighbor { address, action } = cli.command {
            assert_eq!(address.unwrap(), "10.0.0.1");
            assert!(action.is_none());
        } else {
            panic!("expected Neighbor command");
        }
    }

    #[test]
    fn test_parse_neighbor_add() {
        let cli = Cli::try_parse_from([
            "rustbgpctl",
            "neighbor",
            "10.0.0.1",
            "add",
            "--asn",
            "65001",
        ])
        .unwrap();
        if let Command::Neighbor {
            address: Some(addr),
            action: Some(NeighborAction::Add { asn, .. }),
        } = cli.command
        {
            assert_eq!(addr, "10.0.0.1");
            assert_eq!(asn, 65001);
        } else {
            panic!("expected Neighbor Add command");
        }
    }

    #[test]
    fn test_parse_rib_best() {
        let cli = Cli::try_parse_from(["rustbgpctl", "rib"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Rib {
                action: None,
                family: None,
                ..
            }
        ));
    }

    #[test]
    fn test_parse_rib_received() {
        let cli = Cli::try_parse_from(["rustbgpctl", "rib", "received", "10.0.0.1"]).unwrap();
        if let Command::Rib {
            action: Some(RibAction::Received { address, .. }),
            ..
        } = cli.command
        {
            assert_eq!(address, "10.0.0.1");
        } else {
            panic!("expected Rib Received command");
        }
    }

    #[test]
    fn test_parse_rib_advertised_explain() {
        let cli = Cli::try_parse_from([
            "rustbgpctl",
            "rib",
            "--prefix",
            "203.0.113.0/24",
            "advertised",
            "192.0.2.1",
            "--explain",
        ])
        .unwrap();
        if let Command::Rib {
            action: Some(RibAction::Advertised {
                address, explain, ..
            }),
            prefix,
            ..
        } = cli.command
        {
            assert_eq!(address, "192.0.2.1");
            assert!(explain);
            assert_eq!(prefix.as_deref(), Some("203.0.113.0/24"));
        } else {
            panic!("expected Rib Advertised explain command");
        }
    }

    #[test]
    fn test_parse_rib_add() {
        let cli = Cli::try_parse_from([
            "rustbgpctl",
            "rib",
            "add",
            "10.0.0.0/24",
            "--nexthop",
            "10.0.0.1",
        ])
        .unwrap();
        if let Command::Rib {
            action: Some(RibAction::Add {
                prefix, nexthop, ..
            }),
            ..
        } = cli.command
        {
            assert_eq!(prefix, "10.0.0.0/24");
            assert_eq!(nexthop, "10.0.0.1");
        } else {
            panic!("expected Rib Add command");
        }
    }

    #[test]
    fn test_parse_shutdown() {
        let cli =
            Cli::try_parse_from(["rustbgpctl", "shutdown", "--reason", "maintenance"]).unwrap();
        if let Command::Shutdown { reason } = cli.command {
            assert_eq!(reason.unwrap(), "maintenance");
        } else {
            panic!("expected Shutdown command");
        }
    }

    #[test]
    fn test_parse_json_flag() {
        let cli = Cli::try_parse_from(["rustbgpctl", "--json", "health"]).unwrap();
        assert!(cli.json);
    }

    #[test]
    fn test_parse_no_color_flag() {
        let cli = Cli::try_parse_from(["rustbgpctl", "--no-color", "health"]).unwrap();
        assert!(cli.no_color);
    }

    #[test]
    fn test_parse_addr_flag() {
        let cli =
            Cli::try_parse_from(["rustbgpctl", "--addr", "10.0.0.1:50051", "health"]).unwrap();
        assert_eq!(cli.addr, "10.0.0.1:50051");
    }

    #[test]
    fn test_parse_unix_addr_flag() {
        let cli = Cli::try_parse_from([
            "rustbgpctl",
            "--addr",
            "unix:///run/rustbgpd/grpc.sock",
            "health",
        ])
        .unwrap();
        assert_eq!(cli.addr, "unix:///run/rustbgpd/grpc.sock");
    }

    #[test]
    fn test_parse_token_file_flag() {
        let cli = Cli::try_parse_from([
            "rustbgpctl",
            "--token-file",
            "/run/rustbgpd/token",
            "health",
        ])
        .unwrap();
        assert_eq!(cli.token_file.as_deref(), Some("/run/rustbgpd/token"));
    }

    #[test]
    fn test_parse_watch() {
        let cli = Cli::try_parse_from(["rustbgpctl", "watch"]).unwrap();
        assert!(matches!(cli.command, Command::Watch { .. }));
    }

    #[test]
    fn test_parse_community_str() {
        assert_eq!(
            parse_community_str("65001:100").unwrap(),
            (65001 << 16) | 100
        );
        assert!(parse_community_str("invalid").is_err());
        assert!(parse_community_str("70000:1").is_err());
    }
}

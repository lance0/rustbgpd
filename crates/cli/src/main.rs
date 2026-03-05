mod commands;
mod error;
mod output;

pub mod proto {
    tonic::include_proto!("rustbgpd.v1");
}

use clap::{Parser, Subcommand};
use std::time::Duration;
use tonic::transport::{Channel, Endpoint};

use crate::error::CliError;
use crate::output::parse_family;

#[derive(Parser)]
#[command(name = "rustbgpctl", about = "CLI for rustbgpd", version)]
struct Cli {
    /// gRPC server address
    #[arg(
        long,
        short = 's',
        default_value = "127.0.0.1:50051",
        env = "RUSTBGPD_ADDR",
        global = true
    )]
    addr: String,

    /// Output in JSON format
    #[arg(long, short = 'j', global = true)]
    json: bool,

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

async fn connect(addr: &str) -> Result<Channel, CliError> {
    let uri = if addr.starts_with("http") {
        addr.to_string()
    } else {
        format!("http://{addr}")
    };
    let channel = Endpoint::from_shared(uri)
        .map_err(|e| CliError::Argument(format!("invalid address: {e}")))?
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await?;
    Ok(channel)
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

    if let Err(e) = run(cli).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    let channel = connect(&cli.addr).await?;
    let json = cli.json;

    match cli.command {
        Command::Global => commands::global::run(channel, json).await,

        Command::Neighbor { address, action } => match (address, action) {
            (None, None) => commands::neighbor::list(channel, json).await,
            (Some(addr), None) => commands::neighbor::show(channel, &addr, json).await,
            (
                Some(addr),
                Some(NeighborAction::Add {
                    asn,
                    description,
                    hold_time,
                    max_prefixes,
                    families,
                }),
            ) => {
                commands::neighbor::add(
                    channel,
                    &addr,
                    commands::neighbor::AddNeighborOpts {
                        asn,
                        description,
                        hold_time,
                        max_prefixes,
                        families,
                    },
                    json,
                )
                .await
            }
            (Some(addr), Some(NeighborAction::Delete)) => {
                commands::neighbor::delete(channel, &addr, json).await
            }
            (Some(addr), Some(NeighborAction::Enable)) => {
                commands::neighbor::enable(channel, &addr, json).await
            }
            (Some(addr), Some(NeighborAction::Disable { reason })) => {
                commands::neighbor::disable(channel, &addr, reason, json).await
            }
            (Some(addr), Some(NeighborAction::Softreset { family })) => {
                commands::neighbor::softreset(channel, &addr, family, json).await
            }
            (None, Some(_)) => Err(CliError::Argument(
                "neighbor address required for this action".into(),
            )),
        },

        Command::Rib { action, family } => {
            let family_val = resolve_family(&family)?;
            match action {
                None => commands::rib::best(channel, family_val, json).await,
                Some(RibAction::Received {
                    address,
                    family: fam,
                }) => {
                    let f = resolve_family(&fam.or(family))?;
                    commands::rib::received(channel, &address, f, json).await
                }
                Some(RibAction::Advertised {
                    address,
                    family: fam,
                }) => {
                    let f = resolve_family(&fam.or(family))?;
                    commands::rib::advertised(channel, &address, f, json).await
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
                    let parsed_communities: Vec<u32> = communities
                        .iter()
                        .map(|s| parse_community_str(s))
                        .collect::<Result<_, _>>()
                        .map_err(CliError::Argument)?;
                    commands::rib::add_route(
                        channel,
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
                    commands::rib::delete_route(channel, &prefix, path_id, json).await
                }
            }
        }

        Command::Watch { address, family } => {
            let family_val = resolve_family(&family)?;
            commands::watch::run(channel, address, family_val, json).await
        }

        Command::Flowspec { action, family } => {
            let family_val = resolve_family(&family)?;
            match action {
                None => commands::flowspec::list(channel, family_val, json).await,
                Some(FlowspecAction::Add {
                    family: fam,
                    components,
                    action: actions,
                }) => {
                    let f = parse_family(&fam).ok_or_else(|| {
                        CliError::Argument(format!("unknown address family: {fam}"))
                    })?;
                    commands::flowspec::add(channel, f, &components, &actions, json).await
                }
                Some(FlowspecAction::Delete {
                    family: fam,
                    components,
                }) => {
                    let f = parse_family(&fam).ok_or_else(|| {
                        CliError::Argument(format!("unknown address family: {fam}"))
                    })?;
                    commands::flowspec::delete(channel, f, &components, json).await
                }
            }
        }

        Command::Health => commands::control::health(channel, json).await,
        Command::Metrics => commands::control::metrics(channel).await,
        Command::Shutdown { reason } => commands::control::shutdown(channel, reason, json).await,
        Command::MrtDump => commands::control::mrt_dump(channel, json).await,
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
                family: None
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
    fn test_parse_addr_flag() {
        let cli =
            Cli::try_parse_from(["rustbgpctl", "--addr", "10.0.0.1:50051", "health"]).unwrap();
        assert_eq!(cli.addr, "10.0.0.1:50051");
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

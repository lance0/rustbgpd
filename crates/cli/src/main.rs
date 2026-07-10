#![deny(unsafe_code)]

mod commands;
mod connection;
mod error;
mod output;
#[cfg(test)]
mod test_support;
mod tui;

pub mod proto {
    #![allow(clippy::large_enum_variant)]

    tonic::include_proto!("rustbgpd.v1");
}

use crate::connection::connect;
use crate::error::CliError;
use crate::output::parse_family;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

const BINARY_NAME: &str = "rbgp";

#[derive(Parser)]
#[command(name = "rbgp", bin_name = "rbgp", about = "CLI for rustbgpd", version)]
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

    /// Runtime config diagnostics
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Manage BGP neighbors
    #[command(visible_alias = "summary")]
    Neighbor {
        /// Neighbor address (omit to list all)
        address: Option<String>,

        #[command(subcommand)]
        action: Option<NeighborAction>,
    },

    /// Inspect single-hop BFD sessions (ADR-0067)
    Bfd {
        #[command(subcommand)]
        action: Option<BfdAction>,
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

        /// Scope --explain to a specific peer's Add-Path send view.
        /// When set, candidates are filtered by the peer's export
        /// policy + sendable families and the top
        /// `add_path_send_max` are tagged with their advertised
        /// rank. Omit for the global Loc-RIB view.
        #[arg(long, requires = "explain")]
        explain_peer: Option<String>,

        /// Filter by origin ASN (last ASN in AS_PATH)
        #[arg(long)]
        origin_asn: Option<u32>,

        /// Filter by community (e.g., 65001:100 or BLACKHOLE); may be repeated
        #[arg(short = 'c', long, value_delimiter = ',')]
        community: Vec<String>,

        /// Filter by large community (e.g., 65001:100:200); may be repeated
        #[arg(long, value_delimiter = ',')]
        large_community: Vec<String>,
    },

    /// Show the RFC 9107 ORR topology graph derived from BGP-LS
    Topology {
        #[command(subcommand)]
        action: TopologyAction,
    },

    /// Show RFC 9107 ORR per-vantage status (resolution, SPF reach, peers)
    Orr,

    /// Compare live RIB views against an external snapshot (read-only)
    Diff {
        #[command(subcommand)]
        action: DiffAction,
    },

    /// Manage FlowSpec routes
    Flowspec {
        #[command(subcommand)]
        action: Option<FlowspecAction>,

        /// Address family (ipv4_flowspec, ipv6_flowspec)
        #[arg(short = 'a', long)]
        family: Option<String>,
    },

    /// Manage EVPN routes (list, add, delete — RFC 7432)
    Evpn {
        #[command(subcommand)]
        action: Option<EvpnAction>,

        /// Route type filter (1..=5) — applies when no subcommand is given.
        #[arg(long)]
        route_type: Option<u32>,

        /// Peer IP address filter (list mode only)
        #[arg(long)]
        peer: Option<String>,

        /// Route Distinguisher filter (list mode only), e.g. "65000:100"
        #[arg(long)]
        rd: Option<String>,
    },

    /// Watch route updates (streaming)
    Watch {
        /// Neighbor address filter
        address: Option<String>,

        /// Address family filter
        #[arg(short = 'a', long)]
        family: Option<String>,
    },

    /// Show recent route update events
    Events {
        #[command(subcommand)]
        action: Option<EventsAction>,

        /// Neighbor address filter
        #[arg(long)]
        address: Option<String>,

        /// Address family filter
        #[arg(short = 'a', long)]
        family: Option<String>,

        /// Exact prefix filter, e.g. 203.0.113.0/24
        #[arg(long)]
        prefix: Option<String>,

        /// Maximum recent route events to return (default 100; route history only)
        #[arg(short, long)]
        limit: Option<u32>,
    },

    /// Check daemon health
    Health,

    /// Write a redacted support bundle for operators and issue reports
    Doctor {
        /// Output directory. Defaults to `rustbgpd-support-<unix-seconds>`.
        #[arg(long, value_name = "DIR")]
        output: Option<PathBuf>,
    },

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

    /// Toggle the RFC 8326 GRACEFUL_SHUTDOWN community on outbound updates
    /// for one peer (`--peer X`) or every currently-managed peer (omit
    /// `--peer`). Receivers that honor RFC 8326 will set local_pref = 0
    /// on tagged paths, draining traffic ahead of planned maintenance.
    Gshut {
        /// Peer address; omit to toggle for all peers.
        #[arg(long)]
        peer: Option<String>,

        /// Clear instead of enabling.
        #[arg(long)]
        clear: bool,
    },

    /// Live TUI dashboard
    Top {
        /// Poll interval in seconds (1-60)
        #[arg(short = 'i', long, default_value = "2")]
        interval: u64,
    },

    /// Manage named `[[policy_definitions]]` entries and the global /
    /// per-neighbor import/export chains. Backed by PolicyService.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Manage named `[[neighbor_sets]]` entries used by policy
    /// `match_neighbor_set`. Backed by PolicyService.
    NeighborSet {
        #[command(subcommand)]
        action: NeighborSetAction,
    },

    /// Manage named `[[peer_groups]]` entries and bind/unbind neighbors
    /// to them. Backed by PeerGroupService.
    PeerGroup {
        #[command(subcommand)]
        action: PeerGroupAction,
    },

    /// Manage `[[dynamic_neighbors]]` prefix ranges that auto-accept inbound
    /// peers into a peer group. Backed by NeighborService.
    DynamicNeighbor {
        #[command(subcommand)]
        action: DynamicNeighborAction,
    },

    /// Manage `[[fib_tables]]` (ADR-0061 general unicast FIB export) at runtime.
    /// Hot-applies through the FIB reconciler and persists to the config.
    FibTable {
        #[command(subcommand)]
        action: FibTableAction,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Diff a candidate TOML file against the daemon's live runtime snapshot
    Diff {
        /// Candidate TOML file to validate and compare
        #[arg(long, value_name = "PATH")]
        from_file: String,
    },

    /// Validate and classify a candidate transaction without mutation
    Plan {
        /// Candidate TOML file to validate and classify
        #[arg(long, value_name = "PATH")]
        from_file: String,

        /// Optional runtime snapshot token to check while planning
        #[arg(long, value_name = "TOKEN")]
        expected_runtime_snapshot_token: Option<String>,
    },

    /// Commit a previously planned candidate transaction
    Apply {
        /// Candidate TOML file to validate and commit
        #[arg(long, value_name = "PATH")]
        from_file: String,

        /// Runtime snapshot token returned by config plan
        #[arg(long, value_name = "TOKEN")]
        expected_runtime_snapshot_token: String,

        /// Optional audit/correlation identifier
        #[arg(long, value_name = "ID")]
        client_request_id: Option<String>,

        /// Optional human change note; not logged verbatim by the daemon
        #[arg(long, value_name = "TEXT")]
        comment: Option<String>,

        /// Optional confirmed-commit handle; requires explicit confirm/abort
        #[arg(long, value_name = "ID")]
        confirm_id: Option<String>,

        /// Confirmed-commit timeout in seconds; daemon default is 600, max is 86400
        #[arg(
            long = "confirm-timeout",
            value_name = "SECONDS",
            requires = "confirm_id"
        )]
        confirm_timeout_seconds: Option<u32>,
    },

    /// Confirm a pending confirmed config transaction
    Confirm {
        /// Confirmed-commit handle passed to config apply
        confirm_id: String,
    },

    /// Abort a pending confirmed config transaction and roll back immediately
    Abort {
        /// Confirmed-commit handle passed to config apply
        confirm_id: String,
    },

    /// Show pending or last confirmed-transaction lifecycle state
    Status,
}

#[derive(Subcommand)]
enum PolicyAction {
    /// List configured policies (names + statement counts)
    List,
    /// Check an `.rpol` policy file locally: parse, typecheck, and run
    /// its in-language `test` blocks. No daemon connection. Exit codes:
    /// 0 clean, 1 diagnostics, 2 test failures.
    Check {
        /// Path to the `.rpol` file
        file: String,
    },
    /// Dry-run a candidate `.rpol` policy against the daemon's live
    /// RIB (ADR-0096): the file compiles server-side and evaluates
    /// read-only over a route snapshot — counts, per-term hit
    /// counters, and before/after attribute diffs. No route state or
    /// session is touched. Exit codes: 0 ran, 1 compile diagnostics.
    Test {
        /// Path to the `.rpol` file
        file: String,
        /// Policy to evaluate: a name, or a call-form with u32
        /// arguments for parameterized policies, e.g. "customer-in(200)"
        #[arg(long)]
        policy: String,
        /// Evaluation direction: import (Adj-RIB-In) or export
        /// (Loc-RIB best routes)
        #[arg(long)]
        direction: String,
        /// Peer address: restricts the import snapshot to one peer's
        /// Adj-RIB-In, or sets the export evaluation target peer
        #[arg(long)]
        peer: Option<String>,
        /// Address family filter (ipv4_unicast, ipv6_unicast)
        #[arg(short = 'a', long)]
        family: Option<String>,
        /// Maximum routes to evaluate (0 = all)
        #[arg(long, default_value_t = 0)]
        limit: u32,
        /// Maximum before/after attribute diffs to show
        #[arg(long, default_value_t = 10)]
        show_changes: u32,
    },
    /// Show one policy by name
    Get {
        /// Policy name
        name: String,
    },
    /// Set (create or replace) a policy from a JSON file
    Set {
        /// Policy name
        name: String,
        /// JSON file containing the PolicyDefinition shape
        #[arg(long, value_name = "PATH")]
        from_file: String,
    },
    /// Delete a policy by name
    Delete {
        /// Policy name
        name: String,
    },
    /// Manage global / per-neighbor import/export chains
    Chain {
        #[command(subcommand)]
        action: PolicyChainAction,
    },
    /// Show live per-term policy hit counters (ADR-0096): how many
    /// routes matched each term of the installed import/export chains
    /// since chain install. Counters reset when a chain is replaced
    /// (policy reload / hot-apply); import chains report their install
    /// generation so a replacement is visible.
    #[command(visible_alias = "counters")]
    Stats {
        /// Restrict to one peer's installed chain
        #[arg(long)]
        peer: Option<String>,
        /// Direction: export (default), import, or both
        #[arg(long, default_value = "export", value_parser = ["import", "export", "both"])]
        direction: String,
    },
    /// Explain the import-policy decision for a prefix on a neighbor
    /// (ADR-0073): why it was permitted / denied / withdrawn, or
    /// not-seen / evicted / stale. Reads the per-session decision
    /// cache; requires `[policy.explain].enabled` on the daemon.
    Explain {
        /// Neighbor (peer) address whose import-decision cache to read
        #[arg(long)]
        neighbor: String,
        /// Prefix in CIDR form, e.g. `192.0.2.0/24` or `2001:db8::/32`
        #[arg(long)]
        prefix: String,
        /// Add-Path identifier; omit to show every matching path
        #[arg(long)]
        path_id: Option<u32>,
    },
}

#[derive(Subcommand)]
enum PolicyChainAction {
    /// Show the global chains, or the per-neighbor chains when
    /// `--neighbor` is given.
    Show {
        /// Neighbor address (omit for the global chains)
        #[arg(long)]
        neighbor: Option<String>,
    },
    /// Replace the import chain. Empty list is rejected — use
    /// `clear-import` instead. Apply globally by omitting `--neighbor`.
    SetImport {
        /// Neighbor address (omit for global)
        #[arg(long)]
        neighbor: Option<String>,
        /// Ordered policy names that compose the chain
        policies: Vec<String>,
    },
    /// Replace the export chain.
    SetExport {
        #[arg(long)]
        neighbor: Option<String>,
        policies: Vec<String>,
    },
    /// Clear the import chain entirely.
    ClearImport {
        #[arg(long)]
        neighbor: Option<String>,
    },
    /// Clear the export chain entirely.
    ClearExport {
        #[arg(long)]
        neighbor: Option<String>,
    },
}

#[derive(Subcommand)]
enum NeighborSetAction {
    /// List configured neighbor sets
    List,
    /// Show one neighbor set by name
    Get { name: String },
    /// Set (create or replace) a neighbor set from a JSON file
    Set {
        name: String,
        #[arg(long, value_name = "PATH")]
        from_file: String,
    },
    /// Delete a neighbor set
    Delete { name: String },
}

#[derive(Subcommand)]
enum PeerGroupAction {
    /// List configured peer groups
    List,
    /// Show one peer group by name
    Get { name: String },
    /// Set (create or replace) a peer group from a JSON file
    Set {
        name: String,
        #[arg(long, value_name = "PATH")]
        from_file: String,
    },
    /// Delete a peer group
    Delete { name: String },
    /// Bind a neighbor to a peer group
    Attach {
        /// Neighbor address
        address: String,
        /// Peer-group name
        #[arg(long)]
        group: String,
    },
    /// Unbind a neighbor from its peer group
    Detach {
        /// Neighbor address
        address: String,
    },
}

#[derive(Subcommand)]
enum DynamicNeighborAction {
    /// List configured dynamic neighbor ranges
    List,
    /// Add a dynamic neighbor range
    Add {
        /// Prefix range (e.g. 10.0.0.0/24)
        prefix: String,
        /// Peer group the dynamic peers inherit
        #[arg(long)]
        peer_group: String,
        /// Expected remote ASN (0 = accept any ASN from OPEN)
        #[arg(long, default_value_t = 0)]
        asn: u32,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
    },
    /// Delete a dynamic neighbor range by prefix
    Delete {
        /// Prefix range to remove
        prefix: String,
    },
}

#[derive(Subcommand)]
enum FibTableAction {
    /// List the configured FIB tables and runtime availability
    List,
    /// Create or replace a FIB table by name (full definition, not a patch)
    Set {
        /// Table name (unique handle)
        name: String,
        /// Linux route table id
        #[arg(long)]
        table_id: u32,
        /// Kernel route metric / priority for daemon-owned rows
        #[arg(long)]
        metric: u32,
        /// Address families (comma-separated, e.g. ipv4_unicast,ipv6_unicast).
        /// Empty defaults to both unicast families.
        #[arg(long, value_delimiter = ',')]
        families: Vec<String>,
        /// Peer-group allow-list (repeatable / comma-separated). Empty = all.
        #[arg(long = "allowed-peer-group", value_delimiter = ',')]
        allowed_peer_groups: Vec<String>,
        /// Neighbor-address allow-list (repeatable / comma-separated). Empty = all.
        #[arg(long = "allowed-neighbor", value_delimiter = ',')]
        allowed_neighbors: Vec<String>,
        /// Hard cap on eligible routes (rows). Unset = no cap.
        #[arg(long)]
        max_routes: Option<u32>,
        /// Global ECMP cap (1..=256). Unset/1 = single next-hop.
        #[arg(long)]
        maximum_paths: Option<u32>,
        /// Per-class eBGP ECMP cap (overrides maximum_paths for eBGP).
        #[arg(long)]
        maximum_paths_ebgp: Option<u32>,
        /// Per-class iBGP ECMP cap (overrides maximum_paths for iBGP).
        #[arg(long)]
        maximum_paths_ibgp: Option<u32>,
    },
    /// Delete a FIB table by name
    Delete {
        /// Table name to remove
        name: String,
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
        /// RFC 9687 send hold time in seconds (0 disables; must exceed
        /// the hold time; default: max(480, 2 x hold time))
        #[arg(long)]
        send_hold_time: Option<u32>,
        /// Max prefix limit
        #[arg(long)]
        max_prefixes: Option<u32>,
        /// Address families (comma-separated)
        #[arg(long, value_delimiter = ',')]
        families: Vec<String>,
        /// Enable transparent route-server client mode (eBGP only)
        #[arg(long)]
        route_server_client: bool,
        /// RFC 7947 per-client best-path (path-hiding mitigation);
        /// requires --route-server-client
        #[arg(long, requires = "route_server_client")]
        per_client_best: bool,
        /// Local BGP Role for RFC 9234 route-leak protection
        #[arg(long, value_name = "ROLE")]
        role: Option<String>,
        /// Require the peer to advertise a compatible BGP Role capability
        #[arg(long)]
        strict_role: bool,
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
enum DiffAction {
    /// Compare the live Adj-RIB-Out against an incumbent NDJSON snapshot
    ///
    /// The snapshot format (`rbgp-ribsnap/1`) is one JSON object per line:
    /// a header record, route records, and a counted completion trailer
    /// (see docs/ribdiff.md). Comparison is semantic (multiset of paths
    /// per peer/family/NLRI; RFC 7911 path IDs are never compared) and
    /// fail-closed: equality is never asserted from incomplete, truncated,
    /// over-limit, or drifting input.
    ///
    /// Live-source limitation: the daemon proto carries MED as a bare
    /// integer, so MED-absent and MED 0 are indistinguishable over gRPC;
    /// live med=0 is compared as absent and snapshot producers should omit
    /// `med` when it is zero or absent (or pass --ignore-attribute med).
    #[command(after_help = "Exit codes:\n  \
        0  complete inputs, no semantic differences\n  \
        1  complete inputs, differences found\n  \
        2  incomplete, malformed, stale, mixed-generation, unsupported, or \
        over-limit input, or an operational error (equality never asserted)")]
    Advertised {
        /// Peer address to compare; may be repeated. Omit to compare every
        /// peer present in the snapshot.
        #[arg(long)]
        peer: Vec<String>,

        /// Path to the incumbent `rbgp-ribsnap/1` NDJSON snapshot
        #[arg(long, value_name = "PATH")]
        against: String,

        /// Address family filter (ipv4_unicast, ipv6_unicast); may be repeated
        #[arg(short = 'a', long)]
        family: Vec<String>,

        /// Maximum retained routes per side; exceeding it refuses the
        /// comparison (exit 2)
        #[arg(long, default_value_t = 4_000_000)]
        max_routes: usize,

        /// Maximum snapshot bytes read; exceeding it refuses the
        /// comparison (exit 2)
        #[arg(long, default_value_t = 1 << 30)]
        max_input_bytes: u64,

        /// Attribute to exclude from comparison on both sides (origin,
        /// as_path, next_hop, med, local_pref, communities,
        /// extended_communities, large_communities, unknown); may be
        /// repeated
        #[arg(long)]
        ignore_attribute: Vec<String>,

        /// Maximum detailed difference rows in human output (--json is
        /// always complete)
        #[arg(long, default_value_t = 20)]
        detail: usize,

        /// Overall wall-clock budget in seconds; expiry refuses the
        /// comparison (exit 2)
        #[arg(long, default_value_t = 120)]
        deadline: u64,
    },

    /// Produce an `rbgp-ribsnap/1` snapshot from an incumbent's own output
    /// (offline; no daemon connection)
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },
}

#[derive(Subcommand)]
enum SnapshotAction {
    /// Convert an RFC 6396 TABLE_DUMP_V2 MRT dump into a snapshot
    ///
    /// TABLE_DUMP_V2 is, by default, a collector RIB view — not a
    /// per-client post-policy Adj-RIB-Out. The required --view flag is
    /// the producer's attestation of what the dump actually is: only
    /// `adj-rib-out-capture` yields a snapshot; `loc-rib` and
    /// `adj-rib-in` are refused (exit 2) because comparing them against
    /// an Adj-RIB-Out would report false divergence or false equality.
    ///
    /// RFC 8050 Add-Path subtypes are supported (path identifiers are
    /// emitted as `path_id`); AS_PATH is decoded as 4-octet per RFC 6396
    /// §4.3.4, and both the abbreviated and full RFC 4760 MP_REACH_NLRI
    /// forms are accepted. See docs/ribdiff.md for the adapter contract.
    #[command(after_help = "Exit codes:\n  \
        0  snapshot emitted on stdout\n  \
        2  refused (non-comparable view) or malformed/unreadable input \
        (nothing emitted)")]
    FromMrt {
        /// Path to the MRT TABLE_DUMP_V2 file
        file: PathBuf,

        /// Attestation of what the dump is: adj-rib-out-capture (a
        /// per-client post-policy capture; accepted), loc-rib, or
        /// adj-rib-in (both refused as non-comparable)
        #[arg(long, value_name = "VIEW")]
        view: String,

        /// Peer address the captured routes were advertised to
        #[arg(long)]
        peer: String,

        /// ASN of that peer
        #[arg(long)]
        peer_asn: u32,

        /// Free-form provenance label appended to the header `source`
        #[arg(long)]
        source: Option<String>,

        /// Capture-round generation stamped into the header
        #[arg(long, default_value_t = 1)]
        generation: u64,
    },

    /// Convert a captured RFC 7854/8671 BMP byte stream into a snapshot
    ///
    /// Input is an offline file of raw BMP version 3 messages captured
    /// from the START of the incumbent's BMP session (e.g. the TCP
    /// payload of its BMP export); streaming-socket ingestion is out of
    /// scope. Only Route Monitoring for the post-policy Adj-RIB-Out view
    /// (O=1, L=1) contributes routes: Adj-RIB-In messages (O=0) are
    /// skipped with a note, and a pre-policy Adj-RIB-Out stream (O=1,
    /// L=0) is refused as non-comparable. Add-Path decoding follows the
    /// negotiation in each Peer Up's OPENs; live updates interleaved
    /// with the initial dump supersede dump entries; a reconnect or
    /// Peer Down invalidates the affected state. Every emitted
    /// peer/family must have reached End-of-RIB — an incomplete dump is
    /// refused, never emitted. See docs/ribdiff.md.
    #[command(after_help = "Exit codes:\n  \
        0  snapshot emitted on stdout\n  \
        2  refused: pre-policy view, incomplete (missing End-of-RIB), \
        malformed, truncated, out-of-sequence, or over-limit input \
        (nothing emitted)")]
    FromBmp {
        /// Path to the captured BMP byte stream
        file: PathBuf,

        /// Peer address to emit; may be repeated. Omit to emit every
        /// complete global-instance peer (all of which must then be
        /// complete)
        #[arg(long)]
        peer: Vec<String>,

        /// Free-form provenance label appended to the header `source`
        #[arg(long)]
        source: Option<String>,

        /// Capture-round generation stamped into the header
        #[arg(long, default_value_t = 1)]
        generation: u64,
    },
}

#[derive(Subcommand)]
enum BfdAction {
    /// List all BFD sessions (default)
    List,
    /// Show a single BFD session by peer address
    Show {
        /// Peer address
        address: String,
    },
}

#[derive(Subcommand)]
enum RibAction {
    /// Show received routes from a neighbor
    #[command(visible_alias = "recv")]
    Received {
        /// Neighbor address
        address: String,
        /// Address family filter
        #[arg(short = 'a', long)]
        family: Option<String>,
    },
    /// Show advertised routes to a neighbor
    #[command(visible_alias = "sent")]
    Advertised {
        /// Neighbor address
        address: String,
        /// Address family filter
        #[arg(short = 'a', long)]
        family: Option<String>,
        /// Explain whether this exact prefix would be advertised to the peer
        #[arg(long)]
        explain: bool,
        /// Route Distinguisher ("asn:nn" or "ip:nn") - explain the
        /// VPNv4/VPNv6 export ladder for the (RD, prefix) identity,
        /// including the RFC 4684 RT-Constrain membership gate
        #[arg(long, requires = "explain")]
        rd: Option<String>,
    },
    /// Show RFC 7999 BLACKHOLE discard install status
    Blackholes,
    /// Show ADR-0061 general FIB route install status
    Fib {
        /// FIB table-name filter
        #[arg(long)]
        table: Option<String>,
        /// FIB route state filter: installed, rejected, failed
        #[arg(long)]
        state: Option<String>,
        /// Exact reason-code filter, e.g. owned or route_limit_exceeded
        #[arg(long)]
        reason: Option<String>,
        /// Exact prefix filter, e.g. 203.0.113.0/24
        #[arg(long)]
        prefix: Option<String>,
        /// Source peer-address filter
        #[arg(long)]
        peer: Option<String>,
        /// Maximum FIB status rows to return; omitted returns the full snapshot
        #[arg(long)]
        page_size: Option<u32>,
        /// Page token returned by a previous paginated FIB status query
        #[arg(long)]
        page_token: Option<String>,
    },
    /// Show BGP-LS routes learned from peers (RFC 9552)
    #[command(name = "bgpls", visible_alias = "bgp-ls")]
    BgpLs {
        /// BGP-LS family filter: linkstate (aliases bgpls, bgp-ls) or
        /// linkstate_vpn (aliases bgpls-vpn, bgp-ls-vpn)
        #[arg(short = 'a', long)]
        family: Option<String>,
        /// Peer IP address filter
        #[arg(long)]
        peer: Option<String>,
        /// NLRI type filter (1=node, 2=link, 3=IPv4 prefix, 4=IPv6 prefix)
        #[arg(long)]
        nlri_type: Option<u32>,
    },
    /// Show VPNv4/VPNv6 routes learned from peers (RFC 4364/4659)
    #[command(name = "vpn")]
    Vpn {
        /// VPN family filter: l3vpn_ipv4_unicast (alias vpnv4) or
        /// l3vpn_ipv6_unicast (alias vpnv6)
        #[arg(short = 'a', long)]
        family: Option<String>,
        /// Peer IP address filter
        #[arg(long)]
        peer: Option<String>,
    },
    /// Show IPv4/IPv6 labeled-unicast routes learned from peers (RFC 8277)
    #[command(name = "labeled")]
    Labeled {
        /// Labeled family filter: ipv4_labeled_unicast (alias labeled-v4) or
        /// ipv6_labeled_unicast (alias labeled-v6)
        #[arg(short = 'a', long)]
        family: Option<String>,
        /// Peer IP address filter
        #[arg(long)]
        peer: Option<String>,
    },
    /// Show RT-Constrain routes (RFC 4684, single IPv4 family)
    #[command(name = "rtc")]
    Rtc {
        /// Peer IP address filter
        #[arg(long)]
        peer: Option<String>,
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
        /// Communities (e.g., 65001:100 or BLACKHOLE)
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
enum TopologyAction {
    /// List topology nodes (BGP-LS node identities across all peers)
    Nodes,
    /// List usable directed topology links (with IGP metrics)
    Links,
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

#[derive(Subcommand)]
enum EventsAction {
    /// Watch the unified live event stream
    Watch {
        /// Event category filter: route, session, policy, dataplane, evpn, bfd
        #[arg(long = "category", value_delimiter = ',')]
        categories: Vec<String>,

        /// Neighbor address filter
        #[arg(long)]
        address: Option<String>,

        /// Address family filter
        #[arg(short = 'a', long)]
        family: Option<String>,

        /// Exact prefix filter, e.g. 203.0.113.0/24
        #[arg(long)]
        prefix: Option<String>,

        /// Event type filter: added, withdrawn, best_changed,
        /// state_changed, established, lost, peer_enabled, peer_disabled,
        /// notification_sent, notification_received, policy_changed,
        /// dataplane_status_changed, dataplane_route_installed,
        /// dataplane_route_withdrawn, dataplane_route_failed, evpn_added,
        /// evpn_withdrawn, evpn_best_changed, bfd_up, bfd_down,
        /// bfd_state_changed
        #[arg(long = "type", value_delimiter = ',')]
        event_types: Vec<String>,

        /// Print recent route history before tailing the live stream.
        /// Applies only to route-capable event streams. Mutually
        /// exclusive with `--from-event-id`; `--backfill` replays the
        /// daemon's process-local route ring (resets on restart),
        /// while `--from-event-id` replays the durable event outbox
        /// (survives restart).
        #[arg(long, default_value_t = 0)]
        backfill: u32,

        /// ADR-0072 durable cursor: replay committed events with
        /// `event_id > N` from the daemon's local event outbox,
        /// then tail the live stream. `0` replays everything
        /// retained. Survives daemon restart. Returns
        /// `FAILED_PRECONDITION` when the daemon was started with
        /// `[event_history].enabled = false` or EHM is unavailable.
        #[arg(long, value_name = "EVENT_ID")]
        from_event_id: Option<u64>,
    },
    /// Show recent session lifecycle events
    Sessions {
        /// Neighbor address filter
        #[arg(long)]
        address: Option<String>,

        /// Session event type filter: state_changed, established, lost,
        /// peer_enabled, peer_disabled
        #[arg(long = "type", value_delimiter = ',')]
        event_types: Vec<String>,

        /// Maximum recent session events to return (default 100; explicit 0 requests the daemon's full bounded window)
        #[arg(short, long)]
        limit: Option<u32>,
    },
    /// Show recent policy / neighbor-set / peer-group / chain mutation events
    Policy {
        /// Neighbor address filter. Only peer-scoped policy events match.
        #[arg(long)]
        address: Option<String>,

        /// Policy event type filter: policy_changed
        #[arg(long = "type", value_delimiter = ',')]
        event_types: Vec<String>,

        /// Maximum recent policy events to return (default 100; explicit 0 requests the daemon's full bounded window)
        #[arg(short, long)]
        limit: Option<u32>,
    },
    /// Show recent EVPN route events
    Evpn {
        /// Neighbor address filter. Matches current and previous best-path peer.
        #[arg(long)]
        address: Option<String>,

        /// EVPN route type filter (1..=5)
        #[arg(long)]
        route_type: Option<u32>,

        /// Route Distinguisher filter, e.g. "65000:100"
        #[arg(long)]
        rd: Option<String>,

        /// EVPN event type filter: evpn_added, evpn_withdrawn, evpn_best_changed
        #[arg(long = "type", value_delimiter = ',')]
        event_types: Vec<String>,

        /// Maximum recent EVPN events to return (default 100; explicit 0 requests the daemon's full bounded window)
        #[arg(short, long)]
        limit: Option<u32>,
    },
}

#[derive(Subcommand)]
enum EvpnAction {
    /// List EVPN routes (default action — same as omitting the subcommand).
    List {
        #[arg(long)]
        route_type: Option<u32>,
        #[arg(long)]
        peer: Option<String>,
        #[arg(long)]
        rd: Option<String>,
    },
    /// Inject a Type 2 MAC/IP route.
    AddMacIp {
        /// Route Distinguisher, "asn:value" / "ip:value".
        #[arg(long)]
        rd: String,
        /// Ethernet-tag identifying the EVI (default 0).
        #[arg(long, default_value_t = 0)]
        ethernet_tag: u32,
        /// MAC address "aa:bb:cc:dd:ee:ff".
        #[arg(long)]
        mac: String,
        /// Host IP (optional — MAC-only route if omitted).
        #[arg(long)]
        ip: Option<String>,
        /// VNI for this EVI (required).
        #[arg(long)]
        label: u32,
        /// Optional second label for RFC 9135 symmetric IRB.
        #[arg(long)]
        label2: Option<u32>,
        /// VTEP loopback IP (next-hop).
        #[arg(long)]
        next_hop: String,
        /// Optional route targets, each "asn:value".
        #[arg(long, value_delimiter = ',')]
        rt: Vec<String>,
        /// Disable the RFC 8365 VXLAN encapsulation ext community.
        #[arg(long)]
        no_vxlan_encap: bool,
    },
    /// Inject a Type 3 IMET route.
    AddImet {
        #[arg(long)]
        rd: String,
        #[arg(long, default_value_t = 0)]
        ethernet_tag: u32,
        /// Originator IP (required for Type 3).
        #[arg(long)]
        ip: String,
        /// VTEP loopback IP (next-hop).
        #[arg(long)]
        next_hop: String,
        #[arg(long, value_delimiter = ',')]
        rt: Vec<String>,
        #[arg(long)]
        no_vxlan_encap: bool,
    },
    /// Inject a Type 5 IP Prefix route.
    AddIpPrefix {
        #[arg(long)]
        rd: String,
        /// Ethernet Tag ID. Must be 0 for supported Type 5 injection.
        #[arg(long, default_value_t = 0)]
        ethernet_tag: u32,
        /// IP prefix, e.g. "10.0.0.0/24" or "2001:db8::/48".
        #[arg(long)]
        prefix: String,
        /// L3VNI for this IP-VRF.
        #[arg(long)]
        label: u32,
        /// VTEP loopback IP (next-hop).
        #[arg(long)]
        next_hop: String,
        /// Optional Type 5 Gateway IP for overlay-index injection. Omit for interface-less Type 5.
        #[arg(long)]
        gateway: Option<String>,
        /// Router MAC extended community value. Required unless --no-vxlan-encap is set.
        #[arg(long)]
        router_mac: Option<String>,
        #[arg(long, value_delimiter = ',')]
        rt: Vec<String>,
        #[arg(long)]
        no_vxlan_encap: bool,
    },
    /// Withdraw a Type 2 MAC/IP route by its key fields.
    DeleteMacIp {
        #[arg(long)]
        rd: String,
        #[arg(long, default_value_t = 0)]
        ethernet_tag: u32,
        #[arg(long)]
        mac: String,
        #[arg(long)]
        ip: Option<String>,
    },
    /// Withdraw a Type 3 IMET route by its key fields.
    DeleteImet {
        #[arg(long)]
        rd: String,
        #[arg(long, default_value_t = 0)]
        ethernet_tag: u32,
        #[arg(long)]
        ip: String,
    },
    /// Withdraw a Type 5 IP Prefix route by its key fields.
    DeleteIpPrefix {
        #[arg(long)]
        rd: String,
        /// Ethernet Tag ID. Must be 0 for Type 5 withdrawal.
        #[arg(long, default_value_t = 0)]
        ethernet_tag: u32,
        /// IP prefix, e.g. "10.0.0.0/24" or "2001:db8::/48".
        #[arg(long)]
        prefix: String,
    },
    /// Clear one duplicate-MAC local-origin quarantine.
    ClearDuplicateMac {
        /// L2VNI containing the quarantined MAC.
        #[arg(long)]
        vni: u32,
        /// MAC address "aa:bb:cc:dd:ee:ff".
        #[arg(long)]
        mac: String,
    },
    /// Ethernet Segment runtime controls and diagnose state.
    Es {
        #[command(subcommand)]
        action: EsAction,
    },
    /// Show the committed ADR-0063 EVPN runtime generation.
    Runtime,
    /// List local EVPN instances configured on this VTEP. Empty when
    /// the daemon is acting purely as an EVPN route reflector.
    Instances,
    /// List rustbgpd-owned FDB nexthop groups (ADR-0059 aliasing ECMP).
    Nexthops,
    /// List managed EVPN netdev ownership/status rows (ADR-0091).
    ManagedNetdevs,
    /// List configured IP-VRFs (Gate 9, ADR-0058) and their
    /// readiness verdict from the most recent reconcile pass.
    Vrfs {
        /// Operator-facing IP-VRF name. When provided, fetch just
        /// this one VRF with detailed not-ready reasons; otherwise
        /// list every configured IP-VRF.
        name: Option<String>,
    },
    /// Summarize EVPN VTEP alpha state and key metrics.
    Diagnose,
}

#[derive(Subcommand)]
enum EsAction {
    /// List configured Ethernet Segments joined with live drain,
    /// DF/AC-gate, same-ESI bias, and FDB-NHG state.
    List {
        /// Optional ESI filter as 10 colon-separated hex octets.
        esi: Option<String>,
    },
    /// Drain an Ethernet Segment before access-circuit maintenance:
    /// withdraw its Type 4 + EAD routes (exiting DF election) and the
    /// member VNIs' local Type 2 routes, and suppress new local-MAC
    /// origination. In-memory only — a daemon restart clears the drain.
    Drain {
        /// ESI as 10 colon-separated hex octets,
        /// e.g. "00:11:22:33:44:55:66:77:88:99".
        esi: String,
    },
    /// Undrain an Ethernet Segment: re-originate its Type 4 + EAD
    /// routes, re-run DF election, and replay cached local MAC state.
    Undrain {
        /// ESI as 10 colon-separated hex octets,
        /// e.g. "00:11:22:33:44:55:66:77:88:99".
        esi: String,
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

struct RibStatusFilterArgs<'a> {
    family: &'a Option<String>,
    prefix: &'a Option<String>,
    longer: bool,
    explain: bool,
    explain_peer: &'a Option<String>,
    origin_asn: Option<u32>,
    community: &'a [String],
    large_community: &'a [String],
}

fn reject_rib_status_filters(
    binary_name: &str,
    command: &str,
    filters: RibStatusFilterArgs<'_>,
) -> Result<(), CliError> {
    if filters.family.is_some()
        || filters.prefix.is_some()
        || filters.longer
        || filters.explain
        || filters.explain_peer.is_some()
        || filters.origin_asn.is_some()
        || !filters.community.is_empty()
        || !filters.large_community.is_empty()
    {
        if command == "fib" {
            return Err(CliError::Argument(format!(
                "rib fib does not support parent route filters; put FIB status filters after `fib`, for example `{binary_name} rib fib --prefix 203.0.113.0/24`"
            )));
        }
        return Err(CliError::Argument(format!(
            "rib {command} does not support route filters; use `{binary_name} rib {command}`"
        )));
    }
    Ok(())
}

fn reject_events_parent_filters_for_subcommand(
    subcommand: &str,
    address: &Option<String>,
    family: &Option<String>,
    prefix: &Option<String>,
    limit: Option<u32>,
) -> Result<(), CliError> {
    if address.is_some() || family.is_some() || prefix.is_some() || limit.is_some() {
        return Err(CliError::Argument(format!(
            "`events` route-history filters must be used without a subcommand; put live/history filters after `{subcommand}` instead"
        )));
    }
    Ok(())
}

/// Parse community string "ASN:value" or a well-known alias into u32.
fn parse_community_str(s: &str) -> Result<u32, String> {
    match s {
        "BLACKHOLE" => return Ok(rustbgpd_wire::COMMUNITY_BLACKHOLE),
        "NO_EXPORT" => return Ok(rustbgpd_wire::COMMUNITY_NO_EXPORT),
        "NO_ADVERTISE" => return Ok(rustbgpd_wire::COMMUNITY_NO_ADVERTISE),
        "NO_EXPORT_SUBCONFED" => return Ok(rustbgpd_wire::COMMUNITY_NO_EXPORT_SUBCONFED),
        "GRACEFUL_SHUTDOWN" => return Ok(rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN),
        "LLGR_STALE" => return Ok(rustbgpd_wire::COMMUNITY_LLGR_STALE),
        "NO_LLGR" => return Ok(rustbgpd_wire::COMMUNITY_NO_LLGR),
        _ => {}
    }

    let (high, low) = s.split_once(':').ok_or_else(|| {
        format!("invalid community: {s} (expected ASN:value or well-known alias)")
    })?;
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
    let binary_name = invoked_binary_name();
    let cli = parse_cli(binary_name);

    let no_color = cli.no_color || std::env::var_os("NO_COLOR").is_some();
    if no_color || cli.json {
        owo_colors::set_override(false);
    }

    if let Err(e) = run(cli, binary_name).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn invoked_binary_name() -> &'static str {
    BINARY_NAME
}

fn cli_command(binary_name: &'static str) -> clap::Command {
    Cli::command().name(binary_name).bin_name(binary_name)
}

fn parse_cli(binary_name: &'static str) -> Cli {
    let matches = cli_command(binary_name).get_matches();
    Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit())
}

fn generate_completions(shell: Shell, binary_name: &'static str, output: &mut dyn std::io::Write) {
    clap_complete::generate(shell, &mut cli_command(binary_name), binary_name, output);
}

async fn run(cli: Cli, binary_name: &'static str) -> Result<(), CliError> {
    // Shell completions don't need a gRPC connection.
    if let Command::Completions { shell } = cli.command {
        generate_completions(shell, binary_name, &mut std::io::stdout());
        return Ok(());
    }

    // `policy check` runs the .rpol frontend in-process — no daemon.
    if let Command::Policy {
        action: PolicyAction::Check { file },
    } = &cli.command
    {
        std::process::exit(commands::policy::check_local(file, cli.json));
    }

    // `diff` owns its 0/1/2 exit-code contract (2 = any operational
    // error, including an unreachable daemon), so it bypasses the generic
    // connect-then-exit-1 path.
    if let Command::Diff {
        action:
            DiffAction::Advertised {
                peer,
                against,
                family,
                max_routes,
                max_input_bytes,
                ignore_attribute,
                detail,
                deadline,
            },
    } = &cli.command
    {
        let opts = commands::diff::AdvertisedDiffOpts {
            peers: peer.clone(),
            against: PathBuf::from(against),
            families: family.clone(),
            max_routes: *max_routes,
            max_input_bytes: *max_input_bytes,
            ignore_attributes: ignore_attribute.clone(),
            detail: *detail,
            deadline_seconds: *deadline,
            json: cli.json,
        };
        let code = match connect(&cli.addr, cli.token_file.as_deref()).await {
            Ok(connection) => commands::diff::advertised(connection, &opts).await,
            Err(e) => {
                eprintln!("Error: {e}");
                commands::diff::EXIT_INCOMPARABLE
            }
        };
        std::process::exit(code);
    }

    // `diff snapshot from-mrt` is a pure offline adapter (no daemon
    // connection); it owns its 0/2 exit-code contract.
    if let Command::Diff {
        action:
            DiffAction::Snapshot {
                action:
                    SnapshotAction::FromMrt {
                        file,
                        view,
                        peer,
                        peer_asn,
                        source,
                        generation,
                    },
            },
    } = &cli.command
    {
        let opts = commands::ribsnap::FromMrtOpts {
            file,
            view,
            peer,
            peer_asn: *peer_asn,
            source: source.as_deref(),
            generation: *generation,
        };
        std::process::exit(commands::ribsnap::from_mrt(&opts));
    }

    // `diff snapshot from-bmp` is likewise a pure offline adapter.
    if let Command::Diff {
        action:
            DiffAction::Snapshot {
                action:
                    SnapshotAction::FromBmp {
                        file,
                        peer,
                        source,
                        generation,
                    },
            },
    } = &cli.command
    {
        let opts = commands::ribsnap_bmp::FromBmpOpts {
            file,
            peers: peer,
            source: source.as_deref(),
            generation: *generation,
        };
        std::process::exit(commands::ribsnap_bmp::from_bmp(&opts));
    }

    let addr = cli.addr.clone();
    let token_file_configured = cli.token_file.is_some();
    let connection = connect(&cli.addr, cli.token_file.as_deref()).await?;
    let json = cli.json;

    match cli.command {
        Command::Global => commands::global::run(connection, json).await,

        Command::Bfd { action } => match action {
            Some(BfdAction::Show { address }) => {
                commands::bfd::show(connection, &address, json).await
            }
            Some(BfdAction::List) | None => commands::bfd::list(connection, json).await,
        },

        Command::Config { action } => match action {
            ConfigAction::Diff { from_file } => {
                commands::config::diff(connection, &from_file, json).await
            }
            ConfigAction::Plan {
                from_file,
                expected_runtime_snapshot_token,
            } => {
                commands::config::plan(
                    connection,
                    &from_file,
                    expected_runtime_snapshot_token.as_deref(),
                    json,
                )
                .await
            }
            ConfigAction::Apply {
                from_file,
                expected_runtime_snapshot_token,
                client_request_id,
                comment,
                confirm_id,
                confirm_timeout_seconds,
            } => {
                commands::config::apply(
                    connection,
                    commands::config::ApplyOptions {
                        from_file: &from_file,
                        expected_runtime_snapshot_token: &expected_runtime_snapshot_token,
                        client_request_id: client_request_id.as_deref(),
                        comment: comment.as_deref(),
                        confirm_id: confirm_id.as_deref(),
                        confirm_timeout_seconds,
                    },
                    json,
                )
                .await
            }
            ConfigAction::Confirm { confirm_id } => {
                commands::config::confirm(connection, &confirm_id, json).await
            }
            ConfigAction::Abort { confirm_id } => {
                commands::config::abort(connection, &confirm_id, json).await
            }
            ConfigAction::Status => commands::config::status(connection, json).await,
        },

        Command::Neighbor { address, action } => match (address, action) {
            (None, None) => commands::neighbor::list(connection, json).await,
            (Some(addr), None) => commands::neighbor::show(connection, &addr, json).await,
            (
                Some(addr),
                Some(NeighborAction::Add {
                    asn,
                    description,
                    hold_time,
                    send_hold_time,
                    max_prefixes,
                    families,
                    route_server_client,
                    per_client_best,
                    role,
                    strict_role,
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
                        send_hold_time,
                        max_prefixes,
                        families,
                        route_server_client,
                        per_client_best,
                        role,
                        strict_role,
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
            explain_peer,
            origin_asn,
            community,
            large_community,
        } => {
            match action {
                Some(RibAction::Fib {
                    table,
                    state,
                    reason,
                    prefix: fib_prefix,
                    peer,
                    page_size,
                    page_token,
                }) => {
                    reject_rib_status_filters(
                        binary_name,
                        "fib",
                        RibStatusFilterArgs {
                            family: &family,
                            prefix: &prefix,
                            longer,
                            explain,
                            explain_peer: &explain_peer,
                            origin_asn,
                            community: &community,
                            large_community: &large_community,
                        },
                    )?;
                    return commands::rib::fib(
                        connection,
                        commands::rib::FibRouteFilterOpts {
                            table,
                            state,
                            reason,
                            prefix: fib_prefix,
                            peer,
                            page_size,
                            page_token,
                        },
                        json,
                    )
                    .await;
                }
                Some(RibAction::Blackholes) => {
                    reject_rib_status_filters(
                        binary_name,
                        "blackholes",
                        RibStatusFilterArgs {
                            family: &family,
                            prefix: &prefix,
                            longer,
                            explain,
                            explain_peer: &explain_peer,
                            origin_asn,
                            community: &community,
                            large_community: &large_community,
                        },
                    )?;
                    return commands::rib::blackholes(connection, json).await;
                }
                Some(RibAction::BgpLs {
                    family: bgpls_family,
                    peer,
                    nlri_type,
                }) => {
                    reject_rib_status_filters(
                        binary_name,
                        "bgpls",
                        RibStatusFilterArgs {
                            family: &None,
                            prefix: &prefix,
                            longer,
                            explain,
                            explain_peer: &explain_peer,
                            origin_asn,
                            community: &community,
                            large_community: &large_community,
                        },
                    )?;
                    let family = bgpls_family.or(family);
                    return commands::rib::bgpls(
                        connection,
                        family.as_deref(),
                        peer,
                        nlri_type,
                        json,
                    )
                    .await;
                }
                Some(RibAction::Vpn {
                    family: vpn_family,
                    peer,
                }) => {
                    reject_rib_status_filters(
                        binary_name,
                        "vpn",
                        RibStatusFilterArgs {
                            family: &None,
                            prefix: &prefix,
                            longer,
                            explain,
                            explain_peer: &explain_peer,
                            origin_asn,
                            community: &community,
                            large_community: &large_community,
                        },
                    )?;
                    let family = vpn_family.or(family);
                    return commands::rib::vpn(connection, family.as_deref(), peer, json).await;
                }
                Some(RibAction::Labeled {
                    family: labeled_family,
                    peer,
                }) => {
                    reject_rib_status_filters(
                        binary_name,
                        "labeled",
                        RibStatusFilterArgs {
                            family: &None,
                            prefix: &prefix,
                            longer,
                            explain,
                            explain_peer: &explain_peer,
                            origin_asn,
                            community: &community,
                            large_community: &large_community,
                        },
                    )?;
                    let family = labeled_family.or(family);
                    return commands::rib::labeled(connection, family.as_deref(), peer, json).await;
                }
                Some(RibAction::Rtc { peer }) => {
                    reject_rib_status_filters(
                        binary_name,
                        "rtc",
                        RibStatusFilterArgs {
                            family: &family,
                            prefix: &prefix,
                            longer,
                            explain,
                            explain_peer: &explain_peer,
                            origin_asn,
                            community: &community,
                            large_community: &large_community,
                        },
                    )?;
                    return commands::rib::rtc(connection, peer, json).await;
                }
                _ => {}
            }

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
                        commands::rib::explain_best_path(
                            connection,
                            prefix,
                            explain_peer.as_deref(),
                            json,
                        )
                        .await
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
                    rd,
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
                        commands::rib::explain_advertised(
                            connection,
                            &address,
                            prefix,
                            rd.as_deref(),
                            json,
                        )
                        .await
                    } else {
                        commands::rib::advertised(connection, &address, f, &filters, json).await
                    }
                }
                Some(
                    RibAction::Blackholes
                    | RibAction::Fib { .. }
                    | RibAction::BgpLs { .. }
                    | RibAction::Vpn { .. }
                    | RibAction::Labeled { .. }
                    | RibAction::Rtc { .. },
                ) => {
                    unreachable!("RIB status subcommands return before route filter handling")
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

        Command::Topology { action } => match action {
            TopologyAction::Nodes => commands::topology::nodes(connection, json).await,
            TopologyAction::Links => commands::topology::links(connection, json).await,
        },
        Command::Orr => commands::orr::status(connection, json).await,
        Command::Watch { address, family } => {
            let family_val = resolve_family(&family)?;
            commands::watch::run(connection, address, family_val, json).await
        }

        Command::Events {
            action,
            address,
            family,
            prefix,
            limit,
        } => match action {
            Some(EventsAction::Watch {
                categories,
                address: watch_address,
                family: watch_family,
                prefix: watch_prefix,
                event_types,
                backfill,
                from_event_id,
            }) => {
                reject_events_parent_filters_for_subcommand(
                    "events watch",
                    &address,
                    &family,
                    &prefix,
                    limit,
                )?;
                let family_val = resolve_family(&watch_family)?;
                commands::watch::events_watch(
                    connection,
                    commands::watch::EventsWatchOptions {
                        categories,
                        neighbor: watch_address,
                        family: family_val,
                        prefix: watch_prefix,
                        event_types,
                        backfill,
                        from_event_id,
                        json,
                    },
                )
                .await
            }
            Some(EventsAction::Sessions {
                address: session_address,
                event_types,
                limit: session_limit,
            }) => {
                reject_events_parent_filters_for_subcommand(
                    "events sessions",
                    &address,
                    &family,
                    &prefix,
                    limit,
                )?;
                let limit = session_limit.unwrap_or(100);
                commands::watch::session_history(
                    connection,
                    session_address,
                    event_types,
                    limit,
                    json,
                )
                .await
            }
            Some(EventsAction::Policy {
                address: policy_address,
                event_types,
                limit: policy_limit,
            }) => {
                reject_events_parent_filters_for_subcommand(
                    "events policy",
                    &address,
                    &family,
                    &prefix,
                    limit,
                )?;
                let limit = policy_limit.unwrap_or(100);
                commands::watch::policy_history(
                    connection,
                    policy_address,
                    event_types,
                    limit,
                    json,
                )
                .await
            }
            Some(EventsAction::Evpn {
                address: evpn_address,
                route_type,
                rd,
                event_types,
                limit: evpn_limit,
            }) => {
                reject_events_parent_filters_for_subcommand(
                    "events evpn",
                    &address,
                    &family,
                    &prefix,
                    limit,
                )?;
                let limit = evpn_limit.unwrap_or(100);
                commands::watch::evpn_history(
                    connection,
                    evpn_address,
                    route_type,
                    rd,
                    event_types,
                    limit,
                    json,
                )
                .await
            }
            None => {
                let family_val = resolve_family(&family)?;
                let limit = limit.unwrap_or(100);
                commands::watch::history(connection, address, family_val, prefix, limit, json).await
            }
        },

        Command::Evpn {
            action,
            route_type,
            peer,
            rd,
        } => match action {
            None => commands::evpn::list(connection, route_type, peer, rd, json).await,
            Some(EvpnAction::List {
                route_type,
                peer,
                rd,
            }) => commands::evpn::list(connection, route_type, peer, rd, json).await,
            Some(EvpnAction::AddMacIp {
                rd,
                ethernet_tag,
                mac,
                ip,
                label,
                label2,
                next_hop,
                rt,
                no_vxlan_encap,
            }) => {
                commands::evpn::add_mac_ip(
                    connection,
                    rd,
                    ethernet_tag,
                    mac,
                    ip.unwrap_or_default(),
                    label,
                    label2.unwrap_or(0),
                    next_hop,
                    rt,
                    no_vxlan_encap,
                    json,
                )
                .await
            }
            Some(EvpnAction::AddImet {
                rd,
                ethernet_tag,
                ip,
                next_hop,
                rt,
                no_vxlan_encap,
            }) => {
                commands::evpn::add_imet(
                    connection,
                    rd,
                    ethernet_tag,
                    ip,
                    next_hop,
                    rt,
                    no_vxlan_encap,
                    json,
                )
                .await
            }
            Some(EvpnAction::AddIpPrefix {
                rd,
                ethernet_tag,
                prefix,
                label,
                next_hop,
                gateway,
                router_mac,
                rt,
                no_vxlan_encap,
            }) => {
                commands::evpn::add_ip_prefix(
                    connection,
                    rd,
                    ethernet_tag,
                    prefix,
                    label,
                    next_hop,
                    gateway,
                    router_mac,
                    rt,
                    no_vxlan_encap,
                    json,
                )
                .await
            }
            Some(EvpnAction::DeleteMacIp {
                rd,
                ethernet_tag,
                mac,
                ip,
            }) => {
                commands::evpn::delete_mac_ip(
                    connection,
                    rd,
                    ethernet_tag,
                    mac,
                    ip.unwrap_or_default(),
                    json,
                )
                .await
            }
            Some(EvpnAction::DeleteImet {
                rd,
                ethernet_tag,
                ip,
            }) => commands::evpn::delete_imet(connection, rd, ethernet_tag, ip, json).await,
            Some(EvpnAction::DeleteIpPrefix {
                rd,
                ethernet_tag,
                prefix,
            }) => {
                commands::evpn::delete_ip_prefix(connection, rd, ethernet_tag, prefix, json).await
            }
            Some(EvpnAction::ClearDuplicateMac { vni, mac }) => {
                commands::evpn::clear_duplicate_mac(connection, vni, mac, json).await
            }
            Some(EvpnAction::Es { action }) => match action {
                EsAction::List { esi } => {
                    commands::evpn::list_ethernet_segments(connection, esi, json).await
                }
                EsAction::Drain { esi } => {
                    commands::evpn::set_es_drain(connection, esi, true, json).await
                }
                EsAction::Undrain { esi } => {
                    commands::evpn::set_es_drain(connection, esi, false, json).await
                }
            },
            Some(EvpnAction::Runtime) => commands::evpn::runtime(connection, json).await,
            Some(EvpnAction::Instances) => commands::evpn::list_instances(connection, json).await,
            Some(EvpnAction::Nexthops) => commands::evpn::list_nexthops(connection, json).await,
            Some(EvpnAction::ManagedNetdevs) => {
                commands::evpn::list_managed_netdevs(connection, json).await
            }
            Some(EvpnAction::Vrfs { name }) => match name {
                Some(name) => commands::evpn::get_ip_vrf(connection, name, json).await,
                None => commands::evpn::list_ip_vrfs(connection, json).await,
            },
            Some(EvpnAction::Diagnose) => commands::evpn::diagnose(connection, json).await,
        },

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
        Command::Doctor { output } => {
            commands::doctor::run(
                connection,
                output.as_deref(),
                &addr,
                token_file_configured,
                json,
            )
            .await
        }
        Command::Metrics => commands::control::metrics(connection).await,
        Command::Shutdown { reason } => commands::control::shutdown(connection, reason, json).await,
        Command::MrtDump => commands::control::mrt_dump(connection, json).await,
        Command::Gshut { peer, clear } => {
            commands::neighbor::set_graceful_shutdown(connection, peer, !clear, json).await
        }
        Command::Top { interval } => {
            if !(1..=60).contains(&interval) {
                return Err(CliError::Argument(
                    "interval must be between 1 and 60 seconds".into(),
                ));
            }
            tui::run(connection, interval).await
        }
        Command::Policy { action } => match action {
            PolicyAction::Check { .. } => unreachable!("handled before connect"),
            PolicyAction::Test {
                file,
                policy,
                direction,
                peer,
                family,
                limit,
                show_changes,
            } => {
                commands::policy::test(
                    connection,
                    commands::policy::TestOptions {
                        file: &file,
                        policy: &policy,
                        direction: &direction,
                        peer: peer.as_deref(),
                        family: family.as_deref(),
                        limit,
                        show_changes,
                    },
                    json,
                )
                .await
            }
            PolicyAction::List => commands::policy::list(connection, json).await,
            PolicyAction::Get { name } => commands::policy::get(connection, &name, json).await,
            PolicyAction::Set { name, from_file } => {
                commands::policy::set(connection, &name, &from_file, json).await
            }
            PolicyAction::Delete { name } => {
                commands::policy::delete(connection, &name, json).await
            }
            PolicyAction::Stats { peer, direction } => {
                commands::policy::stats(connection, peer.as_deref(), &direction, json).await
            }
            PolicyAction::Explain {
                neighbor,
                prefix,
                path_id,
            } => {
                commands::policy::explain_import(connection, &neighbor, &prefix, path_id, json)
                    .await
            }
            PolicyAction::Chain { action } => match action {
                PolicyChainAction::Show { neighbor } => {
                    commands::policy::chain_show(connection, neighbor.as_deref(), json).await
                }
                PolicyChainAction::SetImport { neighbor, policies } => {
                    if policies.is_empty() {
                        return Err(CliError::Argument(
                            "set-import requires at least one policy name; use clear-import to drop the chain".into(),
                        ));
                    }
                    commands::policy::chain_set(
                        connection,
                        commands::policy::ChainDirection::Import,
                        neighbor.as_deref(),
                        policies,
                        json,
                    )
                    .await
                }
                PolicyChainAction::SetExport { neighbor, policies } => {
                    if policies.is_empty() {
                        return Err(CliError::Argument(
                            "set-export requires at least one policy name; use clear-export to drop the chain".into(),
                        ));
                    }
                    commands::policy::chain_set(
                        connection,
                        commands::policy::ChainDirection::Export,
                        neighbor.as_deref(),
                        policies,
                        json,
                    )
                    .await
                }
                PolicyChainAction::ClearImport { neighbor } => {
                    commands::policy::chain_clear(
                        connection,
                        commands::policy::ChainDirection::Import,
                        neighbor.as_deref(),
                        json,
                    )
                    .await
                }
                PolicyChainAction::ClearExport { neighbor } => {
                    commands::policy::chain_clear(
                        connection,
                        commands::policy::ChainDirection::Export,
                        neighbor.as_deref(),
                        json,
                    )
                    .await
                }
            },
        },
        Command::NeighborSet { action } => match action {
            NeighborSetAction::List => commands::neighbor_set::list(connection, json).await,
            NeighborSetAction::Get { name } => {
                commands::neighbor_set::get(connection, &name, json).await
            }
            NeighborSetAction::Set { name, from_file } => {
                commands::neighbor_set::set(connection, &name, &from_file, json).await
            }
            NeighborSetAction::Delete { name } => {
                commands::neighbor_set::delete(connection, &name, json).await
            }
        },
        Command::PeerGroup { action } => match action {
            PeerGroupAction::List => commands::peer_group::list(connection, json).await,
            PeerGroupAction::Get { name } => {
                commands::peer_group::get(connection, &name, json).await
            }
            PeerGroupAction::Set { name, from_file } => {
                commands::peer_group::set(connection, &name, &from_file, json).await
            }
            PeerGroupAction::Delete { name } => {
                commands::peer_group::delete(connection, &name, json).await
            }
            PeerGroupAction::Attach { address, group } => {
                commands::peer_group::attach(connection, &address, &group, json).await
            }
            PeerGroupAction::Detach { address } => {
                commands::peer_group::detach(connection, &address, json).await
            }
        },
        Command::DynamicNeighbor { action } => match action {
            DynamicNeighborAction::List => commands::dynamic_neighbor::list(connection, json).await,
            DynamicNeighborAction::Add {
                prefix,
                peer_group,
                asn,
                description,
            } => {
                commands::dynamic_neighbor::add(
                    connection,
                    &prefix,
                    &peer_group,
                    asn,
                    description,
                    json,
                )
                .await
            }
            DynamicNeighborAction::Delete { prefix } => {
                commands::dynamic_neighbor::delete(connection, &prefix, json).await
            }
        },
        Command::FibTable { action } => match action {
            FibTableAction::List => commands::fib_table::list(connection, json).await,
            FibTableAction::Set {
                name,
                table_id,
                metric,
                families,
                allowed_peer_groups,
                allowed_neighbors,
                max_routes,
                maximum_paths,
                maximum_paths_ebgp,
                maximum_paths_ibgp,
            } => {
                commands::fib_table::set(
                    connection,
                    &name,
                    table_id,
                    metric,
                    families,
                    allowed_peer_groups,
                    allowed_neighbors,
                    max_routes,
                    maximum_paths,
                    maximum_paths_ebgp,
                    maximum_paths_ibgp,
                    json,
                )
                .await
            }
            FibTableAction::Delete { name } => {
                commands::fib_table::delete(connection, &name, json).await
            }
        },
        Command::Completions { .. } => unreachable!("handled before connect"),

        Command::Diff { .. } => unreachable!("handled before connect"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_rbgp_command_renders_rbgp_usage() {
        let mut command = cli_command(BINARY_NAME);
        let help = command.render_long_help().to_string();

        assert!(help.contains("Usage: rbgp"));
        assert!(!help.contains("Usage: rustbgpctl"));
    }

    #[test]
    fn test_rbgp_command_parses_same_surface() {
        let matches = cli_command(BINARY_NAME)
            .try_get_matches_from(["rbgp", "global"])
            .unwrap();
        let cli = Cli::from_arg_matches(&matches).unwrap();

        assert!(matches!(cli.command, Command::Global));
    }

    #[test]
    fn test_rbgp_completion_uses_short_name() {
        let mut output = Vec::new();
        generate_completions(Shell::Bash, BINARY_NAME, &mut output);
        let completion = String::from_utf8(output).unwrap();

        assert!(completion.contains("_rbgp()"));
        assert!(completion.contains("cmd=\"rbgp\""));
        assert!(!completion.contains("rustbgpctl"));
    }

    #[test]
    fn test_parse_global() {
        let cli = Cli::try_parse_from(["rbgp", "global"]).unwrap();
        assert!(matches!(cli.command, Command::Global));
    }

    #[test]
    fn test_parse_config_apply_confirmed() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "config",
            "apply",
            "--from-file",
            "candidate.toml",
            "--expected-runtime-snapshot-token",
            "kv1:old:1",
            "--confirm-id",
            "deploy-123",
            "--confirm-timeout",
            "120",
        ])
        .unwrap();
        let Command::Config {
            action:
                ConfigAction::Apply {
                    confirm_id,
                    confirm_timeout_seconds,
                    ..
                },
        } = cli.command
        else {
            panic!("expected config apply");
        };
        assert_eq!(confirm_id.as_deref(), Some("deploy-123"));
        assert_eq!(confirm_timeout_seconds, Some(120));
    }

    #[test]
    fn test_parse_config_apply_confirm_timeout_requires_confirm_id() {
        let result = Cli::try_parse_from([
            "rbgp",
            "config",
            "apply",
            "--from-file",
            "candidate.toml",
            "--expected-runtime-snapshot-token",
            "kv1:old:1",
            "--confirm-timeout",
            "120",
        ]);

        match result {
            Err(error) => {
                assert_eq!(
                    error.kind(),
                    clap::error::ErrorKind::MissingRequiredArgument
                );
            }
            Ok(_) => panic!("--confirm-timeout must require --confirm-id"),
        }
    }

    #[test]
    fn test_parse_config_confirm_abort_status() {
        let cli = Cli::try_parse_from(["rbgp", "config", "confirm", "deploy-123"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Config {
                action: ConfigAction::Confirm { .. }
            }
        ));

        let cli = Cli::try_parse_from(["rbgp", "config", "abort", "deploy-123"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Config {
                action: ConfigAction::Abort { .. }
            }
        ));

        let cli = Cli::try_parse_from(["rbgp", "config", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Config {
                action: ConfigAction::Status
            }
        ));
    }

    #[test]
    fn test_parse_health() {
        let cli = Cli::try_parse_from(["rbgp", "health"]).unwrap();
        assert!(matches!(cli.command, Command::Health));
    }

    #[test]
    fn test_parse_doctor() {
        let cli = Cli::try_parse_from(["rbgp", "doctor", "--output", "support"]).unwrap();
        if let Command::Doctor { output } = cli.command {
            assert_eq!(output.as_deref(), Some(std::path::Path::new("support")));
        } else {
            panic!("expected Doctor command");
        }
    }

    #[test]
    fn test_parse_neighbor_list() {
        let cli = Cli::try_parse_from(["rbgp", "neighbor"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Neighbor {
                address: None,
                action: None
            }
        ));
    }

    #[test]
    fn test_parse_summary_alias() {
        let cli = Cli::try_parse_from(["rbgp", "summary"]).unwrap();
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
        let cli = Cli::try_parse_from(["rbgp", "neighbor", "10.0.0.1"]).unwrap();
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
            "rbgp",
            "neighbor",
            "10.0.0.1",
            "add",
            "--asn",
            "65001",
            "--role",
            "provider",
            "--strict-role",
        ])
        .unwrap();
        if let Command::Neighbor {
            address: Some(addr),
            action:
                Some(NeighborAction::Add {
                    asn,
                    role,
                    strict_role,
                    ..
                }),
        } = cli.command
        {
            assert_eq!(addr, "10.0.0.1");
            assert_eq!(asn, 65001);
            assert_eq!(role.as_deref(), Some("provider"));
            assert!(strict_role);
        } else {
            panic!("expected Neighbor Add command");
        }
    }

    #[test]
    fn test_parse_rib_best() {
        let cli = Cli::try_parse_from(["rbgp", "rib"]).unwrap();
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
        let cli = Cli::try_parse_from(["rbgp", "rib", "received", "10.0.0.1"]).unwrap();
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
    fn test_parse_familiar_rib_aliases() {
        let cli = Cli::try_parse_from(["rbgp", "rib", "recv", "10.0.0.1"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Rib {
                action: Some(RibAction::Received { .. }),
                ..
            }
        ));

        let cli = Cli::try_parse_from(["rbgp", "rib", "sent", "10.0.0.1"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Rib {
                action: Some(RibAction::Advertised { .. }),
                ..
            }
        ));
    }

    #[test]
    fn test_parse_rib_bgpls() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "rib",
            "bgpls",
            "--family",
            "linkstate_vpn",
            "--peer",
            "192.0.2.1",
            "--nlri-type",
            "1",
        ])
        .unwrap();
        if let Command::Rib {
            action:
                Some(RibAction::BgpLs {
                    family,
                    peer,
                    nlri_type,
                }),
            ..
        } = cli.command
        {
            assert_eq!(family.as_deref(), Some("linkstate_vpn"));
            assert_eq!(peer.as_deref(), Some("192.0.2.1"));
            assert_eq!(nlri_type, Some(1));
        } else {
            panic!("expected Rib BGP-LS command");
        }
    }

    #[test]
    fn rib_blackholes_rejects_route_filters() {
        let err = reject_rib_status_filters(
            BINARY_NAME,
            "blackholes",
            RibStatusFilterArgs {
                family: &Some("ipv4_unicast".to_string()),
                prefix: &None,
                longer: false,
                explain: false,
                explain_peer: &None,
                origin_asn: None,
                community: &[],
                large_community: &[],
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("use `rbgp rib blackholes`"),
            "unexpected error: {err}"
        );

        let err = reject_rib_status_filters(
            BINARY_NAME,
            "blackholes",
            RibStatusFilterArgs {
                family: &None,
                prefix: &Some("203.0.113.66/32".to_string()),
                longer: false,
                explain: false,
                explain_peer: &None,
                origin_asn: None,
                community: &[],
                large_community: &[],
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("use `rbgp rib blackholes`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rib_fib_rejects_route_filters() {
        let err = reject_rib_status_filters(
            BINARY_NAME,
            "fib",
            RibStatusFilterArgs {
                family: &None,
                prefix: &Some("203.0.113.0/24".to_string()),
                longer: false,
                explain: false,
                explain_peer: &None,
                origin_asn: None,
                community: &[],
                large_community: &[],
            },
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("`rbgp rib fib --prefix 203.0.113.0/24`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parse_rib_fib_filters() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "rib",
            "fib",
            "--table",
            "edge",
            "--state",
            "rejected",
            "--reason",
            "route_limit_exceeded",
            "--prefix",
            "203.0.113.0/24",
            "--peer",
            "198.51.100.2",
            "--page-size",
            "50",
            "--page-token",
            "100",
        ])
        .unwrap();

        if let Command::Rib {
            action:
                Some(RibAction::Fib {
                    table,
                    state,
                    reason,
                    prefix,
                    peer,
                    page_size,
                    page_token,
                }),
            ..
        } = cli.command
        {
            assert_eq!(table.as_deref(), Some("edge"));
            assert_eq!(state.as_deref(), Some("rejected"));
            assert_eq!(reason.as_deref(), Some("route_limit_exceeded"));
            assert_eq!(prefix.as_deref(), Some("203.0.113.0/24"));
            assert_eq!(peer.as_deref(), Some("198.51.100.2"));
            assert_eq!(page_size, Some(50));
            assert_eq!(page_token.as_deref(), Some("100"));
        } else {
            panic!("expected Rib Fib command");
        }
    }

    #[test]
    fn test_parse_rib_advertised_explain() {
        let cli = Cli::try_parse_from([
            "rbgp",
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
    fn test_parse_diff_advertised() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "diff",
            "advertised",
            "--peer",
            "192.0.2.1",
            "--against",
            "incumbent.ndjson",
            "--ignore-attribute",
            "med",
            "--max-routes",
            "1000",
        ])
        .unwrap();
        let Command::Diff {
            action:
                DiffAction::Advertised {
                    peer,
                    against,
                    ignore_attribute,
                    max_routes,
                    max_input_bytes,
                    detail,
                    deadline,
                    ..
                },
        } = cli.command
        else {
            panic!("expected Diff Advertised command");
        };
        assert_eq!(peer, vec!["192.0.2.1"]);
        assert_eq!(against, "incumbent.ndjson");
        assert_eq!(ignore_attribute, vec!["med"]);
        assert_eq!(max_routes, 1000);
        assert_eq!(max_input_bytes, 1 << 30);
        assert_eq!(detail, 20);
        assert_eq!(deadline, 120);
    }

    #[test]
    fn test_parse_policy_counters_alias() {
        let cli = Cli::try_parse_from(["rbgp", "policy", "counters"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Policy {
                action: PolicyAction::Stats { .. }
            }
        ));
    }

    #[test]
    fn test_parse_evpn_diagnose() {
        let cli = Cli::try_parse_from(["rbgp", "evpn", "diagnose"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Evpn {
                action: Some(EvpnAction::Diagnose),
                ..
            }
        ));
    }

    #[test]
    fn test_parse_evpn_nexthops() {
        let cli = Cli::try_parse_from(["rbgp", "evpn", "nexthops"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Evpn {
                action: Some(EvpnAction::Nexthops),
                ..
            }
        ));
    }

    #[test]
    fn test_parse_evpn_managed_netdevs() {
        let cli = Cli::try_parse_from(["rbgp", "evpn", "managed-netdevs"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Evpn {
                action: Some(EvpnAction::ManagedNetdevs),
                ..
            }
        ));
    }

    #[test]
    fn test_parse_evpn_add_ip_prefix() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "evpn",
            "add-ip-prefix",
            "--rd",
            "65000:5000",
            "--prefix",
            "10.50.0.0/24",
            "--label",
            "5000",
            "--next-hop",
            "192.0.2.10",
            "--gateway",
            "192.0.2.254",
            "--router-mac",
            "02:00:00:00:50:00",
            "--rt",
            "65000:5000",
        ])
        .unwrap();
        if let Command::Evpn {
            action:
                Some(EvpnAction::AddIpPrefix {
                    rd,
                    prefix,
                    label,
                    gateway,
                    router_mac,
                    ..
                }),
            ..
        } = cli.command
        {
            assert_eq!(rd, "65000:5000");
            assert_eq!(prefix, "10.50.0.0/24");
            assert_eq!(label, 5000);
            assert_eq!(gateway.as_deref(), Some("192.0.2.254"));
            assert_eq!(router_mac.as_deref(), Some("02:00:00:00:50:00"));
        } else {
            panic!("expected Evpn AddIpPrefix command");
        }
    }

    #[test]
    fn test_parse_evpn_add_ip_prefix_without_router_mac_for_no_vxlan() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "evpn",
            "add-ip-prefix",
            "--rd",
            "65000:5000",
            "--prefix",
            "10.50.0.0/24",
            "--label",
            "5000",
            "--next-hop",
            "192.0.2.10",
            "--rt",
            "65000:5000",
            "--no-vxlan-encap",
        ])
        .unwrap();
        if let Command::Evpn {
            action:
                Some(EvpnAction::AddIpPrefix {
                    gateway,
                    router_mac,
                    no_vxlan_encap,
                    ..
                }),
            ..
        } = cli.command
        {
            assert!(gateway.is_none());
            assert!(router_mac.is_none());
            assert!(no_vxlan_encap);
        } else {
            panic!("expected Evpn AddIpPrefix command");
        }
    }

    #[test]
    fn test_parse_evpn_delete_ip_prefix() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "evpn",
            "delete-ip-prefix",
            "--rd",
            "65000:5000",
            "--prefix",
            "10.50.0.0/24",
        ])
        .unwrap();
        if let Command::Evpn {
            action: Some(EvpnAction::DeleteIpPrefix { rd, prefix, .. }),
            ..
        } = cli.command
        {
            assert_eq!(rd, "65000:5000");
            assert_eq!(prefix, "10.50.0.0/24");
        } else {
            panic!("expected Evpn DeleteIpPrefix command");
        }
    }

    #[test]
    fn test_parse_evpn_clear_duplicate_mac() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "evpn",
            "clear-duplicate-mac",
            "--vni",
            "100",
            "--mac",
            "aa:bb:cc:dd:ee:ff",
        ])
        .unwrap();
        if let Command::Evpn {
            action: Some(EvpnAction::ClearDuplicateMac { vni, mac }),
            ..
        } = cli.command
        {
            assert_eq!(vni, 100);
            assert_eq!(mac, "aa:bb:cc:dd:ee:ff");
        } else {
            panic!("expected Evpn ClearDuplicateMac command");
        }
    }

    #[test]
    fn test_parse_evpn_es_drain_and_undrain() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "evpn",
            "es",
            "list",
            "00:11:22:33:44:55:66:77:88:99",
        ])
        .unwrap();
        if let Command::Evpn {
            action:
                Some(EvpnAction::Es {
                    action: EsAction::List { esi },
                }),
            ..
        } = cli.command
        {
            assert_eq!(esi.as_deref(), Some("00:11:22:33:44:55:66:77:88:99"));
        } else {
            panic!("expected Evpn Es List command");
        }

        let cli = Cli::try_parse_from([
            "rbgp",
            "evpn",
            "es",
            "drain",
            "00:11:22:33:44:55:66:77:88:99",
        ])
        .unwrap();
        if let Command::Evpn {
            action:
                Some(EvpnAction::Es {
                    action: EsAction::Drain { esi },
                }),
            ..
        } = cli.command
        {
            assert_eq!(esi, "00:11:22:33:44:55:66:77:88:99");
        } else {
            panic!("expected Evpn Es Drain command");
        }

        let cli = Cli::try_parse_from([
            "rbgp",
            "evpn",
            "es",
            "undrain",
            "00:11:22:33:44:55:66:77:88:99",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Evpn {
                action: Some(EvpnAction::Es {
                    action: EsAction::Undrain { .. }
                }),
                ..
            }
        ));
    }

    #[test]
    fn test_parse_evpn_runtime() {
        let cli = Cli::try_parse_from(["rbgp", "evpn", "runtime"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Evpn {
                action: Some(EvpnAction::Runtime),
                ..
            }
        ));
    }

    #[test]
    fn test_parse_rib_add() {
        let cli =
            Cli::try_parse_from(["rbgp", "rib", "add", "10.0.0.0/24", "--nexthop", "10.0.0.1"])
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
        let cli = Cli::try_parse_from(["rbgp", "shutdown", "--reason", "maintenance"]).unwrap();
        if let Command::Shutdown { reason } = cli.command {
            assert_eq!(reason.unwrap(), "maintenance");
        } else {
            panic!("expected Shutdown command");
        }
    }

    #[test]
    fn test_parse_json_flag() {
        let cli = Cli::try_parse_from(["rbgp", "--json", "health"]).unwrap();
        assert!(cli.json);
    }

    #[test]
    fn test_parse_no_color_flag() {
        let cli = Cli::try_parse_from(["rbgp", "--no-color", "health"]).unwrap();
        assert!(cli.no_color);
    }

    #[test]
    fn test_parse_addr_flag() {
        let cli = Cli::try_parse_from(["rbgp", "--addr", "10.0.0.1:50051", "health"]).unwrap();
        assert_eq!(cli.addr, "10.0.0.1:50051");
    }

    #[test]
    fn test_parse_unix_addr_flag() {
        let cli =
            Cli::try_parse_from(["rbgp", "--addr", "unix:///run/rustbgpd/grpc.sock", "health"])
                .unwrap();
        assert_eq!(cli.addr, "unix:///run/rustbgpd/grpc.sock");
    }

    #[test]
    fn test_parse_token_file_flag() {
        let cli =
            Cli::try_parse_from(["rbgp", "--token-file", "/run/rustbgpd/token", "health"]).unwrap();
        assert_eq!(cli.token_file.as_deref(), Some("/run/rustbgpd/token"));
    }

    #[test]
    fn test_parse_watch() {
        let cli = Cli::try_parse_from(["rbgp", "watch"]).unwrap();
        assert!(matches!(cli.command, Command::Watch { .. }));
    }

    #[test]
    fn test_parse_events() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "events",
            "--prefix",
            "203.0.113.0/24",
            "--limit",
            "25",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Events {
                action: None,
                prefix: Some(ref prefix),
                limit: Some(25),
                ..
            } if prefix == "203.0.113.0/24"
        ));
    }

    #[test]
    fn test_parse_events_watch() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "events",
            "watch",
            "--prefix",
            "203.0.113.0/24",
            "--type",
            "added,best_changed",
            "--backfill",
            "25",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Events {
                action: Some(EventsAction::Watch {
                    prefix: Some(ref prefix),
                    ref event_types,
                    backfill: 25,
                    ..
                }),
                ..
            } if prefix == "203.0.113.0/24" && event_types.len() == 2
        ));
    }

    #[test]
    fn test_parse_events_watch_category() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "events",
            "watch",
            "--category",
            "session",
            "--type",
            "established,lost",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Events {
                action: Some(EventsAction::Watch {
                    ref categories,
                    ref event_types,
                    ..
                }),
                ..
            } if categories == &vec!["session".to_string()] && event_types.len() == 2
        ));
    }

    #[test]
    fn test_parse_events_watch_policy_category() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "events",
            "watch",
            "--category",
            "policy",
            "--type",
            "policy_changed",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Events {
                action: Some(EventsAction::Watch {
                    ref categories,
                    ref event_types,
                    ..
                }),
                ..
            } if categories == &vec!["policy".to_string()] && event_types == &vec!["policy_changed".to_string()]
        ));
    }

    #[test]
    fn test_parse_events_sessions() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "events",
            "sessions",
            "--address",
            "10.0.0.2",
            "--type",
            "established,lost",
            "--limit",
            "5",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Events {
                action: Some(EventsAction::Sessions {
                    address: Some(ref address),
                    ref event_types,
                    limit: Some(5),
                }),
                ..
            } if address == "10.0.0.2" && event_types.len() == 2
        ));
    }

    #[test]
    fn test_parse_events_policy() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "events",
            "policy",
            "--address",
            "10.0.0.2",
            "--type",
            "policy_changed",
            "--limit",
            "5",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Events {
                action: Some(EventsAction::Policy {
                    address: Some(ref address),
                    ref event_types,
                    limit: Some(5),
                }),
                ..
            } if address == "10.0.0.2" && event_types == &vec!["policy_changed".to_string()]
        ));
    }

    #[test]
    fn test_parse_events_evpn() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "events",
            "evpn",
            "--address",
            "10.0.0.2",
            "--route-type",
            "2",
            "--rd",
            "65000:100",
            "--type",
            "evpn_added,evpn_best_changed",
            "--limit",
            "5",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Events {
                action: Some(EventsAction::Evpn {
                    address: Some(ref address),
                    route_type: Some(2),
                    rd: Some(ref rd),
                    ref event_types,
                    limit: Some(5),
                }),
                ..
            } if address == "10.0.0.2"
                && rd == "65000:100"
                && event_types == &vec!["evpn_added".to_string(), "evpn_best_changed".to_string()]
        ));
    }

    #[test]
    fn events_parent_filters_are_rejected_for_subcommands() {
        let err = reject_events_parent_filters_for_subcommand(
            "events sessions",
            &Some("10.0.0.2".to_string()),
            &None,
            &None,
            Some(5),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("route-history filters"),
            "unexpected error: {err}"
        );

        let cli = Cli::try_parse_from([
            "rbgp",
            "events",
            "--address",
            "10.0.0.2",
            "--limit",
            "5",
            "sessions",
            "--type",
            "lost",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Events {
                action: Some(EventsAction::Sessions {
                    address: None,
                    ref event_types,
                    limit: None,
                }),
                address: Some(ref address),
                limit: Some(5),
                ..
            } if address == "10.0.0.2" && event_types == &vec!["lost".to_string()]
        ));
    }

    #[test]
    fn test_parse_events_watch_dataplane_category() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "events",
            "watch",
            "--category",
            "dataplane",
            "--type",
            "dataplane_status_changed",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Events {
                action: Some(EventsAction::Watch {
                    ref categories,
                    ref event_types,
                    ..
                }),
                ..
            } if categories == &vec!["dataplane".to_string()] && event_types.len() == 1
        ));
    }

    #[test]
    fn test_parse_events_watch_evpn_category() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "events",
            "watch",
            "--category",
            "evpn",
            "--type",
            "evpn_added,evpn_withdrawn",
            "--address",
            "192.0.2.1",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Events {
                action: Some(EventsAction::Watch {
                    ref categories,
                    ref event_types,
                    address: Some(ref address),
                    ..
                }),
                ..
            } if categories == &vec!["evpn".to_string()]
                && event_types == &vec!["evpn_added".to_string(), "evpn_withdrawn".to_string()]
                && address == "192.0.2.1"
        ));
    }

    #[test]
    fn test_parse_events_watch_comma_filters() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "events",
            "watch",
            "--category",
            "route,session",
            "--type",
            "added,established",
            "--address",
            "192.0.2.1",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Events {
                action: Some(EventsAction::Watch {
                    ref categories,
                    ref event_types,
                    address: Some(ref address),
                    ..
                }),
                ..
            } if categories == &vec!["route".to_string(), "session".to_string()]
                && event_types == &vec!["added".to_string(), "established".to_string()]
                && address == "192.0.2.1"
        ));
    }

    #[test]
    fn test_parse_community_str() {
        assert_eq!(
            parse_community_str("65001:100").unwrap(),
            (65001 << 16) | 100
        );
        assert_eq!(
            parse_community_str("BLACKHOLE").unwrap(),
            rustbgpd_wire::COMMUNITY_BLACKHOLE
        );
        assert_eq!(
            parse_community_str("NO_EXPORT").unwrap(),
            rustbgpd_wire::COMMUNITY_NO_EXPORT
        );
        assert_eq!(
            parse_community_str("NO_ADVERTISE").unwrap(),
            rustbgpd_wire::COMMUNITY_NO_ADVERTISE
        );
        assert_eq!(
            parse_community_str("NO_EXPORT_SUBCONFED").unwrap(),
            rustbgpd_wire::COMMUNITY_NO_EXPORT_SUBCONFED
        );
        assert_eq!(
            parse_community_str("GRACEFUL_SHUTDOWN").unwrap(),
            rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN
        );
        assert_eq!(
            parse_community_str("LLGR_STALE").unwrap(),
            rustbgpd_wire::COMMUNITY_LLGR_STALE
        );
        assert_eq!(
            parse_community_str("NO_LLGR").unwrap(),
            rustbgpd_wire::COMMUNITY_NO_LLGR
        );
        assert!(parse_community_str("invalid").is_err());
        assert!(parse_community_str("70000:1").is_err());
    }

    #[test]
    fn test_parse_policy_list() {
        let cli = Cli::try_parse_from(["rbgp", "policy", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Policy {
                action: PolicyAction::List
            }
        ));
    }

    #[test]
    fn test_parse_policy_set_requires_from_file() {
        // Missing --from-file flag should be a parse error.
        let result = Cli::try_parse_from(["rbgp", "policy", "set", "p1"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_policy_chain_set_import() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "policy",
            "chain",
            "set-import",
            "--neighbor",
            "10.0.0.2",
            "p1",
            "p2",
        ])
        .unwrap();
        if let Command::Policy {
            action:
                PolicyAction::Chain {
                    action: PolicyChainAction::SetImport { neighbor, policies },
                },
        } = cli.command
        {
            assert_eq!(neighbor.as_deref(), Some("10.0.0.2"));
            assert_eq!(policies, vec!["p1".to_string(), "p2".to_string()]);
        } else {
            panic!("expected Policy Chain SetImport");
        }
    }

    #[test]
    fn test_parse_neighbor_set_get() {
        let cli = Cli::try_parse_from(["rbgp", "neighbor-set", "get", "transit-peers"]).unwrap();
        if let Command::NeighborSet {
            action: NeighborSetAction::Get { name },
        } = cli.command
        {
            assert_eq!(name, "transit-peers");
        } else {
            panic!("expected NeighborSet Get");
        }
    }

    #[test]
    fn test_parse_peer_group_attach() {
        let cli = Cli::try_parse_from([
            "rbgp",
            "peer-group",
            "attach",
            "10.0.0.2",
            "--group",
            "transit",
        ])
        .unwrap();
        if let Command::PeerGroup {
            action: PeerGroupAction::Attach { address, group },
        } = cli.command
        {
            assert_eq!(address, "10.0.0.2");
            assert_eq!(group, "transit");
        } else {
            panic!("expected PeerGroup Attach");
        }
    }
}

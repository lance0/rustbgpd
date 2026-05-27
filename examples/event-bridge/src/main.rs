//! Reference external-collector bridge for ADR-0072.
//!
//! Streams `BgpEvent` from a running rustbgpd over the
//! `SubscribeFromEvent` gRPC RPC and writes one JSON object per
//! line to stdout. This is a **reference skeleton**, not a
//! maintained bus connector — operators copy this and replace the
//! stdout writer with their Kafka / NATS / Vector / journald sink,
//! and persist `last_seen_event_id` after their downstream sink
//! confirms durable receipt of each event.
//!
//! Cursor semantics (`--from-event-id`):
//!
//! - absent (default) ⇒ live-only stream, no replay.
//! - `0`              ⇒ replay everything retained, then live.
//! - `N` (`N > 0`)    ⇒ replay events with `event_id > N`, then live.
//!
//! If the daemon emits a leading `StreamLagEvent` (cursor older
//! than retention), the bridge emits it as a JSON line marked
//! `category: "unspecified", event_type: "BGP_EVENT_TYPE_STREAM_LAGGED"`
//! and then continues. Operators should alert on those.
//!
//! Global-ordering caveat: events are emitted in `event_id` order
//! at the source (EHM-actor arrival order). Causal joins across
//! categories should use `timestamp` from each event, not
//! `event_id`. See ADR-0072.

use std::io::Write;

use clap::Parser;
use rustbgpd_api::json_format::bgp_event_to_json_line;
use rustbgpd_api::proto;
use tonic::transport::Channel;

#[derive(Parser, Debug)]
#[command(
    name = "event-bridge",
    about = "Reference bridge: SubscribeFromEvent → JSON-lines on stdout"
)]
struct Args {
    /// rustbgpd gRPC endpoint, e.g. `http://127.0.0.1:50051`.
    #[arg(long, env = "EVENT_BRIDGE_ADDR")]
    addr: String,

    /// Optional durable cursor. Absent ⇒ live-only. `0` ⇒ replay
    /// everything retained, then live. `N > 0` ⇒ replay events
    /// with `event_id > N`, then live.
    #[arg(long, value_name = "EVENT_ID")]
    from_event_id: Option<u64>,

    /// Restrict to one or more categories. Repeat the flag or
    /// comma-separate. Valid: route, session, policy, evpn, bfd,
    /// dataplane.  Empty selects all retained categories.
    #[arg(long = "category", value_delimiter = ',')]
    categories: Vec<String>,
}

fn parse_category(s: &str) -> Option<proto::EventCategory> {
    match s.to_ascii_lowercase().as_str() {
        "route" => Some(proto::EventCategory::Route),
        "session" => Some(proto::EventCategory::Session),
        "policy" => Some(proto::EventCategory::Policy),
        "evpn" => Some(proto::EventCategory::Evpn),
        "bfd" => Some(proto::EventCategory::Bfd),
        "dataplane" => Some(proto::EventCategory::Dataplane),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    // Resolve category labels into the proto enum ints.
    let categories: Vec<i32> = args
        .categories
        .iter()
        .map(String::as_str)
        .map(|s| parse_category(s).ok_or_else(|| format!("unknown category: {s}")))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|c| c as i32)
        .collect();

    tracing::info!(addr = %args.addr, from_event_id = ?args.from_event_id, "connecting to rustbgpd");
    let channel = Channel::from_shared(args.addr.clone())?.connect().await?;
    let mut client = proto::event_service_client::EventServiceClient::new(channel);

    let request = proto::SubscribeFromEventRequest {
        from_event_id: args.from_event_id,
        categories,
        event_types: Vec::new(),
        neighbor_address: String::new(),
        afi_safi: proto::AddressFamily::Unspecified as i32,
        prefix: String::new(),
        prefix_length: 0,
    };

    let mut stream = client.subscribe_from_event(request).await?.into_inner();

    // `last_seen_event_id` is in-memory only on purpose: a real
    // operator wrapper persists it externally **after** their
    // downstream sink confirms durable receipt. We expose the
    // value via a final summary line on stream end so the wrapper
    // can do its own bookkeeping for the next reconnect.
    let mut last_seen: Option<u64> = None;
    let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());

    while let Some(event) = stream.message().await? {
        let line = bgp_event_to_json_line(&event);
        // Write + newline + flush: only update `last_seen` after a
        // successful flushed write so a partial-write crash does
        // not advance the cursor past unwritten events. This is
        // the property an external wrapper would persist.
        stdout.write_all(line.as_bytes())?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        if let Some(id) = event.event_id {
            last_seen = Some(id);
        }
    }

    if let Some(id) = last_seen {
        tracing::info!(last_seen_event_id = id, "stream ended");
    } else {
        tracing::info!("stream ended with no events delivered");
    }
    Ok(())
}

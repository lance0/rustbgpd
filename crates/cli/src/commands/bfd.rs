//! `rustbgpctl bfd` — single-hop BFD session inspection (ADR-0067).

use crate::connection::Connection;
use crate::error::CliError;
use crate::proto::bfd_service_client::BfdServiceClient;
use crate::proto::{BfdSession, BfdSessionState, GetBfdSessionsRequest};
use serde::Serialize;

#[derive(Serialize)]
struct JsonBfdSession {
    peer_address: String,
    state: String,
    diagnostic: String,
    strict: bool,
}

fn state_label(state: i32) -> &'static str {
    match BfdSessionState::try_from(state).unwrap_or(BfdSessionState::Unspecified) {
        BfdSessionState::Up => "up",
        BfdSessionState::Down => "down",
        BfdSessionState::Init => "init",
        BfdSessionState::AdminDown => "admin-down",
        BfdSessionState::Unspecified => "unspecified",
    }
}

fn to_json(session: &BfdSession) -> JsonBfdSession {
    JsonBfdSession {
        peer_address: session.peer_address.clone(),
        state: state_label(session.state).to_string(),
        diagnostic: session.diagnostic.clone(),
        strict: session.strict,
    }
}

async fn fetch(connection: Connection, peer: Option<&str>) -> Result<Vec<BfdSession>, CliError> {
    let mut client =
        BfdServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .get_bfd_sessions(GetBfdSessionsRequest {
            peer_address: peer.unwrap_or_default().to_string(),
        })
        .await?
        .into_inner();
    Ok(resp.sessions)
}

/// List all BFD sessions.
pub async fn list(connection: Connection, json: bool) -> Result<(), CliError> {
    let sessions = fetch(connection, None).await?;
    print_sessions(&sessions, json);
    Ok(())
}

/// Show a single BFD session by peer address.
pub async fn show(connection: Connection, peer: &str, json: bool) -> Result<(), CliError> {
    let sessions = fetch(connection, Some(peer)).await?;
    print_sessions(&sessions, json);
    Ok(())
}

fn print_sessions(sessions: &[BfdSession], json: bool) {
    if json {
        let out: Vec<JsonBfdSession> = sessions.iter().map(to_json).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out)
                .expect("failed to serialize BFD session list as JSON")
        );
    } else if sessions.is_empty() {
        println!("No BFD sessions");
    } else {
        println!("{:<40} {:<11} {:<7} Diagnostic", "Peer", "State", "Strict");
        println!("{}", "-".repeat(80));
        for s in sessions {
            println!(
                "{:<40} {:<11} {:<7} {}",
                s.peer_address,
                state_label(s.state),
                if s.strict { "yes" } else { "no" },
                s.diagnostic
            );
        }
    }
}

//! `rbgp bfd` — single-hop BFD session inspection (ADR-0067).

use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::bfd_service_client::BfdServiceClient;
use crate::proto::{BfdSession, BfdSessionState, GetBfdSessionsRequest};
use serde::Serialize;

#[derive(Serialize)]
struct JsonBfdSession {
    peer_address: String,
    state: String,
    diagnostic: String,
    strict: bool,
    remote_administrative_down: Option<bool>,
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
        remote_administrative_down: session.remote_administrative_down,
    }
}

/// Human diagnostic text. Healthy/current-daemon rows stay byte-for-byte
/// identical to the pre-field output; only a locally Down session needs the
/// additional RFC 5882 cause context.
fn human_diagnostic(session: &BfdSession) -> String {
    if BfdSessionState::try_from(session.state) != Ok(BfdSessionState::Down) {
        return session.diagnostic.clone();
    }
    match session.remote_administrative_down {
        Some(true) => format!("{} (remote AdminDown; BGP permitted)", session.diagnostic),
        Some(false) => session.diagnostic.clone(),
        None => format!(
            "{} (remote AdminDown cause unknown; serving daemon predates field 5)",
            session.diagnostic
        ),
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
    print_sessions(&sessions, json)
}

/// Show a single BFD session by peer address.
pub async fn show(connection: Connection, peer: &str, json: bool) -> Result<(), CliError> {
    let sessions = fetch(connection, Some(peer)).await?;
    print_sessions(&sessions, json)
}

fn print_sessions(sessions: &[BfdSession], json: bool) -> Result<(), CliError> {
    if json {
        let out: Vec<JsonBfdSession> = sessions.iter().map(to_json).collect();
        output::print_json_pretty(&out)?;
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
                human_diagnostic(s)
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;
    use tonic::Code;

    fn session(
        peer: &str,
        state: BfdSessionState,
        diagnostic: &str,
        strict: bool,
        remote_administrative_down: Option<bool>,
    ) -> BfdSession {
        BfdSession {
            peer_address: peer.to_string(),
            state: state as i32,
            diagnostic: diagnostic.to_string(),
            strict,
            remote_administrative_down,
        }
    }

    fn server_session(
        peer: &str,
        state: BfdSessionState,
        diagnostic: &str,
        strict: bool,
        remote_administrative_down: Option<bool>,
    ) -> rustbgpd_api::proto::BfdSession {
        rustbgpd_api::proto::BfdSession {
            peer_address: peer.to_string(),
            state: state as i32,
            diagnostic: diagnostic.to_string(),
            strict,
            remote_administrative_down,
        }
    }

    #[test]
    fn bfd_session_json_shape_is_stable() {
        let value = serde_json::to_value(to_json(&session(
            "192.0.2.1",
            BfdSessionState::Down,
            "none",
            true,
            Some(true),
        )))
        .unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "peer_address": "192.0.2.1",
                "state": "down",
                "diagnostic": "none",
                "strict": true,
                "remote_administrative_down": true,
            })
        );
    }

    /// Load-bearing proof: defaulting an absent optional bool to false makes
    /// the JSON `null` assertion and the human unknown-cause assertion red;
    /// adding unconditional text makes the healthy byte-identity assertion red.
    #[test]
    fn remote_admin_down_presence_and_human_labels_are_explicit() {
        let healthy = session("192.0.2.1", BfdSessionState::Up, "none", false, Some(false));
        assert_eq!(human_diagnostic(&healthy), "none");

        let old_down = session("192.0.2.1", BfdSessionState::Down, "none", true, None);
        assert!(human_diagnostic(&old_down).contains("cause unknown"));
        assert_eq!(
            serde_json::to_value(to_json(&old_down)).unwrap()["remote_administrative_down"],
            serde_json::Value::Null,
        );

        let remote_admin_down =
            session("192.0.2.1", BfdSessionState::Down, "none", true, Some(true));
        assert_eq!(
            human_diagnostic(&remote_admin_down),
            "none (remote AdminDown; BGP permitted)"
        );
    }

    #[tokio::test]
    async fn list_sends_empty_filter_and_renders_sessions() {
        let server = spawn_mock_server(None).await;
        *server.state.bfd_sessions.lock().await = vec![server_session(
            "192.0.2.1",
            BfdSessionState::Up,
            "none",
            false,
            Some(false),
        )];
        let connection = connect(&server.addr, None).await.unwrap();

        list(connection, true).await.unwrap();

        assert_eq!(server.state.bfd_calls.load(Ordering::SeqCst), 1);
        let request = server
            .state
            .last_bfd_request
            .lock()
            .await
            .clone()
            .expect("BFD request captured");
        assert!(request.peer_address.is_empty());
    }

    #[tokio::test]
    async fn show_sends_peer_filter() {
        let server = spawn_mock_server(None).await;
        *server.state.bfd_sessions.lock().await = vec![
            server_session("192.0.2.1", BfdSessionState::Up, "none", false, Some(false)),
            server_session(
                "192.0.2.2",
                BfdSessionState::Down,
                "control_detection_time_expired",
                true,
                Some(false),
            ),
        ];
        let connection = connect(&server.addr, None).await.unwrap();

        show(connection, "192.0.2.2", true).await.unwrap();

        assert_eq!(server.state.bfd_calls.load(Ordering::SeqCst), 1);
        let request = server
            .state
            .last_bfd_request
            .lock()
            .await
            .clone()
            .expect("BFD request captured");
        assert_eq!(request.peer_address, "192.0.2.2");
    }

    #[tokio::test]
    async fn list_rpc_error_maps_to_cli_error() {
        let server = spawn_mock_server(None).await;
        *server.state.bfd_error.lock().await =
            Some((Code::PermissionDenied, "bfd denied".to_string()));
        let connection = connect(&server.addr, None).await.unwrap();

        let err = list(connection, true)
            .await
            .expect_err("RPC error should map to CliError");

        assert!(
            matches!(err, CliError::Rpc(ref message) if message.contains("bfd denied")),
            "{err:?}"
        );
        assert_eq!(server.state.bfd_calls.load(Ordering::SeqCst), 1);
    }
}

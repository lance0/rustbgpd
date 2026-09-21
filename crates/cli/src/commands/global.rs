use crate::connection::{Connection, read_rpc};
use crate::error::CliError;
use crate::output::{self, JsonGlobal, outln};
use crate::proto::GetGlobalRequest;
use crate::proto::global_service_client::GlobalServiceClient;

fn tcp_ao_support_label(value: i32) -> &'static str {
    match crate::proto::TcpAoSupport::try_from(value) {
        Ok(crate::proto::TcpAoSupport::Supported) => "supported",
        Ok(crate::proto::TcpAoSupport::Unsupported) => "unsupported",
        Ok(crate::proto::TcpAoSupport::ProbeFailed) => "probe_failed",
        Ok(crate::proto::TcpAoSupport::Unspecified) | Err(_) => "unknown",
    }
}

fn json_global(resp: &crate::proto::GlobalState) -> JsonGlobal {
    JsonGlobal {
        asn: resp.asn,
        router_id: resp.router_id.clone(),
        listen_port: resp.listen_port,
        tcp_ao_support: tcp_ao_support_label(resp.tcp_ao_support).to_string(),
        tcp_ao_detail: resp.tcp_ao_detail.clone(),
    }
}

pub async fn run(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        GlobalServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = read_rpc("GetGlobal", client.get_global(GetGlobalRequest {}))
        .await?
        .into_inner();

    if json {
        let out = json_global(&resp);
        output::print_json_pretty(&out)?;
    } else {
        outln!("ASN:         {}", resp.asn)?;
        outln!("Router ID:   {}", resp.router_id)?;
        outln!("Listen Port: {}", resp.listen_port)?;
        outln!(
            "TCP-AO:      {}{}",
            tcp_ao_support_label(resp.tcp_ao_support),
            if resp.tcp_ao_detail.is_empty() {
                String::new()
            } else {
                format!(" ({})", resp.tcp_ao_detail)
            }
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;

    #[test]
    fn global_json_projection_covers_curated_state() {
        let mut state = crate::proto::GlobalState {
            asn: u32::MAX,
            router_id: "192.0.2.1".into(),
            listen_port: 179,
            tcp_ao_support: 3,
            tcp_ao_detail: "inspection failed".into(),
            // Used by the policy freshness consumer, outside the global CLI summary.
            policy_generation_loaded_timestamp_seconds: i64::MAX,
        };
        assert_eq!(
            serde_json::to_value(json_global(&state)).unwrap(),
            serde_json::json!({
                "asn": u32::MAX, "router_id": "192.0.2.1", "listen_port": 179,
                "tcp_ao_support": "probe_failed", "tcp_ao_detail": "inspection failed"
            })
        );
        state.tcp_ao_detail.clear();
        state.tcp_ao_support = 999;
        assert_eq!(
            serde_json::to_value(json_global(&state)).unwrap(),
            serde_json::json!({
                "asn": u32::MAX, "router_id": "192.0.2.1", "listen_port": 179,
                "tcp_ao_support": "unknown"
            })
        );
    }

    #[tokio::test]
    async fn run_calls_get_global() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        run(connection, true).await.unwrap();

        assert_eq!(server.state.global_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn tcp_ao_support_labels_are_stable() {
        assert_eq!(
            tcp_ao_support_label(crate::proto::TcpAoSupport::Supported as i32),
            "supported"
        );
        assert_eq!(
            tcp_ao_support_label(crate::proto::TcpAoSupport::Unsupported as i32),
            "unsupported"
        );
        assert_eq!(
            tcp_ao_support_label(crate::proto::TcpAoSupport::ProbeFailed as i32),
            "probe_failed"
        );
    }
}

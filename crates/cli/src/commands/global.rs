use crate::connection::Connection;
use crate::error::CliError;
use crate::output::{self, JsonGlobal};
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

pub async fn run(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        GlobalServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client.get_global(GetGlobalRequest {}).await?.into_inner();

    if json {
        let out = JsonGlobal {
            asn: resp.asn,
            router_id: resp.router_id.clone(),
            listen_port: resp.listen_port,
            tcp_ao_support: tcp_ao_support_label(resp.tcp_ao_support).to_string(),
            tcp_ao_detail: resp.tcp_ao_detail.clone(),
        };
        output::print_json_pretty(&out)?;
    } else {
        println!("ASN:         {}", resp.asn);
        println!("Router ID:   {}", resp.router_id);
        println!("Listen Port: {}", resp.listen_port);
        println!(
            "TCP-AO:      {}{}",
            tcp_ao_support_label(resp.tcp_ao_support),
            if resp.tcp_ao_detail.is_empty() {
                String::new()
            } else {
                format!(" ({})", resp.tcp_ao_detail)
            }
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;

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

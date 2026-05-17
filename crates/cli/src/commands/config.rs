use crate::connection::Connection;
use crate::error::CliError;
use crate::proto::DiffRuntimeConfigRequest;
use crate::proto::config_service_client::ConfigServiceClient;

pub async fn diff(connection: Connection, from_file: &str, json: bool) -> Result<(), CliError> {
    let candidate_toml = std::fs::read_to_string(from_file)
        .map_err(|error| CliError::Argument(format!("failed to read {from_file}: {error}")))?;
    let mut client =
        ConfigServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .diff_runtime_config(DiffRuntimeConfigRequest { candidate_toml })
        .await?
        .into_inner();

    if json {
        println!("{}", resp.diff_json);
    } else {
        print!("{}", resp.human_text);
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
    async fn diff_sends_candidate_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.toml");
        std::fs::write(&path, "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n").unwrap();
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        diff(connection, path.to_str().unwrap(), true)
            .await
            .unwrap();

        assert_eq!(server.state.config_diff_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            server.state.last_config_diff.lock().await.as_deref(),
            Some("[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\n")
        );
    }
}

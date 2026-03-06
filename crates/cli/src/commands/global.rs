use crate::connection::Connection;
use crate::error::CliError;
use crate::output::JsonGlobal;
use crate::proto::GetGlobalRequest;
use crate::proto::global_service_client::GlobalServiceClient;

pub async fn run(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        GlobalServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client.get_global(GetGlobalRequest {}).await?.into_inner();

    if json {
        let out = JsonGlobal {
            asn: resp.asn,
            router_id: resp.router_id.clone(),
            listen_port: resp.listen_port,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("failed to serialize global state as JSON")
        );
    } else {
        println!("ASN:         {}", resp.asn);
        println!("Router ID:   {}", resp.router_id);
        println!("Listen Port: {}", resp.listen_port);
    }
    Ok(())
}

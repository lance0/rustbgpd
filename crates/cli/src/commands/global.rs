use tonic::transport::Channel;

use crate::error::CliError;
use crate::output::JsonGlobal;
use crate::proto::global_service_client::GlobalServiceClient;
use crate::proto::GetGlobalRequest;

pub async fn run(channel: Channel, json: bool) -> Result<(), CliError> {
    let mut client = GlobalServiceClient::new(channel);
    let resp = client
        .get_global(GetGlobalRequest {})
        .await?
        .into_inner();

    if json {
        let out = JsonGlobal {
            asn: resp.asn,
            router_id: resp.router_id.clone(),
            listen_port: resp.listen_port,
        };
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("ASN:         {}", resp.asn);
        println!("Router ID:   {}", resp.router_id);
        println!("Listen Port: {}", resp.listen_port);
    }
    Ok(())
}
